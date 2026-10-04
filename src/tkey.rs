//! Transaction key establishment: TKEY (RFC 2930) messages.
//!
//! A resolver establishes or deletes a shared TSIG key with a query for
//! type TKEY (RFC 2930 §4): the question is `key-name TKEY ANY` and the
//! additional section carries a TKEY record (owner: the key name, CLASS
//! ANY, TTL 0) with the algorithm, the requested validity, the mode and
//! the key exchange data. The server answers with a TKEY record in the
//! answer section; a non-zero TKEY error says why the exchange failed
//! (§2.6). Some modes need more records (a Diffie-Hellman KEY in the
//! additional section, §4.1) or authentication (deletion and resolver
//! assignment MUST be signed with TSIG or SIG(0), §4.2, §4.5): push and
//! sign them after the TKEY.
//!
//! This module builds and reads those messages; the key agreement itself
//! (Diffie-Hellman, GSS-API tokens, encryption under a KEY) is the
//! caller's. The record data is [`rdata::Tkey`](crate::rdata::Tkey).
//!
//! ```
//! use dnsbox::rdata::{Tkey, TkeyMode, TsigRcode};
//! use dnsbox::{Message, MessageBuilder, NameBuf, Section};
//! use dnsbox::tkey;
//!
//! // Resolver: start a GSS-API negotiation.
//! let key_name: NameBuf = "1234.sig-client.example".parse()?;
//! let alg: NameBuf = "gss-tsig".parse()?;
//! let token = [0x60, 0x82, 0x01, 0x00]; // from the GSS-API library
//! let mut buf = [0u8; 512];
//! let mut b = MessageBuilder::new(&mut buf)?;
//! b.set_id(0x2930);
//! tkey::build_query(&mut b, &key_name, &Tkey::new(alg.as_name(), 0, 0, TkeyMode::GSSAPI, &token))?;
//! let query = Message::parse_validated(b.finish())?;
//!
//! // Server: read the request, answer with its own token.
//! let request = tkey::find(&query)?.expect("a TKEY query");
//! assert_eq!(request.key_name, key_name.as_name());
//! assert_eq!(request.section, Section::Additional);
//! assert_eq!(request.data.mode, TkeyMode::GSSAPI);
//! let reply = Tkey { key: &[0xa1, 0x00], ..request.data };
//! let mut rbuf = [0u8; 512];
//! let mut r = MessageBuilder::new(&mut rbuf)?;
//! tkey::build_response(&mut r, &query, request.key_name, &reply)?;
//! let response = Message::parse_validated(r.finish())?;
//!
//! // Resolver: the answer.
//! let answer = tkey::find(&response)?.expect("a TKEY answer");
//! assert_eq!(answer.section, Section::Answer);
//! assert_eq!(answer.data.error, TsigRcode::NOERROR);
//! assert_eq!(answer.data.key, [0xa1, 0x00]);
//! # Ok::<(), dnsbox::Error>(())
//! ```

use crate::builder::MessageBuilder;
use crate::message::{Message, Section};
use crate::name::{Name, ToName};
use crate::rdata::{ParseRdata, Tkey};
use crate::wire::OutBuf;
use crate::{Class, Flags, Opcode, Result, Rtype};

/// Writes a TKEY query into an empty builder (RFC 2930 §4): opcode QUERY
/// with RD clear (§4: TKEY queries "SHOULD NOT be flagged as recursive"),
/// the question `key_name TKEY ANY`, and `tkey` in the additional section
/// as a record owned by `key_name`, CLASS ANY, TTL 0 (§2, §2.2). The ID is
/// left as set on the builder. Records the mode needs (a KEY, §4.1, §4.4)
/// and a TSIG or SIG(0) signature can be appended afterwards.
///
/// # Errors
///
/// [`Error::SectionOrder`](crate::Error::SectionOrder) if the builder is
/// not empty, [`Error::InvalidRdata`](crate::Error::InvalidRdata) if
/// `tkey` cannot be encoded, or
/// [`Error::BufferTooSmall`](crate::Error::BufferTooSmall) if the query
/// does not fit; on any error the builder is left unchanged.
///
/// ```
/// use dnsbox::rdata::{Tkey, TkeyMode};
/// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
/// use dnsbox::tkey;
///
/// // Ask the server to delete a key (to be signed with that key, §4.2).
/// let key_name: NameBuf = "key.example".parse()?;
/// let alg: NameBuf = "hmac-sha256".parse()?;
/// let mut buf = [0u8; 512];
/// let mut b = MessageBuilder::new(&mut buf)?;
/// tkey::build_query(&mut b, &key_name, &Tkey::new(alg.as_name(), 0, 0, TkeyMode::KEY_DELETION, &[]))?;
/// let query = Message::parse_validated(b.finish())?;
/// assert!(!query.flags().rd());
/// let q = query.questions().next().unwrap()?;
/// assert_eq!((q.qtype(), q.qclass()), (Rtype::TKEY, Class::ANY));
/// let rr = query.additional().next().unwrap()?;
/// assert_eq!((rr.class(), rr.ttl()), (Class::ANY, 0));
/// assert_eq!(rr.to_string(), "key.example. 0 ANY TKEY hmac-sha256. 0 0 5 NOERROR 0 0");
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn build_query<B: OutBuf>(
    b: &mut MessageBuilder<B>,
    key_name: impl ToName,
    tkey: &Tkey<'_>,
) -> Result<()> {
    let key_name = key_name.to_name();
    let cp = b.checkpoint();
    let flags = b.header().flags;
    let res = (|| {
        if !b.is_empty() {
            return Err(crate::Error::SectionOrder);
        }
        b.set_flags(Flags::default().with_opcode(Opcode::QUERY));
        b.push_question(key_name, Rtype::TKEY, Class::ANY)?;
        b.push_additional(key_name, Class::ANY, 0, tkey)
    })();
    if res.is_err() {
        b.rollback(cp);
        b.set_flags(flags);
    }
    res
}

/// Writes the response to a TKEY query into an empty builder (RFC 2930
/// §4): same ID, QR set, opcode and RD echoed, the question copied, and
/// `tkey` in the answer section as a record owned by `key_name`, CLASS
/// ANY, TTL 0. `key_name` is normally the query's key name; with server
/// assignment it is the name the server chose (§2.1, §4.4). To refuse,
/// answer with [`Tkey::with_error`](crate::rdata::Tkey::with_error) (the
/// header RCODE stays NOERROR, §2.6).
///
/// # Errors
///
/// [`Error::SectionOrder`](crate::Error::SectionOrder) if the builder is
/// not empty, the parse error of a malformed question section,
/// [`Error::InvalidRdata`](crate::Error::InvalidRdata) if `tkey` cannot
/// be encoded, or [`Error::BufferTooSmall`](crate::Error::BufferTooSmall)
/// if the response does not fit; on any error the builder is left
/// unchanged.
///
/// ```
/// use dnsbox::rdata::{Tkey, TkeyMode, TsigRcode};
/// use dnsbox::{Message, MessageBuilder, Rcode};
/// use dnsbox::tkey;
///
/// // Server: refuse a mode it does not implement.
/// fn refuse<'b>(query: &[u8], out: &'b mut [u8]) -> dnsbox::Result<&'b mut [u8]> {
///     let query = Message::parse(query)?;
///     let request = tkey::find(&query)?.ok_or(dnsbox::Error::InvalidRdata)?;
///     let mut b = dnsbox::MessageBuilder::new(out)?;
///     let reply = request.data.with_error(TsigRcode::BADMODE);
///     tkey::build_response(&mut b, &query, request.key_name, &reply)?;
///     Ok(b.finish())
/// }
///
/// let name: dnsbox::NameBuf = "k.example".parse()?;
/// let mut qbuf = [0u8; 512];
/// let mut q = MessageBuilder::new(&mut qbuf)?;
/// let dh = Tkey::new(dnsbox::Name::ROOT, 0, 0, TkeyMode::DIFFIE_HELLMAN, &[1, 2, 3]);
/// tkey::build_query(&mut q, &name, &dh)?;
/// let mut rbuf = [0u8; 512];
/// let response = Message::parse_validated(refuse(q.finish(), &mut rbuf)?)?;
/// assert_eq!(response.flags().rcode(), Rcode::NOERROR);
/// let answer = tkey::find(&response)?.unwrap();
/// assert_eq!(answer.data.error, TsigRcode::BADMODE);
/// assert!(answer.data.key.is_empty());
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn build_response<B: OutBuf>(
    b: &mut MessageBuilder<B>,
    query: &Message<'_>,
    key_name: impl ToName,
    tkey: &Tkey<'_>,
) -> Result<()> {
    let key_name = key_name.to_name();
    let cp = b.checkpoint();
    let (id, flags) = (b.header().id, b.header().flags);
    let res = (|| {
        b.start_response(query)?;
        b.push_answer(key_name, Class::ANY, 0, tkey)
    })();
    if res.is_err() {
        b.rollback(cp);
        b.set_id(id);
        b.set_flags(flags);
    }
    res
}

/// A TKEY record found in a message by [`find`].
///
/// ```
/// use dnsbox::rdata::{Tkey, TkeyMode};
/// use dnsbox::{Message, MessageBuilder, NameBuf, Section};
/// use dnsbox::tkey;
///
/// let key_name: NameBuf = "k.example".parse()?;
/// let mut buf = [0u8; 512];
/// let mut b = MessageBuilder::new(&mut buf)?;
/// let data = Tkey::new(dnsbox::Name::ROOT, 100, 200, TkeyMode::GSSAPI, &[7]);
/// tkey::build_query(&mut b, &key_name, &data)?;
/// let msg = Message::parse(b.finish())?;
/// let found = tkey::find(&msg)?.unwrap();
/// assert_eq!((found.key_name, found.section, found.data), (key_name.as_name(), Section::Additional, data));
/// assert!(found.data.is_valid_at(150));
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct TkeyRecord<'a> {
    /// The key name (the record's owner name, §2.1).
    pub key_name: Name<'a>,
    /// The section the record is in: additional in a query, answer in a
    /// response (§4), additional when a server includes it spontaneously
    /// (§5).
    pub section: Section,
    /// The record data.
    pub data: Tkey<'a>,
}

/// Finds the first TKEY record of `msg` (in message order: answer,
/// authority, additional), or `None` if there is none. The record's
/// CLASS and TTL are not checked (RFC 2930 §2: "ignored").
///
/// # Errors
///
/// The parse error of a malformed record before it, or of the TKEY RDATA.
///
/// ```
/// use dnsbox::{Message, MessageBuilder, NameBuf, Rtype, Class};
/// use dnsbox::tkey;
///
/// let name: NameBuf = "example.com".parse()?;
/// let mut buf = [0u8; 512];
/// let msg = MessageBuilder::query(&mut buf, 1, &name, Rtype::A, Class::IN)?.finish();
/// assert_eq!(tkey::find(&Message::parse(msg)?)?, None);
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn find<'a>(msg: &Message<'a>) -> Result<Option<TkeyRecord<'a>>> {
    for item in msg.records() {
        let (section, rr) = item?;
        if rr.rtype() == Tkey::RTYPE {
            return Ok(Some(TkeyRecord {
                key_name: rr.name(),
                section,
                data: rr.data_as::<Tkey<'a>>()?,
            }));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdata::{TkeyMode, TsigRcode};
    use crate::{Error, NameBuf};

    fn names() -> (NameBuf, NameBuf) {
        (
            "key.example".parse().unwrap(),
            "hmac-sha256".parse().unwrap(),
        )
    }

    #[test]
    fn query_and_response() {
        let (key, alg) = names();
        let data = Tkey::new(alg.as_name(), 1, 2, TkeyMode::DIFFIE_HELLMAN, &[9; 16]);
        let mut buf = [0u8; 512];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.set_id(77);
        // Leftover flags are replaced.
        b.set_flags(Flags::default().with_rd(true).with_qr(true));
        build_query(&mut b, &key, &data).unwrap();
        let query = b.finish().to_vec();
        let q = Message::parse_validated(&query).unwrap();
        assert_eq!(q.id(), 77);
        assert!(!q.flags().rd() && !q.flags().qr());
        assert_eq!(q.flags().opcode(), Opcode::QUERY);
        assert_eq!(
            (q.header().qdcount, q.header().ancount, q.header().arcount),
            (1, 0, 1)
        );
        let found = find(&q).unwrap().unwrap();
        assert_eq!(found.data, data);

        let mut rbuf = [0u8; 512];
        let mut r = MessageBuilder::new(&mut rbuf).unwrap();
        let assigned: NameBuf = "89n3mDgX072pp.server1.example.com".parse().unwrap();
        build_response(&mut r, &q, &assigned, &data.with_error(TsigRcode::BADALG)).unwrap();
        let resp = Message::parse_validated(r.finish()).unwrap();
        assert_eq!(resp.id(), 77);
        assert!(resp.flags().qr());
        assert_eq!(
            resp.questions().next().unwrap().unwrap().name(),
            key.as_name()
        );
        let rr = resp.answers().next().unwrap().unwrap();
        assert_eq!((rr.class(), rr.ttl()), (Class::ANY, 0));
        let found = find(&resp).unwrap().unwrap();
        assert_eq!(found.key_name, assigned.as_name());
        assert_eq!(found.section, Section::Answer);
        assert_eq!(found.data.error, TsigRcode::BADALG);
    }

    #[test]
    fn errors_leave_the_builder_unchanged() {
        let (key, alg) = names();
        let data = Tkey::new(alg.as_name(), 1, 2, TkeyMode::GSSAPI, &[0; 64]);
        // Not empty.
        let mut buf = [0u8; 512];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.push_question(&key, Rtype::A, Class::IN).unwrap();
        let before = b.as_bytes().to_vec();
        assert_eq!(build_query(&mut b, &key, &data), Err(Error::SectionOrder));
        assert_eq!(b.as_bytes(), before);
        // Too small for the TKEY record: nothing (not even the question)
        // is left behind, and the flags are restored.
        let mut small = [0u8; 60];
        let mut b = MessageBuilder::new(&mut small).unwrap();
        b.set_flags(Flags::default().with_rd(true));
        let before = b.as_bytes().to_vec();
        assert_eq!(build_query(&mut b, &key, &data), Err(Error::BufferTooSmall));
        assert_eq!(b.as_bytes(), before);
        assert!(b.header().flags.rd());
        // Response: the same.
        let mut qbuf = [0u8; 512];
        let mut q = MessageBuilder::new(&mut qbuf).unwrap();
        build_query(&mut q, &key, &data).unwrap();
        let q = Message::parse(q.finish()).unwrap();
        let mut b = MessageBuilder::new(&mut small).unwrap();
        b.set_id(5);
        let before = b.as_bytes().to_vec();
        assert_eq!(
            build_response(&mut b, &q, &key, &data),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(b.as_bytes(), before);
        assert_eq!(b.header().id, 5);
    }

    #[test]
    fn find_errors() {
        let (key, alg) = names();
        let data = Tkey::new(alg.as_name(), 1, 2, TkeyMode::GSSAPI, &[]);
        let mut buf = [0u8; 512];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        build_query(&mut b, &key, &data).unwrap();
        let mut wire = b.finish().to_vec();
        // Truncate the TKEY RDATA: its RDLENGTH now overruns the message.
        wire.pop();
        assert_eq!(
            find(&Message::parse(&wire).unwrap()),
            Err(Error::UnexpectedEof)
        );
    }
}
