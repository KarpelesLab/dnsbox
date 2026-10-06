//! Transaction key establishment: TKEY (RFC 2930).
//!
//! A resolver establishes or deletes a shared TSIG key with a query for
//! type TKEY (RFC 2930 §4): the question is `key-name TKEY ANY` and the
//! additional section carries a TKEY record (owner: the key name, CLASS
//! ANY, TTL 0) with the algorithm, the requested validity, the mode and
//! the key exchange data. The server answers with a TKEY record in the
//! answer section; a non-zero TKEY error says why the exchange failed
//! (§2.6). Some modes need a KEY record next to the TKEY (§4.1, §4.4,
//! §4.5). Except in GSS-API mode, queries and responses MUST be
//! authenticated with TSIG or SIG(0) under a key established earlier
//! (§3): sign them after the TKEY records are written ([`crate::tsig`],
//! [`crate::sig0`]), and verify them before handing them to this module.
//!
//! What this module does, mode by mode (§2.5):
//!
//! | Mode | Messages | Key agreement |
//! |------|----------|---------------|
//! | Diffie-Hellman (§4.1) | [`build_query_with_key`], [`find_request`], [`find_answer`], [`keys`]; the RFC 2539 KEY format is [`DhKey`] | [`DhKeyPair`] (feature `tkey`): well-known groups 1 and 2 (and BIND's 3) or an explicit group, the MD5 mixing of §4.1 ([`dh_keying_material`]), client and server helpers returning the TSIG key ([`SharedKey`]) |
//! | Key deletion (§4.2, §5.1) | [`build_deletion_query`], [`build_deletion_response`], [`push_deletion_notice`], [`find_deletion`] | none needed |
//! | GSS-API (§4.3, RFC 3645) | [`build_query`], [`build_response`], [`find_request`], [`find_answer`] carry the tokens | **out of scope**: the token exchange needs a GSS-API mechanism (Kerberos, NTLM) and RFC 3645's `gss-tsig` signs with GSS-API MICs, neither of which dnsbox provides |
//! | Server assignment (§4.4) | as Diffie-Hellman, with the resolver's RSA KEY | [`respond_server_assigned`], [`server_assigned_key`] (feature `tkey`): RSAES-PKCS1-v1_5 of §6 |
//! | Resolver assignment (§4.5) | as Diffie-Hellman, with the server's RSA KEY | [`build_resolver_assigned_query`], [`accept_resolver_assigned`], [`resolver_assigned_key`] (feature `tkey`) |
//!
//! The record data is [`rdata::Tkey`](crate::rdata::Tkey). Everything but
//! the cryptography works without features and without allocation;
//! everything that reads a message is linear in its size and does at most
//! one Diffie-Hellman computation or a bounded number of RSA operations
//! ([`MAX_ENCRYPTED_BLOCKS`]) per call, whatever the message holds.
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
//! let request = tkey::find_request(&query)?;
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
//! let answer = tkey::find_answer(&response)?;
//! assert_eq!(answer.section, Section::Answer);
//! assert_eq!(answer.data.error, TsigRcode::NOERROR);
//! assert_eq!(answer.data.key, [0xa1, 0x00]);
//! # Ok::<(), dnsbox::Error>(())
//! ```
#![cfg_attr(
    feature = "tkey",
    doc = "
[`DhKeyPair`]: DhKeyPair
[`dh_keying_material`]: dh_keying_material
[`SharedKey`]: SharedKey
[`respond_server_assigned`]: respond_server_assigned
[`server_assigned_key`]: server_assigned_key
[`build_resolver_assigned_query`]: build_resolver_assigned_query
[`accept_resolver_assigned`]: accept_resolver_assigned
[`resolver_assigned_key`]: resolver_assigned_key
[`MAX_ENCRYPTED_BLOCKS`]: MAX_ENCRYPTED_BLOCKS
"
)]
#![cfg_attr(
    not(feature = "tkey"),
    doc = "
[`DhKeyPair`]: crate#cargo-features
[`dh_keying_material`]: crate#cargo-features
[`SharedKey`]: crate#cargo-features
[`respond_server_assigned`]: crate#cargo-features
[`server_assigned_key`]: crate#cargo-features
[`build_resolver_assigned_query`]: crate#cargo-features
[`accept_resolver_assigned`]: crate#cargo-features
[`resolver_assigned_key`]: crate#cargo-features
[`MAX_ENCRYPTED_BLOCKS`]: crate#cargo-features
"
)]

#[cfg(feature = "tkey")]
mod assign;
mod dh;
#[cfg(feature = "tkey")]
mod exchange;

#[cfg(feature = "tkey")]
#[cfg_attr(docsrs, doc(cfg(feature = "tkey")))]
pub use assign::{
    MAX_ENCRYPTED_BLOCKS, accept_resolver_assigned, build_resolver_assigned_query,
    decrypt_keying_material, encrypt_keying_material, resolver_assigned_key,
    respond_server_assigned, rsa_public_key, server_assigned_key,
};
pub use dh::{DhKey, DhPrime, well_known_prime};
#[cfg(feature = "tkey")]
#[cfg_attr(docsrs, doc(cfg(feature = "tkey")))]
pub use exchange::{DhGroup, DhKeyPair, KeyGrant, SharedKey, dh_keying_material};

/// The `purecrypto` crate dnsbox was built against, for naming the RSA
/// key and RNG types the key agreement helpers take (e.g.
/// `purecrypto::rsa::BoxedRsaPrivateKey`, `purecrypto::rng::OsRng`).
#[cfg(feature = "tkey")]
#[cfg_attr(docsrs, doc(cfg(feature = "tkey")))]
pub use ::purecrypto;

use crate::builder::MessageBuilder;
use crate::message::{Message, Section};
use crate::name::{Name, ToName};
use crate::rdata::{Key, ParseRdata, Tkey, TkeyMode, TsigRcode};
use crate::wire::OutBuf;
use crate::{Class, Error, Flags, Opcode, Result, Rtype};

/// Runs `f` on `b`; on error, restores the builder (content, ID and
/// flags) to its state before the call.
fn atomic<B: OutBuf, T>(
    b: &mut MessageBuilder<B>,
    f: impl FnOnce(&mut MessageBuilder<B>) -> Result<T>,
) -> Result<T> {
    let cp = b.checkpoint();
    let (id, flags) = (b.header().id, b.header().flags);
    let res = f(b);
    if res.is_err() {
        b.rollback(cp);
        b.set_id(id);
        b.set_flags(flags);
    }
    res
}

/// Writes a TKEY query into an empty builder (RFC 2930 §4): opcode QUERY
/// with RD clear (§4: TKEY queries "SHOULD NOT be flagged as recursive"),
/// the question `key_name TKEY ANY`, and `tkey` in the additional section
/// as a record owned by `key_name`, CLASS ANY, TTL 0 (§2, §2.2). The ID is
/// left as set on the builder. Records the mode needs (a KEY, §4.1, §4.4)
/// and a TSIG or SIG(0) signature can be appended afterwards.
///
/// # Errors
///
/// [`Error::SectionOrder`] if the builder is
/// not empty, [`Error::InvalidRdata`] if
/// `tkey` cannot be encoded, or
/// [`Error::BufferTooSmall`] if the query
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
    atomic(b, |b| {
        if !b.is_empty() {
            return Err(Error::SectionOrder);
        }
        b.set_flags(Flags::default().with_opcode(Opcode::QUERY));
        b.push_question(key_name, Rtype::TKEY, Class::ANY)?;
        b.push_additional(key_name, Class::ANY, 0, tkey)
    })
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
/// [`Error::SectionOrder`] if the builder is
/// not empty, the parse error of a malformed question section,
/// [`Error::InvalidRdata`] if `tkey` cannot
/// be encoded, or [`Error::BufferTooSmall`]
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
    atomic(b, |b| {
        b.start_response(query)?;
        b.push_answer(key_name, Class::ANY, 0, tkey)
    })
}

/// A TKEY record found in a message by [`find`], [`find_request`],
/// [`find_answer`] or [`find_deletion`].
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

/// Writes a TKEY query that carries a KEY into an empty builder: the query
/// of [`build_query`], then `key` as a record owned by `key_owner`, CLASS
/// ANY, TTL 0, also in the additional section. This is the query of
/// Diffie-Hellman exchanged keying (the resolver's DH KEY, RFC 2930 §4.1),
/// server assigned keying (the resolver's KEY the server encrypts to,
/// §4.4) and resolver assigned keying (the server's KEY the keying
/// material is encrypted under, §4.5). The KEY's owner is the name the
/// key is published under, not the TKEY key name.
///
/// # Errors
///
/// As [`build_query`]; on any error the builder is left unchanged.
///
/// ```
/// use dnsbox::dnssec::Algorithm;
/// use dnsbox::rdata::{Key, Tkey, TkeyMode};
/// use dnsbox::{Message, MessageBuilder, NameBuf, Rtype, Section};
/// use dnsbox::tkey;
///
/// let key_name: NameBuf = "k1.server.example".parse()?;
/// let owner: NameBuf = "resolver.example".parse()?;
/// let alg: NameBuf = "hmac-sha256".parse()?;
/// // A Diffie-Hellman KEY (RFC 2539) on well-known group 2.
/// let public = [0, 1, 2, 0, 0, 0, 2, 0x12, 0x34];
/// let key = Key::new(0x0200, 3, Algorithm::DH, &public);
/// let nonce = [7u8; 16];
/// let request = Tkey::new(alg.as_name(), 1_700_000_000, 1_700_086_400, TkeyMode::DIFFIE_HELLMAN, &nonce);
/// let mut buf = [0u8; 512];
/// let mut b = MessageBuilder::new(&mut buf)?;
/// tkey::build_query_with_key(&mut b, &key_name, &request, &owner, &key)?;
/// let query = Message::parse_validated(b.finish())?;
/// assert_eq!(tkey::find_request(&query)?.data, request);
/// let (name, found) = tkey::keys(&query, Section::Additional).next().unwrap()?;
/// assert_eq!((name, found), (owner.as_name(), key));
/// let dh = tkey::DhKey::parse(found.public_key)?;
/// assert_eq!(dh.public_value, [0x12, 0x34]);
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn build_query_with_key<B: OutBuf>(
    b: &mut MessageBuilder<B>,
    key_name: impl ToName,
    tkey: &Tkey<'_>,
    key_owner: impl ToName,
    key: &Key<'_>,
) -> Result<()> {
    let key_owner = key_owner.to_name();
    atomic(b, |b| {
        build_query(b, key_name, tkey)?;
        b.push_additional(key_owner, Class::ANY, 0, key)
    })
}

/// The single TKEY record of `msg` (§3: "There MUST NOT be more than one
/// TKEY RR in a DNS query or response"), or `None`.
fn single<'a>(msg: &Message<'a>) -> Result<Option<TkeyRecord<'a>>> {
    let mut found = None;
    for item in msg.records() {
        let (section, rr) = item?;
        if rr.rtype() == Tkey::RTYPE {
            if found.is_some() {
                return Err(Error::InvalidTkey);
            }
            found = Some(TkeyRecord {
                key_name: rr.name(),
                section,
                data: rr.data_as::<Tkey<'a>>()?,
            });
        }
    }
    Ok(found)
}

/// Reads the TKEY request of a query, as a server does before acting on
/// it (RFC 2930 §3, §4): the message must be a QUERY (QR clear) with one
/// question of type TKEY, and carry exactly one TKEY record, owned by the
/// question name, in the additional section (or in the answer section,
/// where Windows 2000 put it and BIND accepts it). Which mode to serve,
/// and whether the query is suitably authenticated (§3: TSIG or SIG(0),
/// except in GSS-API mode), is the caller's decision.
///
/// # Errors
///
/// [`Error::InvalidTkey`] if the query breaks these rules (answer
/// FORMERR), or the parse error of a malformed question or record.
///
/// ```
/// use dnsbox::rdata::{Tkey, TkeyMode};
/// use dnsbox::{Class, Error, Message, MessageBuilder, Name, NameBuf, Rtype};
/// use dnsbox::tkey;
///
/// let key_name: NameBuf = "k.example".parse()?;
/// let mut buf = [0u8; 512];
/// let mut b = MessageBuilder::new(&mut buf)?;
/// tkey::build_query(&mut b, &key_name, &Tkey::new(Name::ROOT, 0, 0, TkeyMode::GSSAPI, &[1]))?;
/// let query = Message::parse(b.finish())?;
/// assert_eq!(tkey::find_request(&query)?.data.mode, TkeyMode::GSSAPI);
///
/// // An ordinary query is no TKEY request.
/// let mut buf = [0u8; 512];
/// let a = MessageBuilder::query(&mut buf, 1, &key_name, Rtype::A, Class::IN)?.finish();
/// assert_eq!(tkey::find_request(&Message::parse(a)?), Err(Error::InvalidTkey));
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn find_request<'a>(query: &Message<'a>) -> Result<TkeyRecord<'a>> {
    let flags = query.flags();
    if flags.qr() || flags.opcode() != Opcode::QUERY || query.header().qdcount != 1 {
        return Err(Error::InvalidTkey);
    }
    let question = query.questions().next().ok_or(Error::UnexpectedEof)??;
    if question.qtype() != Rtype::TKEY {
        return Err(Error::InvalidTkey);
    }
    match single(query)? {
        Some(r)
            if r.key_name == question.name()
                && matches!(r.section, Section::Additional | Section::Answer) =>
        {
            Ok(r)
        }
        _ => Err(Error::InvalidTkey),
    }
}

/// Reads the TKEY answer of a response, as a resolver does (RFC 2930
/// §3, §4): the message must be a response (QR set) with RCODE NOERROR
/// and carry exactly one TKEY record, in the answer section. Its owner is
/// the key name, which the server may have chosen (§2.1). The TKEY error
/// field is not checked: a non-zero one says why the server refused
/// (§2.6). Matching the response to the query (ID, question) and its
/// authentication (§3) are the caller's.
///
/// # Errors
///
/// [`Error::ErrorResponse`] if the RCODE (with EDNS, the extended one) is
/// not NOERROR, [`Error::InvalidTkey`] if the response breaks the rules
/// above, or the parse error of a malformed record or OPT record.
///
/// ```
/// use dnsbox::rdata::{Tkey, TkeyMode, TsigRcode};
/// use dnsbox::{Message, MessageBuilder, Name, NameBuf};
/// use dnsbox::tkey;
///
/// let key_name: NameBuf = "k.example".parse()?;
/// let mut qbuf = [0u8; 512];
/// let mut q = MessageBuilder::new(&mut qbuf)?;
/// let request = Tkey::new(Name::ROOT, 0, 0, TkeyMode::new(9), &[]);
/// tkey::build_query(&mut q, &key_name, &request)?;
/// let query = Message::parse(q.finish())?;
/// let mut rbuf = [0u8; 512];
/// let mut r = MessageBuilder::new(&mut rbuf)?;
/// tkey::build_response(&mut r, &query, &key_name, &request.with_error(TsigRcode::BADMODE))?;
/// let answer = tkey::find_answer(&Message::parse(r.finish())?)?;
/// assert_eq!(answer.data.error, TsigRcode::BADMODE);
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn find_answer<'a>(response: &Message<'a>) -> Result<TkeyRecord<'a>> {
    if !response.flags().qr() {
        return Err(Error::InvalidTkey);
    }
    if response.effective_rcode()? != crate::Rcode::NOERROR {
        return Err(Error::ErrorResponse);
    }
    match single(response)? {
        Some(r) if r.section == Section::Answer => Ok(r),
        _ => Err(Error::InvalidTkey),
    }
}

/// The KEY records of one section of `msg`, with their owner names, in
/// message order (CLASS and TTL are not looked at). TKEY exchanges carry
/// the parties' public keys this way: Diffie-Hellman KEYs (RFC 2539,
/// [`DhKey`]) for §4.1, encryption KEYs for §4.4 and §4.5.
/// `Section::Question` yields nothing.
///
/// Items are `Err` (once, then the iterator ends) when a record of the
/// section, or a KEY's RDATA, is malformed.
///
/// ```
/// use dnsbox::dnssec::Algorithm;
/// use dnsbox::rdata::{Key, Tkey, TkeyMode};
/// use dnsbox::{Message, MessageBuilder, Name, NameBuf, Section};
/// use dnsbox::tkey;
///
/// let name: NameBuf = "k.example".parse()?;
/// let key = Key::new(0x0200, 3, Algorithm::RSASHA256, &[1, 3, 0xc5]);
/// let mut buf = [0u8; 512];
/// let mut b = MessageBuilder::new(&mut buf)?;
/// let request = Tkey::new(Name::ROOT, 0, 0, TkeyMode::SERVER_ASSIGNMENT, &[]);
/// tkey::build_query_with_key(&mut b, &name, &request, &name, &key)?;
/// let query = Message::parse(b.finish())?;
/// let found: Vec<_> = tkey::keys(&query, Section::Additional).collect::<Result<_, _>>()?;
/// assert_eq!(found, [(name.as_name(), key)]);
/// assert_eq!(tkey::keys(&query, Section::Answer).count(), 0);
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn keys<'a>(
    msg: &Message<'a>,
    section: Section,
) -> impl Iterator<Item = Result<(Name<'a>, Key<'a>)>> + use<'a> {
    let mut records = msg.section(section);
    let mut failed = false;
    core::iter::from_fn(move || {
        if failed {
            return None;
        }
        for rr in records.by_ref() {
            let item = rr.and_then(|rr| {
                (rr.rtype() == Rtype::KEY)
                    .then(|| rr.data_as::<Key<'a>>().map(|k| (rr.name(), k)))
                    .transpose()
            });
            match item {
                Ok(None) => {}
                Ok(Some(k)) => return Some(Ok(k)),
                Err(e) => {
                    failed = true;
                    return Some(Err(e));
                }
            }
        }
        None
    })
}

/// Writes a key deletion query into an empty builder (RFC 2930 §4.2): the
/// query of [`build_query`] with a TKEY of mode KEY-DELETION for the key
/// `key_name` of algorithm `algorithm`, no key data, and both times set
/// to `now` (seconds since the epoch, as BIND writes them; the server
/// ignores them). The query MUST then be authenticated, for instance with
/// a TSIG signature under the very key to delete (§4.2).
///
/// # Errors
///
/// As [`build_query`]; on any error the builder is left unchanged.
///
/// ```
/// # #[cfg(feature = "tsig")] {
/// use dnsbox::tsig::{HmacKey, TsigAlgorithm, TsigSigner};
/// use dnsbox::{Message, MessageBuilder, NameBuf};
/// use dnsbox::tkey;
///
/// let key_name: NameBuf = "k1.server.example".parse()?;
/// let key = HmacKey::new(&key_name, TsigAlgorithm::HmacSha256, b"the shared secret");
/// let now = 1_700_000_000;
/// let mut buf = [0u8; 512];
/// let mut b = MessageBuilder::new(&mut buf)?;
/// b.set_id(0x2930);
/// tkey::build_deletion_query(&mut b, &key_name, TsigAlgorithm::HmacSha256.name(), now)?;
/// TsigSigner::request(&key).sign(&mut b, u64::from(now))?;
/// let query = b.finish();
/// let request = tkey::find_request(&Message::parse(query)?)?;
/// assert_eq!(request.data.to_string(), "hmac-sha256. 1700000000 1700000000 5 NOERROR 0 0");
/// # }
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn build_deletion_query<B: OutBuf>(
    b: &mut MessageBuilder<B>,
    key_name: impl ToName,
    algorithm: impl ToName,
    now: u32,
) -> Result<()> {
    let tkey = Tkey::new(algorithm.to_name(), now, now, TkeyMode::KEY_DELETION, &[]);
    build_query(b, key_name, &tkey)
}

/// Writes the answer to a key deletion request into an empty builder
/// (RFC 2930 §4.2): the response of [`build_response`] with the
/// request's TKEY record (key name, algorithm, times, mode KEY-DELETION)
/// and error NOERROR when the key was deleted, or BADNAME when the server
/// had no key of that name. The response MUST then be signed (§3), with a
/// key other than the one just deleted being unavailable, typically with
/// that key itself: sign before discarding it.
///
/// Deleting the key is the caller's job, after checking that the request
/// is authenticated (§4.2) and, as BIND does, that whoever signed it may
/// delete that key (for instance, the identity that created it).
///
/// # Errors
///
/// [`Error::InvalidTkey`] if `request` is not a deletion request, and the
/// errors of [`build_response`]; on any error the builder is left
/// unchanged.
///
/// ```
/// use dnsbox::rdata::TsigRcode;
/// use dnsbox::{Message, MessageBuilder, NameBuf};
/// use dnsbox::tkey;
///
/// let key_name: NameBuf = "unknown.example".parse()?;
/// let alg: NameBuf = "hmac-sha256".parse()?;
/// let mut qbuf = [0u8; 512];
/// let mut q = MessageBuilder::new(&mut qbuf)?;
/// tkey::build_deletion_query(&mut q, &key_name, &alg, 1_700_000_000)?;
/// let query = Message::parse(q.finish())?;
///
/// // Server: no such key.
/// let request = tkey::find_request(&query)?;
/// let mut rbuf = [0u8; 512];
/// let mut r = MessageBuilder::new(&mut rbuf)?;
/// tkey::build_deletion_response(&mut r, &query, &request, false)?;
/// let response = Message::parse(r.finish())?;
/// let answer = tkey::find_deletion(&response)?.unwrap();
/// assert_eq!((answer.key_name, answer.data.error), (key_name.as_name(), TsigRcode::BADNAME));
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn build_deletion_response<B: OutBuf>(
    b: &mut MessageBuilder<B>,
    query: &Message<'_>,
    request: &TkeyRecord<'_>,
    deleted: bool,
) -> Result<()> {
    if request.data.mode != TkeyMode::KEY_DELETION {
        return Err(Error::InvalidTkey);
    }
    let error = if deleted {
        TsigRcode::NOERROR
    } else {
        TsigRcode::BADNAME
    };
    build_response(b, query, request.key_name, &request.data.with_error(error))
}

/// Appends a spontaneous key deletion notice to a response being built
/// (RFC 2930 §5.1): a TKEY record of mode KEY-DELETION for `key_name`,
/// CLASS ANY, TTL 0, in the additional section, both times set to `now`
/// (they are ignored). The response SHOULD then be signed; a client that
/// verifies it discards the key ([`find_deletion`]).
///
/// # Errors
///
/// [`Error::SectionOrder`] if a later section was already written, or
/// [`Error::BufferTooSmall`] if the record does not fit; on any error the
/// builder is left unchanged.
///
/// ```
/// use dnsbox::rdata::{A, TkeyMode};
/// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype, Section};
/// use dnsbox::tkey;
///
/// let qname: NameBuf = "www.example".parse()?;
/// let key_name: NameBuf = "k1.server.example".parse()?;
/// let alg: NameBuf = "hmac-sha256".parse()?;
/// let mut qbuf = [0u8; 512];
/// let query = MessageBuilder::query(&mut qbuf, 7, &qname, Rtype::A, Class::IN)?.finish();
/// let query = Message::parse(query)?;
/// let mut buf = [0u8; 512];
/// let mut b = MessageBuilder::response(&mut buf, &query)?;
/// b.push_answer(&qname, Class::IN, 300, &A::new([192, 0, 2, 1].into()))?;
/// tkey::push_deletion_notice(&mut b, &key_name, &alg, 1_700_000_000)?;
/// let response = Message::parse_validated(b.finish())?;
/// let notice = tkey::find_deletion(&response)?.unwrap();
/// assert_eq!((notice.key_name, notice.section), (key_name.as_name(), Section::Additional));
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn push_deletion_notice<B: OutBuf>(
    b: &mut MessageBuilder<B>,
    key_name: impl ToName,
    algorithm: impl ToName,
    now: u32,
) -> Result<()> {
    let tkey = Tkey::new(algorithm.to_name(), now, now, TkeyMode::KEY_DELETION, &[]);
    b.push_additional(key_name, Class::ANY, 0, &tkey)
}

/// Finds a key deletion in a response (QR set): the answer to a deletion
/// request (RFC 2930 §4.2, answer section) or a spontaneous notice (§5.1,
/// additional section), as the single TKEY record of the message with
/// mode KEY-DELETION. Returns `None` for a response without a TKEY record
/// or with another mode. An error of NOERROR (deleted) or BADNAME (the
/// server had no such key) both mean the server no longer holds the key
/// named by [`TkeyRecord::key_name`]; only act on an authenticated
/// response (§3, §5.1).
///
/// # Errors
///
/// [`Error::InvalidTkey`] for a query or for more than one TKEY record,
/// or the parse error of a malformed record.
///
/// ```
/// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
/// use dnsbox::tkey;
///
/// let name: NameBuf = "www.example".parse()?;
/// let mut qbuf = [0u8; 512];
/// let query = MessageBuilder::query(&mut qbuf, 7, &name, Rtype::A, Class::IN)?.finish();
/// let mut buf = [0u8; 512];
/// let response = MessageBuilder::response(&mut buf, &Message::parse(query)?)?.finish();
/// assert_eq!(tkey::find_deletion(&Message::parse(response)?)?, None);
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn find_deletion<'a>(msg: &Message<'a>) -> Result<Option<TkeyRecord<'a>>> {
    if !msg.flags().qr() {
        return Err(Error::InvalidTkey);
    }
    Ok(single(msg)?.filter(|r| {
        r.data.mode == TkeyMode::KEY_DELETION
            && matches!(r.section, Section::Answer | Section::Additional)
    }))
}

#[cfg(test)]
mod tests;
