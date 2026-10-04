//! Zone change notification: NOTIFY (RFC 1996).
//!
//! A primary tells its secondaries that a zone changed with a NOTIFY
//! query (opcode 4, AA set) whose question is `zone SOA class` and whose
//! answer section may carry the new SOA as a hint (RFC 1996 §3.7). The
//! secondary acknowledges with a response echoing the ID and question
//! (§4.7), then checks the primary's SOA and transfers the zone.
//!
//! ```
//! use dnsbox::{Class, Message, MessageBuilder, NameBuf};
//! use dnsbox::notify::{self, NotifyMessage};
//!
//! let zone: NameBuf = "example.com".parse()?;
//! let mut buf = [0u8; 512];
//! let mut b = MessageBuilder::new(&mut buf)?;
//! b.set_id(10);
//! notify::build_query(&mut b, &zone, Class::IN, None)?;
//! let query = b.finish();
//!
//! let n = NotifyMessage::new(Message::parse_validated(query)?)?;
//! assert_eq!(n.zone().name(), zone.as_name());
//! let mut rbuf = [0u8; 512];
//! let mut r = MessageBuilder::new(&mut rbuf)?;
//! notify::build_response(&mut r, &n)?;
//! assert!(NotifyMessage::new(Message::parse(r.finish())?)?.is_response());
//! # Ok::<(), dnsbox::Error>(())
//! ```

use crate::builder::MessageBuilder;
use crate::message::{Message, Question, Record};
use crate::name::ToName;
use crate::rdata::{ParseRdata, Soa};
use crate::wire::OutBuf;
use crate::{Class, Error, Flags, Opcode, Result, Rtype};

/// Writes a NOTIFY query for `zone` into an empty builder (RFC 1996 §3.7):
/// opcode NOTIFY, AA set, question `zone SOA class`, and, if `soa` is
/// given as `(ttl, soa)`, the new SOA in the answer section as a hint
/// (§3.11). The ID is left as set on the builder.
///
/// # Errors
///
/// [`Error::SectionOrder`] if the builder is not empty, or
/// [`Error::BufferTooSmall`] if the query does not fit; on any error the
/// builder is left unchanged.
///
/// ```
/// use dnsbox::notify::{self, NotifyMessage};
/// use dnsbox::rdata::{ParseRdataText, Soa};
/// use dnsbox::{Class, Message, MessageBuilder, NameBuf};
///
/// let zone: NameBuf = "example.com".parse()?;
/// let mut sbuf = [0u8; 128];
/// let soa = Soa::from_text("ns1.example.com. hostmaster.example.com. 2024060101 7200 900 1209600 3600", &mut sbuf)?;
/// let mut buf = [0u8; 512];
/// let mut b = MessageBuilder::new(&mut buf)?;
/// b.set_id(4321);
/// notify::build_query(&mut b, &zone, Class::IN, Some((3600, &soa)))?;
/// let n = NotifyMessage::new(Message::parse_validated(b.finish())?)?;
/// assert_eq!(n.serial()?, Some(2024060101));
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn build_query<B: OutBuf>(
    b: &mut MessageBuilder<B>,
    zone: impl ToName,
    class: Class,
    soa: Option<(u32, &Soa<'_>)>,
) -> Result<()> {
    if !b.is_empty() {
        return Err(Error::SectionOrder);
    }
    let cp = b.checkpoint();
    let flags = b.header().flags;
    let res = (|| {
        b.set_flags(Flags::default().with_opcode(Opcode::NOTIFY).with_aa(true));
        let zone = zone.to_name();
        b.push_question(zone, Rtype::SOA, class)?;
        if let Some((ttl, soa)) = soa {
            b.push_answer(zone, class, ttl, soa)?;
        }
        Ok(())
    })();
    if res.is_err() {
        b.rollback(cp);
        b.set_flags(flags);
    }
    res
}

/// Writes the response to a NOTIFY query into an empty builder (RFC 1996
/// §4.7): same ID, opcode NOTIFY, QR and AA set, the question echoed.
/// See the [module example](self).
///
/// # Errors
///
/// [`Error::SectionOrder`] if the builder is not empty, or
/// [`Error::BufferTooSmall`] if the response does not fit; on any error
/// the builder is left unchanged.
///
/// ```
/// use dnsbox::notify::{self, NotifyMessage};
/// use dnsbox::{Message, MessageBuilder};
///
/// // Secondary side: acknowledge a NOTIFY received in `wire`.
/// fn acknowledge<'b>(wire: &[u8], out: &'b mut [u8]) -> dnsbox::Result<&'b mut [u8]> {
///     let notify = NotifyMessage::new(Message::parse(wire)?)?;
///     let mut b = MessageBuilder::new(out)?;
///     notify::build_response(&mut b, &notify)?;
///     Ok(b.finish())
/// }
/// ```
pub fn build_response<B: OutBuf>(
    b: &mut MessageBuilder<B>,
    query: &NotifyMessage<'_>,
) -> Result<()> {
    if !b.is_empty() {
        return Err(Error::SectionOrder);
    }
    let cp = b.checkpoint();
    let (id, flags) = (b.header().id, b.header().flags);
    b.set_id(query.message().id());
    b.set_flags(
        Flags::default()
            .with_opcode(Opcode::NOTIFY)
            .with_qr(true)
            .with_aa(true),
    );
    let res = b.copy_question(&query.zone());
    if res.is_err() {
        b.rollback(cp);
        b.set_id(id);
        b.set_flags(flags);
    }
    res
}

/// A parsed NOTIFY message, query or response (RFC 1996 §3).
///
/// A secondary checks the zone and the SOA hint before deciding to
/// transfer (see also the [module example](self)):
///
/// ```
/// use dnsbox::notify::NotifyMessage;
/// use dnsbox::{Message, Name};
///
/// fn should_refresh(wire: &[u8], our_zone: Name<'_>, our_serial: u32) -> dnsbox::Result<bool> {
///     let n = NotifyMessage::new(Message::parse(wire)?)?;
///     if n.is_response() || n.zone().name() != our_zone {
///         return Ok(false);
///     }
///     // No hint, or a newer one: query the primary's SOA (RFC 1996 §3.11).
///     Ok(n.serial()?.is_none_or(|s| dnsbox::xfr::serial_newer(s, our_serial)))
/// }
/// ```
#[derive(Clone, Copy, Debug)]
pub struct NotifyMessage<'a> {
    msg: Message<'a>,
    zone: Question<'a>,
}

impl<'a> NotifyMessage<'a> {
    /// Wraps a message, checking that its opcode is NOTIFY and that it has
    /// exactly one question (RFC 1996 §3.7: QDCOUNT 1).
    ///
    /// # Errors
    ///
    /// [`Error::WrongType`] for another opcode, [`Error::InvalidRdata`] for
    /// a bad question count, or the parse error of the question.
    pub fn new(msg: Message<'a>) -> Result<Self> {
        if msg.flags().opcode() != Opcode::NOTIFY {
            return Err(Error::WrongType);
        }
        if msg.header().qdcount != 1 {
            return Err(Error::InvalidRdata);
        }
        let zone = msg.questions().next().ok_or(Error::UnexpectedEof)??;
        Ok(NotifyMessage { msg, zone })
    }

    /// The underlying message.
    #[inline]
    #[must_use]
    pub const fn message(&self) -> Message<'a> {
        self.msg
    }

    /// The question: the zone name, the type that changed (normally SOA,
    /// §3.7) and the class.
    #[inline]
    #[must_use]
    pub const fn zone(&self) -> Question<'a> {
        self.zone
    }

    /// Whether this is the response (QR set).
    #[inline]
    #[must_use]
    pub const fn is_response(&self) -> bool {
        self.msg.flags().qr()
    }

    /// The SOA hint from the answer section, if any (§3.7, §3.11): the
    /// first SOA record owned by the zone name. A secondary must still
    /// query the primary before acting on it (§3.11).
    ///
    /// # Errors
    ///
    /// The parse error of a malformed answer record or SOA.
    pub fn soa(&self) -> Result<Option<(Record<'a>, Soa<'a>)>> {
        for rr in self.msg.answers() {
            let rr = rr?;
            if rr.rtype() == Soa::RTYPE && rr.name() == self.zone.name() {
                return Ok(Some((rr, rr.data_as::<Soa<'a>>()?)));
            }
        }
        Ok(None)
    }

    /// The serial of the SOA hint, if any.
    ///
    /// # Errors
    ///
    /// As [`soa`](Self::soa).
    pub fn serial(&self) -> Result<Option<u32>> {
        Ok(self.soa()?.map(|(_, soa)| soa.serial))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Name, NameBuf};
    use std::vec::Vec;

    fn soa(serial: u32) -> (NameBuf, NameBuf, u32) {
        (
            "ns1.example.com".parse().unwrap(),
            "hostmaster.example.com".parse().unwrap(),
            serial,
        )
    }

    #[test]
    fn query_with_hint() {
        let zone: NameBuf = "example.com".parse().unwrap();
        let (m, r, serial) = soa(2);
        let data = Soa {
            mname: m.as_name(),
            rname: r.as_name(),
            serial,
            refresh: 7200,
            retry: 3600,
            expire: 1_209_600,
            minimum: 300,
        };
        let mut buf = [0u8; 512];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.set_id(0x4ab7);
        build_query(&mut b, &zone, Class::IN, Some((0, &data))).unwrap();
        let wire = b.finish().to_vec();
        // BIND 9.18's NOTIFY for the same zone (without its TSIG; see
        // tests/data/named/update1.notify.bin).
        assert_eq!(
            wire,
            crate::testutil::hex(
                "4ab724000001000100000000076578616d706c6503636f6d0000060001c00c\
                 00060001000000000027036e7331c00c0a686f73746d6173746572c00c00000002\
                 00001c2000000e10001275000000012c"
            )
        );
        let n = NotifyMessage::new(Message::parse_validated(&wire).unwrap()).unwrap();
        assert!(!n.is_response());
        assert!(n.message().flags().aa());
        assert_eq!(n.zone().qtype(), Rtype::SOA);
        assert_eq!(n.serial(), Ok(Some(2)));
        let (rr, s) = n.soa().unwrap().unwrap();
        assert_eq!(rr.ttl(), 0);
        assert_eq!(s.mname, m.as_name());

        let mut rbuf = [0u8; 512];
        let mut rb = MessageBuilder::new(&mut rbuf).unwrap();
        build_response(&mut rb, &n).unwrap();
        let resp = rb.finish().to_vec();
        let rn = NotifyMessage::new(Message::parse_validated(&resp).unwrap()).unwrap();
        assert!(rn.is_response());
        assert_eq!(rn.message().id(), 0x4ab7);
        assert_eq!(rn.zone().name(), zone.as_name());
        assert_eq!(rn.serial(), Ok(None));
    }

    #[test]
    fn errors() {
        let zone: NameBuf = "example.com".parse().unwrap();
        // Builders must start empty, and are atomic.
        let mut buf = [0u8; 512];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.push_question(&zone, Rtype::A, Class::IN).unwrap();
        assert_eq!(
            build_query(&mut b, &zone, Class::IN, None),
            Err(Error::SectionOrder)
        );
        let mut small = [0u8; 20];
        let mut b = MessageBuilder::new(&mut small).unwrap();
        b.set_flags(Flags::default().with_rd(true));
        assert_eq!(
            build_query(&mut b, &zone, Class::IN, None),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(b.header().flags, Flags::default().with_rd(true));
        assert!(b.is_empty());

        // Not a NOTIFY / bad counts.
        let mut buf = [0u8; 512];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.push_question(&zone, Rtype::SOA, Class::IN).unwrap();
        let q = b.finish().to_vec();
        assert_eq!(
            NotifyMessage::new(Message::parse(&q).unwrap()).err(),
            Some(Error::WrongType)
        );
        let mut buf = [0u8; 512];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.set_flags(Flags::default().with_opcode(Opcode::NOTIFY));
        let empty = b.finish().to_vec();
        assert_eq!(
            NotifyMessage::new(Message::parse(&empty).unwrap()).err(),
            Some(Error::InvalidRdata)
        );
        // Truncations.
        let mut buf = [0u8; 512];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        let (m, r, serial) = soa(9);
        let data = Soa {
            mname: m.as_name(),
            rname: r.as_name(),
            serial,
            refresh: 1,
            retry: 1,
            expire: 1,
            minimum: 1,
        };
        build_query(&mut b, &zone, Class::IN, Some((60, &data))).unwrap();
        let wire: Vec<u8> = b.finish().to_vec();
        for end in 0..wire.len() {
            if let Ok(m) = Message::parse(&wire[..end])
                && let Ok(n) = NotifyMessage::new(m)
            {
                assert!(n.serial().is_err() || end == wire.len());
            }
        }
        // A hint for another name is ignored.
        let mut buf = [0u8; 512];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.set_flags(Flags::default().with_opcode(Opcode::NOTIFY));
        b.push_question(&zone, Rtype::SOA, Class::IN).unwrap();
        b.push_answer(Name::ROOT, Class::IN, 0, &data).unwrap();
        let other = b.finish().to_vec();
        let n = NotifyMessage::new(Message::parse(&other).unwrap()).unwrap();
        assert_eq!(n.serial(), Ok(None));
    }
}
