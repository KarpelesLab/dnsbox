//! Owned, heap-backed messages, questions and records (`alloc` feature).
//!
//! The views of [`crate::message`] borrow from the received buffer. The
//! types here own their data, so they can be stored, sent across threads,
//! edited, (de)serialized (feature `serde`) and written back out:
//!
//! - [`OwnedQuestion`] and [`OwnedRecord`] hold their owner name as a
//!   [`NameBuf`];
//! - [`OwnedRData`] holds the record data as uncompressed wire bytes in one
//!   heap allocation, and hands out the typed [`RData`] view over them on
//!   demand ([`OwnedRData::as_rdata`], [`OwnedRecord::data`]). This keeps
//!   every one of the ~80 typed record formats (and unknown ones, RFC 3597)
//!   available without a parallel owned type per format;
//! - [`OwnedMessage`] holds the header fields and the four sections as
//!   vectors.
//!
//! Conversions: `from_*` / [`TryFrom`] from the views (names inside RDATA
//! are decompressed), `to_owned_*` methods on the views, `push_to` /
//! [`OwnedMessage::write_to`] into a [`MessageBuilder`] (which recompresses
//! the names it may compress, RFC 3597 §4), and [`OwnedMessage::to_vec`].
//!
//! ```
//! use dnsbox::{Message, OwnedMessage, Rtype, rdata::RData};
//!
//! # let wire: &[u8] = &[
//! #     0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
//! #     7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
//! #     0, 1, 0, 1,
//! #     0xc0, 12, 0, 1, 0, 1, 0, 0, 0x0e, 0x10, 0, 4, 93, 184, 216, 34,
//! # ];
//! let mut msg = OwnedMessage::from_wire(wire)?;
//! assert_eq!(msg.answers[0].rtype(), Rtype::A);
//! msg.answers[0].ttl = 60;
//! let RData::A(a) = msg.answers[0].data()? else { unreachable!() };
//! assert_eq!(a.addr.to_string(), "93.184.216.34");
//!
//! let wire = msg.to_vec()?;
//! let again = Message::parse_validated(&wire)?;
//! assert_eq!(again.answers().next().unwrap()?.ttl(), 60);
//! # Ok::<(), dnsbox::Error>(())
//! ```
//!
//! # serde
//!
//! With the `serde` feature the owned types serialize as structs (JSON
//! shown; compact formats use the same fields):
//!
//! ```text
//! OwnedQuestion  {"name": "example.com.", "type": "A", "class": "IN"}
//! OwnedRecord    {"name": "example.com.", "type": "A", "class": "IN",
//!                 "ttl": 3600, "rdata": "\\# 4 5DB8D822"}
//! OwnedRData     {"type": "A", "rdata": "\\# 4 5DB8D822"}
//! OwnedMessage   {"id": 4660, "flags": {"qr": true, "opcode": "QUERY", ...},
//!                 "questions": [...], "answers": [...], "authority": [...],
//!                 "additional": [...]}
//! ```
//!
//! Names are presentation strings; types, classes, opcodes and RCODEs are
//! mnemonics in human-readable formats and integers otherwise; the header
//! flags are a struct of bits (the raw 16-bit word in compact formats).
//! RDATA is written in the RFC 3597 §5 generic form (`\# <length> <hex>`)
//! in human-readable formats and as a byte string otherwise: the
//! uncompressed wire bytes, so every record type, known or not,
//! round-trips exactly. Human-readable input may also use the type's
//! presentation format (`"10 mail.example.com."`, relative names completed
//! with the root), parsed as [`OwnedRData::from_text`] does; byte strings
//! are checked like [`OwnedRData::from_wire`]. Either way typed formats
//! must be valid for the record's class; a lone `OwnedRData` has no class,
//! so the data of a type defined only for class IN (A, AAAA, SVCB, ...),
//! which is opaque in other classes, is accepted as it is. Missing sections of a message are
//! empty, and a section holds at most 65535 entries (the header counts
//! are 16-bit, RFC 1035 §4.1.1): longer input is refused while it is read,
//! so its size is bounded by the format, not only by the input.
//!
//! # Master files
//!
//! Records read from a master file (RFC 1035 §5) convert with
//! `OwnedRecord::from` a [`ZoneRecord`] or [`ZoneRecordBuf`] (e.g. from
//! [`zone::parse`](crate::zone::parse)); a single entry parses with
//! [`str::parse`] ([`OwnedRecord`]'s [`FromStr`]), and standalone RDATA
//! text with [`OwnedRData::from_text`].

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use crate::builder::MessageBuilder;
use crate::edns::OptHeader;
use crate::message::dig::{self, DigMessage, DigRecord};
use crate::message::{Message, Question, Record, Section};
use crate::name::{Name, NameBuf, ToName};
use crate::rdata::{ComposeRdata, RData};
use crate::wire::{Composer, OutBuf, WireReader};
use crate::zone::{Entry, ZoneReader, ZoneRecord, ZoneRecordBuf};
use crate::{Class, Error, Flags, Header, Rcode, Result, Rtype};

#[cfg(feature = "serde")]
mod serde_impl;
#[cfg(test)]
mod tests;

/// The largest RDATA: RDLENGTH is a 16-bit field (RFC 1035 §3.2.1).
const MAX_RDATA_LEN: usize = u16::MAX as usize;

/// Owned record data: the record type plus the RDATA in uncompressed wire
/// form (RFC 1035 §3.2.1, RFC 3597 §4), in one heap allocation.
///
/// The typed view is decoded on demand: [`as_rdata`](Self::as_rdata) for a
/// class-independent view, [`parse`](Self::parse) with exact
/// [`RData::parse`] semantics for a given class. Names inside the RDATA are
/// stored uncompressed, so the bytes are self-contained.
///
/// As record data for the [`MessageBuilder`] ([`ComposeRdata`]), the bytes
/// are re-encoded through the typed view, so the names that RFC 3597 §4
/// allows to be compressed are compressed again, and DNSSEC canonical form
/// ([`Canonical`](crate::wire::Canonical)) lowercases the right names.
///
/// Equality and hashing compare the type and the bytes exactly (names
/// inside RDATA case-sensitively).
///
/// ```
/// use dnsbox::rdata::RData;
/// use dnsbox::{Class, OwnedRData, Rtype};
///
/// let srv = OwnedRData::from_text(Rtype::SRV, Class::IN, "0 5 443 www.example.com.")?;
/// assert_eq!(srv.rtype(), Rtype::SRV);
/// assert_eq!(srv.len(), 6 + 17);
/// match srv.parse(Class::IN)? {
///     RData::Srv(view) => assert_eq!(view.port, 443),
///     other => panic!("unexpected {other}"),
/// }
/// // Owned values can be stored and sent across threads.
/// let records: Vec<OwnedRData> = vec![srv.clone(), srv];
/// assert_eq!(records[0], records[1]);
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct OwnedRData {
    rtype: Rtype,
    data: Box<[u8]>,
}

impl OwnedRData {
    /// Encodes any record data (a parsed view such as [`RData`] or
    /// [`Mx`](crate::rdata::Mx), or a compose-only helper such as
    /// [`TxtParts`](crate::rdata::TxtParts)), writing names uncompressed.
    ///
    /// # Errors
    ///
    /// Fails with the composer's error, or [`Error::BufferTooSmall`] if the
    /// RDATA exceeds 65535 octets (RFC 1035 §3.2.1).
    ///
    /// ```
    /// use dnsbox::{NameBuf, OwnedRData, Rtype};
    /// use dnsbox::rdata::Mx;
    ///
    /// let exchange: NameBuf = "mail.example.com".parse()?;
    /// let mx = OwnedRData::new(&Mx { preference: 10, exchange: exchange.as_name() })?;
    /// assert_eq!(mx.rtype(), Rtype::MX);
    /// assert_eq!(mx.to_string(), "10 mail.example.com.");
    /// assert_eq!(mx.as_wire(), b"\x00\x0a\x04mail\x07example\x03com\x00");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn new<D: ComposeRdata + ?Sized>(data: &D) -> Result<Self> {
        let mut buf = Vec::new();
        data.compose_rdata(&mut buf)?;
        if buf.len() > MAX_RDATA_LEN {
            return Err(Error::BufferTooSmall);
        }
        Ok(OwnedRData {
            rtype: data.rtype(),
            data: buf.into_boxed_slice(),
        })
    }

    /// Decodes and re-encodes uncompressed wire RDATA of the given type and
    /// class, with [`RData::parse`] semantics: typed formats must be valid
    /// (their error is returned), unknown types and class-mismatched data
    /// are kept opaque (RFC 3597).
    ///
    /// # Errors
    ///
    /// The typed format's parse error for malformed RDATA.
    ///
    /// ```
    /// use dnsbox::{Class, Error, OwnedRData, Rtype};
    ///
    /// let a = OwnedRData::from_wire(Rtype::A, Class::IN, &[192, 0, 2, 1])?;
    /// assert_eq!(a.to_string(), "192.0.2.1");
    /// assert_eq!(OwnedRData::from_wire(Rtype::A, Class::IN, &[1]), Err(Error::UnexpectedEof));
    /// // An unregistered type is opaque.
    /// let x = OwnedRData::from_wire(Rtype::new(65280), Class::IN, &[1])?;
    /// assert_eq!(x.to_string(), "\\# 1 01");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn from_wire(rtype: Rtype, class: Class, rdata: &[u8]) -> Result<Self> {
        let parsed = RData::parse(rtype, class, WireReader::new(rdata))?;
        Self::new(&parsed)
    }

    /// Parses the presentation format of `rtype`'s RDATA, or the RFC 3597
    /// §5 generic form (`\\# <length> <hex>`), as it appears in a master
    /// file (RFC 1035 §5.1) for a record of `class` ([`RData::parse_text`]).
    /// Relative names are taken relative to the root.
    ///
    /// # Errors
    ///
    /// Fails with the parser's error, e.g. [`Error::NoTextFormat`] for a
    /// type without a presentation format of its own given in that format.
    ///
    /// ```
    /// use dnsbox::{Class, OwnedRData, Rtype};
    ///
    /// let mx = OwnedRData::from_text(Rtype::MX, Class::IN, "10 mail.example.com.")?;
    /// assert_eq!(mx.as_wire(), b"\x00\x0a\x04mail\x07example\x03com\x00");
    /// let a = OwnedRData::from_text(Rtype::A, Class::IN, r"\# 4 C0000201")?;
    /// assert_eq!(a.to_string(), "192.0.2.1");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn from_text(rtype: Rtype, class: Class, text: &str) -> Result<Self> {
        let wire = RData::text_to_wire(rtype, class, text)?;
        Ok(Self::from_checked(rtype, wire))
    }

    /// Wraps RDATA that [`RData::parse`] already accepted (uncompressed,
    /// at most 65535 octets).
    pub(crate) fn from_checked(rtype: Rtype, rdata: Vec<u8>) -> Self {
        debug_assert!(rdata.len() <= MAX_RDATA_LEN);
        OwnedRData {
            rtype,
            data: rdata.into_boxed_slice(),
        }
    }

    /// The record type.
    ///
    /// ```
    /// use dnsbox::{Class, OwnedRData, Rtype};
    ///
    /// let data = OwnedRData::from_text(Rtype::AAAA, Class::IN, "2001:db8::1")?;
    /// assert_eq!(data.rtype(), Rtype::AAAA);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub fn rtype(&self) -> Rtype {
        self.rtype
    }

    /// The RDATA in uncompressed wire form.
    ///
    /// ```
    /// use dnsbox::{Class, OwnedRData, Rtype};
    ///
    /// let cname = OwnedRData::from_text(Rtype::CNAME, Class::IN, "web.example.")?;
    /// // Names are stored uncompressed.
    /// assert_eq!(cname.as_wire(), b"\x03web\x07example\x00");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub fn as_wire(&self) -> &[u8] {
        &self.data
    }

    /// The RDATA length (RDLENGTH, with names uncompressed).
    ///
    /// ```
    /// use dnsbox::{Class, OwnedRData, Rtype};
    ///
    /// let a = OwnedRData::from_text(Rtype::A, Class::IN, "192.0.2.1")?;
    /// let txt = OwnedRData::from_text(Rtype::TXT, Class::IN, "\"hello\" \"world\"")?;
    /// assert_eq!((a.len(), txt.len()), (4, 12));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the RDATA is empty (e.g. a dynamic-update deletion,
    /// RFC 2136 §2.5.2).
    ///
    /// ```
    /// use dnsbox::{Class, OwnedRData, Rtype};
    ///
    /// // "Delete an RRset" in a dynamic update: no RDATA (RFC 2136 §2.5.2).
    /// let delete = OwnedRData::from_wire(Rtype::A, Class::ANY, &[])?;
    /// assert!(delete.is_empty());
    /// assert!(!OwnedRData::from_text(Rtype::A, Class::IN, "192.0.2.1")?.is_empty());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Decodes the RDATA as [`RData::parse`] would for a record of `class`
    /// (class-specific formats such as A are only typed in class IN,
    /// RFC 3597 §4; empty data in class NONE/ANY is opaque, RFC 2136 §2.5).
    ///
    /// # Errors
    ///
    /// As [`RData::parse`]; data built through this type was valid for
    /// the class it was built for.
    ///
    /// ```
    /// use dnsbox::rdata::RData;
    /// use dnsbox::{Class, OwnedRData, Rtype};
    ///
    /// let a = OwnedRData::from_text(Rtype::A, Class::IN, "192.0.2.1")?;
    /// assert!(matches!(a.parse(Class::IN)?, RData::A(_)));
    /// // A's format is only defined for class IN (RFC 1035 §3.4.1).
    /// assert!(matches!(a.parse(Class::CH)?, RData::Unknown(_)));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn parse(&self, class: Class) -> Result<RData<'_>> {
        RData::parse(self.rtype, class, WireReader::new(&self.data))
    }

    /// The typed view, class-independently: the typed format when the
    /// bytes decode as one (in class IN), [`RData::Unknown`] otherwise.
    /// Never fails.
    ///
    /// ```
    /// use dnsbox::rdata::RData;
    /// use dnsbox::{Class, OwnedRData, Rtype};
    ///
    /// let mx = OwnedRData::from_text(Rtype::MX, Class::IN, "10 mail.example.")?;
    /// let RData::Mx(view) = mx.as_rdata() else { panic!("an MX") };
    /// assert_eq!(view.preference, 10);
    /// assert_eq!(view.exchange.to_string(), "mail.example.");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn as_rdata(&self) -> RData<'_> {
        self.parse(Class::IN)
            .unwrap_or(RData::Unknown(crate::rdata::UnknownRdata::new(
                self.rtype, &self.data,
            )))
    }
}

impl ComposeRdata for OwnedRData {
    #[inline]
    fn rtype(&self) -> Rtype {
        self.rtype
    }

    /// Writes the RDATA through its typed view, so names are compressed
    /// or canonicalized as the record type's RFC says; opaque data is
    /// copied verbatim (it holds no compressible names, RFC 3597 §4).
    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        self.as_rdata().compose_rdata(c)
    }
}

impl<'a> TryFrom<&RData<'a>> for OwnedRData {
    type Error = Error;

    /// See [`OwnedRData::new`].
    fn try_from(data: &RData<'a>) -> Result<Self> {
        Self::new(data)
    }
}

impl<'a> TryFrom<RData<'a>> for OwnedRData {
    type Error = Error;

    /// See [`OwnedRData::new`].
    fn try_from(data: RData<'a>) -> Result<Self> {
        Self::new(&data)
    }
}

impl fmt::Display for OwnedRData {
    /// Presentation format of the RDATA (see [`RData`]'s `Display`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.as_rdata(), f)
    }
}

impl fmt::Debug for OwnedRData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedRData")
            .field("rtype", &self.rtype)
            .field("data", &format_args!("{self}"))
            .finish()
    }
}

/// An owned entry of the question section (RFC 1035 §4.1.2).
///
/// ```
/// use dnsbox::{Class, OwnedQuestion, Rtype};
///
/// let q = OwnedQuestion::new(&"example.com".parse::<dnsbox::NameBuf>()?, Rtype::AAAA, Class::IN);
/// assert_eq!(q.to_string(), "example.com. IN AAAA");
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OwnedQuestion {
    /// QNAME.
    pub name: NameBuf,
    /// QTYPE.
    pub qtype: Rtype,
    /// QCLASS.
    pub qclass: Class,
}

impl OwnedQuestion {
    /// Builds a question.
    ///
    /// ```
    /// use dnsbox::{Class, NameBuf, OwnedQuestion, Rtype};
    ///
    /// let zone: NameBuf = "example.com".parse()?;
    /// let q = OwnedQuestion::new(&zone, Rtype::SOA, Class::IN);
    /// assert_eq!((q.name, q.qtype, q.qclass), (zone, Rtype::SOA, Class::IN));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn new(name: impl ToName, qtype: Rtype, qclass: Class) -> Self {
        OwnedQuestion {
            name: NameBuf::from_name(name.to_name()),
            qtype,
            qclass,
        }
    }

    /// Copies a question view (decompressing its name).
    ///
    /// ```
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, OwnedQuestion, Rtype};
    ///
    /// let name: NameBuf = "example.com".parse()?;
    /// let mut buf = [0u8; 64];
    /// let query = Message::parse(MessageBuilder::query(&mut buf, 1, &name, Rtype::A, Class::IN)?.finish())?;
    /// // Remember the question of an outstanding query.
    /// let pending = OwnedQuestion::from_question(&query.questions().next().unwrap()?);
    /// assert_eq!(pending.to_string(), "example.com. IN A");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn from_question(q: &Question<'_>) -> Self {
        Self::new(q.name(), q.qtype(), q.qclass())
    }

    /// Appends the question to a builder (RFC 1035 §4.1.2).
    ///
    /// # Errors
    ///
    /// As [`MessageBuilder::push_question`].
    ///
    /// ```
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, OwnedQuestion, Rtype};
    ///
    /// let q = OwnedQuestion::new(&"example.org".parse::<NameBuf>()?, Rtype::NS, Class::IN);
    /// let mut buf = [0u8; 64];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// q.push_to(&mut b)?;
    /// let msg = Message::parse_validated(b.finish())?;
    /// assert_eq!(msg.questions().next().unwrap()?.to_string(), "example.org. IN NS");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn push_to<B: OutBuf>(&self, b: &mut MessageBuilder<B>) -> Result<()> {
        b.push_question(&self.name, self.qtype, self.qclass)
    }
}

impl From<&Question<'_>> for OwnedQuestion {
    #[inline]
    fn from(q: &Question<'_>) -> Self {
        Self::from_question(q)
    }
}

impl From<Question<'_>> for OwnedQuestion {
    #[inline]
    fn from(q: Question<'_>) -> Self {
        Self::from_question(&q)
    }
}

impl fmt::Display for OwnedQuestion {
    /// `name class type`, as [`Question`]'s `Display`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.name, self.qclass, self.qtype)
    }
}

/// An owned resource record (RFC 1035 §4.1.3).
///
/// The TYPE is that of the [`rdata`](Self::rdata). CLASS and TTL are the
/// raw fields, as in [`Record`] (for OPT they carry the EDNS header, RFC
/// 6891 §6.1.3; see [`OptHeader::from_fields`]).
///
/// ```
/// use dnsbox::{Class, NameBuf, OwnedRData, OwnedRecord};
/// use dnsbox::rdata::A;
///
/// let name: NameBuf = "www.example.com".parse()?;
/// let rr = OwnedRecord::new(&name, Class::IN, 300, OwnedRData::new(&A { addr: [192, 0, 2, 1].into() })?);
/// assert_eq!(rr.to_string(), "www.example.com. 300 IN A 192.0.2.1");
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OwnedRecord {
    /// The owner name.
    pub name: NameBuf,
    /// CLASS (raw).
    pub class: Class,
    /// TTL (raw; RFC 2181 §8 says to treat a set top bit as zero).
    pub ttl: u32,
    /// TYPE and RDATA.
    pub rdata: OwnedRData,
}

impl OwnedRecord {
    /// Builds a record.
    ///
    /// ```
    /// use dnsbox::{Class, NameBuf, OwnedRData, OwnedRecord, Rtype};
    ///
    /// let name: NameBuf = "example.com".parse()?;
    /// let rdata = OwnedRData::from_text(Rtype::CAA, Class::IN, "0 issue \"letsencrypt.org\"")?;
    /// let rr = OwnedRecord::new(&name, Class::IN, 3600, rdata);
    /// assert_eq!(rr.to_string(), "example.com. 3600 IN CAA 0 issue \"letsencrypt.org\"");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn new(name: impl ToName, class: Class, ttl: u32, rdata: OwnedRData) -> Self {
        OwnedRecord {
            name: NameBuf::from_name(name.to_name()),
            class,
            ttl,
            rdata,
        }
    }

    /// Copies a record view. The RDATA is decoded (typed formats must be
    /// valid, as for [`Record::data`]) and stored with its names
    /// decompressed.
    ///
    /// # Errors
    ///
    /// The RDATA parse error, as for [`Record::data`].
    ///
    /// ```
    /// use dnsbox::{Message, OwnedRecord};
    /// # use dnsbox::{Class, MessageBuilder, NameBuf, rdata::Cname};
    /// # let (alias, target): (NameBuf, NameBuf) = ("www.example".parse()?, "web.example".parse()?);
    /// # let mut buf = [0u8; 128];
    /// # let mut b = MessageBuilder::new(&mut buf)?;
    /// # b.push_answer(&alias, Class::IN, 60, &Cname::new(target.as_name()))?;
    /// # let wire = b.finish();
    /// let msg = Message::parse(wire)?;
    /// let owned: Vec<OwnedRecord> = msg
    ///     .answers()
    ///     .map(|rr| OwnedRecord::from_record(&rr?))
    ///     .collect::<Result<_, _>>()?;
    /// drop(msg); // the owned records do not borrow the message
    /// assert_eq!(owned[0].to_string(), "www.example. 60 IN CNAME web.example.");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn from_record(rr: &Record<'_>) -> Result<Self> {
        Ok(Self::new(
            rr.name(),
            rr.class(),
            rr.ttl(),
            OwnedRData::new(&rr.data()?)?,
        ))
    }

    /// TYPE.
    ///
    /// ```
    /// use dnsbox::{OwnedRecord, Rtype};
    ///
    /// let rr: OwnedRecord = "_imaps._tcp.example.com. 300 IN SRV 0 1 993 mail.example.com.".parse()?;
    /// assert_eq!(rr.rtype(), Rtype::SRV);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub fn rtype(&self) -> Rtype {
        self.rdata.rtype()
    }

    /// The typed RDATA, decoded exactly as [`Record::data`] would decode
    /// it for this record's class.
    ///
    /// # Errors
    ///
    /// As [`OwnedRData::parse`].
    ///
    /// ```
    /// use dnsbox::rdata::RData;
    /// use dnsbox::OwnedRecord;
    ///
    /// let rr: OwnedRecord = "_imaps._tcp.example.com. 300 IN SRV 0 1 993 mail.example.com.".parse()?;
    /// let RData::Srv(srv) = rr.data()? else { panic!("an SRV") };
    /// assert_eq!((srv.port, srv.target.to_string()), (993, "mail.example.com.".to_string()));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub fn data(&self) -> Result<RData<'_>> {
        self.rdata.parse(self.class)
    }

    /// Appends the record to `section` of a builder, which recompresses the
    /// names it may compress.
    ///
    /// # Errors
    ///
    /// As [`MessageBuilder::push_record`].
    ///
    /// ```
    /// use dnsbox::{Message, MessageBuilder, OwnedRecord, Section};
    ///
    /// let rrs: Vec<OwnedRecord> = ["example.com. 300 IN NS ns1.example.com.", "ns1.example.com. 300 IN A 192.0.2.53"]
    ///     .iter()
    ///     .map(|s| s.parse())
    ///     .collect::<Result<_, _>>()?;
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// rrs[0].push_to(&mut b, Section::Authority)?;
    /// rrs[1].push_to(&mut b, Section::Additional)?;
    /// let msg = Message::parse_validated(b.finish())?;
    /// assert_eq!((msg.header().nscount, msg.header().arcount), (1, 1));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn push_to<B: OutBuf>(&self, b: &mut MessageBuilder<B>, section: Section) -> Result<()> {
        b.push_record(section, &self.name, self.class, self.ttl, &self.rdata)
    }
}

impl TryFrom<&Record<'_>> for OwnedRecord {
    type Error = Error;

    /// See [`OwnedRecord::from_record`].
    #[inline]
    fn try_from(rr: &Record<'_>) -> Result<Self> {
        Self::from_record(rr)
    }
}

impl TryFrom<Record<'_>> for OwnedRecord {
    type Error = Error;

    /// See [`OwnedRecord::from_record`].
    #[inline]
    fn try_from(rr: Record<'_>) -> Result<Self> {
        Self::from_record(&rr)
    }
}

impl From<ZoneRecordBuf> for OwnedRecord {
    /// A record read from a master file ([`zone::parse`](crate::zone::parse),
    /// [`Records`](crate::zone::Records)); its RDATA is kept as read
    /// (already checked, names uncompressed). The line number is dropped.
    fn from(rr: ZoneRecordBuf) -> Self {
        OwnedRecord {
            name: rr.name,
            class: rr.class,
            ttl: rr.ttl,
            rdata: OwnedRData::from_checked(rr.rtype, rr.rdata),
        }
    }
}

impl From<ZoneRecord<'_>> for OwnedRecord {
    /// A record read by a [`ZoneReader`]; see
    /// `From<ZoneRecordBuf>`.
    fn from(rr: ZoneRecord<'_>) -> Self {
        OwnedRecord {
            rdata: OwnedRData::from_checked(rr.rtype, rr.rdata.to_vec()),
            name: rr.name,
            class: rr.class,
            ttl: rr.ttl,
        }
    }
}

impl From<&ZoneRecord<'_>> for OwnedRecord {
    /// See `From<ZoneRecord>`.
    fn from(rr: &ZoneRecord<'_>) -> Self {
        OwnedRecord {
            name: rr.name.clone(),
            class: rr.class,
            ttl: rr.ttl,
            rdata: OwnedRData::from_checked(rr.rtype, rr.rdata.to_vec()),
        }
    }
}

impl FromStr for OwnedRecord {
    type Err = Error;

    /// Parses one master-file entry, `owner [ttl] [class] type rdata`
    /// (RFC 1035 §5.1; TTL and class in either order), with the
    /// [`ZoneReader`] rules: relative names are
    /// relative to the root, the class defaults to IN, and a TTL is
    /// required (an SOA's MINIMUM stands in for it). The entry may span
    /// lines in parentheses and carry a comment.
    ///
    /// `$ORIGIN` and `$TTL` before the record apply to it.
    ///
    /// # Errors
    ///
    /// The reader's error ([`Error::MissingTtl`],
    /// [`Error::InvalidText`], ...), [`Error::UnexpectedEof`] for
    /// text holding no record, and [`Error::InvalidText`] for more
    /// than one record (including a `$GENERATE` range of more than one)
    /// or an `$INCLUDE`.
    ///
    /// ```
    /// use dnsbox::{OwnedRecord, Rtype};
    ///
    /// let rr: OwnedRecord = "mail.example.com. 3600 IN MX 10 mx1.example.com.".parse()?;
    /// assert_eq!(rr.rtype(), Rtype::MX);
    /// assert_eq!(rr.to_string(), "mail.example.com. 3600 IN MX 10 mx1.example.com.");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    fn from_str(s: &str) -> Result<Self> {
        let mut reader = ZoneReader::new(s);
        let mut rdata = alloc::vec![0u8; MAX_RDATA_LEN];
        let rr = match reader.next_entry(&mut rdata)? {
            Some(Entry::Record(rr)) => OwnedRecord::from(rr),
            Some(_) => return Err(Error::InvalidText),
            None => return Err(Error::UnexpectedEof),
        };
        match reader.next_entry(&mut rdata)? {
            None => Ok(rr),
            Some(_) => Err(Error::InvalidText),
        }
    }
}

impl fmt::Display for OwnedRecord {
    /// Zone-file style, `name ttl class type rdata`, as [`Record`]'s
    /// `Display`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} ",
            self.name,
            self.ttl,
            self.class,
            self.rtype()
        )?;
        match self.data() {
            Ok(d) => fmt::Display::fmt(&d, f),
            Err(_) => crate::text::fmt_generic_rdata(f, self.rdata.as_wire()),
        }
    }
}

/// An owned DNS message (RFC 1035 §4.1): header fields and the four
/// sections. Section counts are the lengths of the vectors.
///
/// `Display` is the `dig` form of the borrowed [`Message`] view.
///
/// ```
/// use dnsbox::{Class, Flags, Message, NameBuf, Opcode, OwnedMessage, OwnedQuestion, Rtype};
///
/// let mut q = OwnedMessage::new(0x1234, Flags::default().with_rd(true));
/// q.questions.push(OwnedQuestion::new(&"example.com".parse::<NameBuf>()?, Rtype::A, Class::IN));
/// let wire = q.to_vec()?;
/// assert_eq!(wire.len(), 29);
/// assert_eq!(OwnedMessage::from_wire(&wire)?, q);
/// assert!(q.to_string().starts_with(";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4660\n"));
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct OwnedMessage {
    /// Transaction ID.
    pub id: u16,
    /// QR, opcode, flag bits and header RCODE (RFC 1035 §4.1.1).
    pub flags: Flags,
    /// The question section (the zone section in UPDATE, RFC 2136 §2.3).
    pub questions: Vec<OwnedQuestion>,
    /// The answer section (prerequisites in UPDATE).
    pub answers: Vec<OwnedRecord>,
    /// The authority section (updates in UPDATE).
    pub authority: Vec<OwnedRecord>,
    /// The additional section, including the OPT, TSIG and SIG(0) records.
    pub additional: Vec<OwnedRecord>,
}

/// The shortest question in wire form: the root name, type and class.
const MIN_QUESTION_LEN: usize = 5;

/// The shortest record in wire form: the root name, type, class, TTL and
/// RDLENGTH, no RDATA.
const MIN_RECORD_LEN: usize = 11;

/// The entries to reserve for a section whose header count is `count`, in
/// a message of `len` octets. The count is the sender's claim: reserve no
/// more than the message can hold, so that a 12-octet header cannot make
/// us allocate room for 4 x 65535 entries (some 70 MB).
fn reserve(count: u16, len: usize, min_entry_len: usize) -> usize {
    let room = len.saturating_sub(Header::LEN);
    usize::from(count).min(room / min_entry_len)
}

impl OwnedMessage {
    /// An empty message with the given ID and flags.
    ///
    /// ```
    /// use dnsbox::{Flags, OwnedMessage};
    ///
    /// let msg = OwnedMessage::new(42, Flags::default().with_qr(true).with_aa(true));
    /// assert_eq!(msg.header()?.id, 42);
    /// assert!(msg.questions.is_empty() && msg.answers.is_empty());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn new(id: u16, flags: Flags) -> Self {
        OwnedMessage {
            id,
            flags,
            ..Default::default()
        }
    }

    /// Copies a message view: every question and record, with names
    /// decompressed. Typed RDATA must be valid (as for [`Record::data`]);
    /// the first error met while walking the message is returned. Trailing
    /// bytes after the last record are not checked (see
    /// [`from_wire`](Self::from_wire)).
    ///
    /// # Errors
    ///
    /// The first parse error met while walking the message.
    ///
    /// ```
    /// use dnsbox::rdata::A;
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, OwnedMessage, Rtype};
    ///
    /// let name: NameBuf = "www.example".parse()?;
    /// let mut qbuf = [0u8; 64];
    /// let query = Message::parse(MessageBuilder::query(&mut qbuf, 5, &name, Rtype::A, Class::IN)?.finish())?;
    /// let mut buf = [0u8; 128];
    /// let mut b = MessageBuilder::response(&mut buf, &query)?;
    /// b.push_answer(&name, Class::IN, 60, &A::new([192, 0, 2, 1].into()))?;
    /// let response = Message::parse(b.finish())?;
    /// // Edit a received response: here, cap the TTLs.
    /// let mut owned = OwnedMessage::from_message(&response)?;
    /// for rr in &mut owned.answers {
    ///     rr.ttl = rr.ttl.min(30);
    /// }
    /// assert_eq!(owned.answers[0].to_string(), "www.example. 30 IN A 192.0.2.1");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn from_message(msg: &Message<'_>) -> Result<Self> {
        let h = msg.header();
        let len = msg.as_bytes().len();
        let mut m = OwnedMessage {
            id: h.id,
            flags: h.flags,
            questions: Vec::with_capacity(reserve(h.qdcount, len, MIN_QUESTION_LEN)),
            answers: Vec::with_capacity(reserve(h.ancount, len, MIN_RECORD_LEN)),
            authority: Vec::with_capacity(reserve(h.nscount, len, MIN_RECORD_LEN)),
            additional: Vec::with_capacity(reserve(h.arcount, len, MIN_RECORD_LEN)),
        };
        for q in msg.questions() {
            m.questions.push(OwnedQuestion::from_question(&q?));
        }
        for rr in msg.records() {
            let (section, rr) = rr?;
            let rr = OwnedRecord::from_record(&rr)?;
            if let Some(v) = m.section_mut(section) {
                v.push(rr);
            }
        }
        Ok(m)
    }

    /// Parses and [validates](Message::validate) wire bytes, then copies
    /// them. See the [module example](self).
    ///
    /// # Errors
    ///
    /// The first error [`Message::validate`] finds.
    ///
    /// ```
    /// use dnsbox::{Error, OwnedMessage, Rtype};
    ///
    /// let wire = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
    ///              \x07example\x03com\x00\x00\x0f\x00\x01";
    /// let msg = OwnedMessage::from_wire(wire)?;
    /// assert_eq!((msg.id, msg.questions[0].qtype), (0x1234, Rtype::MX));
    /// // Trailing garbage is rejected.
    /// let mut longer = wire.to_vec();
    /// longer.push(0);
    /// assert_eq!(OwnedMessage::from_wire(&longer), Err(Error::TrailingData));
    /// # Ok::<(), Error>(())
    /// ```
    pub fn from_wire(wire: &[u8]) -> Result<Self> {
        Self::from_message(&Message::parse_validated(wire)?)
    }

    /// The header, with counts from the section lengths.
    ///
    /// # Errors
    ///
    /// [`Error::CountOverflow`] if a section holds more than 65535
    /// entries.
    ///
    /// ```
    /// use dnsbox::{Flags, OwnedMessage, OwnedRecord};
    ///
    /// let mut msg = OwnedMessage::new(9, Flags::default().with_qr(true));
    /// msg.answers.push("example. 60 IN A 192.0.2.1".parse::<OwnedRecord>()?);
    /// msg.answers.push("example. 60 IN A 192.0.2.2".parse::<OwnedRecord>()?);
    /// let h = msg.header()?;
    /// assert_eq!((h.id, h.qdcount, h.ancount), (9, 0, 2));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn header(&self) -> Result<Header> {
        let count = |n: usize| u16::try_from(n).map_err(|_| Error::CountOverflow);
        Ok(Header {
            id: self.id,
            flags: self.flags,
            qdcount: count(self.questions.len())?,
            ancount: count(self.answers.len())?,
            nscount: count(self.authority.len())?,
            arcount: count(self.additional.len())?,
        })
    }

    /// The records of a section (empty for [`Section::Question`]; see
    /// [`questions`](Self::questions)).
    ///
    /// ```
    /// use dnsbox::{Flags, OwnedMessage, OwnedRecord, Section};
    ///
    /// let mut msg = OwnedMessage::new(1, Flags::default());
    /// msg.authority.push("example. 3600 IN NS ns1.example.".parse::<OwnedRecord>()?);
    /// let counts: Vec<usize> = Section::ALL.iter().map(|&s| msg.section(s).len()).collect();
    /// assert_eq!(counts, [0, 0, 1, 0]);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn section(&self, section: Section) -> &[OwnedRecord] {
        match section {
            Section::Question => &[],
            Section::Answer => &self.answers,
            Section::Authority => &self.authority,
            Section::Additional => &self.additional,
        }
    }

    /// The records of a section, mutably (`None` for
    /// [`Section::Question`]).
    ///
    /// ```
    /// use dnsbox::{Flags, OwnedMessage, OwnedRecord, Section};
    ///
    /// let mut msg = OwnedMessage::new(1, Flags::default());
    /// let rr: OwnedRecord = "example. 60 IN TXT \"hello\"".parse()?;
    /// msg.section_mut(Section::Additional).expect("a record section").push(rr);
    /// assert_eq!(msg.additional.len(), 1);
    /// assert!(msg.section_mut(Section::Question).is_none());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn section_mut(&mut self, section: Section) -> Option<&mut Vec<OwnedRecord>> {
        match section {
            Section::Question => None,
            Section::Answer => Some(&mut self.answers),
            Section::Authority => Some(&mut self.authority),
            Section::Additional => Some(&mut self.additional),
        }
    }

    /// Every record (answer, authority, additional) with its section, in
    /// wire order.
    ///
    /// ```
    /// use dnsbox::{Flags, OwnedMessage, OwnedRecord, Section};
    ///
    /// let mut msg = OwnedMessage::new(1, Flags::default().with_qr(true));
    /// msg.answers.push("www.example. 60 IN A 192.0.2.1".parse::<OwnedRecord>()?);
    /// msg.additional.push("ns.example. 60 IN A 192.0.2.53".parse::<OwnedRecord>()?);
    /// let lines: Vec<String> = msg.records().map(|(s, rr)| format!("{s}: {rr}")).collect();
    /// assert_eq!(lines, ["ANSWER: www.example. 60 IN A 192.0.2.1", "ADDITIONAL: ns.example. 60 IN A 192.0.2.53"]);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn records(&self) -> impl Iterator<Item = (Section, &OwnedRecord)> {
        let answers = self.answers.iter().map(|rr| (Section::Answer, rr));
        let authority = self.authority.iter().map(|rr| (Section::Authority, rr));
        let additional = self.additional.iter().map(|rr| (Section::Additional, rr));
        answers.chain(authority).chain(additional)
    }

    /// The first OPT record of the additional section (RFC 6891 §6.1.1).
    ///
    /// ```
    /// use dnsbox::edns::OptHeader;
    /// use dnsbox::{Class, MessageBuilder, NameBuf, OwnedMessage, Rtype};
    ///
    /// let name: NameBuf = "example.com".parse()?;
    /// let mut b = MessageBuilder::query_vec(1, &name, Rtype::A, Class::IN)?;
    /// b.push_edns(OptHeader::new(1232), &())?;
    /// let msg = OwnedMessage::from_wire(&b.finish())?;
    /// let opt = msg.opt().expect("EDNS");
    /// assert_eq!((opt.rtype(), opt.class.get()), (Rtype::OPT, 1232));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn opt(&self) -> Option<&OwnedRecord> {
        self.additional.iter().find(|rr| rr.rtype() == Rtype::OPT)
    }

    /// The EDNS header fields of the first OPT record (RFC 6891 §6.1.3).
    ///
    /// ```
    /// use dnsbox::edns::OptHeader;
    /// use dnsbox::{Class, MessageBuilder, NameBuf, OwnedMessage, Rtype};
    ///
    /// let name: NameBuf = "example.com".parse()?;
    /// let mut b = MessageBuilder::query_vec(1, &name, Rtype::DNSKEY, Class::IN)?;
    /// b.push_edns(OptHeader::new(4096).with_dnssec_ok(true), &())?;
    /// let msg = OwnedMessage::from_wire(&b.finish())?;
    /// let edns = msg.opt_header().expect("EDNS");
    /// assert_eq!(edns.udp_payload_size, 4096);
    /// assert!(edns.dnssec_ok());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn opt_header(&self) -> Option<OptHeader> {
        self.opt()
            .map(|rr| OptHeader::from_fields(rr.class, rr.ttl))
    }

    /// The full response code: the header RCODE combined with the extended
    /// RCODE of the OPT record, if any (RFC 6891 §6.1.3).
    ///
    /// ```
    /// use dnsbox::{Flags, OwnedMessage, Rcode};
    ///
    /// let msg = OwnedMessage::new(1, Flags::default().with_qr(true).with_rcode(Rcode::SERVFAIL));
    /// assert_eq!(msg.effective_rcode(), Rcode::SERVFAIL); // no OPT record
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn effective_rcode(&self) -> Rcode {
        match self.opt_header() {
            Some(h) => h.rcode(self.flags),
            None => self.flags.rcode(),
        }
    }

    /// Writes the message into an empty builder: sets the ID and flags,
    /// then pushes every question and record in order (record-level pushes:
    /// no truncation, an entry that does not fit fails the call with
    /// [`Error::BufferTooSmall`]). Names are compressed if the builder
    /// compresses.
    ///
    /// # Errors
    ///
    /// The errors of [`MessageBuilder::push_question`] and
    /// [`MessageBuilder::push_record`]: [`Error::BufferTooSmall`] for an
    /// entry that does not fit, [`Error::SectionOrder`] if the builder
    /// already held records. The entries written before the failing one
    /// stay in the builder (use a [checkpoint](MessageBuilder::checkpoint)
    /// to undo them).
    ///
    /// ```
    /// use dnsbox::{Flags, MessageBuilder, OwnedMessage};
    ///
    /// let msg = OwnedMessage::new(7, Flags::default().with_qr(true));
    /// // Into a stack buffer, with a TCP length prefix.
    /// let mut buf = [0u8; 64];
    /// let mut b = MessageBuilder::new_tcp(&mut buf)?;
    /// msg.write_to(&mut b)?;
    /// assert_eq!(b.finish().len(), 2 + 12);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn write_to<B: OutBuf>(&self, b: &mut MessageBuilder<B>) -> Result<()> {
        b.set_id(self.id);
        b.set_flags(self.flags);
        for q in &self.questions {
            q.push_to(b)?;
        }
        for (section, rr) in self.records() {
            rr.push_to(b, section)?;
        }
        Ok(())
    }

    /// Encodes the message with name compression into a new `Vec`.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] beyond 65535 octets or
    /// [`Error::CountOverflow`] beyond 65535 entries in a section.
    ///
    /// ```
    /// use dnsbox::{Flags, Message, OwnedMessage, OwnedRecord};
    ///
    /// let mut msg = OwnedMessage::new(3, Flags::default().with_qr(true));
    /// msg.answers.push("www.example. 60 IN A 192.0.2.1".parse::<OwnedRecord>()?);
    /// msg.answers.push("www.example. 60 IN A 192.0.2.2".parse::<OwnedRecord>()?);
    /// let wire = msg.to_vec()?;
    /// // The second owner name is compressed to a pointer.
    /// assert_eq!(wire.len(), 12 + (13 + 10 + 4) + (2 + 10 + 4));
    /// assert_eq!(Message::parse_validated(&wire)?.header().ancount, 2);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        let mut b = MessageBuilder::new_vec();
        self.write_to(&mut b)?;
        Ok(b.finish())
    }
}

impl TryFrom<&Message<'_>> for OwnedMessage {
    type Error = Error;

    /// See [`OwnedMessage::from_message`].
    #[inline]
    fn try_from(msg: &Message<'_>) -> Result<Self> {
        Self::from_message(msg)
    }
}

impl TryFrom<Message<'_>> for OwnedMessage {
    type Error = Error;

    /// See [`OwnedMessage::from_message`].
    #[inline]
    fn try_from(msg: Message<'_>) -> Result<Self> {
        Self::from_message(&msg)
    }
}

impl fmt::Display for OwnedMessage {
    /// The `dig` form, exactly as [`Message`]'s `Display` shows the encoded
    /// message.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        dig::fmt_dig(f, self)
    }
}

impl Message<'_> {
    /// Copies the message into an [`OwnedMessage`]; see
    /// [`OwnedMessage::from_message`].
    ///
    /// # Errors
    ///
    /// As [`OwnedMessage::from_message`].
    ///
    /// ```
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
    ///
    /// let name: NameBuf = "example.com".parse()?;
    /// let mut buf = [0u8; 64];
    /// let wire = MessageBuilder::query(&mut buf, 77, &name, Rtype::A, Class::IN)?.finish();
    /// let owned = Message::parse(wire)?.to_owned_message()?;
    /// wire.fill(0); // the copy does not borrow the buffer
    /// assert_eq!(owned.id, 77);
    /// assert_eq!(owned.questions[0].to_string(), "example.com. IN A");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub fn to_owned_message(&self) -> Result<OwnedMessage> {
        OwnedMessage::from_message(self)
    }
}

impl Question<'_> {
    /// Copies the question into an [`OwnedQuestion`].
    ///
    /// ```
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, OwnedQuestion, Rtype};
    ///
    /// let name: NameBuf = "example.com".parse()?;
    /// let mut buf = [0u8; 64];
    /// let wire = MessageBuilder::query(&mut buf, 1, &name, Rtype::HTTPS, Class::IN)?.finish();
    /// let q: OwnedQuestion = Message::parse(wire)?.questions().next().unwrap()?.to_owned_question();
    /// assert_eq!((q.name, q.qtype), (name, Rtype::HTTPS));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub fn to_owned_question(&self) -> OwnedQuestion {
        OwnedQuestion::from_question(self)
    }
}

impl Record<'_> {
    /// Copies the record into an [`OwnedRecord`]; see
    /// [`OwnedRecord::from_record`].
    ///
    /// # Errors
    ///
    /// As [`OwnedRecord::from_record`].
    ///
    /// ```
    /// use dnsbox::rdata::A;
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, OwnedRecord};
    ///
    /// let name: NameBuf = "example".parse()?;
    /// let mut buf = [0u8; 128];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.push_answer(&name, Class::IN, 60, &A::new([192, 0, 2, 1].into()))?;
    /// let msg = Message::parse(b.finish())?;
    /// // Keep the records once the message buffer is reused.
    /// let mut cache: Vec<OwnedRecord> = Vec::new();
    /// for rr in msg.answers() {
    ///     cache.push(rr?.to_owned_record()?);
    /// }
    /// assert_eq!(cache[0].name, name);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub fn to_owned_record(&self) -> Result<OwnedRecord> {
        OwnedRecord::from_record(self)
    }
}

impl RData<'_> {
    /// Copies the record data into an [`OwnedRData`] (uncompressed wire
    /// form); see [`OwnedRData::new`].
    ///
    /// # Errors
    ///
    /// As [`OwnedRData::new`].
    ///
    /// ```
    /// use dnsbox::{Class, Rtype, RData, WireReader};
    ///
    /// let view = RData::parse(Rtype::A, Class::IN, WireReader::new(&[192, 0, 2, 1]))?;
    /// let owned = view.to_owned_rdata()?;
    /// assert_eq!(owned.as_rdata(), view);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub fn to_owned_rdata(&self) -> Result<OwnedRData> {
        OwnedRData::new(self)
    }
}

impl DigRecord for &OwnedRecord {
    fn name(&self) -> Name<'_> {
        self.name.as_name()
    }
    fn rtype(&self) -> Rtype {
        self.rdata.rtype()
    }
    fn class(&self) -> Class {
        self.class
    }
    fn ttl(&self) -> u32 {
        self.ttl
    }
    fn raw_rdata(&self) -> &[u8] {
        self.rdata.as_wire()
    }
    fn rdata(&self) -> Result<RData<'_>> {
        self.data()
    }
}

impl DigMessage for OwnedMessage {
    type Record<'r> = &'r OwnedRecord;

    fn dig_id(&self) -> u16 {
        self.id
    }

    fn dig_flags(&self) -> Flags {
        self.flags
    }

    fn dig_counts(&self) -> [u16; 4] {
        let c = |n: usize| u16::try_from(n).unwrap_or(u16::MAX);
        [
            c(self.questions.len()),
            c(self.answers.len()),
            c(self.authority.len()),
            c(self.additional.len()),
        ]
    }

    fn dig_questions(&self) -> impl Iterator<Item = Result<(Name<'_>, Rtype, Class)>> {
        self.questions
            .iter()
            .map(|q| Ok((q.name.as_name(), q.qtype, q.qclass)))
    }

    fn dig_records(&self) -> impl Iterator<Item = Result<(Section, &OwnedRecord)>> {
        self.records().map(Ok)
    }

    fn dig_trailing(&self) -> usize {
        0
    }
}
