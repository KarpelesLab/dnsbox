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
//! must be valid for the record's class. Missing sections of a message are
//! empty.
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
    #[inline]
    pub fn rtype(&self) -> Rtype {
        self.rtype
    }

    /// The RDATA in uncompressed wire form.
    #[inline]
    pub fn as_wire(&self) -> &[u8] {
        &self.data
    }

    /// The RDATA length (RDLENGTH, with names uncompressed).
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the RDATA is empty (e.g. a dynamic-update deletion,
    /// RFC 2136 §2.5.2).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Decodes the RDATA as [`RData::parse`] would for a record of `class`
    /// (class-specific formats such as A are only typed in class IN,
    /// RFC 3597 §4; empty data in class NONE/ANY is opaque, RFC 2136 §2.5).
    pub fn parse(&self, class: Class) -> Result<RData<'_>> {
        RData::parse(self.rtype, class, WireReader::new(&self.data))
    }

    /// The typed view, class-independently: the typed format when the
    /// bytes decode as one (in class IN), [`RData::Unknown`] otherwise.
    /// Never fails.
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
    pub fn new(name: impl ToName, qtype: Rtype, qclass: Class) -> Self {
        OwnedQuestion {
            name: NameBuf::from_name(name.to_name()),
            qtype,
            qclass,
        }
    }

    /// Copies a question view (decompressing its name).
    pub fn from_question(q: &Question<'_>) -> Self {
        Self::new(q.name(), q.qtype(), q.qclass())
    }

    /// Appends the question to a builder (RFC 1035 §4.1.2).
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
    pub fn from_record(rr: &Record<'_>) -> Result<Self> {
        Ok(Self::new(
            rr.name(),
            rr.class(),
            rr.ttl(),
            OwnedRData::new(&rr.data()?)?,
        ))
    }

    /// TYPE.
    #[inline]
    pub fn rtype(&self) -> Rtype {
        self.rdata.rtype()
    }

    /// The typed RDATA, decoded exactly as [`Record::data`] would decode
    /// it for this record's class.
    #[inline]
    pub fn data(&self) -> Result<RData<'_>> {
        self.rdata.parse(self.class)
    }

    /// Appends the record to `section` of a builder, which recompresses the
    /// names it may compress.
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
    /// Fails with the reader's error ([`Error::MissingTtl`],
    /// [`Error::InvalidText`], ...), with [`Error::UnexpectedEof`] for
    /// text holding no record, and with [`Error::InvalidText`] for more
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

impl OwnedMessage {
    /// An empty message with the given ID and flags.
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
    pub fn from_message(msg: &Message<'_>) -> Result<Self> {
        let h = msg.header();
        let mut m = OwnedMessage {
            id: h.id,
            flags: h.flags,
            questions: Vec::with_capacity(h.qdcount.into()),
            answers: Vec::with_capacity(h.ancount.into()),
            authority: Vec::with_capacity(h.nscount.into()),
            additional: Vec::with_capacity(h.arcount.into()),
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
    /// them.
    pub fn from_wire(wire: &[u8]) -> Result<Self> {
        Self::from_message(&Message::parse_validated(wire)?)
    }

    /// The header, with counts from the section lengths. Fails with
    /// [`Error::CountOverflow`] if a section holds more than 65535 entries.
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
    pub fn records(&self) -> impl Iterator<Item = (Section, &OwnedRecord)> {
        let answers = self.answers.iter().map(|rr| (Section::Answer, rr));
        let authority = self.authority.iter().map(|rr| (Section::Authority, rr));
        let additional = self.additional.iter().map(|rr| (Section::Additional, rr));
        answers.chain(authority).chain(additional)
    }

    /// The first OPT record of the additional section (RFC 6891 §6.1.1).
    pub fn opt(&self) -> Option<&OwnedRecord> {
        self.additional.iter().find(|rr| rr.rtype() == Rtype::OPT)
    }

    /// The EDNS header fields of the first OPT record (RFC 6891 §6.1.3).
    pub fn opt_header(&self) -> Option<OptHeader> {
        self.opt()
            .map(|rr| OptHeader::from_fields(rr.class, rr.ttl))
    }

    /// The full response code: the header RCODE combined with the extended
    /// RCODE of the OPT record, if any (RFC 6891 §6.1.3).
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

    /// Encodes the message with name compression into a new `Vec`. Fails
    /// with [`Error::BufferTooSmall`] beyond 65535 octets or
    /// [`Error::CountOverflow`] beyond 65535 entries in a section.
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
    #[inline]
    pub fn to_owned_message(&self) -> Result<OwnedMessage> {
        OwnedMessage::from_message(self)
    }
}

impl Question<'_> {
    /// Copies the question into an [`OwnedQuestion`].
    #[inline]
    pub fn to_owned_question(&self) -> OwnedQuestion {
        OwnedQuestion::from_question(self)
    }
}

impl Record<'_> {
    /// Copies the record into an [`OwnedRecord`]; see
    /// [`OwnedRecord::from_record`].
    #[inline]
    pub fn to_owned_record(&self) -> Result<OwnedRecord> {
        OwnedRecord::from_record(self)
    }
}

impl RData<'_> {
    /// Copies the record data into an [`OwnedRData`] (uncompressed wire
    /// form); see [`OwnedRData::new`].
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
