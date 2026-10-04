//! Zero-copy message views (RFC 1035 §4.1).
//!
//! [`Message::parse`] checks only the 12-byte header; the four sections are
//! decoded lazily by iterators that yield `Result<Question>` /
//! `Result<Record>`, checking each entry and the section counts as they go.
//! Callers that prefer to fail fast can call [`Message::validate`] (or
//! [`Message::parse_validated`]) first, which walks the whole message once
//! and reports the first error.
//!
//! [`Message`], [`Question`], [`Record`] and [`Section`] are re-exported
//! at the crate root. A whole message displays in `dig`'s layout.
//!
//! # Examples
//!
//! ```
//! use dnsbox::rdata::{Mx, RData};
//! use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype, Section};
//!
//! # let name: NameBuf = "example.com".parse()?;
//! # let mx: NameBuf = "mx.example.com".parse()?;
//! # let mut buf = [0u8; 512];
//! # let mut b = MessageBuilder::new(&mut buf)?;
//! # b.set_flags(dnsbox::Flags::default().with_qr(true));
//! # b.push_question(&name, Rtype::MX, Class::IN)?;
//! # b.push_answer(&name, Class::IN, 300, &Mx { preference: 10, exchange: mx.as_name() })?;
//! # b.push_additional(&mx, Class::IN, 300, &dnsbox::rdata::A::new([192, 0, 2, 25].into()))?;
//! # let wire: &[u8] = b.finish();
//! // `wire` holds a response: example.com MX, with glue for the exchange.
//! let msg = Message::parse(wire)?;
//! assert!(msg.flags().qr());
//! let q = msg.questions().next().expect("one question")?;
//! assert_eq!(q.qtype(), Rtype::MX);
//!
//! // One pass over all three record sections.
//! for item in msg.records() {
//!     let (section, rr) = item?;
//!     match rr.data()? {
//!         RData::Mx(_) => assert_eq!(section, Section::Answer),
//!         RData::A(a) => assert_eq!(a.addr.octets(), [192, 0, 2, 25]),
//!         _ => {}
//!     }
//! }
//!
//! // Or a typed view of one record.
//! let mx: Mx<'_> = msg.answers().next().expect("an answer")?.data_as()?;
//! assert_eq!(mx.exchange.to_string(), "mx.example.com.");
//!
//! // `dig`-style text of the whole message.
//! let text = msg.to_string();
//! assert!(text.contains(";; ANSWER SECTION:\nexample.com.\t\t300\tIN\tMX\t10 mx.example.com.\n"));
//! # Ok::<(), dnsbox::Error>(())
//! ```

use core::fmt;

use crate::name::{Name, NameCache};
use crate::rdata::{ParseRdata, RData};
use crate::wire::WireReader;
use crate::{Class, Error, Flags, Header, Result, Rtype};

/// The four message sections, in wire order (RFC 1035 §4.1).
///
/// In UPDATE messages (RFC 2136 §2) they are the Zone, Prerequisite, Update
/// and Additional sections.
///
/// Sections compare in wire order.
///
/// ```
/// use dnsbox::{Header, Section};
///
/// let header = Header { ancount: 2, arcount: 1, ..Header::default() };
/// let counts: Vec<u16> = Section::ALL.iter().map(|s| s.count(&header)).collect();
/// assert_eq!(counts, [0, 2, 0, 1]);
/// assert!(Section::Answer < Section::Additional);
/// assert_eq!(Section::Authority.to_string(), "AUTHORITY");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Section {
    /// Question section (QDCOUNT entries); Zone section in UPDATE.
    Question,
    /// Answer section (ANCOUNT records); Prerequisite section in UPDATE.
    Answer,
    /// Authority section (NSCOUNT records); Update section in UPDATE.
    Authority,
    /// Additional section (ARCOUNT records).
    Additional,
}

impl Section {
    /// All sections, in wire order.
    pub const ALL: [Section; 4] = [
        Section::Question,
        Section::Answer,
        Section::Authority,
        Section::Additional,
    ];

    /// Position of the section in wire order (0–3).
    #[inline]
    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }

    /// The section's entry count from a header.
    #[inline]
    #[must_use]
    pub const fn count(self, header: &Header) -> u16 {
        match self {
            Section::Question => header.qdcount,
            Section::Answer => header.ancount,
            Section::Authority => header.nscount,
            Section::Additional => header.arcount,
        }
    }
}

impl fmt::Display for Section {
    /// The section name as `dig` prints it: `QUESTION`, `ANSWER`,
    /// `AUTHORITY` or `ADDITIONAL`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Section::Question => "QUESTION",
            Section::Answer => "ANSWER",
            Section::Authority => "AUTHORITY",
            Section::Additional => "ADDITIONAL",
        })
    }
}

/// A parsed DNS message: a view over the caller's buffer.
///
/// ```
/// use dnsbox::{Message, Rtype};
///
/// let wire = b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
///              \x07example\x03com\x00\x00\x01\x00\x01";
/// let msg = Message::parse_validated(wire)?;
/// let q = msg.questions().next().unwrap()?;
/// assert_eq!(q.name().to_string(), "example.com.");
/// assert_eq!(q.qtype(), Rtype::A);
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Message<'a> {
    buf: &'a [u8],
    header: Header,
}

impl<'a> Message<'a> {
    /// Wraps `buf`, parsing only the header. Sections are decoded lazily.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedEof`] if `buf` is shorter than the 12-byte
    /// header. Everything after the header is checked later, by the
    /// iterators or [`validate`](Self::validate).
    #[inline]
    pub const fn parse(buf: &'a [u8]) -> Result<Self> {
        match Header::parse(buf) {
            Ok(header) => Ok(Message { buf, header }),
            Err(e) => Err(e),
        }
    }

    /// Wraps `buf` and [validates](Self::validate) the whole message.
    ///
    /// # Errors
    ///
    /// The first error [`validate`](Self::validate) finds.
    ///
    /// ```
    /// use dnsbox::{Error, Message};
    ///
    /// // An answer record whose owner name points forward: rejected.
    /// let wire = b"\0\x01\x81\x80\0\0\0\x01\0\0\0\0\xc0\x0e\0\x01\0\x01\0\0\0\x3c\0\x04\xc0\0\x02\x01";
    /// assert!(Message::parse(wire).is_ok()); // only the header is checked
    /// assert_eq!(Message::parse_validated(wire).unwrap_err(), Error::BadPointer);
    /// ```
    pub fn parse_validated(buf: &'a [u8]) -> Result<Self> {
        let msg = Self::parse(buf)?;
        msg.validate()?;
        Ok(msg)
    }

    /// The raw message bytes.
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.buf
    }

    /// The header.
    #[inline]
    #[must_use]
    pub const fn header(&self) -> Header {
        self.header
    }

    /// The transaction ID.
    #[inline]
    #[must_use]
    pub const fn id(&self) -> u16 {
        self.header.id
    }

    /// The flags word (QR, opcode, flag bits, header RCODE).
    #[inline]
    #[must_use]
    pub const fn flags(&self) -> Flags {
        self.header.flags
    }

    /// Iterates over the question section.
    #[inline]
    pub fn questions(&self) -> Questions<'a> {
        Questions {
            msg: self.buf,
            pos: Header::LEN,
            remaining: self.header.qdcount,
        }
    }

    /// Iterates over the answer section.
    ///
    /// ```
    /// use dnsbox::rdata::A;
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf};
    ///
    /// let name: NameBuf = "example".parse()?;
    /// let mut buf = [0u8; 128];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.push_answer(&name, Class::IN, 60, &A::new([192, 0, 2, 1].into()))?;
    /// b.push_answer(&name, Class::IN, 60, &A::new([192, 0, 2, 2].into()))?;
    /// let msg = Message::parse(b.finish())?;
    /// let addrs: Vec<A> = msg.answers().map(|rr| rr?.data_as()).collect::<Result<_, _>>()?;
    /// assert_eq!(addrs.len(), 2);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub fn answers(&self) -> Records<'a> {
        self.section(Section::Answer)
    }

    /// Iterates over the authority section.
    #[inline]
    pub fn authority(&self) -> Records<'a> {
        self.section(Section::Authority)
    }

    /// Iterates over the additional section.
    #[inline]
    pub fn additional(&self) -> Records<'a> {
        self.section(Section::Additional)
    }

    /// Iterates over the records of a section. The preceding sections are
    /// skipped (without full validation) on the first call to `next`.
    /// `Section::Question` yields nothing; use [`questions`](Self::questions).
    #[inline]
    pub fn section(&self, section: Section) -> Records<'a> {
        let remaining = match section {
            Section::Question => 0,
            s => s.count(&self.header),
        };
        Records {
            msg: self.buf,
            pos: NOT_LOCATED,
            section,
            header: self.header,
            remaining,
            names: NameCache::new(),
        }
    }

    /// Iterates over every resource record (answer, authority, additional)
    /// with the section it belongs to, in wire order. See [`AllRecords`].
    #[inline]
    pub fn records(&self) -> AllRecords<'a> {
        let h = &self.header;
        AllRecords {
            msg: self.buf,
            pos: NOT_LOCATED,
            qdcount: h.qdcount,
            section: 0,
            remaining: [h.ancount, h.nscount, h.arcount],
            names: NameCache::new(),
        }
    }

    /// The offset at which `section` starts, skipping the earlier ones.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedEof`] if the earlier sections are cut short (the
    /// header counts promise more entries than the message holds), or a
    /// name decoding error for a malformed name in them.
    pub fn section_offset(&self, section: Section) -> Result<usize> {
        skip_to(self.buf, &self.header, section)
    }

    /// Walks the whole message once and reports the first error: every
    /// name (with pointer hardening), every section count, every RDATA
    /// with a typed implementation, and no trailing bytes after the last
    /// record.
    ///
    /// # Errors
    ///
    /// The first error found: [`Error::UnexpectedEof`] for a message that
    /// holds fewer entries than its counts, a name decoding error
    /// ([`Error::BadPointer`], [`Error::NameTooLong`], ...), an RDATA
    /// error ([`Error::InvalidRdata`], ...), or [`Error::TrailingData`]
    /// for bytes after the last record.
    ///
    /// ```
    /// use dnsbox::{Error, Message};
    ///
    /// // A header claiming one answer, and nothing after it.
    /// let wire = [0, 1, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0];
    /// let msg = Message::parse(&wire)?;
    /// assert_eq!(msg.validate(), Err(Error::UnexpectedEof));
    /// # Ok::<(), Error>(())
    /// ```
    pub fn validate(&self) -> Result<()> {
        let mut end = Header::LEN;
        for q in self.questions() {
            end = q?.end;
        }
        for rr in self.records() {
            let (_, rr) = rr?;
            rr.data()?;
            end = rr.end();
        }
        if end != self.buf.len() {
            return Err(Error::TrailingData);
        }
        Ok(())
    }
}

/// Skips over the name at `pos` without following pointers, returning the
/// offset just past it.
#[inline]
fn skip_name(msg: &[u8], mut pos: usize) -> Result<usize> {
    loop {
        let &b = msg.get(pos).ok_or(Error::UnexpectedEof)?;
        match b {
            0 => return Ok(pos + 1),
            1..=0x3f => pos += 1 + usize::from(b),
            0xc0..=0xff => {
                return if pos + 2 > msg.len() {
                    Err(Error::UnexpectedEof)
                } else {
                    Ok(pos + 2)
                };
            }
            _ => return Err(Error::BadLabelType),
        }
        if pos > msg.len() {
            return Err(Error::UnexpectedEof);
        }
    }
}

/// `pos` of an iterator that has not located its section yet (no entry
/// can start inside the header).
const NOT_LOCATED: usize = 0;

/// Finds the start of `section` by skipping the entries before it: names
/// are stepped over without following pointers and RDATA is not looked at.
fn skip_to(msg: &[u8], header: &Header, section: Section) -> Result<usize> {
    let mut pos = Header::LEN;
    if msg.len() < pos {
        return Err(Error::UnexpectedEof);
    }
    for s in Section::ALL {
        if s == section {
            break;
        }
        for _ in 0..s.count(header) {
            pos = skip_name(msg, pos)?;
            pos += if s == Section::Question {
                4
            } else {
                // TYPE, CLASS, TTL, then RDLENGTH and the RDATA.
                let Some(&[l0, l1]) = msg.get(pos + 8..pos + 10) else {
                    return Err(Error::UnexpectedEof);
                };
                10 + usize::from(u16::from_be_bytes([l0, l1]))
            };
            if pos > msg.len() {
                return Err(Error::UnexpectedEof);
            }
        }
    }
    Ok(pos)
}

/// An entry of the question section (RFC 1035 §4.1.2).
///
/// ```
/// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
///
/// let name: NameBuf = "example.org".parse()?;
/// let mut buf = [0u8; 64];
/// let query = MessageBuilder::query(&mut buf, 1, &name, Rtype::AAAA, Class::IN)?.finish();
/// let q = Message::parse(query)?.questions().next().unwrap()?;
/// assert_eq!((q.name(), q.qtype(), q.qclass()), (name.as_name(), Rtype::AAAA, Class::IN));
/// assert_eq!(q.range(), 12..query.len());
/// assert_eq!(q.to_string(), "example.org. IN AAAA");
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Question<'a> {
    name: Name<'a>,
    qtype: Rtype,
    qclass: Class,
    start: usize,
    end: usize,
}

impl<'a> Question<'a> {
    /// Parses a question at the reader's position.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedEof`] if the entry is cut short, or a name
    /// decoding error.
    pub fn parse(r: &mut WireReader<'a>) -> Result<Self> {
        let q = Self::parse_at(r.message(), r.position(), r.end())?;
        r.skip(q.end - q.start)?;
        Ok(q)
    }

    /// Parses a question at `start`, whose in-place bytes must end before
    /// `end`.
    #[inline]
    fn parse_at(msg: &'a [u8], start: usize, end: usize) -> Result<Self> {
        let (name, pos) = Name::parse_bounded(msg, start, end, true)?;
        // One bounds check for the fixed fields.
        let Some(&[t0, t1, c0, c1]) = msg
            .get(..end)
            .and_then(|w| w.get(pos..))
            .and_then(<[u8]>::first_chunk)
        else {
            return Err(Error::UnexpectedEof);
        };
        Ok(Question {
            name,
            qtype: Rtype::new(u16::from_be_bytes([t0, t1])),
            qclass: Class::new(u16::from_be_bytes([c0, c1])),
            start,
            end: pos + 4,
        })
    }

    /// QNAME.
    #[inline]
    #[must_use]
    pub const fn name(&self) -> Name<'a> {
        self.name
    }

    /// QTYPE.
    #[inline]
    #[must_use]
    pub const fn qtype(&self) -> Rtype {
        self.qtype
    }

    /// QCLASS. In a query carrying the unicast-response bit (mDNS), the
    /// top bit is part of this raw value.
    #[inline]
    #[must_use]
    pub const fn qclass(&self) -> Class {
        self.qclass
    }

    /// Byte range of the entry within the message.
    #[inline]
    #[must_use]
    pub const fn range(&self) -> core::ops::Range<usize> {
        self.start..self.end
    }
}

impl fmt::Display for Question<'_> {
    /// `name class type`, as in a `dig` question section.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.name, self.qclass, self.qtype)
    }
}

/// A resource record (RFC 1035 §4.1.3), viewed in place.
///
/// The fixed fields are decoded when the record is located; the RDATA only
/// on request, as the typed [`RData`] ([`data`](Self::data)) or one
/// specific type ([`data_as`](Self::data_as)).
///
/// ```
/// use dnsbox::rdata::{A, RData};
/// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
///
/// let name: NameBuf = "www.example.com".parse()?;
/// let mut buf = [0u8; 128];
/// let mut b = MessageBuilder::new(&mut buf)?;
/// b.push_answer(&name, Class::IN, 3600, &A::new([192, 0, 2, 7].into()))?;
/// let wire = b.finish();
///
/// let rr = Message::parse(wire)?.answers().next().unwrap()?;
/// assert_eq!(rr.name(), name.as_name());
/// assert_eq!((rr.rtype(), rr.class(), rr.ttl()), (Rtype::A, Class::IN, 3600));
/// assert_eq!(rr.rdata(), [192, 0, 2, 7]);
/// assert!(matches!(rr.data()?, RData::A(a) if a.addr.octets() == [192, 0, 2, 7]));
/// assert_eq!(rr.data_as::<A>()?.addr.to_string(), "192.0.2.7");
/// assert_eq!(rr.to_string(), "www.example.com. 3600 IN A 192.0.2.7");
/// assert_eq!(&wire[rr.rdata_range()], rr.rdata());
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Record<'a> {
    /// The owner name; it also holds the whole message.
    name: Name<'a>,
    rtype: Rtype,
    class: Class,
    ttl: u32,
    start: usize,
    rdata_start: usize,
    rdata_len: u16,
}

impl<'a> Record<'a> {
    /// Parses a record at the reader's position. The reader must span the
    /// whole message (so RDATA names can be decompressed later).
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedEof`] if the fixed fields or the RDATA are cut
    /// short, or an owner-name decoding error. The RDATA itself is not
    /// checked.
    pub fn parse(r: &mut WireReader<'a>) -> Result<Self> {
        let msg = r.message();
        let start = r.position();
        let (name, pos) = Name::parse_bounded(msg, start, r.end(), true)?;
        let rr = Self::parse_fixed(msg, start, name, pos, r.end())?;
        r.skip(rr.end() - start)?;
        Ok(rr)
    }

    /// Parses a record at `start` of a whole message, remembering decoded
    /// owner-name suffixes in `names` (the iterators' fast path).
    #[inline]
    fn parse_cached(msg: &'a [u8], start: usize, names: &mut NameCache) -> Result<Self> {
        let (name, pos) = Name::parse_cached(msg, start, names)?;
        Self::parse_fixed(msg, start, name, pos, msg.len())
    }

    /// Parses the fields after the owner name (which ends at `pos`): TYPE,
    /// CLASS, TTL, RDLENGTH, and the RDATA bounds, all before `end`. The
    /// RDATA itself is left for [`data`](Self::data).
    #[inline(always)]
    fn parse_fixed(
        msg: &'a [u8],
        start: usize,
        name: Name<'a>,
        pos: usize,
        end: usize,
    ) -> Result<Self> {
        let window = msg.get(..end).unwrap_or(msg);
        // One bounds check for the ten fixed octets.
        let Some(&[t0, t1, c0, c1, l0, l1, l2, l3, r0, r1]) =
            window.get(pos..).and_then(<[u8]>::first_chunk)
        else {
            return Err(Error::UnexpectedEof);
        };
        let rdata_start = pos + 10;
        let rdata_len = u16::from_be_bytes([r0, r1]);
        // `rdata_start <= window.len()`: the ten octets were there.
        if window.len() - rdata_start < usize::from(rdata_len) {
            return Err(Error::UnexpectedEof);
        }
        Ok(Record {
            name,
            rtype: Rtype::new(u16::from_be_bytes([t0, t1])),
            class: Class::new(u16::from_be_bytes([c0, c1])),
            ttl: u32::from_be_bytes([l0, l1, l2, l3]),
            start,
            rdata_start,
            rdata_len,
        })
    }

    /// The owner name.
    #[inline]
    #[must_use]
    pub const fn name(&self) -> Name<'a> {
        self.name
    }

    /// TYPE.
    #[inline]
    #[must_use]
    pub const fn rtype(&self) -> Rtype {
        self.rtype
    }

    /// CLASS. For OPT this is the UDP payload size (RFC 6891 §6.1.2).
    #[inline]
    #[must_use]
    pub const fn class(&self) -> Class {
        self.class
    }

    /// TTL, as the raw 32-bit field. RFC 2181 §8 says values with the top
    /// bit set should be treated as zero; for OPT the field holds the
    /// extended RCODE, version and flags (RFC 6891 §6.1.3).
    #[inline]
    #[must_use]
    pub const fn ttl(&self) -> u32 {
        self.ttl
    }

    /// The raw RDATA bytes. For the RFC 1035 types these may contain
    /// compression pointers relative to the message; use
    /// [`data`](Self::data) to decode them.
    #[inline]
    #[must_use]
    pub fn rdata(&self) -> &'a [u8] {
        self.message()
            .get(self.rdata_start..self.rdata_start + self.rdata_len as usize)
            .unwrap_or(&[])
    }

    /// A reader whose window is exactly the RDATA, able to decompress names.
    #[inline]
    #[must_use]
    pub fn rdata_reader(&self) -> WireReader<'a> {
        WireReader::with_range(
            self.message(),
            self.rdata_start,
            self.rdata_start + self.rdata_len as usize,
        )
        .unwrap_or(WireReader::new(&[]))
    }

    /// Decodes the RDATA into the typed [`RData`] enum (unknown types are
    /// kept opaque).
    ///
    /// # Errors
    ///
    /// The type's parse error for malformed RDATA ([`Error::InvalidRdata`],
    /// [`Error::UnexpectedEof`], [`Error::TrailingData`], a name decoding
    /// error, ...).
    #[inline]
    pub fn data(&self) -> Result<RData<'a>> {
        RData::parse(self.rtype, self.class, self.rdata_reader())
    }

    /// Decodes the RDATA as a specific type.
    ///
    /// # Errors
    ///
    /// [`Error::WrongType`] if the record is of another type, otherwise as
    /// [`data`](Self::data).
    pub fn data_as<T: ParseRdata<'a>>(&self) -> Result<T> {
        if self.rtype != T::RTYPE {
            return Err(Error::WrongType);
        }
        let mut r = self.rdata_reader();
        let data = T::parse_rdata(&mut r)?;
        r.finish()?;
        Ok(data)
    }

    /// The message this record belongs to.
    #[inline]
    #[must_use]
    pub const fn message(&self) -> &'a [u8] {
        self.name.buffer()
    }

    /// Offset of the first byte of the record (its owner name).
    #[inline]
    #[must_use]
    pub const fn start(&self) -> usize {
        self.start
    }

    /// Offset just past the record.
    #[inline]
    #[must_use]
    pub const fn end(&self) -> usize {
        self.rdata_start + self.rdata_len as usize
    }

    /// Byte range of the RDATA within the message.
    #[inline]
    #[must_use]
    pub const fn rdata_range(&self) -> core::ops::Range<usize> {
        self.rdata_start..self.end()
    }
}

impl fmt::Display for Record<'_> {
    /// Zone-file style: `name ttl class type rdata`. RDATA that fails to
    /// parse is shown in the generic RFC 3597 form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} ",
            self.name, self.ttl, self.class, self.rtype
        )?;
        match self.data() {
            Ok(d) => fmt::Display::fmt(&d, f),
            Err(_) => crate::text::fmt_generic_rdata(f, self.rdata()),
        }
    }
}

/// Iterator over the question section; see [`Message::questions`].
///
/// Yields exactly QDCOUNT items unless an error occurs, in which case the
/// error is yielded once and iteration stops.
///
/// ```
/// use dnsbox::{Error, Message};
///
/// // QDCOUNT is 2, but only one question follows.
/// let wire = b"\0\x01\0\0\0\x02\0\0\0\0\0\0\x01a\0\0\x01\0\x01";
/// let mut questions = Message::parse(wire)?.questions();
/// assert!(questions.next().unwrap().is_ok());
/// assert_eq!(questions.next().unwrap().unwrap_err(), Error::UnexpectedEof);
/// assert!(questions.next().is_none());
/// # Ok::<(), Error>(())
/// ```
#[derive(Clone, Debug)]
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct Questions<'a> {
    msg: &'a [u8],
    pos: usize,
    /// Entries left; 0 once done or after an error.
    remaining: u16,
}

impl<'a> Iterator for Questions<'a> {
    type Item = Result<Question<'a>>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        match Question::parse_at(self.msg, self.pos, self.msg.len()) {
            Ok(q) => {
                self.pos = q.end;
                self.remaining -= 1;
                Some(Ok(q))
            }
            Err(e) => {
                self.remaining = 0;
                Some(Err(e))
            }
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.remaining as usize))
    }
}

impl core::iter::FusedIterator for Questions<'_> {}

/// Iterator over the records of one section; see [`Message::section`].
///
/// Yields exactly the section's count of items unless an error occurs, in
/// which case the error is yielded once and iteration stops.
///
/// ```
/// use dnsbox::rdata::Txt;
/// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Section};
///
/// let name: NameBuf = "example".parse()?;
/// let mut buf = [0u8; 128];
/// let mut b = MessageBuilder::new(&mut buf)?;
/// b.push_authority(&name, Class::IN, 60, &Txt::from_wire(b"\x01a")?)?;
/// let msg = Message::parse(b.finish())?;
///
/// let records = msg.section(Section::Authority);
/// assert_eq!(records.section(), Section::Authority);
/// let ttls: Vec<u32> = records.map(|rr| rr.map(|rr| rr.ttl())).collect::<Result<_, _>>()?;
/// assert_eq!(ttls, [60]);
/// assert_eq!(msg.answers().count(), 0);
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Debug)]
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct Records<'a> {
    msg: &'a [u8],
    /// Offset of the next record; [`NOT_LOCATED`] until the section start
    /// has been located.
    pos: usize,
    section: Section,
    header: Header,
    /// Records left; 0 once done or after an error.
    remaining: u16,
    /// Owner-name suffixes decoded so far.
    names: NameCache,
}

impl<'a> Records<'a> {
    /// The section being iterated.
    #[inline]
    #[must_use]
    pub const fn section(&self) -> Section {
        self.section
    }

    #[cold]
    fn fail(&mut self, e: Error) -> Option<Result<Record<'a>>> {
        self.remaining = 0;
        Some(Err(e))
    }
}

impl<'a> Iterator for Records<'a> {
    type Item = Result<Record<'a>>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        if self.pos == NOT_LOCATED {
            match skip_to(self.msg, &self.header, self.section) {
                Ok(pos) => self.pos = pos,
                Err(e) => return self.fail(e),
            }
        }
        match Record::parse_cached(self.msg, self.pos, &mut self.names) {
            Ok(rr) => {
                self.pos = rr.end();
                self.remaining -= 1;
                Some(Ok(rr))
            }
            Err(e) => self.fail(e),
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.remaining as usize))
    }
}

impl core::iter::FusedIterator for Records<'_> {}

/// Iterator over all resource records with their section; see
/// [`Message::records`].
///
/// The question section is skipped (errors in it are reported), then the
/// answer, authority and additional records are yielded in wire order, in
/// one pass.
///
/// ```
/// use dnsbox::rdata::A;
/// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Section};
///
/// let name: NameBuf = "ns.example".parse()?;
/// let a = A::new([192, 0, 2, 53].into());
/// let mut buf = [0u8; 128];
/// let mut b = MessageBuilder::new(&mut buf)?;
/// b.push_answer(&name, Class::IN, 60, &a)?;
/// b.push_additional(&name, Class::IN, 60, &a)?;
/// let msg = Message::parse(b.finish())?;
///
/// let sections: Vec<Section> = msg.records().map(|r| r.map(|(s, _)| s)).collect::<Result<_, _>>()?;
/// assert_eq!(sections, [Section::Answer, Section::Additional]);
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Debug)]
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct AllRecords<'a> {
    msg: &'a [u8],
    /// Offset of the next record; [`NOT_LOCATED`] before the first call.
    pos: usize,
    /// QDCOUNT, to skip the question section on the first call.
    qdcount: u16,
    /// Index into `remaining` of the current section; past the end once
    /// done or after an error.
    section: u8,
    /// Records left in the answer, authority and additional sections.
    remaining: [u16; 3],
    /// Owner-name suffixes decoded so far.
    names: NameCache,
}

impl<'a> AllRecords<'a> {
    /// Locates the answer section, then continues as usual. Errors in the
    /// question section are reported even if there are no records.
    #[cold]
    fn locate(&mut self) -> Option<Result<(Section, Record<'a>)>> {
        let header = Header {
            qdcount: self.qdcount,
            ..Header::default()
        };
        match skip_to(self.msg, &header, Section::Answer) {
            Ok(pos) => {
                self.pos = pos;
                self.next()
            }
            Err(e) => {
                // Any other position: never locate again.
                self.pos = Header::LEN;
                self.section = 3;
                Some(Err(e))
            }
        }
    }
}

impl<'a> Iterator for AllRecords<'a> {
    type Item = Result<(Section, Record<'a>)>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.pos == NOT_LOCATED {
            return self.locate();
        }
        loop {
            let i = usize::from(self.section);
            let remaining = self.remaining.get_mut(i)?;
            if *remaining == 0 {
                self.section += 1;
                continue;
            }
            return match Record::parse_cached(self.msg, self.pos, &mut self.names) {
                Ok(rr) => {
                    *remaining -= 1;
                    self.pos = rr.end();
                    let section = match i {
                        0 => Section::Answer,
                        1 => Section::Authority,
                        _ => Section::Additional,
                    };
                    Some(Ok((section, rr)))
                }
                Err(e) => {
                    self.section = 3;
                    Some(Err(e))
                }
            };
        }
    }
}

impl core::iter::FusedIterator for AllRecords<'_> {}

pub(crate) mod dig;
#[cfg(test)]
mod tests;
