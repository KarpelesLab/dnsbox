//! Zero-copy message views (RFC 1035 §4.1).
//!
//! [`Message::parse`] checks only the 12-byte header; the four sections are
//! decoded lazily by iterators that yield `Result<Question>` /
//! `Result<Record>`, checking each entry and the section counts as they go.
//! Callers that prefer to fail fast can call [`Message::validate`] (or
//! [`Message::parse_validated`]) first, which walks the whole message once
//! and reports the first error.

use core::fmt;

use crate::name::Name;
use crate::rdata::{ParseRdata, RData};
use crate::wire::WireReader;
use crate::{Class, Error, Flags, Header, Result, Rtype};

/// The four message sections, in wire order (RFC 1035 §4.1).
///
/// In UPDATE messages (RFC 2136 §2) they are the Zone, Prerequisite, Update
/// and Additional sections.
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
    pub const fn index(self) -> usize {
        self as usize
    }

    /// The section's entry count from a header.
    #[inline]
    pub const fn count(self, header: &Header) -> u16 {
        match self {
            Section::Question => header.qdcount,
            Section::Answer => header.ancount,
            Section::Authority => header.nscount,
            Section::Additional => header.arcount,
        }
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
    #[inline]
    pub const fn parse(buf: &'a [u8]) -> Result<Self> {
        match Header::parse(buf) {
            Ok(header) => Ok(Message { buf, header }),
            Err(e) => Err(e),
        }
    }

    /// Wraps `buf` and [validates](Self::validate) the whole message.
    pub fn parse_validated(buf: &'a [u8]) -> Result<Self> {
        let msg = Self::parse(buf)?;
        msg.validate()?;
        Ok(msg)
    }

    /// The raw message bytes.
    #[inline]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.buf
    }

    /// The header.
    #[inline]
    pub const fn header(&self) -> Header {
        self.header
    }

    /// The transaction ID.
    #[inline]
    pub const fn id(&self) -> u16 {
        self.header.id
    }

    /// The flags word (QR, opcode, flag bits, header RCODE).
    #[inline]
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
            failed: false,
        }
    }

    /// Iterates over the answer section.
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
            pos: None,
            section,
            header: self.header,
            remaining,
            failed: false,
        }
    }

    /// Iterates over every resource record (answer, authority, additional)
    /// with the section it belongs to, in wire order.
    #[inline]
    pub fn records(&self) -> AllRecords<'a> {
        AllRecords {
            inner: Records {
                msg: self.buf,
                pos: None,
                section: Section::Answer,
                header: self.header,
                remaining: self.header.ancount,
                failed: false,
            },
            started: false,
        }
    }

    /// The offset at which `section` starts, skipping the earlier ones.
    pub fn section_offset(&self, section: Section) -> Result<usize> {
        skip_to(self.buf, &self.header, section)
    }

    /// Walks the whole message once and reports the first error: every
    /// name (with pointer hardening), every section count, every RDATA
    /// with a typed implementation, and no trailing bytes after the last
    /// record.
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

/// Skips over a name without following pointers.
fn skip_name(r: &mut WireReader<'_>) -> Result<()> {
    loop {
        let b = r.read_u8()?;
        match b {
            0 => return Ok(()),
            1..=0x3f => r.skip(b as usize)?,
            0xc0..=0xff => return r.skip(1),
            _ => return Err(Error::BadLabelType),
        }
    }
}

/// Finds the start of `section` by skipping the entries before it.
fn skip_to(msg: &[u8], header: &Header, section: Section) -> Result<usize> {
    let mut r = WireReader::new(msg);
    r.skip(Header::LEN)?;
    for s in Section::ALL {
        if s == section {
            break;
        }
        for _ in 0..s.count(header) {
            skip_name(&mut r)?;
            if s == Section::Question {
                r.skip(4)?;
            } else {
                r.skip(8)?;
                let len = r.read_u16()?;
                r.skip(len as usize)?;
            }
        }
    }
    Ok(r.position())
}

/// An entry of the question section (RFC 1035 §4.1.2).
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
    pub fn parse(r: &mut WireReader<'a>) -> Result<Self> {
        let start = r.position();
        let name = r.read_name()?;
        let qtype = Rtype::new(r.read_u16()?);
        let qclass = Class::new(r.read_u16()?);
        Ok(Question {
            name,
            qtype,
            qclass,
            start,
            end: r.position(),
        })
    }

    /// QNAME.
    #[inline]
    pub const fn name(&self) -> Name<'a> {
        self.name
    }

    /// QTYPE.
    #[inline]
    pub const fn qtype(&self) -> Rtype {
        self.qtype
    }

    /// QCLASS. In a query carrying the unicast-response bit (mDNS), the
    /// top bit is part of this raw value.
    #[inline]
    pub const fn qclass(&self) -> Class {
        self.qclass
    }

    /// Byte range of the entry within the message.
    #[inline]
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
#[derive(Clone, Copy, Debug)]
pub struct Record<'a> {
    msg: &'a [u8],
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
    pub fn parse(r: &mut WireReader<'a>) -> Result<Self> {
        let start = r.position();
        let name = r.read_name()?;
        let rtype = Rtype::new(r.read_u16()?);
        let class = Class::new(r.read_u16()?);
        let ttl = r.read_u32()?;
        let rdata_len = r.read_u16()?;
        let rdata_start = r.position();
        r.skip(rdata_len as usize)?;
        Ok(Record {
            msg: r.message(),
            name,
            rtype,
            class,
            ttl,
            start,
            rdata_start,
            rdata_len,
        })
    }

    /// The owner name.
    #[inline]
    pub const fn name(&self) -> Name<'a> {
        self.name
    }

    /// TYPE.
    #[inline]
    pub const fn rtype(&self) -> Rtype {
        self.rtype
    }

    /// CLASS. For OPT this is the UDP payload size (RFC 6891 §6.1.2).
    #[inline]
    pub const fn class(&self) -> Class {
        self.class
    }

    /// TTL, as the raw 32-bit field. RFC 2181 §8 says values with the top
    /// bit set should be treated as zero; for OPT the field holds the
    /// extended RCODE, version and flags (RFC 6891 §6.1.3).
    #[inline]
    pub const fn ttl(&self) -> u32 {
        self.ttl
    }

    /// The raw RDATA bytes. For the RFC 1035 types these may contain
    /// compression pointers relative to the message; use
    /// [`data`](Self::data) to decode them.
    #[inline]
    pub fn rdata(&self) -> &'a [u8] {
        self.msg
            .get(self.rdata_start..self.rdata_start + self.rdata_len as usize)
            .unwrap_or(&[])
    }

    /// A reader whose window is exactly the RDATA, able to decompress names.
    #[inline]
    pub fn rdata_reader(&self) -> WireReader<'a> {
        WireReader::with_range(
            self.msg,
            self.rdata_start,
            self.rdata_start + self.rdata_len as usize,
        )
        .unwrap_or(WireReader::new(&[]))
    }

    /// Decodes the RDATA into the typed [`RData`] enum (unknown types are
    /// kept opaque).
    #[inline]
    pub fn data(&self) -> Result<RData<'a>> {
        RData::parse(self.rtype, self.class, self.rdata_reader())
    }

    /// Decodes the RDATA as a specific type, failing with
    /// [`Error::WrongType`] if the record is of another type.
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
    pub const fn message(&self) -> &'a [u8] {
        self.msg
    }

    /// Offset of the first byte of the record (its owner name).
    #[inline]
    pub const fn start(&self) -> usize {
        self.start
    }

    /// Offset just past the record.
    #[inline]
    pub const fn end(&self) -> usize {
        self.rdata_start + self.rdata_len as usize
    }

    /// Byte range of the RDATA within the message.
    #[inline]
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
#[derive(Clone, Debug)]
pub struct Questions<'a> {
    msg: &'a [u8],
    pos: usize,
    remaining: u16,
    failed: bool,
}

impl<'a> Iterator for Questions<'a> {
    type Item = Result<Question<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 || self.failed {
            return None;
        }
        let mut r = match WireReader::with_range(self.msg, self.pos, self.msg.len()) {
            Ok(r) => r,
            Err(e) => {
                self.failed = true;
                return Some(Err(e));
            }
        };
        match Question::parse(&mut r) {
            Ok(q) => {
                self.pos = r.position();
                self.remaining -= 1;
                Some(Ok(q))
            }
            Err(e) => {
                self.failed = true;
                Some(Err(e))
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.failed {
            (0, Some(0))
        } else {
            (0, Some(self.remaining as usize))
        }
    }
}

impl core::iter::FusedIterator for Questions<'_> {}

/// Iterator over the records of one section; see [`Message::section`].
///
/// Yields exactly the section's count of items unless an error occurs, in
/// which case the error is yielded once and iteration stops.
#[derive(Clone, Debug)]
pub struct Records<'a> {
    msg: &'a [u8],
    /// Offset of the next record; `None` until the section start has been
    /// located.
    pos: Option<usize>,
    section: Section,
    header: Header,
    remaining: u16,
    failed: bool,
}

impl<'a> Records<'a> {
    /// The section being iterated.
    #[inline]
    pub const fn section(&self) -> Section {
        self.section
    }

    fn fail(&mut self, e: Error) -> Option<Result<Record<'a>>> {
        self.failed = true;
        Some(Err(e))
    }
}

impl<'a> Iterator for Records<'a> {
    type Item = Result<Record<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 || self.failed {
            return None;
        }
        let pos = match self.pos {
            Some(pos) => pos,
            None => match skip_to(self.msg, &self.header, self.section) {
                Ok(pos) => pos,
                Err(e) => return self.fail(e),
            },
        };
        let mut r = match WireReader::with_range(self.msg, pos, self.msg.len()) {
            Ok(r) => r,
            Err(e) => return self.fail(e),
        };
        match Record::parse(&mut r) {
            Ok(rr) => {
                self.pos = Some(r.position());
                self.remaining -= 1;
                Some(Ok(rr))
            }
            Err(e) => self.fail(e),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.failed {
            (0, Some(0))
        } else {
            (0, Some(self.remaining as usize))
        }
    }
}

impl core::iter::FusedIterator for Records<'_> {}

/// Iterator over all resource records with their section; see
/// [`Message::records`].
#[derive(Clone, Debug)]
pub struct AllRecords<'a> {
    inner: Records<'a>,
    started: bool,
}

impl<'a> Iterator for AllRecords<'a> {
    type Item = Result<(Section, Record<'a>)>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.inner.failed {
                return None;
            }
            if !self.started {
                self.started = true;
                match skip_to(self.inner.msg, &self.inner.header, Section::Answer) {
                    Ok(pos) => self.inner.pos = Some(pos),
                    Err(e) => {
                        self.inner.failed = true;
                        return Some(Err(e));
                    }
                }
            }
            if self.inner.remaining > 0 {
                let section = self.inner.section;
                return self.inner.next().map(|r| r.map(|rr| (section, rr)));
            }
            let next = match self.inner.section {
                Section::Question | Section::Answer => Section::Authority,
                Section::Authority => Section::Additional,
                Section::Additional => return None,
            };
            self.inner.section = next;
            self.inner.remaining = next.count(&self.inner.header);
        }
    }
}

impl core::iter::FusedIterator for AllRecords<'_> {}

#[cfg(test)]
mod tests;
