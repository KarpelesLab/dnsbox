//! Zero-copy message views (RFC 1035 §4.1).
//!
//! [`Message::parse`] checks only the 12-byte header; the four sections are
//! decoded lazily by iterators that yield `Result<Question>` /
//! `Result<Record>`, checking each entry and the section counts as they go.
//! Callers that prefer to fail fast can call [`Message::validate`] (or
//! [`Message::parse_validated`]) first, which walks the whole message once
//! and reports the first error.

use core::fmt;

use crate::name::{Name, NameCache};
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
            pos: NOT_LOCATED,
            section,
            header: self.header,
            remaining,
            names: NameCache::new(),
        }
    }

    /// Iterates over every resource record (answer, authority, additional)
    /// with the section it belongs to, in wire order.
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
        self.message()
            .get(self.rdata_start..self.rdata_start + self.rdata_len as usize)
            .unwrap_or(&[])
    }

    /// A reader whose window is exactly the RDATA, able to decompress names.
    #[inline]
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
        self.name.buffer()
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
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
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
