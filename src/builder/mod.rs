//! Single-pass message building (RFC 1035 §4.1).
//!
//! [`MessageBuilder`] writes a message straight into an [`OutBuf`] — a
//! caller-supplied `&mut [u8]` (via [`MessageBuilder::new`]) or, with the
//! `alloc` feature, a `Vec<u8>` (via [`MessageBuilder::new_vec`]):
//!
//! - sections must be written in order (question → answer → authority →
//!   additional); going back fails with
//!   [`Error::SectionOrder`];
//! - the header counts are maintained automatically, so the buffer always
//!   holds a well-formed message;
//! - owner names, question names and names in the RDATA of the RFC 1035
//!   types are compressed through a fixed-size table of the labels already
//!   written (128 labels, under 1 KiB, no allocation; lookups cost one
//!   probe per label and at most 32 false candidates per name, so hash
//!   collisions cannot blow up the cost; a full table only means less
//!   compression). Matching is case-sensitive, so the case of every name
//!   is preserved (0x20 randomisation). Names in any other RDATA are never
//!   compressed (RFC 3597 §4). Compression can be turned off;
//! - every push is atomic: if an entry does not fit (buffer or
//!   [size limit](MessageBuilder::set_limit)), the message is rolled back to
//!   its state before the push and the error returned. [`checkpoint`] /
//!   [`rollback`] expose the same mechanism for multi-record units;
//! - RRset-level pushes ([`push_rrset`], [`copy_section`],
//!   [`copy_message`]) implement truncation (RFC 2181 §9): an RRset that
//!   does not fit is removed entirely and, depending on the
//!   [`Truncation`] policy, the TC bit is set or an error returned. Space
//!   can be [reserved](MessageBuilder::set_reserve) for records that must
//!   still go in afterwards (OPT, TSIG);
//! - [`query`](MessageBuilder::query) and
//!   [`response`](MessageBuilder::response) start the common message
//!   shapes; [`push_raw_records`] appends pre-encoded records;
//! - [`new_tcp`](MessageBuilder::new_tcp) writes the 2-byte TCP length
//!   prefix (RFC 1035 §4.2.2) in front of the message; see also
//!   [`crate::tcp`].
//!
//!
//! # Examples
//!
//! A response with an answer RRset, a referral-style authority record and
//! glue, written into a stack buffer:
//!
//! ```
//! use dnsbox::rdata::{A, Ns};
//! use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rcode, Rtype, Section};
//!
//! let zone: NameBuf = "example.com".parse()?;
//! let ns1: NameBuf = "ns1.example.com".parse()?;
//! let mut qbuf = [0u8; 512];
//! let query = MessageBuilder::query(&mut qbuf, 0x4242, &zone, Rtype::A, Class::IN)?.finish();
//! let query = Message::parse(query)?;
//!
//! let mut buf = [0u8; 512];
//! let mut b = MessageBuilder::response(&mut buf, &query)?;
//! b.set_flags(b.header().flags.with_aa(true));
//! let addrs = [A::new([192, 0, 2, 1].into()), A::new([192, 0, 2, 2].into())];
//! let _ = b.push_rrset(Section::Answer, &zone, Class::IN, 300, &addrs)?;
//! b.push_authority(&zone, Class::IN, 86400, &Ns { nsdname: ns1.as_name() })?;
//! b.push_additional(&ns1, Class::IN, 86400, &A::new([192, 0, 2, 53].into()))?;
//! let wire = b.finish();
//!
//! let msg = Message::parse_validated(wire)?;
//! assert_eq!(msg.id(), 0x4242);
//! assert!(msg.flags().aa() && msg.flags().rd());
//! assert_eq!(msg.flags().rcode(), Rcode::NOERROR);
//! let h = msg.header();
//! assert_eq!((h.qdcount, h.ancount, h.nscount, h.arcount), (1, 2, 1, 1));
//! # Ok::<(), dnsbox::Error>(())
//! ```
//!
//! [`checkpoint`]: MessageBuilder::checkpoint
//! [`rollback`]: MessageBuilder::rollback
//! [`push_rrset`]: MessageBuilder::push_rrset
//! [`copy_section`]: MessageBuilder::copy_section
//! [`copy_message`]: MessageBuilder::copy_message
//! [`push_raw_records`]: MessageBuilder::push_raw_records
#![cfg_attr(
    feature = "alloc",
    doc = "[`MessageBuilder::new_vec`]: MessageBuilder::new_vec"
)]
#![cfg_attr(
    not(feature = "alloc"),
    doc = "[`MessageBuilder::new_vec`]: crate#cargo-features"
)]

mod compress;
mod framing;
mod query;
mod raw;
mod truncate;

pub use self::query::response_flags;
pub use self::truncate::{Outcome, Truncation};

use core::fmt;

use self::compress::CompressionTable;
use crate::message::{Question, Record, Section};
use crate::name::{MAX_LABELS, MAX_NAME_LEN, Name, ToName};
use crate::rdata::ComposeRdata;
use crate::wire::{Composer, NameEncoding, OutBuf, WireWriter, put_name_uncompressed};
use crate::{Class, Error, Flags, Header, Result, Rtype};

/// Maximum size of a DNS message (the TCP length prefix is 16 bits).
pub const MAX_MESSAGE_LEN: usize = 65535;

/// Initial capacity of the `Vec` behind [`MessageBuilder::new_vec`]: the
/// classic UDP payload limit (RFC 1035 §4.2.1), which typical messages fit
/// in.
#[cfg(feature = "alloc")]
const DEFAULT_VEC_CAPACITY: usize = 512;

/// A saved builder state; see [`MessageBuilder::checkpoint`].
///
/// ```
/// use dnsbox::rdata::A;
/// use dnsbox::{Class, MessageBuilder, NameBuf};
///
/// let name: NameBuf = "example".parse()?;
/// let mut buf = [0u8; 512];
/// let mut b = MessageBuilder::new(&mut buf)?;
/// let cp = b.checkpoint();
/// b.push_answer(&name, Class::IN, 60, &A::new([192, 0, 2, 1].into()))?;
/// b.push_answer(&name, Class::IN, 60, &A::new([192, 0, 2, 2].into()))?;
/// // Changed our mind: drop both records as one unit.
/// b.rollback(cp);
/// assert_eq!(b.header().ancount, 0);
/// assert!(b.is_empty());
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    len: usize,
    counts: [u16; 4],
    section: Section,
    table_len: usize,
}

/// Writes a DNS message into an [`OutBuf`].
///
/// ```
/// use dnsbox::{Class, Flags, Message, MessageBuilder, NameBuf, Rtype, Section};
/// use dnsbox::rdata::{A, Mx};
///
/// let name: NameBuf = "example.com".parse()?;
/// let mail: NameBuf = "mail.example.com".parse()?;
/// let mut buf = [0u8; 512];
/// let mut b = MessageBuilder::new(&mut buf)?;
/// b.set_id(7);
/// b.set_flags(Flags::default().with_qr(true));
/// b.push_question(&name, Rtype::MX, Class::IN)?;
/// b.push_answer(&name, Class::IN, 3600, &Mx { preference: 10, exchange: mail.as_name() })?;
/// b.push_additional(&mail, Class::IN, 3600, &A::new([192, 0, 2, 1].into()))?;
/// let wire = b.finish();
///
/// let msg = Message::parse_validated(wire)?;
/// assert_eq!(msg.header().ancount, 1);
/// // Header, question, then each owner name is a 2-byte pointer, and
/// // "mail.example.com" in the MX RDATA is "mail" plus a pointer.
/// assert_eq!(wire.len(), 12 + (13 + 4) + (2 + 10 + 2 + 5 + 2) + (2 + 10 + 4));
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub struct MessageBuilder<B: OutBuf> {
    buf: B,
    /// Offset of the message within `buf` (bytes before it are left alone,
    /// e.g. a TCP length prefix).
    base: usize,
    /// Maximum message length.
    limit: usize,
    header: Header,
    section: Section,
    compress: bool,
    table: CompressionTable,
    /// Bytes kept free below `limit` for records added later.
    reserve: usize,
    /// What RRset-level pushes do when an RRset does not fit.
    policy: Truncation,
    /// Set once an RRset-level push truncated the message.
    truncated: bool,
    /// Whether a 2-byte TCP length prefix precedes the message.
    framed: bool,
}

impl<'b> MessageBuilder<WireWriter<'b>> {
    /// Starts a message at the beginning of `buf`, writing a zeroed
    /// header.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] if `buf` cannot hold the 12-byte header.
    ///
    /// ```
    /// use dnsbox::{Error, MessageBuilder};
    ///
    /// let mut buf = [0u8; 512];
    /// let b = MessageBuilder::new(&mut buf)?;
    /// assert_eq!(b.as_bytes(), [0; 12]); // a zeroed header
    /// let mut tiny = [0u8; 8];
    /// assert!(matches!(MessageBuilder::new(&mut tiny), Err(Error::BufferTooSmall)));
    /// # Ok::<(), Error>(())
    /// ```
    #[inline]
    pub fn new(buf: &'b mut [u8]) -> Result<Self> {
        Self::from_buf(WireWriter::new(buf))
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl MessageBuilder<alloc::vec::Vec<u8>> {
    /// Starts a message in a new growable `Vec`, limited to 65535 bytes.
    ///
    /// The `Vec` starts with room for 512 bytes (the classic UDP limit,
    /// RFC 1035 §4.2.1), so typical messages are written with a single
    /// allocation.
    ///
    /// ```
    /// use dnsbox::{Class, MessageBuilder, NameBuf, Rtype};
    ///
    /// let name: NameBuf = "example.com".parse()?;
    /// let mut b = MessageBuilder::new_vec();
    /// b.push_question(&name, Rtype::TXT, Class::IN)?;
    /// let wire: Vec<u8> = b.finish();
    /// assert_eq!(wire.len(), 29);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub fn new_vec() -> Self {
        Self::new_vec_with_capacity(DEFAULT_VEC_CAPACITY)
    }

    /// Like [`new_vec`](Self::new_vec), preallocating `capacity` bytes
    /// (e.g. the expected response size) so typical messages never
    /// reallocate.
    ///
    /// ```
    /// use dnsbox::rdata::A;
    /// use dnsbox::{Class, MessageBuilder, NameBuf, Section};
    ///
    /// // A zone transfer message: room for 16 KiB up front.
    /// let name: NameBuf = "host.example".parse()?;
    /// let mut b = MessageBuilder::new_vec_with_capacity(16 * 1024);
    /// for i in 1..=200u8 {
    ///     b.push_record(Section::Answer, &name, Class::IN, 60, &A::new([10, 0, 0, i].into()))?;
    /// }
    /// let wire = b.finish();
    /// assert!(wire.capacity() >= 16 * 1024);
    /// assert_eq!(wire.len(), 12 + 28 + 199 * 16);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub fn new_vec_with_capacity(capacity: usize) -> Self {
        let mut buf = alloc::vec::Vec::with_capacity(capacity.max(Header::LEN));
        buf.resize(Header::LEN, 0);
        MessageBuilder {
            buf,
            base: 0,
            limit: MAX_MESSAGE_LEN,
            header: Header::default(),
            section: Section::Question,
            compress: true,
            table: CompressionTable::new(),
            reserve: 0,
            policy: Truncation::Error,
            truncated: false,
            framed: false,
        }
    }
}

impl<B: OutBuf> MessageBuilder<B> {
    /// Starts a message at the current end of `buf` (anything already in
    /// it, such as a TCP length prefix, is kept and not counted as part of
    /// the message). Writes a zeroed header.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] if the buffer cannot hold the 12-byte
    /// header after what it already contains.
    ///
    /// ```
    /// use dnsbox::{MessageBuilder, OutBuf, WireWriter};
    ///
    /// let mut buf = [0u8; 64];
    /// let mut w = WireWriter::new(&mut buf);
    /// w.append(b"prefix")?; // left alone by the builder
    /// let mut b = MessageBuilder::from_buf(w)?;
    /// b.set_id(9);
    /// assert_eq!(b.as_bytes().len(), 12);
    /// let out = b.finish();
    /// assert_eq!(&out[..8], b"prefix\x00\x09");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub fn from_buf(mut buf: B) -> Result<Self> {
        let base = buf.as_bytes().len();
        let limit = buf
            .capacity_limit()
            .saturating_sub(base)
            .min(MAX_MESSAGE_LEN);
        if limit < Header::LEN {
            return Err(Error::BufferTooSmall);
        }
        buf.append(&[0; Header::LEN])?;
        Ok(MessageBuilder {
            buf,
            base,
            limit,
            header: Header::default(),
            section: Section::Question,
            compress: true,
            table: CompressionTable::new(),
            reserve: 0,
            policy: Truncation::Error,
            truncated: false,
            framed: false,
        })
    }

    /// The header as it currently stands (counts included).
    ///
    /// ```
    /// use dnsbox::rdata::A;
    /// use dnsbox::{Class, MessageBuilder, NameBuf, Rtype};
    ///
    /// let name: NameBuf = "example".parse()?;
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::query(&mut buf, 5, &name, Rtype::A, Class::IN)?;
    /// b.push_additional(&name, Class::IN, 60, &A::new([192, 0, 2, 1].into()))?;
    /// let h = b.header();
    /// assert_eq!((h.id, h.qdcount, h.ancount, h.arcount), (5, 1, 0, 1));
    /// assert!(h.flags.rd());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub fn header(&self) -> Header {
        self.header
    }

    /// Sets the transaction ID.
    ///
    /// ```
    /// use dnsbox::{Message, MessageBuilder};
    ///
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.set_id(0x1234);
    /// assert_eq!(&b.as_bytes()[..2], [0x12, 0x34]); // written through at once
    /// assert_eq!(Message::parse(b.finish())?.id(), 0x1234);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn set_id(&mut self, id: u16) {
        self.header.id = id;
        self.sync_header();
    }

    /// Sets the flags word (QR, opcode, flag bits, header RCODE).
    ///
    /// ```
    /// use dnsbox::{Flags, Message, MessageBuilder, Opcode, Rcode};
    ///
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.set_flags(Flags::default().with_qr(true).with_opcode(Opcode::NOTIFY).with_aa(true));
    /// b.set_rcode(Rcode::REFUSED);
    /// let flags = Message::parse(b.finish())?.flags();
    /// assert!(flags.qr() && flags.aa());
    /// assert_eq!((flags.opcode(), flags.rcode()), (Opcode::NOTIFY, Rcode::REFUSED));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn set_flags(&mut self, flags: Flags) {
        self.header.flags = flags;
        self.sync_header();
    }

    /// Enables or disables name compression for names written from now on
    /// (enabled by default).
    ///
    /// ```
    /// use dnsbox::rdata::A;
    /// use dnsbox::{Class, MessageBuilder, NameBuf};
    ///
    /// let name: NameBuf = "www.example.com".parse()?;
    /// let a = A::new([192, 0, 2, 1].into());
    /// let mut buf = [0u8; 128];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.push_answer(&name, Class::IN, 60, &a)?;
    /// b.push_answer(&name, Class::IN, 60, &a)?; // owner: a 2-byte pointer
    /// let compressed = b.len();
    /// let mut buf = [0u8; 128];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.set_compression(false);
    /// b.push_answer(&name, Class::IN, 60, &a)?;
    /// b.push_answer(&name, Class::IN, 60, &a)?; // owner written in full
    /// assert_eq!(b.len(), compressed + 17 - 2);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub fn set_compression(&mut self, enabled: bool) {
        self.compress = enabled;
    }

    /// Whether name compression is enabled.
    ///
    /// ```
    /// use dnsbox::MessageBuilder;
    ///
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// assert!(b.compression());
    /// b.set_compression(false);
    /// assert!(!b.compression());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub const fn compression(&self) -> bool {
        self.compress
    }

    /// Caps the message size (e.g. 512 for plain UDP, or the EDNS payload
    /// size). Values above the buffer capacity or 65535 are clamped. Pushes
    /// that would exceed it fail with [`Error::BufferTooSmall`].
    ///
    /// ```
    /// use dnsbox::rdata::A;
    /// use dnsbox::{Class, Error, MessageBuilder, NameBuf};
    ///
    /// let name: NameBuf = "example".parse()?;
    /// let mut buf = [0u8; 4096];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.set_limit(40); // 12-byte header + 28 bytes
    /// b.push_answer(&name, Class::IN, 60, &A::new([192, 0, 2, 1].into()))?; // 23 bytes
    /// let res = b.push_answer(&name, Class::IN, 60, &A::new([192, 0, 2, 2].into()));
    /// assert_eq!(res, Err(Error::BufferTooSmall));
    /// assert_eq!((b.len(), b.remaining()), (35, 5));
    /// # Ok::<(), Error>(())
    /// ```
    pub fn set_limit(&mut self, limit: usize) {
        let cap = self
            .buf
            .capacity_limit()
            .saturating_sub(self.base)
            .min(MAX_MESSAGE_LEN);
        self.limit = limit.min(cap);
    }

    /// The current size limit.
    ///
    /// ```
    /// use dnsbox::MessageBuilder;
    ///
    /// let mut buf = [0u8; 4096];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// assert_eq!(b.limit(), 4096); // the buffer's capacity
    /// b.set_limit(1232); // the client's EDNS payload size
    /// assert_eq!(b.limit(), 1232);
    /// b.set_limit(100_000); // clamped to the buffer
    /// assert_eq!(b.limit(), 4096);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub const fn limit(&self) -> usize {
        self.limit
    }

    /// Keeps `bytes` free below the [limit](Self::limit): pushes fail (or
    /// truncate) as if the limit were `limit - bytes`. Use it to guarantee
    /// room for records that must be added last even when the message is
    /// truncated — the OPT record (RFC 6891 §7) or a TSIG / SIG(0) record
    /// (RFC 8945 §5.3) — then set it back to 0 before adding them.
    ///
    /// ```
    /// use dnsbox::builder::Truncation;
    /// use dnsbox::rdata::A;
    /// use dnsbox::{Class, MessageBuilder, NameBuf, Section};
    ///
    /// let name: NameBuf = "example".parse()?;
    /// let addrs = [A::new([192, 0, 2, 1].into()); 30];
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.set_truncation(Truncation::SetTc);
    /// b.set_reserve(100); // room for a TSIG record, added last
    /// let _ = b.push_rrset(Section::Answer, &name, Class::IN, 60, &addrs)?; // truncated
    /// b.set_reserve(0);
    /// assert!(b.remaining() >= 100);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub fn set_reserve(&mut self, bytes: usize) {
        self.reserve = bytes;
    }

    /// The number of reserved bytes; see [`set_reserve`](Self::set_reserve).
    ///
    /// ```
    /// use dnsbox::MessageBuilder;
    ///
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.set_reserve(11); // room for an empty OPT record
    /// assert_eq!(b.reserve(), 11);
    /// assert_eq!(b.remaining(), 512 - 12 - 11);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub const fn reserve(&self) -> usize {
        self.reserve
    }

    /// How many more bytes can be written before hitting the limit (minus
    /// the reserve).
    ///
    /// ```
    /// use dnsbox::{Class, MessageBuilder, NameBuf, Rtype};
    ///
    /// let name: NameBuf = "example.com".parse()?;
    /// let mut buf = [0u8; 4096];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.set_limit(512);
    /// assert_eq!(b.remaining(), 500);
    /// b.push_question(&name, Rtype::A, Class::IN)?; // 13 + 4 bytes
    /// assert_eq!(b.remaining(), 483);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub fn remaining(&self) -> usize {
        self.effective_limit().saturating_sub(self.len())
    }

    /// The limit minus the reserve: where pushes stop.
    #[inline]
    pub(crate) fn effective_limit(&self) -> usize {
        self.limit.saturating_sub(self.reserve)
    }

    /// The message written so far.
    ///
    /// ```
    /// use dnsbox::{Class, MessageBuilder, NameBuf, Rtype};
    ///
    /// let name: NameBuf = "a.example".parse()?;
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.push_question(&name, Rtype::A, Class::IN)?;
    /// // Header (QDCOUNT already 1), then the question.
    /// assert_eq!(&b.as_bytes()[4..6], [0, 1]);
    /// assert_eq!(&b.as_bytes()[12..], b"\x01a\x07example\x00\x00\x01\x00\x01");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.buf.as_bytes().get(self.base..).unwrap_or(&[])
    }

    /// Length of the message written so far.
    ///
    /// ```
    /// use dnsbox::{Class, MessageBuilder, NameBuf, Rtype};
    ///
    /// let name: NameBuf = "a.example".parse()?;
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// assert_eq!(b.len(), 12);
    /// b.push_question(&name, Rtype::AAAA, Class::IN)?;
    /// assert_eq!(b.len(), 12 + 11 + 4);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    /// Whether the message holds no question or record yet.
    ///
    /// ```
    /// use dnsbox::{Class, MessageBuilder, NameBuf, Rtype};
    ///
    /// let name: NameBuf = "example".parse()?;
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.set_id(42); // header changes do not count
    /// assert!(b.is_empty());
    /// b.push_question(&name, Rtype::SOA, Class::IN)?;
    /// assert!(!b.is_empty());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() <= Header::LEN
    }

    /// The section currently being written.
    ///
    /// ```
    /// use dnsbox::rdata::Ns;
    /// use dnsbox::{Class, MessageBuilder, NameBuf, Rtype, Section};
    ///
    /// let zone: NameBuf = "example".parse()?;
    /// let ns: NameBuf = "ns1.example".parse()?;
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::query(&mut buf, 1, &zone, Rtype::NS, Class::IN)?;
    /// assert_eq!(b.section(), Section::Question);
    /// b.push_authority(&zone, Class::IN, 3600, &Ns::new(ns.as_name()))?;
    /// assert_eq!(b.section(), Section::Authority);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub const fn section(&self) -> Section {
        self.section
    }

    /// Saves the current state, to be restored with
    /// [`rollback`](Self::rollback).
    ///
    /// ```
    /// use dnsbox::rdata::{A, Aaaa};
    /// use dnsbox::{Class, Error, MessageBuilder, NameBuf};
    ///
    /// // Glue for one name server goes in whole or not at all.
    /// let ns: NameBuf = "ns1.example".parse()?;
    /// let mut buf = [0u8; 4096];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.set_limit(12 + 40);
    /// let cp = b.checkpoint();
    /// let glue = (|| -> Result<(), Error> {
    ///     b.push_additional(&ns, Class::IN, 3600, &A::new([192, 0, 2, 53].into()))?;
    ///     b.push_additional(&ns, Class::IN, 3600, &Aaaa::new("2001:db8::53".parse().unwrap()))
    /// })();
    /// if glue.is_err() {
    ///     b.rollback(cp); // the A record alone would be misleading
    /// }
    /// assert_eq!(b.header().arcount, 0);
    /// # Ok::<(), Error>(())
    /// ```
    #[inline]
    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            len: self.len(),
            counts: [
                self.header.qdcount,
                self.header.ancount,
                self.header.nscount,
                self.header.arcount,
            ],
            section: self.section,
            table_len: self.table.len(),
        }
    }

    /// Restores a state saved by [`checkpoint`](Self::checkpoint) on this
    /// builder, discarding everything written since.
    ///
    /// ```
    /// use dnsbox::rdata::Txt;
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
    ///
    /// let name: NameBuf = "example".parse()?;
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::query(&mut buf, 1, &name, Rtype::TXT, Class::IN)?;
    /// let before = b.len();
    /// let cp = b.checkpoint();
    /// b.push_answer(&name, Class::IN, 60, &Txt::from_wire(b"\x05draft")?)?;
    /// b.rollback(cp);
    /// assert_eq!(b.len(), before);
    /// let msg = Message::parse_validated(b.finish())?;
    /// assert_eq!((msg.header().qdcount, msg.header().ancount), (1, 0));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn rollback(&mut self, cp: Checkpoint) {
        self.buf.truncate(self.base + cp.len.max(Header::LEN));
        [
            self.header.qdcount,
            self.header.ancount,
            self.header.nscount,
            self.header.arcount,
        ] = cp.counts;
        self.section = cp.section;
        self.table.truncate(cp.table_len);
        self.sync_header();
    }

    /// Appends a question (RFC 1035 §4.1.2).
    ///
    /// # Errors
    ///
    /// [`Error::SectionOrder`] once a record has been pushed,
    /// [`Error::BufferTooSmall`] if the question does not fit within the
    /// limit, [`Error::CountOverflow`] past 65535 questions. On error the
    /// message is unchanged.
    ///
    /// ```
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
    ///
    /// let name: NameBuf = "_sip._udp.example.com".parse()?;
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.push_question(&name, Rtype::SRV, Class::IN)?;
    /// let msg = Message::parse_validated(b.finish())?;
    /// let q = msg.questions().next().unwrap()?;
    /// assert_eq!(q.to_string(), "_sip._udp.example.com. IN SRV");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn push_question(&mut self, name: impl ToName, qtype: Rtype, qclass: Class) -> Result<()> {
        let cp = self.checkpoint();
        let res = self.write_question(name.to_name(), qtype, qclass);
        if res.is_err() {
            self.rollback(cp);
        }
        res
    }

    /// Appends a resource record (RFC 1035 §4.1.3) to `section`, which
    /// must not be [`Section::Question`] nor precede the current section.
    /// The TYPE comes from `data`.
    ///
    /// # Errors
    ///
    /// [`Error::SectionOrder`] for [`Section::Question`] or a section
    /// before the current one, [`Error::BufferTooSmall`] if the record does
    /// not fit within the limit (minus the [reserve](Self::set_reserve)),
    /// [`Error::CountOverflow`] past 65535 records in the section, or the
    /// error of `data`'s [`ComposeRdata::compose_rdata`]. On error the
    /// message is unchanged.
    ///
    /// ```
    /// use dnsbox::rdata::A;
    /// use dnsbox::{Class, Error, MessageBuilder, NameBuf, Section};
    ///
    /// let name: NameBuf = "example".parse()?;
    /// let a = A::new([192, 0, 2, 1].into());
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.push_record(Section::Authority, &name, Class::IN, 60, &a)?;
    /// // Sections are written in order.
    /// let res = b.push_record(Section::Answer, &name, Class::IN, 60, &a);
    /// assert_eq!(res, Err(Error::SectionOrder));
    /// # Ok::<(), Error>(())
    /// ```
    pub fn push_record<D: ComposeRdata + ?Sized>(
        &mut self,
        section: Section,
        name: impl ToName,
        class: Class,
        ttl: u32,
        data: &D,
    ) -> Result<()> {
        let cp = self.checkpoint();
        let res = self.write_record(section, name.to_name(), class, ttl, data);
        if res.is_err() {
            self.rollback(cp);
        }
        res
    }

    /// Appends a record to the answer section.
    ///
    /// # Errors
    ///
    /// As [`push_record`](Self::push_record).
    ///
    /// ```
    /// use dnsbox::rdata::{Cname, Txt};
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf};
    ///
    /// let alias: NameBuf = "www.example".parse()?;
    /// let target: NameBuf = "web.example".parse()?;
    /// let mut buf = [0u8; 128];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// // Any `ComposeRdata`: typed views, `RData`, owned data, ...
    /// b.push_answer(&alias, Class::IN, 300, &Cname::new(target.as_name()))?;
    /// b.push_answer(&target, Class::IN, 300, &Txt::from_wire(b"\x05hello")?)?;
    /// assert_eq!(Message::parse_validated(b.finish())?.header().ancount, 2);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub fn push_answer<D: ComposeRdata + ?Sized>(
        &mut self,
        name: impl ToName,
        class: Class,
        ttl: u32,
        data: &D,
    ) -> Result<()> {
        self.push_record(Section::Answer, name, class, ttl, data)
    }

    /// Appends a record to the authority section.
    ///
    /// # Errors
    ///
    /// As [`push_record`](Self::push_record).
    ///
    /// ```
    /// use dnsbox::rdata::Soa;
    /// use dnsbox::ParseRdataText;
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rcode, Rtype};
    ///
    /// // A negative answer: the zone's SOA in the authority section (RFC 2308).
    /// let zone: NameBuf = "example".parse()?;
    /// let qname: NameBuf = "nope.example".parse()?;
    ///
    /// let mut qbuf = [0u8; 512];
    /// let query = Message::parse(MessageBuilder::query(&mut qbuf, 1, &qname, Rtype::A, Class::IN)?.finish())?;
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::response(&mut buf, &query)?;
    /// b.set_rcode(Rcode::NXDOMAIN);
    /// let mut sbuf = [0u8; 64];
    /// let soa = Soa::from_text("ns1.example. hostmaster.example. 2024010101 2h 15m 2w 5m", &mut sbuf)?;
    /// b.push_authority(&zone, Class::IN, 300, &soa)?;
    /// let msg = Message::parse_validated(b.finish())?;
    /// assert_eq!(msg.authority().next().unwrap()?.rtype(), Rtype::SOA);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub fn push_authority<D: ComposeRdata + ?Sized>(
        &mut self,
        name: impl ToName,
        class: Class,
        ttl: u32,
        data: &D,
    ) -> Result<()> {
        self.push_record(Section::Authority, name, class, ttl, data)
    }

    /// Appends a record to the additional section.
    ///
    /// # Errors
    ///
    /// As [`push_record`](Self::push_record).
    ///
    /// ```
    /// use dnsbox::rdata::{A, Mx};
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf};
    ///
    /// let domain: NameBuf = "example".parse()?;
    /// let mx: NameBuf = "mail.example".parse()?;
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.push_answer(&domain, Class::IN, 3600, &Mx { preference: 10, exchange: mx.as_name() })?;
    /// // The exchange's address, so the client need not ask for it.
    /// b.push_additional(&mx, Class::IN, 3600, &A::new([192, 0, 2, 25].into()))?;
    /// let msg = Message::parse_validated(b.finish())?;
    /// assert_eq!(msg.additional().next().unwrap()?.to_string(), "mail.example. 3600 IN A 192.0.2.25");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub fn push_additional<D: ComposeRdata + ?Sized>(
        &mut self,
        name: impl ToName,
        class: Class,
        ttl: u32,
        data: &D,
    ) -> Result<()> {
        self.push_record(Section::Additional, name, class, ttl, data)
    }

    /// Copies a question from a parsed message.
    ///
    /// # Errors
    ///
    /// As [`push_question`](Self::push_question).
    ///
    /// ```
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
    ///
    /// let name: NameBuf = "example.com".parse()?;
    /// let mut qbuf = [0u8; 512];
    /// let query = Message::parse(MessageBuilder::query(&mut qbuf, 1, &name, Rtype::CAA, Class::IN)?.finish())?;
    /// // Forward the question under a new ID.
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.set_id(0x5151);
    /// for q in query.questions() {
    ///     b.copy_question(&q?)?;
    /// }
    /// let forwarded = Message::parse_validated(b.finish())?;
    /// assert_eq!(forwarded.questions().next().unwrap()?.qtype(), Rtype::CAA);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub fn copy_question(&mut self, q: &Question<'_>) -> Result<()> {
        self.push_question(q.name(), q.qtype(), q.qclass())
    }

    /// Copies a record from a parsed message, re-encoding its RDATA (so
    /// compressed names are decompressed and recompressed against this
    /// message).
    ///
    /// # Errors
    ///
    /// The RDATA parse error if `rr` is malformed, otherwise as
    /// [`push_record`](Self::push_record).
    ///
    /// ```
    /// use dnsbox::{Message, MessageBuilder, Section};
    /// # use dnsbox::{Class, NameBuf, rdata::Cname};
    /// # let www: NameBuf = "www.example".parse()?;
    /// # let target: NameBuf = "example".parse()?;
    /// # let mut sbuf = [0u8; 128];
    /// # let mut s = MessageBuilder::new(&mut sbuf)?;
    /// # s.push_answer(&www, Class::IN, 60, &Cname { cname: target.as_name() })?;
    /// # let source = s.finish();
    /// let source = Message::parse(source)?;
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// for rr in source.answers() {
    ///     b.copy_record(Section::Answer, &rr?)?;
    /// }
    /// assert_eq!(b.header().ancount, 1);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn copy_record(&mut self, section: Section, rr: &Record<'_>) -> Result<()> {
        let data = rr.data()?;
        self.push_record(section, rr.name(), rr.class(), rr.ttl(), &data)
    }

    /// Finishes the message, returning the buffer's output (the written
    /// slice for a `&mut [u8]`, the `Vec` itself with `alloc`). For a
    /// builder started with [`new_tcp`](Self::new_tcp) the output includes
    /// the 2-byte length prefix.
    ///
    /// ```
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
    ///
    /// let name: NameBuf = "example.com".parse()?;
    /// let mut buf = [0u8; 512];
    /// let b = MessageBuilder::query(&mut buf, 1, &name, Rtype::A, Class::IN)?;
    /// let wire: &mut [u8] = b.finish(); // exactly the message, ready to send
    /// assert_eq!(wire.len(), 29);
    /// assert_eq!(Message::parse_validated(wire)?.header().qdcount, 1);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub fn finish(mut self) -> B::Output {
        self.sync_header();
        self.buf.into_output()
    }

    fn enter(&mut self, section: Section) -> Result<()> {
        if section < self.section {
            return Err(Error::SectionOrder);
        }
        self.section = section;
        Ok(())
    }

    fn count_mut(&mut self, section: Section) -> &mut u16 {
        match section {
            Section::Question => &mut self.header.qdcount,
            Section::Answer => &mut self.header.ancount,
            Section::Authority => &mut self.header.nscount,
            Section::Additional => &mut self.header.arcount,
        }
    }

    fn bump(&mut self, section: Section) -> Result<()> {
        let count = self.count_mut(section);
        *count = count.checked_add(1).ok_or(Error::CountOverflow)?;
        self.sync_header();
        Ok(())
    }

    fn sync_header(&mut self) {
        let bytes = self.header.to_bytes();
        if let Some(dst) = self
            .buf
            .as_bytes_mut()
            .get_mut(self.base..self.base + Header::LEN)
        {
            dst.copy_from_slice(&bytes);
        }
        if self.framed {
            // The limit keeps the message within 65535 bytes.
            let len = u16::try_from(self.len()).unwrap_or(u16::MAX).to_be_bytes();
            if let Some(dst) = self
                .base
                .checked_sub(2)
                .and_then(|at| self.buf.as_bytes_mut().get_mut(at..at + 2))
            {
                dst.copy_from_slice(&len);
            }
        }
    }

    fn writer(&mut self) -> MsgWriter<'_, B> {
        let limit = self.effective_limit();
        MsgWriter {
            buf: &mut self.buf,
            base: self.base,
            limit,
            table: if self.compress {
                Some(&mut self.table)
            } else {
                None
            },
        }
    }

    fn write_question(&mut self, name: Name<'_>, qtype: Rtype, qclass: Class) -> Result<()> {
        self.enter(Section::Question)?;
        if self.header.qdcount == u16::MAX {
            return Err(Error::CountOverflow);
        }
        let mut w = self.writer();
        w.put_name(name, NameEncoding::Compressible)?;
        let [t0, t1] = qtype.get().to_be_bytes();
        let [c0, c1] = qclass.get().to_be_bytes();
        w.put_bytes(&[t0, t1, c0, c1])?;
        self.bump(Section::Question)
    }

    fn write_record<D: ComposeRdata + ?Sized>(
        &mut self,
        section: Section,
        name: Name<'_>,
        class: Class,
        ttl: u32,
        data: &D,
    ) -> Result<()> {
        if section == Section::Question {
            return Err(Error::SectionOrder);
        }
        self.enter(section)?;
        if *self.count_mut(section) == u16::MAX {
            return Err(Error::CountOverflow);
        }
        let mut w = self.writer();
        w.put_name(name, NameEncoding::Compressible)?;
        // TYPE, CLASS, TTL and an RDLENGTH placeholder in one write.
        let [t0, t1] = data.rtype().get().to_be_bytes();
        let [c0, c1] = class.get().to_be_bytes();
        let [l0, l1, l2, l3] = ttl.to_be_bytes();
        let at = w.pos() + 8;
        w.put_bytes(&[t0, t1, c0, c1, l0, l1, l2, l3, 0, 0])?;
        data.compose_rdata(&mut w)?;
        let len =
            u16::try_from(w.pos().saturating_sub(at + 2)).map_err(|_| Error::BufferTooSmall)?;
        w.patch(at, &len.to_be_bytes())?;
        self.bump(section)
    }
}

impl<B: OutBuf> fmt::Debug for MessageBuilder<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageBuilder")
            .field("header", &self.header)
            .field("section", &self.section)
            .field("len", &self.len())
            .field("limit", &self.limit)
            .field("reserve", &self.reserve)
            .field("compression", &self.compress)
            .field("truncation", &self.policy)
            .field("truncated", &self.truncated)
            .field("framed", &self.framed)
            .finish()
    }
}

/// The [`Composer`] handed to record data while a message is being built:
/// enforces the size limit and compresses names when allowed.
struct MsgWriter<'x, B: OutBuf> {
    buf: &'x mut B,
    base: usize,
    limit: usize,
    table: Option<&'x mut CompressionTable>,
}

impl<B: OutBuf> MsgWriter<'_, B> {
    fn write_compressed(&mut self, table: &mut CompressionTable, name: Name<'_>) -> Result<()> {
        if name.is_root() {
            // Nothing to compress (an OPT record's owner, for one).
            return self.put_u8(0);
        }
        // Names built locally (`NameBuf`) are contiguous: no copy.
        let flat;
        let wire = match name.as_contiguous() {
            Some(wire) => wire,
            None => {
                let mut buf = [0u8; MAX_NAME_LEN];
                let len = name.flatten(&mut buf);
                flat = buf;
                flat.get(..len).ok_or(Error::NameTooLong)?
            }
        };
        let mut offsets = [0u8; MAX_LABELS];
        let n = compress::label_offsets(wire, &mut offsets);
        let offsets = offsets.get(..n).unwrap_or(&[]);
        let msg = self.buf.as_bytes().get(self.base..).unwrap_or(&[]);
        let m = table.lookup(msg, wire, offsets);
        let start = self.pos();
        self.put_bytes(wire.get(..m.literal_len(wire, offsets)).unwrap_or(&[]))?;
        if let Some(ptr) = m.pointer {
            self.put_u16(0xc000 | ptr)?;
        }
        table.insert(wire, offsets, &m, start);
        Ok(())
    }
}

impl<B: OutBuf> Composer for MsgWriter<'_, B> {
    #[inline]
    fn pos(&self) -> usize {
        self.buf.as_bytes().len() - self.base
    }

    #[inline]
    fn put_bytes(&mut self, data: &[u8]) -> Result<()> {
        if self.pos() + data.len() > self.limit {
            return Err(Error::BufferTooSmall);
        }
        self.buf.append(data)
    }

    #[inline]
    fn patch(&mut self, pos: usize, data: &[u8]) -> Result<()> {
        let start = self.base + pos;
        self.buf
            .as_bytes_mut()
            .get_mut(start..start + data.len())
            .ok_or(Error::BufferTooSmall)?
            .copy_from_slice(data);
        Ok(())
    }

    fn put_name(&mut self, name: Name<'_>, encoding: NameEncoding) -> Result<()> {
        match (encoding, self.table.take()) {
            (NameEncoding::Compressible, Some(table)) => {
                let res = self.write_compressed(table, name);
                self.table = Some(table);
                res
            }
            (_, table) => {
                self.table = table;
                put_name_uncompressed(self, name, false)
            }
        }
    }
}

#[cfg(test)]
mod tests;
