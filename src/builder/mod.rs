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
//!   types are compressed through a fixed-size suffix table (see
//!   [`compress`]); names in any other RDATA are never compressed
//!   (RFC 3597 §4). Compression can be turned off;
//! - every push is atomic: if an entry does not fit (buffer or
//!   [size limit](MessageBuilder::set_limit)), the message is rolled back to
//!   its state before the push and the error returned. [`checkpoint`] /
//!   [`rollback`] expose the same mechanism for multi-record units (e.g.
//!   truncating at RRset boundaries, RFC 2181 §9).
//!
//! [`checkpoint`]: MessageBuilder::checkpoint
//! [`rollback`]: MessageBuilder::rollback

pub mod compress;

use core::fmt;

use self::compress::CompressionTable;
use crate::message::{Question, Record, Section};
use crate::name::{MAX_NAME_LEN, Name, ToName};
use crate::rdata::ComposeRdata;
use crate::wire::{Composer, NameEncoding, OutBuf, WireWriter, put_name_uncompressed};
use crate::{Class, Error, Flags, Header, Result, Rtype};

/// Maximum size of a DNS message (the TCP length prefix is 16 bits).
pub const MAX_MESSAGE_LEN: usize = 65535;

/// A saved builder state; see [`MessageBuilder::checkpoint`].
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
}

impl<'b> MessageBuilder<WireWriter<'b>> {
    /// Starts a message at the beginning of `buf`. Fails with
    /// [`Error::BufferTooSmall`] if `buf` cannot hold the 12-byte header.
    pub fn new(buf: &'b mut [u8]) -> Result<Self> {
        Self::from_buf(WireWriter::new(buf))
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl MessageBuilder<alloc::vec::Vec<u8>> {
    /// Starts a message in a new growable `Vec`, limited to 65535 bytes.
    pub fn new_vec() -> Self {
        MessageBuilder {
            buf: alloc::vec![0; Header::LEN],
            base: 0,
            limit: MAX_MESSAGE_LEN,
            header: Header::default(),
            section: Section::Question,
            compress: true,
            table: CompressionTable::new(),
        }
    }
}

impl<B: OutBuf> MessageBuilder<B> {
    /// Starts a message at the current end of `buf` (anything already in
    /// it, such as a TCP length prefix, is kept and not counted as part of
    /// the message). Writes a zeroed header.
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
        })
    }

    /// The header as it currently stands (counts included).
    #[inline]
    pub fn header(&self) -> Header {
        self.header
    }

    /// Sets the transaction ID.
    pub fn set_id(&mut self, id: u16) {
        self.header.id = id;
        self.sync_header();
    }

    /// Sets the flags word (QR, opcode, flag bits, header RCODE).
    pub fn set_flags(&mut self, flags: Flags) {
        self.header.flags = flags;
        self.sync_header();
    }

    /// Enables or disables name compression for names written from now on
    /// (enabled by default).
    #[inline]
    pub fn set_compression(&mut self, enabled: bool) {
        self.compress = enabled;
    }

    /// Whether name compression is enabled.
    #[inline]
    pub const fn compression(&self) -> bool {
        self.compress
    }

    /// Caps the message size (e.g. 512 for plain UDP, or the EDNS payload
    /// size). Values above the buffer capacity or 65535 are clamped. Pushes
    /// that would exceed it fail with [`Error::BufferTooSmall`].
    pub fn set_limit(&mut self, limit: usize) {
        let cap = self
            .buf
            .capacity_limit()
            .saturating_sub(self.base)
            .min(MAX_MESSAGE_LEN);
        self.limit = limit.min(cap);
    }

    /// The current size limit.
    #[inline]
    pub const fn limit(&self) -> usize {
        self.limit
    }

    /// The message written so far.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.buf.as_bytes().get(self.base..).unwrap_or(&[])
    }

    /// Length of the message written so far.
    #[inline]
    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    /// Whether the message holds no question or record yet.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() <= Header::LEN
    }

    /// The section currently being written.
    #[inline]
    pub const fn section(&self) -> Section {
        self.section
    }

    /// Saves the current state, to be restored with
    /// [`rollback`](Self::rollback).
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
    #[inline]
    pub fn copy_question(&mut self, q: &Question<'_>) -> Result<()> {
        self.push_question(q.name(), q.qtype(), q.qclass())
    }

    /// Copies a record from a parsed message, re-encoding its RDATA (so
    /// compressed names are decompressed and recompressed against this
    /// message).
    pub fn copy_record(&mut self, section: Section, rr: &Record<'_>) -> Result<()> {
        let data = rr.data()?;
        self.push_record(section, rr.name(), rr.class(), rr.ttl(), &data)
    }

    /// Finishes the message, returning the buffer's output (the written
    /// slice for a `&mut [u8]`, the `Vec` itself with `alloc`).
    #[inline]
    pub fn finish(self) -> B::Output {
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
    }

    fn writer(&mut self) -> MsgWriter<'_, B> {
        MsgWriter {
            buf: &mut self.buf,
            base: self.base,
            limit: self.limit,
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
        w.put_u16(qtype.get())?;
        w.put_u16(qclass.get())?;
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
        w.put_u16(data.rtype().get())?;
        w.put_u16(class.get())?;
        w.put_u32(ttl)?;
        w.put_u16_prefixed(|w| data.compose_rdata(w))?;
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
            .field("compression", &self.compress)
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
        let mut flat = [0u8; MAX_NAME_LEN];
        let len = name.flatten(&mut flat);
        let wire = flat.get(..len).ok_or(Error::NameTooLong)?;
        let msg = self.buf.as_bytes().get(self.base..).unwrap_or(&[]);
        let plan = compress::plan(table, msg, wire);
        let start = self.pos();
        self.put_bytes(wire.get(..plan.literal_len).unwrap_or(&[]))?;
        if let Some(ptr) = plan.pointer {
            self.put_u16(0xc000 | ptr)?;
        }
        for i in 0..plan.new_labels {
            table.push(plan.hashes[i], start + plan.offsets[i] as usize);
        }
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
