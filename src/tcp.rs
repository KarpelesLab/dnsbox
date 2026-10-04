//! DNS over TCP framing (RFC 1035 §4.2.2, RFC 7766 §8).
//!
//! Over TCP — and over TLS (RFC 7858) — every DNS message is preceded by a
//! two-byte, big-endian length field giving the size of the message
//! (excluding the field itself). A connection may carry many messages back
//! to back, and a single read may return several of them or only part of
//! one (RFC 7766 §8). This module handles both directions without
//! allocating:
//!
//! - writing: [`length_prefix`], [`write_frame`], [`append_frame`] (and
//!   [`MessageBuilder::new_tcp`](crate::MessageBuilder::new_tcp), which
//!   builds a message with its prefix in place);
//! - reading a buffer that already holds whole frames: [`frame_len`],
//!   [`split_frame`], [`frames`];
//! - reading a byte stream: [`FrameReassembler`], which accumulates reads
//!   in a caller-supplied buffer and yields each complete message;
//! - with the `std` feature, blocking `std::io` helpers: [`read_message`]
//!   and [`write_message`].
//!
//! The framing layer does not interpret the messages: a zero-length frame
//! is returned as an empty message (which [`Message::parse`] rejects).
//!
//! # Examples
//!
//! Two queries pipelined on one connection, and the server side reading
//! them back from a stream that delivers bytes in arbitrary pieces:
//!
//! ```
//! use dnsbox::tcp::{FrameReassembler, MAX_FRAME_LEN, append_frame};
//! use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype, WireWriter};
//!
//! let name: NameBuf = "example.com".parse()?;
//! let mut stream_buf = [0u8; 256];
//! let mut stream = WireWriter::new(&mut stream_buf);
//! for (id, qtype) in [(1, Rtype::A), (2, Rtype::AAAA)] {
//!     let mut qbuf = [0u8; 128];
//!     let q = MessageBuilder::query(&mut qbuf, id, &name, qtype, Class::IN)?.finish();
//!     append_frame(&mut stream, q)?;
//! }
//! let stream = stream.into_written();
//!
//! let mut storage = vec![0u8; MAX_FRAME_LEN];
//! let mut frames = FrameReassembler::new(&mut storage);
//! let mut ids = Vec::new();
//! for chunk in stream.chunks(7) {
//!     frames.extend(chunk);
//!     while let Some(msg) = frames.next_frame()? {
//!         ids.push(Message::parse(msg)?.id());
//!     }
//! }
//! assert_eq!(ids, [1, 2]);
//! # Ok::<(), dnsbox::Error>(())
//! ```
//!
//! [`Message::parse`]: crate::Message::parse
#![cfg_attr(
    feature = "std",
    doc = "
[`read_message`]: read_message
[`write_message`]: write_message"
)]
#![cfg_attr(
    not(feature = "std"),
    doc = "
[`read_message`]: crate#cargo-features
[`write_message`]: crate#cargo-features"
)]

use crate::builder::MAX_MESSAGE_LEN;
use crate::wire::OutBuf;
use crate::{Error, Result};

/// Size of the length prefix, in bytes.
pub const PREFIX_LEN: usize = 2;

/// The largest possible frame: the prefix plus a 65535-byte message. A
/// [`FrameReassembler`] buffer of this size can hold any frame.
pub const MAX_FRAME_LEN: usize = PREFIX_LEN + MAX_MESSAGE_LEN;

/// The length prefix for a message of `msg_len` bytes.
///
/// # Errors
///
/// [`Error::MessageTooLong`] if `msg_len` exceeds 65535 bytes.
///
/// ```
/// assert_eq!(dnsbox::tcp::length_prefix(300), Ok([1, 44]));
/// assert!(dnsbox::tcp::length_prefix(65536).is_err());
/// ```
pub const fn length_prefix(msg_len: usize) -> Result<[u8; 2]> {
    if msg_len > MAX_MESSAGE_LEN {
        return Err(Error::MessageTooLong);
    }
    Ok((msg_len as u16).to_be_bytes())
}

/// Writes `msg` with its length prefix at the start of `out`, returning the
/// number of bytes written (`msg.len() + 2`).
///
/// # Errors
///
/// [`Error::MessageTooLong`] if `msg` exceeds 65535 bytes,
/// [`Error::BufferTooSmall`] if `out` is too short; nothing is written
/// then.
///
/// ```
/// let mut out = [0u8; 8];
/// let n = dnsbox::tcp::write_frame(&mut out, b"query")?;
/// assert_eq!(&out[..n], b"\x00\x05query");
/// assert!(dnsbox::tcp::write_frame(&mut out, b"too long!").is_err());
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn write_frame(out: &mut [u8], msg: &[u8]) -> Result<usize> {
    let prefix = length_prefix(msg.len())?;
    let total = PREFIX_LEN + msg.len();
    let dst = out.get_mut(..total).ok_or(Error::BufferTooSmall)?;
    let (head, body) = dst.split_at_mut(PREFIX_LEN);
    head.copy_from_slice(&prefix);
    body.copy_from_slice(msg);
    Ok(total)
}

/// Appends `msg` with its length prefix to `out` (a
/// [`WireWriter`](crate::WireWriter), or a `Vec<u8>` with `alloc`).
///
/// # Errors
///
/// [`Error::MessageTooLong`] if `msg` exceeds 65535 bytes,
/// [`Error::BufferTooSmall`] if `out` cannot hold the frame; nothing is
/// appended then.
///
/// ```
/// use dnsbox::WireWriter;
/// use dnsbox::tcp::append_frame;
///
/// // Pipelining two messages into one write buffer.
/// let mut buf = [0u8; 16];
/// let mut out = WireWriter::new(&mut buf);
/// append_frame(&mut out, b"one")?;
/// append_frame(&mut out, b"two")?;
/// assert_eq!(out.as_bytes(), b"\x00\x03one\x00\x03two");
/// assert!(append_frame(&mut out, b"three").is_err()); // 7 bytes, 6 left
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn append_frame<O: OutBuf + ?Sized>(out: &mut O, msg: &[u8]) -> Result<()> {
    let prefix = length_prefix(msg.len())?;
    let len = out.as_bytes().len();
    if out.capacity_limit().saturating_sub(len) < PREFIX_LEN + msg.len() {
        return Err(Error::BufferTooSmall);
    }
    out.append(&prefix)?;
    if let Err(e) = out.append(msg) {
        out.truncate(len);
        return Err(e);
    }
    Ok(())
}

/// The total size (prefix included) of the frame starting at `buf[0]`, or
/// `None` if `buf` does not hold the whole length prefix yet.
///
/// ```
/// assert_eq!(dnsbox::tcp::frame_len(&[0x01, 0x00, 0xab]), Some(258));
/// assert_eq!(dnsbox::tcp::frame_len(&[0x01]), None);
/// ```
#[must_use]
pub const fn frame_len(buf: &[u8]) -> Option<usize> {
    match *buf {
        [a, b, ..] => Some(PREFIX_LEN + u16::from_be_bytes([a, b]) as usize),
        _ => None,
    }
}

/// Splits the first complete frame off `buf`: returns the message (without
/// its prefix) and the bytes after it, or `None` if `buf` does not hold a
/// complete frame yet.
///
/// ```
/// let buf = [0, 3, b'a', b'b', b'c', 0, 1];
/// let (msg, rest) = dnsbox::tcp::split_frame(&buf).unwrap();
/// assert_eq!((msg, rest), (&b"abc"[..], &[0, 1][..]));
/// assert_eq!(dnsbox::tcp::split_frame(rest), None);
/// ```
#[must_use]
pub fn split_frame(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    let total = frame_len(buf)?;
    let frame = buf.get(PREFIX_LEN..total)?;
    let rest = buf.get(total..)?;
    Some((frame, rest))
}

/// Iterates over the complete frames at the start of `buf`; see
/// [`Frames`].
///
/// ```
/// let buf = [0, 1, b'x', 0, 2, b'y', b'z', 0, 9, 1];
/// let mut it = dnsbox::tcp::frames(&buf);
/// assert_eq!(it.next(), Some(&b"x"[..]));
/// assert_eq!(it.next(), Some(&b"yz"[..]));
/// assert_eq!(it.next(), None);
/// assert_eq!(it.consumed(), 7);
/// assert_eq!(it.remainder(), &[0, 9, 1]); // an incomplete frame
/// ```
#[inline]
pub const fn frames(buf: &[u8]) -> Frames<'_> {
    Frames { buf, pos: 0 }
}

/// Iterator over the complete length-prefixed messages at the start of a
/// buffer. Stops at the first incomplete frame; [`remainder`] then holds
/// the bytes to keep until more data arrives.
///
/// [`remainder`]: Frames::remainder
///
/// ```
/// // Two messages and the start of a third, as one read returned them.
/// let read = [0, 2, 0xab, 0xcd, 0, 1, 0xef, 0, 5, 1, 2];
/// let mut frames = dnsbox::tcp::frames(&read);
/// let messages: Vec<&[u8]> = frames.by_ref().collect();
/// assert_eq!(messages, [&[0xab, 0xcd][..], &[0xef][..]]);
/// assert_eq!(frames.remainder(), [0, 5, 1, 2]); // keep for the next read
/// ```
#[derive(Clone, Debug)]
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct Frames<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Frames<'a> {
    /// The number of bytes consumed by the frames returned so far.
    ///
    /// ```
    /// // After a read: process the whole frames, keep the rest for later.
    /// let mut pending = vec![0, 2, 0xab, 0xcd, 0, 4, 1];
    /// let mut frames = dnsbox::tcp::frames(&pending);
    /// assert_eq!(frames.next(), Some(&[0xab, 0xcd][..]));
    /// assert_eq!(frames.next(), None);
    /// let used = frames.consumed();
    /// assert_eq!(used, 4);
    /// pending.drain(..used);
    /// assert_eq!(pending, [0, 4, 1]);
    /// ```
    #[inline]
    #[must_use]
    pub const fn consumed(&self) -> usize {
        self.pos
    }

    /// The bytes after the frames returned so far.
    ///
    /// ```
    /// let read = [0, 1, 0x42, 0, 3, 7];
    /// let mut frames = dnsbox::tcp::frames(&read);
    /// assert_eq!(frames.by_ref().count(), 1);
    /// // The start of a 3-byte message: one byte of it so far.
    /// assert_eq!(frames.remainder(), [0, 3, 7]);
    /// ```
    #[inline]
    #[must_use]
    pub fn remainder(&self) -> &'a [u8] {
        self.buf.get(self.pos..).unwrap_or(&[])
    }
}

impl<'a> Iterator for Frames<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let rest = self.remainder();
        let (msg, _) = split_frame(rest)?;
        self.pos += PREFIX_LEN + msg.len();
        Some(msg)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.remainder().len() / PREFIX_LEN))
    }
}

/// Reassembles length-prefixed messages from a byte stream, in a
/// caller-supplied buffer (no allocation).
///
/// Feed it what the socket returns — by copying with
/// [`extend`](Self::extend), or by reading straight into
/// [`spare`](Self::spare) and calling [`commit`](Self::commit) — then call
/// [`next_frame`](Self::next_frame) until it returns `Ok(None)`. Any number
/// of messages per read, and messages split across reads, are handled.
///
/// A buffer of [`MAX_FRAME_LEN`] bytes accepts every possible message. With
/// a smaller buffer, a frame that can never fit makes `next_frame` fail
/// with [`Error::BufferTooSmall`]; the caller may then close the connection
/// or [`skip_frame`](Self::skip_frame) it.
///
/// ```
/// use dnsbox::tcp::FrameReassembler;
///
/// let mut storage = [0u8; 64];
/// let mut r = FrameReassembler::new(&mut storage);
/// // Two messages and half of a third arrive in one read...
/// assert_eq!(r.extend(&[0, 2, b'h', b'i', 0, 1, b'!', 0, 3, b'a']), 10);
/// assert_eq!(r.next_frame()?, Some(&b"hi"[..]));
/// assert_eq!(r.next_frame()?, Some(&b"!"[..]));
/// assert_eq!(r.next_frame()?, None);
/// // ...and the rest in the next one.
/// r.extend(b"bc");
/// assert_eq!(r.next_frame()?, Some(&b"abc"[..]));
/// assert!(r.is_empty());
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Debug)]
pub struct FrameReassembler<'b> {
    buf: &'b mut [u8],
    /// Start of the unconsumed data.
    start: usize,
    /// End of the buffered data.
    end: usize,
    /// Bytes of a skipped frame still to be discarded from the stream.
    skip: usize,
}

impl<'b> FrameReassembler<'b> {
    /// Creates a reassembler that buffers data in `buf`.
    ///
    /// ```
    /// use dnsbox::tcp::{FrameReassembler, MAX_FRAME_LEN};
    ///
    /// // Room for any DNS message (65535 bytes plus the prefix).
    /// let mut storage = vec![0u8; MAX_FRAME_LEN];
    /// let r = FrameReassembler::new(&mut storage);
    /// assert_eq!((r.capacity(), r.buffered()), (MAX_FRAME_LEN, 0));
    /// ```
    #[inline]
    pub const fn new(buf: &'b mut [u8]) -> Self {
        FrameReassembler {
            buf,
            start: 0,
            end: 0,
            skip: 0,
        }
    }

    /// The size of the buffer.
    ///
    /// ```
    /// use dnsbox::tcp::FrameReassembler;
    ///
    /// let mut storage = [0u8; 1024];
    /// let mut r = FrameReassembler::new(&mut storage);
    /// r.extend(&[0, 5, 1, 2]);
    /// assert_eq!(r.capacity(), 1024); // unchanged by buffering
    /// ```
    #[inline]
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// The number of buffered bytes not yet returned as frames.
    ///
    /// ```
    /// use dnsbox::tcp::FrameReassembler;
    ///
    /// let mut storage = [0u8; 64];
    /// let mut r = FrameReassembler::new(&mut storage);
    /// r.extend(&[0, 1, 9, 0, 4, 1]);
    /// assert_eq!(r.buffered(), 6);
    /// assert_eq!(r.next_frame()?, Some(&[9][..]));
    /// assert_eq!(r.buffered(), 3); // half of the next frame
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub const fn buffered(&self) -> usize {
        self.end - self.start
    }

    /// Whether no bytes are buffered (the stream is at a frame boundary,
    /// unless a skipped frame is still being discarded).
    ///
    /// ```
    /// use dnsbox::tcp::FrameReassembler;
    ///
    /// let mut storage = [0u8; 64];
    /// let mut r = FrameReassembler::new(&mut storage);
    /// r.extend(&[0, 1, 9]);
    /// assert!(!r.is_empty());
    /// r.next_frame()?;
    /// // At a frame boundary: a clean place to close the connection.
    /// assert!(r.is_empty());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.end == self.start && self.skip == 0
    }

    /// Discards all buffered data (e.g. when the connection is reset).
    ///
    /// ```
    /// use dnsbox::tcp::FrameReassembler;
    ///
    /// let mut storage = [0u8; 64];
    /// let mut r = FrameReassembler::new(&mut storage);
    /// r.extend(&[0, 9, 1, 2, 3]); // a partial message ...
    /// r.clear(); // ... dropped when the connection is re-established
    /// assert!(r.is_empty());
    /// r.extend(&[0, 1, 7]);
    /// assert_eq!(r.next_frame()?, Some(&[7][..]));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub fn clear(&mut self) {
        self.start = 0;
        self.end = 0;
        self.skip = 0;
    }

    /// Moves the unconsumed data to the start of the buffer.
    fn compact(&mut self) {
        if self.start > 0 {
            self.buf.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
    }

    /// The free part of the buffer, to read into directly; report how many
    /// bytes were written with [`commit`](Self::commit). Empty when the
    /// buffer is full (call [`next_frame`](Self::next_frame) first).
    ///
    /// ```
    /// use std::io::Read;
    /// use dnsbox::tcp::FrameReassembler;
    ///
    /// // Read from a socket (here: a byte slice) straight into the buffer.
    /// let mut socket: &[u8] = &[0, 3, b'a', b'b', b'c'];
    /// let mut storage = [0u8; 64];
    /// let mut r = FrameReassembler::new(&mut storage);
    /// let n = socket.read(r.spare()).unwrap();
    /// r.commit(n);
    /// assert_eq!(r.next_frame()?, Some(&b"abc"[..]));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn spare(&mut self) -> &mut [u8] {
        self.compact();
        self.buf.get_mut(self.end..).unwrap_or(&mut [])
    }

    /// Marks `n` bytes written into [`spare`](Self::spare) as received
    /// (clamped to the spare space).
    ///
    /// ```
    /// use dnsbox::tcp::FrameReassembler;
    ///
    /// let mut storage = [0u8; 16];
    /// let mut r = FrameReassembler::new(&mut storage);
    /// let spare = r.spare();
    /// spare[..4].copy_from_slice(&[0, 2, 0xbe, 0xef]); // as a `read` would
    /// r.commit(4);
    /// assert_eq!(r.next_frame()?, Some(&[0xbe, 0xef][..]));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn commit(&mut self, n: usize) {
        let mut n = n.min(self.buf.len() - self.end);
        if self.skip > 0 {
            // Discard the head of the new data, which still belongs to a
            // skipped frame.
            let k = self.skip.min(n);
            self.buf.copy_within(self.end + k..self.end + n, self.end);
            self.skip -= k;
            n -= k;
        }
        self.end += n;
    }

    /// Copies as much of `data` as fits into the buffer, returning how
    /// many bytes were consumed. Keep the rest and pass it again after
    /// draining frames with [`next_frame`](Self::next_frame).
    ///
    /// ```
    /// use dnsbox::tcp::FrameReassembler;
    ///
    /// let mut storage = [0u8; 8];
    /// let mut r = FrameReassembler::new(&mut storage);
    /// let data = [0, 2, 1, 2, 0, 3, 3, 4, 5, 0];
    /// // Only 8 bytes fit: drain frames, then hand over the rest.
    /// let n = r.extend(&data);
    /// assert_eq!(n, 8);
    /// assert_eq!(r.next_frame()?, Some(&[1, 2][..]));
    /// assert_eq!(r.extend(&data[n..]), 2);
    /// assert_eq!(r.next_frame()?, Some(&[3, 4, 5][..]));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn extend(&mut self, data: &[u8]) -> usize {
        let k = self.skip.min(data.len());
        self.skip -= k;
        let data = data.get(k..).unwrap_or(&[]);
        let spare = self.spare();
        let n = spare.len().min(data.len());
        if let (Some(dst), Some(src)) = (spare.get_mut(..n), data.get(..n)) {
            dst.copy_from_slice(src);
        }
        self.end += n;
        k + n
    }

    /// Returns the next complete message (without its prefix), or
    /// `Ok(None)` if more data is needed.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] if the next frame is larger than the
    /// buffer and so can never be completed; see
    /// [`skip_frame`](Self::skip_frame).
    ///
    /// ```
    /// use dnsbox::Error;
    /// use dnsbox::tcp::FrameReassembler;
    ///
    /// let mut storage = [0u8; 8];
    /// let mut r = FrameReassembler::new(&mut storage);
    /// r.extend(&[0, 100, 1, 2]); // a 100-byte message announced
    /// assert_eq!(r.next_frame(), Err(Error::BufferTooSmall));
    /// assert!(r.skip_frame()); // discard it, including the 98 bytes to come
    /// r.extend(&[0u8; 98]);
    /// r.extend(&[0, 1, 42]);
    /// assert_eq!(r.next_frame()?, Some(&[42][..]));
    /// # Ok::<(), Error>(())
    /// ```
    pub fn next_frame(&mut self) -> Result<Option<&[u8]>> {
        let pending = self.buf.get(self.start..self.end).unwrap_or(&[]);
        let Some(total) = frame_len(pending) else {
            return Ok(None);
        };
        if total > self.buf.len() {
            return Err(Error::BufferTooSmall);
        }
        if pending.len() < total {
            return Ok(None);
        }
        let msg_start = self.start + PREFIX_LEN;
        let msg_end = self.start + total;
        self.start = msg_end;
        if self.start == self.end {
            // Nothing left: the next write starts at the beginning of the
            // buffer (the returned slice stays valid until then).
            self.start = 0;
            self.end = 0;
        }
        Ok(Some(self.buf.get(msg_start..msg_end).unwrap_or(&[])))
    }

    /// Discards the frame at the head of the buffer — typically one too
    /// large for the buffer — including the part not received yet.
    /// Returns `false` (and does nothing) if not even its length prefix
    /// has been received.
    ///
    /// ```
    /// use dnsbox::tcp::FrameReassembler;
    ///
    /// let mut storage = [0u8; 16];
    /// let mut r = FrameReassembler::new(&mut storage);
    /// assert!(!r.skip_frame()); // nothing to skip yet
    /// r.extend(&[0, 40]); // a 40-byte message: larger than our buffer
    /// assert!(r.next_frame().is_err());
    /// assert!(r.skip_frame());
    /// r.extend(&[0u8; 40]); // its bytes are discarded as they arrive
    /// r.extend(&[0, 1, 5]);
    /// assert_eq!(r.next_frame()?, Some(&[5][..]));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn skip_frame(&mut self) -> bool {
        let pending = self.buf.get(self.start..self.end).unwrap_or(&[]);
        let Some(total) = frame_len(pending) else {
            return false;
        };
        let have = pending.len().min(total);
        self.start += have;
        self.skip = total - have;
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        }
        true
    }
}

/// Reads one length-prefixed message from `r` into `buf` (std only),
/// returning it, or `Ok(None)` if the stream ended cleanly before the
/// first byte of a frame.
///
/// # Errors
///
/// A message larger than `buf` fails with
/// [`std::io::ErrorKind::InvalidData`] (wrapping
/// [`Error::BufferTooSmall`]); the stream is then out of sync and should
/// be closed. A stream ending inside a frame fails with
/// [`std::io::ErrorKind::UnexpectedEof`]. Other I/O errors of `r` are
/// returned as they are (`Interrupted` reads are retried).
///
/// ```
/// use dnsbox::tcp::{MAX_FRAME_LEN, read_message, write_message};
///
/// // Any `Read`/`Write` works: here an in-memory "connection".
/// let mut wire = Vec::new();
/// write_message(&mut wire, b"first")?;
/// write_message(&mut wire, b"second")?;
///
/// let mut conn = &wire[..];
/// let mut buf = vec![0u8; MAX_FRAME_LEN];
/// assert_eq!(read_message(&mut conn, &mut buf)?, Some(&b"first"[..]));
/// assert_eq!(read_message(&mut conn, &mut buf)?, Some(&b"second"[..]));
/// assert_eq!(read_message(&mut conn, &mut buf)?, None); // clean end
/// # Ok::<(), std::io::Error>(())
/// ```
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub fn read_message<'b, R: std::io::Read + ?Sized>(
    r: &mut R,
    buf: &'b mut [u8],
) -> std::io::Result<Option<&'b [u8]>> {
    use std::io::{self, ErrorKind};
    let mut prefix = [0u8; PREFIX_LEN];
    loop {
        match r.read(&mut prefix[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    r.read_exact(&mut prefix[1..])?;
    let len = u16::from_be_bytes(prefix) as usize;
    let dst = buf
        .get_mut(..len)
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, Error::BufferTooSmall))?;
    r.read_exact(dst)?;
    Ok(Some(dst))
}

/// Writes `msg` with its length prefix to `w` (std only), handing both to
/// the writer together where it supports vectored writes (RFC 7766 §8
/// recommends sending them in one segment).
///
/// # Errors
///
/// [`std::io::ErrorKind::InvalidInput`] for a message over 65535 bytes,
/// [`std::io::ErrorKind::WriteZero`] if the writer stops accepting data,
/// and the other I/O errors of `w` (`Interrupted` writes are retried).
///
/// ```no_run
/// use std::net::TcpStream;
/// use dnsbox::tcp::{MAX_FRAME_LEN, read_message, write_message};
/// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
///
/// let name: NameBuf = "example.com".parse()?;
/// let mut qbuf = [0u8; 512];
/// let query = MessageBuilder::query(&mut qbuf, 1, &name, Rtype::SOA, Class::IN)?.finish();
///
/// let mut conn = TcpStream::connect("192.0.2.53:53")?;
/// write_message(&mut conn, query)?;
/// let mut buf = vec![0u8; MAX_FRAME_LEN];
/// let response = read_message(&mut conn, &mut buf)?.ok_or("closed")?;
/// println!("{}", Message::parse(response)?);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub fn write_message<W: std::io::Write + ?Sized>(w: &mut W, msg: &[u8]) -> std::io::Result<()> {
    use std::io::{self, ErrorKind, IoSlice};
    let prefix =
        length_prefix(msg.len()).map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?;
    let total = PREFIX_LEN + msg.len();
    let mut written = 0;
    while written < total {
        let res = match (
            prefix.get(written..),
            msg.get(written.saturating_sub(PREFIX_LEN)..),
        ) {
            (Some(head), Some(body)) if !head.is_empty() => {
                w.write_vectored(&[IoSlice::new(head), IoSlice::new(body)])
            }
            (_, Some(body)) => w.write(body),
            (_, None) => break,
        };
        match res {
            Ok(0) => return Err(ErrorKind::WriteZero.into()),
            Ok(n) => written += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
