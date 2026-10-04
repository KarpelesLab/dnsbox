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
//! [`Message::parse`]: crate::Message::parse

use crate::builder::MAX_MESSAGE_LEN;
use crate::wire::OutBuf;
use crate::{Error, Result};

/// Size of the length prefix, in bytes.
pub const PREFIX_LEN: usize = 2;

/// The largest possible frame: the prefix plus a 65535-byte message. A
/// [`FrameReassembler`] buffer of this size can hold any frame.
pub const MAX_FRAME_LEN: usize = PREFIX_LEN + MAX_MESSAGE_LEN;

/// The length prefix for a message of `msg_len` bytes, or
/// [`Error::MessageTooLong`] if it exceeds 65535 bytes.
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
/// number of bytes written (`msg.len() + 2`). Fails with
/// [`Error::MessageTooLong`] or [`Error::BufferTooSmall`] without writing.
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
/// [`WireWriter`](crate::WireWriter), or a `Vec<u8>` with `alloc`). On
/// error nothing is appended.
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
#[derive(Clone, Debug)]
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct Frames<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Frames<'a> {
    /// The number of bytes consumed by the frames returned so far.
    #[inline]
    #[must_use]
    pub const fn consumed(&self) -> usize {
        self.pos
    }

    /// The bytes after the frames returned so far.
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
    #[inline]
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// The number of buffered bytes not yet returned as frames.
    #[inline]
    #[must_use]
    pub const fn buffered(&self) -> usize {
        self.end - self.start
    }

    /// Whether no bytes are buffered (the stream is at a frame boundary,
    /// unless a skipped frame is still being discarded).
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.end == self.start && self.skip == 0
    }

    /// Discards all buffered data (e.g. when the connection is reset).
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
    pub fn spare(&mut self) -> &mut [u8] {
        self.compact();
        self.buf.get_mut(self.end..).unwrap_or(&mut [])
    }

    /// Marks `n` bytes written into [`spare`](Self::spare) as received
    /// (clamped to the spare space).
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
    /// `Ok(None)` if more data is needed. Fails with
    /// [`Error::BufferTooSmall`] if the next frame is larger than the
    /// buffer and so can never be completed; see
    /// [`skip_frame`](Self::skip_frame).
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
/// A message larger than `buf` fails with
/// [`std::io::ErrorKind::InvalidData`] (wrapping
/// [`Error::BufferTooSmall`]); the stream is then out of sync and should
/// be closed. A stream ending inside a frame fails with
/// [`std::io::ErrorKind::UnexpectedEof`].
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
/// recommends sending them in one segment). Messages over 65535 bytes fail
/// with [`std::io::ErrorKind::InvalidInput`].
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
