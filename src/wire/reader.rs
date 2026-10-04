use crate::charstr::CharStr;
use crate::name::Name;
use crate::{Error, Result};

/// A bounds-checked read cursor over a DNS message.
///
/// The reader holds the full message buffer, a current position and an end
/// position. Reads never go past the end position; domain names read with
/// [`read_name`](Self::read_name) may however follow compression pointers to
/// anywhere *earlier* in the full message (RFC 1035 §4.1.4).
///
/// All `read_*` methods either succeed and advance the cursor, or fail and
/// leave it where it was. They fail with [`Error::UnexpectedEof`] when the
/// window holds too few bytes.
///
/// # Examples
///
/// ```
/// use dnsbox::{Error, WireReader};
///
/// let data = [0x00, 0x2a, 0xde, 0xad, 0xbe, 0xef, 3, b'a', b'b', b'c'];
/// let mut r = WireReader::new(&data);
/// assert_eq!(r.read_u16()?, 42);
/// assert_eq!(r.read_u32()?, 0xdead_beef);
/// assert_eq!(r.read_char_string()?.as_bytes(), b"abc");
/// assert!(r.is_empty());
///
/// // A failed read leaves the cursor alone.
/// let mut r = WireReader::new(&data[..3]);
/// assert_eq!(r.read_u32(), Err(Error::UnexpectedEof));
/// assert_eq!(r.position(), 0);
/// assert_eq!(r.read_u16()?, 42);
/// assert_eq!(r.finish(), Err(Error::TrailingData)); // one byte unread
/// # Ok::<(), Error>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct WireReader<'a> {
    msg: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> WireReader<'a> {
    /// Creates a reader over all of `buf`, positioned at its start.
    #[inline]
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        WireReader {
            msg: buf,
            pos: 0,
            end: buf.len(),
        }
    }

    /// Creates a reader over `msg[start..end]` that can still follow
    /// compression pointers into the rest of `msg`.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedEof`] if the range is not within `msg`.
    ///
    /// ```
    /// use dnsbox::WireReader;
    ///
    /// // "a." at offset 0, then "b" + a pointer to it in a 4-byte window.
    /// let msg = b"\x01a\x00\x01b\xc0\x00";
    /// let mut r = WireReader::with_range(msg, 3, 7)?;
    /// assert_eq!(r.read_name()?.to_string(), "b.a.");
    /// assert!(r.is_empty());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub const fn with_range(msg: &'a [u8], start: usize, end: usize) -> Result<Self> {
        if start > end || end > msg.len() {
            return Err(Error::UnexpectedEof);
        }
        Ok(WireReader {
            msg,
            pos: start,
            end,
        })
    }

    /// The full message this reader was created over.
    #[inline]
    #[must_use]
    pub const fn message(&self) -> &'a [u8] {
        self.msg
    }

    /// The current position, as an offset from the start of the message.
    #[inline]
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// The end of the readable window, as an offset into the message.
    #[inline]
    #[must_use]
    pub const fn end(&self) -> usize {
        self.end
    }

    /// Number of bytes left before the end of the window.
    #[inline]
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.end - self.pos
    }

    /// Whether the window is exhausted.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pos >= self.end
    }

    /// Checks that the window is exhausted.
    ///
    /// Record-data parsers are expected to consume their whole RDATA; the
    /// RDATA dispatcher calls this after every typed parse.
    ///
    /// # Errors
    ///
    /// [`Error::TrailingData`] if unread bytes remain.
    #[inline]
    pub const fn finish(&self) -> Result<()> {
        if self.pos == self.end {
            Ok(())
        } else {
            Err(Error::TrailingData)
        }
    }

    /// The unread bytes of the window, without consuming them.
    #[inline]
    #[must_use]
    pub fn peek_rest(&self) -> &'a [u8] {
        self.msg.get(self.pos..self.end).unwrap_or(&[])
    }

    /// Returns the next byte without consuming it.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedEof`] if the window is exhausted.
    #[inline]
    pub fn peek_u8(&self) -> Result<u8> {
        if self.pos < self.end {
            self.msg.get(self.pos).copied().ok_or(Error::UnexpectedEof)
        } else {
            Err(Error::UnexpectedEof)
        }
    }

    /// Consumes and returns the next `n` bytes (a slice of the message, no
    /// copy).
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedEof`] if fewer than `n` bytes remain.
    #[inline]
    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.remaining() {
            return Err(Error::UnexpectedEof);
        }
        let out = self
            .msg
            .get(self.pos..self.pos + n)
            .ok_or(Error::UnexpectedEof)?;
        self.pos += n;
        Ok(out)
    }

    /// Consumes and returns everything up to the end of the window.
    #[inline]
    pub fn read_rest(&mut self) -> &'a [u8] {
        let out = self.peek_rest();
        self.pos = self.end;
        out
    }

    /// Skips `n` bytes.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedEof`] if fewer than `n` bytes remain.
    #[inline]
    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.read_bytes(n).map(|_| ())
    }

    /// Consumes `N` bytes into an array.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedEof`] if fewer than `N` bytes remain.
    #[inline]
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let bytes = self.read_bytes(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    /// Reads one byte.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedEof`] if the window is exhausted.
    #[inline]
    pub fn read_u8(&mut self) -> Result<u8> {
        let b = self.peek_u8()?;
        self.pos += 1;
        Ok(b)
    }

    /// Reads a big-endian (network order) `u16`.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedEof`] if fewer than 2 bytes remain.
    #[inline]
    pub fn read_u16(&mut self) -> Result<u16> {
        self.read_array().map(u16::from_be_bytes)
    }

    /// Reads a big-endian `u32`.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedEof`] if fewer than 4 bytes remain.
    #[inline]
    pub fn read_u32(&mut self) -> Result<u32> {
        self.read_array().map(u32::from_be_bytes)
    }

    /// Reads a big-endian 48-bit unsigned integer (e.g. TSIG Time Signed,
    /// RFC 8945 §4.2).
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedEof`] if fewer than 6 bytes remain.
    #[inline]
    pub fn read_u48(&mut self) -> Result<u64> {
        let [a, b, c, d, e, f] = self.read_array()?;
        Ok(u64::from_be_bytes([0, 0, a, b, c, d, e, f]))
    }

    /// Reads a big-endian `u64`.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedEof`] if fewer than 8 bytes remain.
    #[inline]
    pub fn read_u64(&mut self) -> Result<u64> {
        self.read_array().map(u64::from_be_bytes)
    }

    /// Reads a `<character-string>`: one length octet followed by that many
    /// bytes (RFC 1035 §3.3).
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedEof`] if the window ends before the string does.
    #[inline]
    pub fn read_char_string(&mut self) -> Result<CharStr<'a>> {
        let save = self.pos;
        let len = self.read_u8()? as usize;
        match self.read_bytes(len) {
            Ok(bytes) => Ok(CharStr::from_wire_unchecked(bytes)),
            Err(e) => {
                self.pos = save;
                Err(e)
            }
        }
    }

    /// Splits off the next `n` bytes as a separate reader (sharing the same
    /// message, so names in it can still be decompressed) and advances past
    /// them. Use it for length-prefixed sub-structures.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedEof`] if fewer than `n` bytes remain.
    #[inline]
    pub fn sub_reader(&mut self, n: usize) -> Result<WireReader<'a>> {
        if n > self.remaining() {
            return Err(Error::UnexpectedEof);
        }
        let sub = WireReader {
            msg: self.msg,
            pos: self.pos,
            end: self.pos + n,
        };
        self.pos += n;
        Ok(sub)
    }

    /// Reads a domain name, following compression pointers (RFC 1035
    /// §4.1.4) with all the hardening described in [`crate::name`].
    ///
    /// Only use this for names that may legitimately be compressed: owner
    /// and question names, and names in the RDATA of the RFC 1035 types or
    /// of the types listed in RFC 3597 §4 (RP, AFSDB, RT, SIG, PX, NXT,
    /// NAPTR, SRV). Everything else should use
    /// [`read_name_uncompressed`](Self::read_name_uncompressed).
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedEof`] if the name runs past the window,
    /// [`Error::LabelTooLong`] / [`Error::NameTooLong`] for oversized
    /// labels or names, [`Error::BadLabelType`] for reserved label types,
    /// [`Error::BadPointer`] for a pointer that does not point strictly
    /// backwards, [`Error::TooManyPointers`] beyond
    /// [`MAX_POINTERS`](crate::name::MAX_POINTERS).
    #[inline]
    pub fn read_name(&mut self) -> Result<Name<'a>> {
        let (name, next) = Name::parse_bounded(self.msg, self.pos, self.end, true)?;
        self.pos = next;
        Ok(name)
    }

    /// Reads a domain name that must not be compressed (RFC 3597 §4).
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedPointer`] for a compression pointer, otherwise
    /// as [`read_name`](Self::read_name).
    #[inline]
    pub fn read_name_uncompressed(&mut self) -> Result<Name<'a>> {
        let (name, next) = Name::parse_bounded(self.msg, self.pos, self.end, false)?;
        self.pos = next;
        Ok(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers() {
        let data = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
        ];
        let mut r = WireReader::new(&data);
        assert_eq!(r.read_u8(), Ok(1));
        assert_eq!(r.read_u16(), Ok(0x0203));
        assert_eq!(r.read_u32(), Ok(0x0405_0607));
        assert_eq!(r.read_u48(), Ok(0x0809_0a0b_0c0d));
        assert_eq!(r.remaining(), 6);
        assert_eq!(r.read_u64(), Err(Error::UnexpectedEof));
        assert_eq!(r.position(), 13, "failed read must not advance");
        assert_eq!(r.read_bytes(6), Ok(&data[13..]));
        assert!(r.is_empty());
        assert_eq!(r.finish(), Ok(()));
        assert_eq!(r.read_u8(), Err(Error::UnexpectedEof));
        assert_eq!(r.peek_u8(), Err(Error::UnexpectedEof));
    }

    #[test]
    fn windows() {
        let data = [0u8, 1, 2, 3, 4, 5];
        assert!(WireReader::with_range(&data, 4, 3).is_err());
        assert!(WireReader::with_range(&data, 0, 7).is_err());
        let mut r = WireReader::with_range(&data, 1, 4).unwrap();
        assert_eq!(r.peek_rest(), &[1, 2, 3]);
        let mut sub = r.sub_reader(2).unwrap();
        assert_eq!(sub.read_u16(), Ok(0x0102));
        assert_eq!(sub.read_u8(), Err(Error::UnexpectedEof));
        assert_eq!(r.finish(), Err(Error::TrailingData));
        assert!(r.sub_reader(2).is_err());
        assert_eq!(r.read_rest(), &[3]);
        assert_eq!(r.read_rest(), &[] as &[u8]);
        assert_eq!(r.skip(1), Err(Error::UnexpectedEof));
    }

    #[test]
    fn char_strings() {
        let data = [3, b'a', b'b', b'c', 5, b'x'];
        let mut r = WireReader::new(&data);
        assert_eq!(r.read_char_string().unwrap().as_bytes(), b"abc");
        assert_eq!(r.read_char_string(), Err(Error::UnexpectedEof));
        assert_eq!(r.position(), 4);
    }
}
