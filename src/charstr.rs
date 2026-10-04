//! `<character-string>`s (RFC 1035 §3.3): a length octet followed by up to
//! 255 bytes of arbitrary data.
//!
//! [`CharStr`] is one string (re-exported at the crate root), [`CharStrs`]
//! a run of them filling a field (TXT and SPF RDATA, ...). Both borrow the
//! message; their `Display` is the quoted presentation format.
//!
//! ```
//! use dnsbox::WireReader;
//! use dnsbox::charstr::CharStrs;
//!
//! let rdata = b"\x05hello\x00\x07a \"b\" c";
//! let strings = CharStrs::new(rdata)?;
//! assert_eq!(strings.iter().count(), 3);
//! assert_eq!(strings.to_string(), r#""hello" "" "a \"b\" c""#);
//!
//! let mut r = WireReader::new(rdata);
//! assert_eq!(r.read_char_string()?.as_bytes(), b"hello");
//! # Ok::<(), dnsbox::Error>(())
//! ```

use core::fmt;

use crate::wire::Composer;
use crate::{Error, Result};

/// A borrowed `<character-string>` payload (without its length octet),
/// guaranteed to be at most 255 bytes long.
///
/// Its [`Display`](fmt::Display) form is the quoted presentation format of
/// RFC 1035 §5.1: `"` and `\` are backslash-escaped, bytes outside printable
/// ASCII are written as `\DDD`.
///
/// # Examples
///
/// ```
/// use dnsbox::{CharStr, Error, WireWriter};
///
/// let s = CharStr::new(b"v=spf1 -all\x7f")?;
/// assert_eq!(s.len(), 12);
/// assert_eq!(s.to_string(), r#""v=spf1 -all\127""#);
///
/// let mut buf = [0u8; 16];
/// let mut w = WireWriter::new(&mut buf);
/// s.compose(&mut w)?;
/// assert_eq!(w.as_bytes(), b"\x0cv=spf1 -all\x7f");
///
/// assert_eq!(CharStr::new(&[b'x'; 256]), Err(Error::CharStringTooLong));
/// # Ok::<(), Error>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct CharStr<'a>(&'a [u8]);

impl<'a> CharStr<'a> {
    /// Maximum payload length.
    pub const MAX_LEN: usize = 255;

    /// Wraps `bytes` (the payload, without a length octet).
    ///
    /// # Errors
    ///
    /// [`Error::CharStringTooLong`] if `bytes` is longer than 255 bytes.
    ///
    /// ```
    /// use dnsbox::{CharStr, Error};
    ///
    /// let s = CharStr::new(b"google-site-verification=abc")?;
    /// assert_eq!(s.len(), 28);
    /// assert_eq!(CharStr::new(&[0; 300]), Err(Error::CharStringTooLong));
    /// # Ok::<(), Error>(())
    /// ```
    #[inline]
    pub const fn new(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() > Self::MAX_LEN {
            Err(Error::CharStringTooLong)
        } else {
            Ok(CharStr(bytes))
        }
    }

    /// Wraps bytes already known to be at most 255 bytes long.
    #[inline]
    pub(crate) const fn from_wire_unchecked(bytes: &'a [u8]) -> Self {
        CharStr(bytes)
    }

    /// The payload bytes.
    ///
    /// ```
    /// use dnsbox::WireReader;
    ///
    /// // The first string of a TXT record's RDATA.
    /// let mut r = WireReader::new(b"\x0bv=spf1 -all");
    /// assert_eq!(r.read_char_string()?.as_bytes(), b"v=spf1 -all");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// Payload length in bytes.
    ///
    /// ```
    /// use dnsbox::CharStr;
    ///
    /// // The wire form is one length octet longer.
    /// assert_eq!(CharStr::new(b"hello")?.len(), 5);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the payload is empty.
    ///
    /// ```
    /// use dnsbox::CharStr;
    ///
    /// assert!(CharStr::new(b"")?.is_empty());
    /// assert_eq!(CharStr::new(b"")?.to_string(), "\"\"");
    /// assert!(!CharStr::new(b"x")?.is_empty());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Writes the length octet and payload.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] if `c` has no room for them (the length
    /// octet may have been written, as with
    /// [`Composer::put_char_string`]; callers composing a whole record
    /// roll back, as the message builder does).
    ///
    /// ```
    /// use dnsbox::{CharStr, Error, WireWriter};
    ///
    /// // HINFO RDATA: two character-strings.
    /// let mut buf = [0u8; 16];
    /// let mut w = WireWriter::new(&mut buf);
    /// CharStr::new(b"ARM")?.compose(&mut w)?;
    /// CharStr::new(b"Linux")?.compose(&mut w)?;
    /// assert_eq!(w.as_bytes(), b"\x03ARM\x05Linux");
    /// let mut small = [0u8; 3];
    /// let mut w = WireWriter::new(&mut small);
    /// assert_eq!(CharStr::new(b"ARM")?.compose(&mut w), Err(Error::BufferTooSmall));
    /// # Ok::<(), Error>(())
    /// ```
    #[inline]
    pub fn compose<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_char_string(self.0)
    }
}

impl fmt::Display for CharStr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::text::fmt_quoted(f, self.0)
    }
}

impl fmt::Debug for CharStr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A validated run of consecutive `<character-string>`s filling a buffer
/// exactly (the RDATA of TXT, SPF, ...).
///
/// # Examples
///
/// ```
/// use dnsbox::Error;
/// use dnsbox::charstr::CharStrs;
///
/// let strings = CharStrs::new(b"\x02ab\x01c")?;
/// let parts: Vec<&[u8]> = strings.iter().map(|s| s.as_bytes()).collect();
/// assert_eq!(parts, [&b"ab"[..], b"c"]);
/// for s in &strings {
///     assert!(!s.is_empty());
/// }
/// // A length octet promising more than is there.
/// assert_eq!(CharStrs::new(b"\x05ab").unwrap_err(), Error::UnexpectedEof);
/// # Ok::<(), Error>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CharStrs<'a>(&'a [u8]);

impl<'a> CharStrs<'a> {
    /// Validates that `wire` is a sequence of complete length-prefixed
    /// strings. An empty buffer is a valid empty sequence.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedEof`] if the last string is cut short.
    ///
    /// ```
    /// use dnsbox::charstr::CharStrs;
    /// use dnsbox::Error;
    ///
    /// // A TXT RDATA with a long DKIM key split over two strings.
    /// let strings = CharStrs::new(b"\x07v=DKIM1\x09k=rsa; p=")?;
    /// assert_eq!(strings.iter().count(), 2);
    /// assert_eq!(CharStrs::new(b""), Ok(CharStrs::default()));
    /// assert_eq!(CharStrs::new(b"\x09k=rsa"), Err(Error::UnexpectedEof));
    /// # Ok::<(), Error>(())
    /// ```
    pub fn new(wire: &'a [u8]) -> Result<Self> {
        let mut rest = wire;
        while let [len, tail @ ..] = rest {
            rest = tail.get(*len as usize..).ok_or(Error::UnexpectedEof)?;
        }
        Ok(CharStrs(wire))
    }

    /// The encoded bytes (length octets included).
    ///
    /// ```
    /// use dnsbox::charstr::CharStrs;
    ///
    /// let rdata = b"\x02ab\x00";
    /// assert_eq!(CharStrs::new(rdata)?.as_wire(), rdata); // length octets included
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub const fn as_wire(&self) -> &'a [u8] {
        self.0
    }

    /// Whether the sequence holds no strings.
    ///
    /// ```
    /// use dnsbox::charstr::CharStrs;
    ///
    /// assert!(CharStrs::new(b"")?.is_empty());
    /// // One empty string is not an empty sequence.
    /// assert!(!CharStrs::new(b"\x00")?.is_empty());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterates over the strings.
    ///
    /// ```
    /// use dnsbox::charstr::CharStrs;
    ///
    /// // An SPF record split over two strings is read as their concatenation
    /// // (RFC 7208 §3.3).
    /// let strings = CharStrs::new(b"\x0dv=spf1 ip4:19\x0f2.0.2.0/24 -all")?;
    /// let spf: Vec<u8> = strings.iter().flat_map(|s| s.as_bytes().iter().copied()).collect();
    /// assert_eq!(spf, b"v=spf1 ip4:192.0.2.0/24 -all");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub fn iter(&self) -> CharStrIter<'a> {
        CharStrIter(self.0)
    }
}

impl<'a> IntoIterator for CharStrs<'a> {
    type Item = CharStr<'a>;
    type IntoIter = CharStrIter<'a>;
    fn into_iter(self) -> CharStrIter<'a> {
        self.iter()
    }
}

impl<'a> IntoIterator for &CharStrs<'a> {
    type Item = CharStr<'a>;
    type IntoIter = CharStrIter<'a>;
    #[inline]
    fn into_iter(self) -> CharStrIter<'a> {
        self.iter()
    }
}

impl fmt::Display for CharStrs<'_> {
    /// Space-separated quoted strings.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, s) in self.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            fmt::Display::fmt(&s, f)?;
        }
        Ok(())
    }
}

impl fmt::Debug for CharStrs<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// Iterator over a [`CharStrs`], from [`CharStrs::iter`].
///
/// ```
/// use dnsbox::charstr::CharStrs;
///
/// let mut it = CharStrs::new(b"\x01a\x00")?.iter();
/// assert_eq!(it.next().map(|s| s.as_bytes()), Some(&b"a"[..]));
/// assert_eq!(it.next().map(|s| s.len()), Some(0));
/// assert!(it.next().is_none());
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Debug)]
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct CharStrIter<'a>(&'a [u8]);

impl<'a> Iterator for CharStrIter<'a> {
    type Item = CharStr<'a>;

    fn next(&mut self) -> Option<CharStr<'a>> {
        let (len, tail) = self.0.split_first()?;
        let len = *len as usize;
        let (s, rest) = if len <= tail.len() {
            tail.split_at(len)
        } else {
            // Unreachable for a validated `CharStrs`; stay panic-free anyway.
            (tail, &[][..])
        };
        self.0 = rest;
        Some(CharStr(s))
    }
}

impl core::iter::FusedIterator for CharStrIter<'_> {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::ToString;

    #[test]
    fn display_escapes() {
        let s = CharStr::new(b"a \"q\" \\ \x00\xff;").unwrap();
        assert_eq!(s.to_string(), r#""a \"q\" \\ \000\255;""#);
        assert_eq!(CharStr::new(&[0; 256]), Err(Error::CharStringTooLong));
        assert_eq!(CharStr::default().to_string(), "\"\"");
    }

    #[test]
    fn sequences() {
        let s = CharStrs::new(b"\x02hi\x00\x03abc").unwrap();
        let v: std::vec::Vec<_> = s.iter().map(|s| s.as_bytes()).collect();
        assert_eq!(v, [&b"hi"[..], b"", b"abc"]);
        assert_eq!(s.to_string(), r#""hi" "" "abc""#);
        assert_eq!(CharStrs::new(b"\x02h"), Err(Error::UnexpectedEof));
        assert!(CharStrs::new(b"").unwrap().is_empty());
    }
}
