use core::cmp::Ordering;
use core::fmt;
use core::hash::{Hash, Hasher};
use core::str::FromStr;

use super::{MAX_LABEL_LEN, MAX_NAME_LEN, Name};
use crate::{Error, Result};

/// An owned domain name in uncompressed wire form, stored inline (no
/// allocation): a 255-byte array plus two length bytes.
///
/// Parse one from presentation format with [`str::parse`] (RFC 1035 §5.1
/// escapes `\X` and `\DDD` are understood; a trailing dot is optional since
/// all names are absolute), or copy one out of a message with
/// [`Name::to_buf`]. Borrow it as a [`Name`] with [`as_name`](Self::as_name).
///
/// ```
/// use dnsbox::NameBuf;
///
/// let name: NameBuf = "www.Example.com".parse()?;
/// assert_eq!(name.as_wire(), b"\x03www\x07Example\x03com\x00");
/// assert_eq!(name.to_string(), "www.Example.com.");
/// assert_eq!(name, "WWW.example.COM.".parse::<NameBuf>()?);
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone)]
pub struct NameBuf {
    buf: [u8; MAX_NAME_LEN],
    len: u8,
    labels: u8,
}

impl NameBuf {
    /// The root name.
    #[must_use]
    pub const fn root() -> Self {
        NameBuf {
            buf: [0; MAX_NAME_LEN],
            len: 1,
            labels: 0,
        }
    }

    /// Copies a name view (decompressing it if needed).
    #[must_use]
    pub fn from_name(name: Name<'_>) -> Self {
        let mut out = NameBuf::root();
        out.len = name.flatten(&mut out.buf) as u8;
        out.labels = name.label_count() as u8;
        out
    }

    /// Copies an uncompressed wire-format name that fills `wire` exactly.
    ///
    /// # Errors
    ///
    /// As [`Name::from_wire`]: a compression pointer, trailing bytes or a
    /// malformed name.
    pub fn from_wire(wire: &[u8]) -> Result<Self> {
        Name::from_wire(wire).map(Self::from_name)
    }

    /// Builds a name from its labels, left to right (root excluded).
    ///
    /// # Errors
    ///
    /// [`Error::EmptyLabel`] for an empty label, [`Error::LabelTooLong`]
    /// for one over 63 octets, [`Error::NameTooLong`] if the name exceeds
    /// 255 octets.
    ///
    /// ```
    /// use dnsbox::NameBuf;
    /// let n = NameBuf::from_labels([&b"_443"[..], b"_tcp", b"example"])?;
    /// assert_eq!(n.to_string(), "_443._tcp.example.");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn from_labels<'l, I: IntoIterator<Item = &'l [u8]>>(labels: I) -> Result<Self> {
        let mut out = NameBuf::root();
        let mut len = 0usize;
        for label in labels {
            if label.is_empty() {
                return Err(Error::EmptyLabel);
            }
            if label.len() > MAX_LABEL_LEN {
                return Err(Error::LabelTooLong);
            }
            let end = len + 1 + label.len();
            if end >= MAX_NAME_LEN {
                return Err(Error::NameTooLong);
            }
            out.buf[len] = label.len() as u8;
            out.buf[len + 1..end].copy_from_slice(label);
            len = end;
            out.labels += 1;
        }
        out.buf[len] = 0;
        out.len = len as u8 + 1;
        Ok(out)
    }

    /// Borrows the name as a [`Name`] view.
    #[inline]
    #[must_use]
    pub fn as_name(&self) -> Name<'_> {
        Name {
            msg: self.as_wire(),
            start: 0,
            len: self.len,
            labels: self.labels,
            contiguous: true,
        }
    }

    /// The uncompressed wire form, root label included.
    #[inline]
    #[must_use]
    pub fn as_wire(&self) -> &[u8] {
        self.buf.get(..self.len as usize).unwrap_or(&[0])
    }

    /// Length in uncompressed wire form (1 to 255).
    #[inline]
    #[must_use]
    pub const fn wire_len(&self) -> usize {
        self.len as usize
    }

    /// Number of labels, not counting the root.
    #[inline]
    #[must_use]
    pub const fn label_count(&self) -> usize {
        self.labels as usize
    }

    /// Whether this is the root name.
    #[inline]
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.labels == 0
    }

    /// Converts ASCII letters to lowercase in place, as required for the
    /// DNSSEC canonical form (RFC 4034 §6.2).
    #[inline]
    pub fn make_ascii_lowercase(&mut self) {
        let len = self.len as usize;
        if let Some(b) = self.buf.get_mut(..len) {
            // Length octets are < 0x40 and unaffected.
            b.make_ascii_lowercase();
        }
    }

    /// Adds `label` in front of the name (e.g. `*` to form a wildcard).
    ///
    /// # Errors
    ///
    /// [`Error::EmptyLabel`], [`Error::LabelTooLong`] or
    /// [`Error::NameTooLong`] as for [`from_labels`](Self::from_labels);
    /// the name is unchanged then.
    ///
    /// ```
    /// use dnsbox::NameBuf;
    ///
    /// let mut name: NameBuf = "example.com".parse()?;
    /// name.prepend_label(b"*")?;
    /// assert!(name.as_name().is_wildcard());
    /// assert_eq!(name.to_string(), "*.example.com.");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn prepend_label(&mut self, label: &[u8]) -> Result<()> {
        if label.is_empty() {
            return Err(Error::EmptyLabel);
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(Error::LabelTooLong);
        }
        let old = self.len as usize;
        let new = old + 1 + label.len();
        if new > MAX_NAME_LEN {
            return Err(Error::NameTooLong);
        }
        self.buf.copy_within(..old, 1 + label.len());
        self.buf[0] = label.len() as u8;
        self.buf[1..1 + label.len()].copy_from_slice(label);
        self.len = new as u8;
        self.labels += 1;
        Ok(())
    }

    /// Parses presentation format (RFC 1035 §5.1). See [`FromStr`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidText`] for empty text or a bad `\DDD` escape,
    /// [`Error::EmptyLabel`] for `a..b` or a leading dot,
    /// [`Error::LabelTooLong`] and [`Error::NameTooLong`] for oversized
    /// labels and names.
    ///
    /// ```
    /// use dnsbox::{Error, NameBuf};
    ///
    /// let name = NameBuf::from_text(br"my\032host.example.")?;
    /// assert_eq!(name.as_name().first_label().unwrap().as_bytes(), b"my host");
    /// assert_eq!(NameBuf::from_text(b"a..b"), Err(Error::EmptyLabel));
    /// # Ok::<(), Error>(())
    /// ```
    pub fn from_text(text: &[u8]) -> Result<Self> {
        if text == b"." {
            return Ok(NameBuf::root());
        }
        if text.is_empty() {
            return Err(Error::InvalidText);
        }
        let mut out = NameBuf::root();
        // `label_at` is the slot for the current label's length octet.
        let mut label_at = 0usize;
        let mut len = 1usize;
        let mut i = 0usize;
        while let Some(&c) = text.get(i) {
            i += 1;
            let byte = match c {
                b'.' => {
                    let l = len - label_at - 1;
                    if l == 0 {
                        return Err(Error::EmptyLabel);
                    }
                    out.buf[label_at] = l as u8;
                    out.labels += 1;
                    label_at = len;
                    if len >= MAX_NAME_LEN {
                        return Err(Error::NameTooLong);
                    }
                    len += 1;
                    continue;
                }
                b'\\' => {
                    let (b, used) = parse_escape(text.get(i..).unwrap_or(&[]))?;
                    i += used;
                    b
                }
                c => c,
            };
            if len - label_at > MAX_LABEL_LEN {
                return Err(Error::LabelTooLong);
            }
            if len >= MAX_NAME_LEN {
                return Err(Error::NameTooLong);
            }
            out.buf[len] = byte;
            len += 1;
        }
        if len - label_at > 1 {
            // Unterminated final label: close it and append the root.
            out.buf[label_at] = (len - label_at - 1) as u8;
            out.labels += 1;
            if len >= MAX_NAME_LEN {
                return Err(Error::NameTooLong);
            }
            out.buf[len] = 0;
            len += 1;
        } else {
            // Trailing dot: the reserved slot becomes the root label.
            out.buf[label_at] = 0;
        }
        out.len = len as u8;
        Ok(out)
    }
}

/// Decodes the escape following a backslash: `\DDD` (three decimal digits,
/// value ≤ 255) or `\X` (the byte `X` itself). Returns the byte and the
/// number of input bytes consumed.
pub(crate) fn parse_escape(rest: &[u8]) -> Result<(u8, usize)> {
    match rest {
        [a, b, c, ..] if a.is_ascii_digit() => {
            if !b.is_ascii_digit() || !c.is_ascii_digit() {
                return Err(Error::InvalidText);
            }
            let v = u16::from(a - b'0') * 100 + u16::from(b - b'0') * 10 + u16::from(c - b'0');
            u8::try_from(v)
                .map(|v| (v, 3))
                .map_err(|_| Error::InvalidText)
        }
        [a, ..] if a.is_ascii_digit() => Err(Error::InvalidText),
        [x, ..] => Ok((*x, 1)),
        [] => Err(Error::InvalidText),
    }
}

impl FromStr for NameBuf {
    type Err = Error;

    /// Parses a name in presentation format: dot-separated labels with
    /// `\X` and `\DDD` escapes; a trailing dot is optional (names are always
    /// absolute); `.` alone is the root. The empty string is rejected.
    fn from_str(s: &str) -> Result<Self> {
        NameBuf::from_text(s.as_bytes())
    }
}

impl Default for NameBuf {
    fn default() -> Self {
        NameBuf::root()
    }
}

impl<'a> From<Name<'a>> for NameBuf {
    fn from(name: Name<'a>) -> Self {
        NameBuf::from_name(name)
    }
}

impl fmt::Display for NameBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.as_name(), f)
    }
}

impl fmt::Debug for NameBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NameBuf({})", self.as_name())
    }
}

impl PartialEq for NameBuf {
    fn eq(&self, other: &Self) -> bool {
        self.as_name() == other.as_name()
    }
}

impl Eq for NameBuf {}

impl PartialEq<Name<'_>> for NameBuf {
    fn eq(&self, other: &Name<'_>) -> bool {
        self.as_name() == *other
    }
}

impl PartialEq<NameBuf> for Name<'_> {
    fn eq(&self, other: &NameBuf) -> bool {
        *self == other.as_name()
    }
}

impl Hash for NameBuf {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_name().hash(state);
    }
}

impl PartialOrd for NameBuf {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NameBuf {
    /// DNSSEC canonical ordering (RFC 4034 §6.1).
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_name().cmp_canonical(&other.as_name())
    }
}
