//! Domain names (RFC 1035 §2.3.4, §3.1, §4.1.4).
//!
//! Two types cover every use:
//!
//! - [`Name<'a>`]: a borrowed, `Copy` view of a validated name. It points
//!   into a received message (following compression pointers lazily when
//!   iterated) or into any uncompressed wire-format buffer, such as a
//!   [`NameBuf`].
//! - [`NameBuf`]: an owned name in uncompressed wire form, stored inline in a
//!   fixed 255-byte array — no allocation needed. Parse one from
//!   presentation text with [`str::parse`].
//!
//! # Hardening
//!
//! Parsing a name from the wire ([`WireReader::read_name`]) enforces:
//!
//! - every label is at most 63 octets ([`MAX_LABEL_LEN`]) and the whole
//!   uncompressed name at most 255 octets ([`MAX_NAME_LEN`]), RFC 1035
//!   §2.3.4;
//! - label types `0b01` and `0b10` (extended / reserved, RFC 6891 §5) are
//!   rejected with [`Error::BadLabelType`];
//! - a compression pointer must point strictly before the start of the
//!   current run of labels — this rejects forward pointers, self pointers
//!   and every loop, so decompression always terminates;
//! - at most [`MAX_POINTERS`] pointers are followed per name, so the work
//!   per name is bounded independently of the message size.
//!
//! # Comparison
//!
//! Equality and hashing are ASCII-case-insensitive (RFC 4343 §3), and the
//! [`Ord`] implementation is the DNSSEC canonical ordering (RFC 4034 §6.1).
//! Names are always absolute: `example.com` and `example.com.` denote the
//! same name.
//!
//! [`WireReader::read_name`]: crate::WireReader::read_name

mod buf;
mod decode;

use core::cmp::Ordering;
use core::fmt;
use core::hash::{Hash, Hasher};

pub use buf::NameBuf;
pub(crate) use decode::NameCache;

use crate::{Error, Result};

/// Maximum length of a name in uncompressed wire form, root label included
/// (RFC 1035 §2.3.4).
pub const MAX_NAME_LEN: usize = 255;

/// Maximum length of a single label (RFC 1035 §2.3.4).
pub const MAX_LABEL_LEN: usize = 63;

/// Maximum number of non-root labels a name can have (127 one-octet labels
/// fill 254 octets, plus the root).
pub const MAX_LABELS: usize = 127;

/// Maximum number of compression pointers followed while decoding one name.
///
/// A legitimate encoder never needs more than one pointer per label, so
/// this never rejects a valid name.
pub const MAX_POINTERS: usize = 128;

/// A single label of a domain name: 1 to 63 arbitrary octets (the root
/// label is never yielded by [`Name::labels`]).
///
/// Displays in presentation format with escapes (RFC 1035 §5.1).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Label<'a>(&'a [u8]);

impl<'a> Label<'a> {
    /// The raw label octets.
    #[inline]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// Length of the label in octets.
    #[inline]
    #[allow(clippy::len_without_is_empty)] // labels yielded by iterators are never empty
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether this is the wildcard label `*` (RFC 4592 §2.1.1).
    #[inline]
    pub const fn is_wildcard(&self) -> bool {
        matches!(self.0, [b'*'])
    }

    /// ASCII-case-insensitive comparison (RFC 4343 §3).
    #[inline]
    pub fn eq_ignore_case(&self, other: &Label<'_>) -> bool {
        self.0.eq_ignore_ascii_case(other.0)
    }
}

impl fmt::Display for Label<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::text::fmt_label(f, self.0)
    }
}

impl fmt::Debug for Label<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A borrowed, validated domain name.
///
/// Obtained from [`WireReader::read_name`](crate::WireReader::read_name)
/// (possibly compressed, pointing into a message), from
/// [`Name::from_wire`] (uncompressed bytes) or from [`NameBuf::as_name`].
/// All structural validation happens at construction, so the accessors are
/// infallible.
#[derive(Clone, Copy)]
pub struct Name<'a> {
    /// The buffer the name lives in (a whole message, or just the name).
    msg: &'a [u8],
    /// Offset of the first label (never a pointer).
    start: usize,
    /// Uncompressed wire length, root label included (1..=255).
    len: u8,
    /// Number of non-root labels.
    labels: u8,
    /// Whether `msg[start..start + len]` is the full uncompressed name.
    contiguous: bool,
}

impl<'a> Name<'a> {
    /// The root name, `.`.
    pub const ROOT: Name<'static> = Name {
        msg: &[0],
        start: 0,
        len: 1,
        labels: 0,
        contiguous: true,
    };

    /// Parses a name at `start` in `msg`.
    ///
    /// The in-place part of the encoding must end before `end`; pointers
    /// may target anything earlier in `msg`. Returns the name and the
    /// offset just past its in-place encoding.
    #[inline]
    pub(crate) fn parse_bounded(
        msg: &'a [u8],
        start: usize,
        end: usize,
        allow_pointers: bool,
    ) -> Result<(Self, usize)> {
        decode::parse(msg, start, end, allow_pointers, &mut decode::NoCache)
    }

    /// Like [`parse_bounded`](Self::parse_bounded) over the whole message,
    /// remembering decoded suffixes in `cache` (which must only ever be
    /// used with this `msg`). Same results and errors, less work on
    /// compressed messages.
    #[inline]
    pub(crate) fn parse_cached(
        msg: &'a [u8],
        start: usize,
        cache: &mut NameCache,
    ) -> Result<(Self, usize)> {
        decode::parse(msg, start, msg.len(), true, cache)
    }

    /// Wraps an uncompressed wire-format name that fills `wire` exactly.
    ///
    /// Fails if `wire` contains a compression pointer
    /// ([`Error::UnexpectedPointer`]), is malformed, or has bytes after the
    /// root label ([`Error::TrailingData`]).
    pub fn from_wire(wire: &'a [u8]) -> Result<Self> {
        let (name, end) = Self::parse_bounded(wire, 0, wire.len(), false)?;
        if end != wire.len() {
            return Err(Error::TrailingData);
        }
        Ok(name)
    }

    /// The buffer the name was decoded from (for names read from a
    /// message: the whole message).
    #[inline]
    pub(crate) const fn buffer(&self) -> &'a [u8] {
        self.msg
    }

    /// Length of the name in uncompressed wire form, root label included
    /// (1 to 255).
    #[inline]
    pub const fn wire_len(&self) -> usize {
        self.len as usize
    }

    /// Number of labels, not counting the root (0 for the root name).
    #[inline]
    pub const fn label_count(&self) -> usize {
        self.labels as usize
    }

    /// Whether this is the root name.
    #[inline]
    pub const fn is_root(&self) -> bool {
        self.labels == 0
    }

    /// Whether the first label is the wildcard label `*` (RFC 4592).
    #[inline]
    pub fn is_wildcard(&self) -> bool {
        self.first_label().is_some_and(|l| l.is_wildcard())
    }

    /// The uncompressed wire form, if it is stored contiguously (always the
    /// case for names from [`Name::from_wire`] and [`NameBuf`], and for
    /// message names that do not use pointers after their first label).
    #[inline]
    pub fn as_contiguous(&self) -> Option<&'a [u8]> {
        if self.contiguous {
            self.msg.get(self.start..self.start + self.len as usize)
        } else {
            None
        }
    }

    /// Iterates over the labels, left to right, not including the root.
    #[inline]
    pub fn labels(&self) -> Labels<'a> {
        Labels {
            msg: self.msg,
            pos: self.start,
            remaining: self.labels,
        }
    }

    /// The leftmost label, or `None` for the root.
    #[inline]
    pub fn first_label(&self) -> Option<Label<'a>> {
        self.labels().next()
    }

    /// The name with its leftmost label removed, or `None` for the root.
    pub fn parent(&self) -> Option<Name<'a>> {
        let first = self.first_label()?;
        let next = self.start + 1 + first.len();
        Some(Self::resolve(
            self.msg,
            next,
            self.len - 1 - first.len() as u8,
            self.labels - 1,
            self.contiguous,
        ))
    }

    /// Builds a name view at `pos` of an already validated name, following
    /// any leading pointers and recomputing contiguity.
    fn resolve(msg: &'a [u8], mut pos: usize, len: u8, labels: u8, contiguous: bool) -> Self {
        for _ in 0..=MAX_POINTERS {
            match msg.get(pos..pos + 2) {
                Some(&[hi, lo]) if hi >= 0xc0 => {
                    pos = (usize::from(hi & 0x3f) << 8) | usize::from(lo);
                }
                _ => break,
            }
        }
        let mut name = Name {
            msg,
            start: pos,
            len,
            labels,
            contiguous,
        };
        if !contiguous {
            // Contiguous iff walking the labels never meets a pointer.
            let mut p = pos;
            name.contiguous = true;
            while let Some(&b) = msg.get(p) {
                match b {
                    0 => break,
                    1..=0x3f => p += 1 + b as usize,
                    _ => {
                        name.contiguous = false;
                        break;
                    }
                }
            }
        }
        name
    }

    /// The name with its `n` leftmost labels removed, or `None` if it has
    /// fewer than `n` labels.
    pub fn strip_labels(&self, n: usize) -> Option<Name<'a>> {
        let mut name = *self;
        for _ in 0..n {
            name = name.parent()?;
        }
        Some(name)
    }

    /// Whether `self` is `other` or a descendant of it (RFC 1034 §3.1),
    /// comparing case-insensitively. Every name is a subdomain of the root.
    pub fn is_subdomain_of(&self, other: &Name<'_>) -> bool {
        match self.label_count().checked_sub(other.label_count()) {
            Some(extra) => self.strip_labels(extra).is_some_and(|n| n == *other),
            None => false,
        }
    }

    /// Copies the uncompressed wire form into `out`, returning its length.
    pub fn flatten(&self, out: &mut [u8; MAX_NAME_LEN]) -> usize {
        if let Some(bytes) = self.as_contiguous()
            && let Some(dst) = out.get_mut(..bytes.len())
        {
            dst.copy_from_slice(bytes);
            return bytes.len();
        }
        let mut len = 0;
        for label in self.labels() {
            let l = label.as_bytes();
            let Some(dst) = out.get_mut(len..len + 1 + l.len()) else {
                break;
            };
            dst[0] = l.len() as u8;
            dst[1..].copy_from_slice(l);
            len += 1 + l.len();
        }
        if let Some(b) = out.get_mut(len) {
            *b = 0;
            len += 1;
        }
        len
    }

    /// Copies the name into an owned [`NameBuf`].
    #[inline]
    pub fn to_buf(&self) -> NameBuf {
        NameBuf::from_name(*self)
    }

    /// Exact (case-sensitive) comparison of the label octets.
    pub fn eq_exact(&self, other: &Name<'_>) -> bool {
        if self.len != other.len || self.labels != other.labels {
            return false;
        }
        if let (Some(a), Some(b)) = (self.as_contiguous(), other.as_contiguous()) {
            return a == b;
        }
        self.labels()
            .zip(other.labels())
            .all(|(a, b)| a.as_bytes() == b.as_bytes())
    }

    /// Compares two names in DNSSEC canonical order (RFC 4034 §6.1): label
    /// by label from the rightmost, each label as a lowercased octet string
    /// where a shorter prefix sorts first. Equivalent to [`Ord::cmp`].
    pub fn cmp_canonical(&self, other: &Name<'_>) -> Ordering {
        let mut a = [0u8; MAX_NAME_LEN];
        let mut b = [0u8; MAX_NAME_LEN];
        let a_len = self.flatten(&mut a);
        let b_len = other.flatten(&mut b);
        let mut a_off = [0u8; MAX_LABELS];
        let mut b_off = [0u8; MAX_LABELS];
        let a_n = label_offsets(&a[..a_len], &mut a_off);
        let b_n = label_offsets(&b[..b_len], &mut b_off);
        for i in 1..=a_n.min(b_n) {
            let la = label_at(&a, a_off[a_n - i]);
            let lb = label_at(&b, b_off[b_n - i]);
            for (x, y) in la.iter().zip(lb) {
                match x.to_ascii_lowercase().cmp(&y.to_ascii_lowercase()) {
                    Ordering::Equal => {}
                    o => return o,
                }
            }
            match la.len().cmp(&lb.len()) {
                Ordering::Equal => {}
                o => return o,
            }
        }
        a_n.cmp(&b_n)
    }
}

/// Records the offset of each label of a flattened name; returns the count.
fn label_offsets(wire: &[u8], out: &mut [u8; MAX_LABELS]) -> usize {
    let mut n = 0;
    let mut pos = 0usize;
    while let Some(&l) = wire.get(pos) {
        if l == 0 || n >= MAX_LABELS {
            break;
        }
        out[n] = pos as u8;
        n += 1;
        pos += 1 + l as usize;
    }
    n
}

/// The label stored at `off` in a flattened name.
fn label_at(wire: &[u8], off: u8) -> &[u8] {
    let off = off as usize;
    let len = wire.get(off).copied().unwrap_or(0) as usize;
    wire.get(off + 1..off + 1 + len).unwrap_or(&[])
}

impl<'b> PartialEq<Name<'b>> for Name<'_> {
    /// ASCII-case-insensitive equality (RFC 4343 §3).
    fn eq(&self, other: &Name<'b>) -> bool {
        if self.len != other.len || self.labels != other.labels {
            return false;
        }
        if let (Some(a), Some(b)) = (self.as_contiguous(), other.as_contiguous()) {
            // Length octets are < 0x40 and unaffected by ASCII case folding.
            return a.eq_ignore_ascii_case(b);
        }
        self.labels()
            .zip(other.labels())
            .all(|(a, b)| a.eq_ignore_case(&b))
    }
}

impl Eq for Name<'_> {}

impl Hash for Name<'_> {
    /// Hashes the lowercased uncompressed wire form, consistently with the
    /// case-insensitive [`PartialEq`].
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut buf = [0u8; MAX_NAME_LEN];
        let len = self.flatten(&mut buf);
        let bytes = &mut buf[..len];
        bytes.make_ascii_lowercase();
        state.write(bytes);
    }
}

impl PartialOrd for Name<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Name<'_> {
    /// DNSSEC canonical ordering (RFC 4034 §6.1).
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmp_canonical(other)
    }
}

impl fmt::Display for Name<'_> {
    /// Presentation format, absolute (trailing dot), with `\.` and `\DDD`
    /// escapes (RFC 1035 §5.1). The root is `.`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return f.write_str(".");
        }
        for label in self.labels() {
            crate::text::fmt_label(f, label.as_bytes())?;
            f.write_str(".")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Name<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name({self})")
    }
}

impl Default for Name<'_> {
    fn default() -> Self {
        Name::ROOT
    }
}

/// Iterator over the labels of a [`Name`], left to right, root excluded.
#[derive(Clone, Debug)]
pub struct Labels<'a> {
    msg: &'a [u8],
    pos: usize,
    remaining: u8,
}

impl<'a> Iterator for Labels<'a> {
    type Item = Label<'a>;

    #[inline]
    fn next(&mut self) -> Option<Label<'a>> {
        if self.remaining == 0 {
            return None;
        }
        // The name was validated at construction; the bounded loop and
        // checked accesses only keep this panic-free regardless.
        let mut hops = 0;
        loop {
            let b = *self.msg.get(self.pos)?;
            if b < 0xc0 {
                let start = self.pos + 1;
                let end = start + usize::from(b);
                let label = self.msg.get(start..end)?;
                self.pos = end;
                self.remaining -= 1;
                return Some(Label(label));
            }
            hops += 1;
            if hops > MAX_POINTERS {
                return None;
            }
            let lo = *self.msg.get(self.pos + 1)?;
            self.pos = (usize::from(b & 0x3f) << 8) | usize::from(lo);
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining as usize, Some(self.remaining as usize))
    }
}

impl ExactSizeIterator for Labels<'_> {}
impl core::iter::FusedIterator for Labels<'_> {}

/// Anything that can be viewed as a [`Name`]: `Name` itself, [`NameBuf`],
/// and references to either. Builder methods accept `impl ToName`.
pub trait ToName {
    /// Borrows `self` as a name view.
    fn to_name(&self) -> Name<'_>;
}

impl ToName for Name<'_> {
    #[inline]
    fn to_name(&self) -> Name<'_> {
        *self
    }
}

impl ToName for NameBuf {
    #[inline]
    fn to_name(&self) -> Name<'_> {
        self.as_name()
    }
}

impl<T: ToName + ?Sized> ToName for &T {
    #[inline]
    fn to_name(&self) -> Name<'_> {
        (**self).to_name()
    }
}

#[cfg(test)]
mod tests;
