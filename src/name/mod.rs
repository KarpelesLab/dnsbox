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
//! # Examples
//!
//! ```
//! use dnsbox::{Name, NameBuf};
//!
//! let www: NameBuf = "www.Example.com".parse()?;
//! let zone: NameBuf = "example.COM.".parse()?;
//! let name = www.as_name();
//! assert_eq!(name.label_count(), 3);
//! assert!(name.is_subdomain_of(&zone.as_name()));
//! assert_eq!(name.parent(), Some(zone.as_name())); // case-insensitive
//! assert!(!name.parent().unwrap().eq_exact(&zone.as_name()));
//!
//! // Canonical DNSSEC order (RFC 4034 §6.1): by labels from the right.
//! let mut names: Vec<NameBuf> = ["z.example", "example", "a.example", "*.z.example"]
//!     .iter()
//!     .map(|s| s.parse())
//!     .collect::<Result<_, _>>()?;
//! names.sort();
//! let sorted: Vec<String> = names.iter().map(|n| n.to_string()).collect();
//! assert_eq!(sorted, ["example.", "a.example.", "z.example.", "*.z.example."]);
//!
//! // A view over uncompressed wire bytes.
//! let root = Name::from_wire(&[0])?;
//! assert!(root.is_root());
//! # Ok::<(), dnsbox::Error>(())
//! ```
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
///
/// # Examples
///
/// ```
/// use dnsbox::NameBuf;
///
/// let name: NameBuf = r"*.a\.b.example".parse()?;
/// let labels: Vec<_> = name.as_name().labels().collect();
/// assert!(labels[0].is_wildcard());
/// assert_eq!(labels[1].as_bytes(), b"a.b");
/// assert_eq!(labels[1].to_string(), r"a\.b");
/// assert_eq!(labels.len(), 3);
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Label<'a>(&'a [u8]);

impl<'a> Label<'a> {
    /// The raw label octets.
    ///
    /// ```
    /// use dnsbox::NameBuf;
    ///
    /// let name: NameBuf = "_443._tcp.example".parse()?;
    /// let first = name.as_name().first_label().unwrap();
    /// assert_eq!(first.as_bytes(), b"_443");
    /// // A TLSA owner: the port comes from the first label.
    /// let port: u16 = std::str::from_utf8(&first.as_bytes()[1..]).unwrap().parse().unwrap();
    /// assert_eq!(port, 443);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// Length of the label in octets.
    ///
    /// ```
    /// use dnsbox::NameBuf;
    ///
    /// let name: NameBuf = "www.example.com".parse()?;
    /// let lens: Vec<usize> = name.as_name().labels().map(|l| l.len()).collect();
    /// assert_eq!(lens, [3, 7, 3]);
    /// // Each label costs its length plus one octet on the wire, plus the root.
    /// assert_eq!(lens.iter().map(|l| l + 1).sum::<usize>() + 1, name.as_name().wire_len());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[allow(clippy::len_without_is_empty)] // labels yielded by iterators are never empty
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether this is the wildcard label `*` (RFC 4592 §2.1.1).
    ///
    /// ```
    /// use dnsbox::NameBuf;
    ///
    /// let name: NameBuf = "*.example".parse()?;
    /// let mut labels = name.as_name().labels();
    /// assert!(labels.next().unwrap().is_wildcard());
    /// assert!(!labels.next().unwrap().is_wildcard());
    /// // Only a label that is exactly `*` counts.
    /// let other: NameBuf = "*a.example".parse()?;
    /// assert!(!other.as_name().first_label().unwrap().is_wildcard());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_wildcard(&self) -> bool {
        matches!(self.0, [b'*'])
    }

    /// ASCII-case-insensitive comparison (RFC 4343 §3).
    ///
    /// ```
    /// use dnsbox::NameBuf;
    ///
    /// let (a, b): (NameBuf, NameBuf) = ("WWW.example".parse()?, "www.Example".parse()?);
    /// let (la, lb) = (a.as_name().first_label().unwrap(), b.as_name().first_label().unwrap());
    /// assert!(la.eq_ignore_case(&lb));
    /// assert_ne!(la, lb); // `==` on labels is exact
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
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
///
/// # Examples
///
/// Names read from a message follow compression pointers lazily:
///
/// ```
/// use dnsbox::{Name, WireReader};
///
/// // "example.com" at offset 0, then "www" + a pointer to offset 0.
/// let msg = b"\x07example\x03com\x00\x03www\xc0\x00";
/// let mut r = WireReader::new(msg);
/// let zone = r.read_name()?;
/// let www = r.read_name()?;
/// assert_eq!(www.to_string(), "www.example.com.");
/// assert_eq!(www.wire_len(), 17);
/// assert_eq!(www.as_contiguous(), None); // stored in two pieces
/// assert_eq!(www.parent(), Some(zone));
///
/// let mut flat = [0u8; 255];
/// let len = www.flatten(&mut flat);
/// assert_eq!(Name::from_wire(&flat[..len])?, www);
/// # Ok::<(), dnsbox::Error>(())
/// ```
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
    /// # Errors
    ///
    /// [`Error::UnexpectedPointer`] if `wire` contains a compression
    /// pointer, [`Error::TrailingData`] if bytes follow the root label, and
    /// the name decoding errors ([`Error::UnexpectedEof`],
    /// [`Error::LabelTooLong`], [`Error::NameTooLong`],
    /// [`Error::BadLabelType`]) if it is malformed.
    ///
    /// ```
    /// use dnsbox::{Error, Name};
    ///
    /// let name = Name::from_wire(b"\x03www\x07example\x00")?;
    /// assert_eq!(name.to_string(), "www.example.");
    /// assert_eq!(Name::from_wire(b"\x03www\x00\x00"), Err(Error::TrailingData));
    /// assert_eq!(Name::from_wire(b"\x03www"), Err(Error::UnexpectedEof));
    /// # Ok::<(), Error>(())
    /// ```
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
    ///
    /// ```
    /// use dnsbox::{Name, NameBuf};
    ///
    /// let name: NameBuf = "example.com".parse()?;
    /// assert_eq!(name.as_name().wire_len(), 13); // 7example3com0
    /// assert_eq!(Name::ROOT.wire_len(), 1);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub const fn wire_len(&self) -> usize {
        self.len as usize
    }

    /// Number of labels, not counting the root (0 for the root name).
    ///
    /// ```
    /// use dnsbox::{Name, NameBuf};
    ///
    /// // The RRSIG labels field: the owner's label count, minus a wildcard.
    /// let owner: NameBuf = "www.example.com".parse()?;
    /// assert_eq!(owner.as_name().label_count(), 3);
    /// assert_eq!(Name::ROOT.label_count(), 0);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub const fn label_count(&self) -> usize {
        self.labels as usize
    }

    /// Whether this is the root name.
    ///
    /// ```
    /// use dnsbox::{Name, NameBuf};
    ///
    /// let root: NameBuf = ".".parse()?;
    /// assert!(root.as_name().is_root());
    /// assert!(Name::ROOT.is_root());
    /// let tld: NameBuf = "com".parse()?;
    /// assert!(!tld.as_name().is_root());
    /// assert!(tld.as_name().parent().unwrap().is_root());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.labels == 0
    }

    /// Whether the first label is the wildcard label `*` (RFC 4592).
    ///
    /// ```
    /// use dnsbox::NameBuf;
    ///
    /// let wildcard: NameBuf = "*.example.com".parse()?;
    /// assert!(wildcard.as_name().is_wildcard());
    /// // A `*` further down is an ordinary label (RFC 4592 §2.1.1).
    /// let not: NameBuf = "a.*.example.com".parse()?;
    /// assert!(!not.as_name().is_wildcard());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub fn is_wildcard(&self) -> bool {
        self.first_label().is_some_and(|l| l.is_wildcard())
    }

    /// The uncompressed wire form, if it is stored contiguously (always the
    /// case for names from [`Name::from_wire`] and [`NameBuf`], and for
    /// message names that do not use pointers after their first label).
    ///
    /// ```
    /// use dnsbox::rdata::A;
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf};
    ///
    /// let (apex, www): (NameBuf, NameBuf) = ("example".parse()?, "www.example".parse()?);
    /// assert_eq!(apex.as_name().as_contiguous(), Some(&b"\x07example\x00"[..]));
    ///
    /// let mut buf = [0u8; 128];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.push_answer(&apex, Class::IN, 60, &A::new([192, 0, 2, 1].into()))?;
    /// b.push_answer(&www, Class::IN, 60, &A::new([192, 0, 2, 2].into()))?;
    /// let msg = Message::parse(b.finish())?;
    /// let owner = msg.answers().nth(1).unwrap()?.name();
    /// // "www" then a compression pointer to "example.": not contiguous.
    /// assert_eq!(owner.as_contiguous(), None);
    /// assert_eq!(owner.to_buf().as_name().as_contiguous(), Some(&b"\x03www\x07example\x00"[..]));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub fn as_contiguous(&self) -> Option<&'a [u8]> {
        if self.contiguous {
            self.msg.get(self.start..self.start + self.len as usize)
        } else {
            None
        }
    }

    /// Iterates over the labels, left to right, not including the root.
    ///
    /// ```
    /// use dnsbox::NameBuf;
    ///
    /// let name: NameBuf = "mail.example.org".parse()?;
    /// let labels: Vec<String> = name.as_name().labels().map(|l| l.to_string()).collect();
    /// assert_eq!(labels, ["mail", "example", "org"]);
    /// // The last label is the top-level domain.
    /// let tld = name.as_name().labels().last().unwrap();
    /// assert_eq!(tld.as_bytes(), b"org");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub fn labels(&self) -> Labels<'a> {
        Labels {
            msg: self.msg,
            pos: self.start,
            remaining: self.labels,
        }
    }

    /// The leftmost label, or `None` for the root.
    ///
    /// ```
    /// use dnsbox::{Name, NameBuf};
    ///
    /// let host: NameBuf = "printer.office.example".parse()?;
    /// assert_eq!(host.as_name().first_label().unwrap().as_bytes(), b"printer");
    /// assert!(Name::ROOT.first_label().is_none());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub fn first_label(&self) -> Option<Label<'a>> {
        self.labels().next()
    }

    /// The name with its leftmost label removed, or `None` for the root.
    ///
    /// ```
    /// use dnsbox::NameBuf;
    ///
    /// // Walk up to the root, as when looking for the closest enclosing zone.
    /// let name: NameBuf = "a.b.example".parse()?;
    /// let mut ancestors = Vec::new();
    /// let mut cur = name.as_name();
    /// while let Some(parent) = cur.parent() {
    ///     ancestors.push(parent.to_string());
    ///     cur = parent;
    /// }
    /// assert_eq!(ancestors, ["b.example.", "example.", "."]);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
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
    ///
    /// ```
    /// use dnsbox::NameBuf;
    ///
    /// let name: NameBuf = "a.b.example.com".parse()?;
    /// let n = name.as_name();
    /// assert_eq!(n.strip_labels(2).unwrap().to_string(), "example.com.");
    /// assert!(n.strip_labels(4).unwrap().is_root());
    /// assert!(n.strip_labels(5).is_none());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn strip_labels(&self, n: usize) -> Option<Name<'a>> {
        let mut name = *self;
        for _ in 0..n {
            name = name.parent()?;
        }
        Some(name)
    }

    /// Whether `self` is `other` or a descendant of it (RFC 1034 §3.1),
    /// comparing case-insensitively. Every name is a subdomain of the root.
    ///
    /// ```
    /// use dnsbox::{Name, NameBuf};
    ///
    /// let zone: NameBuf = "Example.COM".parse()?;
    /// let host: NameBuf = "mail.example.com".parse()?;
    /// let other: NameBuf = "badexample.com".parse()?;
    /// assert!(host.as_name().is_subdomain_of(&zone.as_name()));
    /// assert!(zone.as_name().is_subdomain_of(&zone.as_name()));
    /// assert!(!other.as_name().is_subdomain_of(&zone.as_name())); // label-wise
    /// assert!(host.as_name().is_subdomain_of(&Name::ROOT));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn is_subdomain_of(&self, other: &Name<'_>) -> bool {
        match self.label_count().checked_sub(other.label_count()) {
            Some(extra) => self.strip_labels(extra).is_some_and(|n| n == *other),
            None => false,
        }
    }

    /// Copies the uncompressed wire form into `out`, returning its length.
    ///
    /// ```
    /// use dnsbox::name::MAX_NAME_LEN;
    /// use dnsbox::rdata::Cname;
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf};
    ///
    /// let (alias, target): (NameBuf, NameBuf) = ("www.example".parse()?, "web.example".parse()?);
    /// let mut buf = [0u8; 128];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.push_answer(&alias, Class::IN, 60, &Cname::new(target.as_name()))?;
    /// let msg = Message::parse(b.finish())?;
    /// let rr = msg.answers().next().unwrap()?;
    /// let cname: Cname<'_> = rr.data_as()?;
    /// // The target is "web" plus a pointer in the message; flatten it.
    /// let mut out = [0u8; MAX_NAME_LEN];
    /// let len = cname.cname.flatten(&mut out);
    /// assert_eq!(&out[..len], b"\x03web\x07example\x00");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
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
    ///
    /// ```
    /// use dnsbox::rdata::A;
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf};
    ///
    /// let name: NameBuf = "host.example".parse()?;
    /// let mut buf = [0u8; 128];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.push_answer(&name, Class::IN, 60, &A::new([192, 0, 2, 1].into()))?;
    /// let wire = b.finish();
    /// // Keep the owner name after the message buffer is gone.
    /// let owner: NameBuf = Message::parse(wire)?.answers().next().unwrap()?.name().to_buf();
    /// wire.fill(0);
    /// assert_eq!(owner, name);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub fn to_buf(&self) -> NameBuf {
        NameBuf::from_name(*self)
    }

    /// Exact (case-sensitive) comparison of the label octets.
    ///
    /// ```
    /// use dnsbox::NameBuf;
    ///
    /// // DNS 0x20: a resolver checks that the response kept its mixed case.
    /// let (sent, echoed): (NameBuf, NameBuf) = ("ExAmPlE.cOm".parse()?, "example.com".parse()?);
    /// assert!(sent.as_name() == echoed.as_name());
    /// assert!(!sent.as_name().eq_exact(&echoed.as_name()));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
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
    ///
    /// ```
    /// use core::cmp::Ordering;
    /// use dnsbox::NameBuf;
    ///
    /// // Labels compare from the right: after `example`, `z` sorts after `b`.
    /// let (x, y): (NameBuf, NameBuf) = ("z.example".parse()?, "a.b.example".parse()?);
    /// assert_eq!(x.as_name().cmp_canonical(&y.as_name()), Ordering::Greater);
    /// let (p, q): (NameBuf, NameBuf) = ("example".parse()?, "\\001.example".parse()?);
    /// assert_eq!(p.as_name().cmp_canonical(&q.as_name()), Ordering::Less);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
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
///
/// ```
/// use dnsbox::NameBuf;
///
/// let name: NameBuf = "www.example.com".parse()?;
/// let labels = name.as_name().labels();
/// assert_eq!(labels.len(), 3);
/// let text: Vec<String> = labels.map(|l| l.to_string()).collect();
/// assert_eq!(text, ["www", "example", "com"]);
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Debug)]
#[must_use = "iterators are lazy and do nothing unless consumed"]
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
///
/// # Examples
///
/// ```
/// use dnsbox::{Name, NameBuf, ToName};
///
/// fn depth(name: impl ToName) -> usize {
///     name.to_name().label_count()
/// }
/// let owned: NameBuf = "a.b.c".parse()?;
/// assert_eq!(depth(&owned), 3);
/// assert_eq!(depth(owned.as_name()), 3);
/// assert_eq!(depth(Name::ROOT), 0);
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub trait ToName {
    /// Borrows `self` as a name view.
    ///
    /// ```
    /// use dnsbox::{Name, NameBuf, ToName};
    ///
    /// // A key type of your own can be passed wherever a name is expected.
    /// struct Zone {
    ///     apex: NameBuf,
    /// }
    /// impl ToName for Zone {
    ///     fn to_name(&self) -> Name<'_> {
    ///         self.apex.as_name()
    ///     }
    /// }
    /// let zone = Zone { apex: "example.com".parse()? };
    /// assert_eq!(zone.to_name().to_string(), "example.com.");
    /// assert!("www.example.com".parse::<NameBuf>()?.as_name().is_subdomain_of(&zone.to_name()));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
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
