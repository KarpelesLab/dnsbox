//! Typed SvcParamValues (RFC 9460 §7–8, RFC 9461, RFC 9540, RFC 9848,
//! RFC 9953): validation of the wire format and presentation format
//! `Display`.

use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr};

use super::SvcParamKey;
use crate::text::Base64;
use crate::{Error, Result};

/// A typed view of one SvcParamValue, as returned by
/// [`SvcParam::value`](super::SvcParam::value).
///
/// Every variant borrows from the record data. Keys without a typed
/// representation (unassigned, private-use, or not yet implemented) are
/// [`SvcParamValue::Unknown`], which keeps the raw value (RFC 9460 §2.1:
/// such values are opaque octets).
///
/// ```
/// use dnsbox::rdata::{SvcParamKey, SvcParamValue};
///
/// let value = SvcParamValue::parse(SvcParamKey::ALPN, b"\x02h3")?;
/// assert!(matches!(value, SvcParamValue::Alpn(a) if a.contains(b"h3")));
/// assert_eq!(value.to_string(), r#""h3""#);
/// let private = SvcParamValue::parse(SvcParamKey::new(65300), b"opaque")?;
/// assert_eq!(private, SvcParamValue::Unknown(b"opaque"));
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SvcParamValue<'a> {
    /// `mandatory`: keys that must be understood (RFC 9460 §8).
    Mandatory(Mandatory<'a>),
    /// `alpn`: ALPN protocol IDs (RFC 9460 §7.1).
    Alpn(Alpn<'a>),
    /// `no-default-alpn` (RFC 9460 §7.1); the value is empty.
    NoDefaultAlpn,
    /// `port` (RFC 9460 §7.2).
    Port(u16),
    /// `ipv4hint` (RFC 9460 §7.3).
    Ipv4Hint(Ipv4Hint<'a>),
    /// `ech`: an ECHConfigList (RFC 9848 §3).
    Ech(Ech<'a>),
    /// `ipv6hint` (RFC 9460 §7.3).
    Ipv6Hint(Ipv6Hint<'a>),
    /// `dohpath`: a DoH URI template (RFC 9461 §5).
    DohPath(DohPath<'a>),
    /// `ohttp` (RFC 9540 §4); the value is empty.
    Ohttp,
    /// `tls-supported-groups` (draft-ietf-tls-key-share-prediction §3.1).
    TlsSupportedGroups(TlsSupportedGroups<'a>),
    /// `docpath`: a DNS over CoAP resource path (RFC 9953 §3).
    DocPath(DocPath<'a>),
    /// `pvd` (draft-ietf-intarea-proxy-config §2.1); the value is empty.
    Pvd,
    /// `oots`: per-transport confidence weights
    /// (draft-johani-dnsop-svcb-oots §2.1).
    Oots(Oots<'a>),
    /// Any other key: the raw value.
    Unknown(&'a [u8]),
}

impl<'a> SvcParamValue<'a> {
    /// Validates the wire-format `value` of `key` and returns its typed
    /// view.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRdata`] if the value does not have the format the
    /// key requires (RFC 9460 §2.2: such an RR is malformed).
    pub fn parse(key: SvcParamKey, value: &'a [u8]) -> Result<Self> {
        Ok(match key {
            SvcParamKey::MANDATORY => SvcParamValue::Mandatory(Mandatory::new(value)?),
            SvcParamKey::ALPN => SvcParamValue::Alpn(Alpn::new(value)?),
            SvcParamKey::NO_DEFAULT_ALPN => {
                empty(value)?;
                SvcParamValue::NoDefaultAlpn
            }
            SvcParamKey::PORT => match *value {
                [hi, lo] => SvcParamValue::Port(u16::from_be_bytes([hi, lo])),
                _ => return Err(Error::InvalidRdata),
            },
            SvcParamKey::IPV4HINT => SvcParamValue::Ipv4Hint(Ipv4Hint::new(value)?),
            SvcParamKey::ECH => SvcParamValue::Ech(Ech(value)),
            SvcParamKey::IPV6HINT => SvcParamValue::Ipv6Hint(Ipv6Hint::new(value)?),
            SvcParamKey::DOHPATH => SvcParamValue::DohPath(DohPath::new(value)?),
            SvcParamKey::OHTTP => {
                empty(value)?;
                SvcParamValue::Ohttp
            }
            SvcParamKey::TLS_SUPPORTED_GROUPS => {
                SvcParamValue::TlsSupportedGroups(TlsSupportedGroups::new(value)?)
            }
            SvcParamKey::DOCPATH => SvcParamValue::DocPath(DocPath::new(value)?),
            SvcParamKey::PVD => {
                empty(value)?;
                SvcParamValue::Pvd
            }
            SvcParamKey::OOTS => SvcParamValue::Oots(Oots::new(value)?),
            _ => SvcParamValue::Unknown(value),
        })
    }
}

impl fmt::Display for SvcParamValue<'_> {
    /// The presentation-format value (what follows `key=`); empty for the
    /// keys whose value is always empty.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SvcParamValue::Mandatory(v) => fmt::Display::fmt(v, f),
            SvcParamValue::Alpn(v) => fmt::Display::fmt(v, f),
            SvcParamValue::Port(p) => fmt::Display::fmt(p, f),
            SvcParamValue::Ipv4Hint(v) => fmt::Display::fmt(v, f),
            SvcParamValue::Ech(v) => fmt::Display::fmt(v, f),
            SvcParamValue::Ipv6Hint(v) => fmt::Display::fmt(v, f),
            SvcParamValue::DohPath(v) => fmt::Display::fmt(v, f),
            SvcParamValue::TlsSupportedGroups(v) => fmt::Display::fmt(v, f),
            SvcParamValue::DocPath(v) => fmt::Display::fmt(v, f),
            SvcParamValue::Oots(v) => fmt::Display::fmt(v, f),
            SvcParamValue::Unknown(v) => crate::text::fmt_quoted(f, v),
            SvcParamValue::NoDefaultAlpn | SvcParamValue::Ohttp | SvcParamValue::Pvd => Ok(()),
        }
    }
}

/// Values of `no-default-alpn`, `ohttp` and `pvd` must be empty.
const fn empty(value: &[u8]) -> Result<()> {
    if value.is_empty() {
        Ok(())
    } else {
        Err(Error::InvalidRdata)
    }
}

/// Checks that `value` is a non-empty sequence of `N`-byte items.
const fn fixed_items<const N: usize>(value: &[u8]) -> Result<()> {
    if value.is_empty() || !value.len().is_multiple_of(N) {
        Err(Error::InvalidRdata)
    } else {
        Ok(())
    }
}

/// Checks a sequence of length-prefixed items (`alpn`, `docpath`) that
/// exactly fills `value`; every item must be 1–255 octets.
fn length_prefixed_items(value: &[u8]) -> Result<()> {
    let mut rest = value;
    while let [len, tail @ ..] = rest {
        if *len == 0 {
            return Err(Error::InvalidRdata);
        }
        rest = tail.get(usize::from(*len)..).ok_or(Error::InvalidRdata)?;
    }
    Ok(())
}

/// Iterates over validated length-prefixed items.
#[derive(Clone, Debug)]
struct ItemIter<'a>(&'a [u8]);

impl<'a> Iterator for ItemIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let (len, tail) = self.0.split_first()?;
        let len = usize::from(*len).min(tail.len());
        let (item, rest) = tail.split_at(len);
        self.0 = rest;
        Some(item)
    }
}

/// Writes one byte as it must appear inside a quoted presentation-format
/// string (RFC 1035 §5.1): `"` and `\` are escaped, bytes outside printable
/// ASCII become `\DDD`.
fn fmt_quoted_byte(f: &mut fmt::Formatter<'_>, b: u8) -> fmt::Result {
    match b {
        b'"' | b'\\' => write!(f, "\\{}", b as char),
        0x20..=0x7e => fmt::Write::write_char(f, b as char),
        _ => write!(f, "\\{b:03}"),
    }
}

/// Writes a quoted comma-separated value-list (RFC 9460 Appendix A.1): a
/// `,` or `\` inside an item is escaped with a backslash at the list
/// level, and the result escaped again as a character-string, so `f\o,o`
/// becomes `"f\\\\o\\,o"`.
fn fmt_quoted_list<'a>(
    f: &mut fmt::Formatter<'_>,
    items: impl Iterator<Item = &'a [u8]>,
) -> fmt::Result {
    f.write_str("\"")?;
    for (i, item) in items.enumerate() {
        if i > 0 {
            f.write_str(",")?;
        }
        for &b in item {
            if b == b',' || b == b'\\' {
                // List-level backslash, itself escaped in the string.
                f.write_str("\\\\")?;
            }
            fmt_quoted_byte(f, b)?;
        }
    }
    f.write_str("\"")
}

/// Writes items separated by commas.
fn fmt_comma_separated<T: fmt::Display>(
    f: &mut fmt::Formatter<'_>,
    items: impl Iterator<Item = T>,
) -> fmt::Result {
    for (i, item) in items.enumerate() {
        if i > 0 {
            f.write_str(",")?;
        }
        fmt::Display::fmt(&item, f)?;
    }
    Ok(())
}

macro_rules! debug_as_list {
    ($ty:ident) => {
        impl fmt::Debug for $ty<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_list().entries(self.iter()).finish()
            }
        }
    };
}

/// The `mandatory` value: a non-empty, strictly increasing list of keys
/// that does not contain `mandatory` itself (RFC 9460 §8).
///
/// ```
/// use dnsbox::rdata::SvcParamKey;
/// use dnsbox::rdata::svcparam::Mandatory;
///
/// let m = Mandatory::new(&[0, 1, 0, 4])?; // alpn, ipv4hint
/// assert!(m.contains(SvcParamKey::IPV4HINT));
/// assert_eq!(m.to_string(), "alpn,ipv4hint");
/// assert!(Mandatory::new(&[0, 4, 0, 1]).is_err()); // not increasing
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Mandatory<'a>(&'a [u8]);

impl<'a> Mandatory<'a> {
    /// Validates a wire-format `mandatory` value.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRdata`] for an empty or odd-length list, keys not in
    /// strictly increasing order, or `mandatory` itself in the list.
    pub fn new(value: &'a [u8]) -> Result<Self> {
        fixed_items::<2>(value)?;
        let mut prev: Option<u16> = None;
        for k in value.as_chunks::<2>().0 {
            let k = u16::from_be_bytes(*k);
            // Strictly increasing (so no duplicates), and key 0 is not
            // allowed in its own list (RFC 9460 §8).
            if k == 0 || prev.is_some_and(|p| k <= p) {
                return Err(Error::InvalidRdata);
            }
            prev = Some(k);
        }
        Ok(Mandatory(value))
    }

    /// The keys, in increasing order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = SvcParamKey> + Clone + use<'a> {
        self.0
            .as_chunks::<2>()
            .0
            .iter()
            .map(|k| SvcParamKey::new(u16::from_be_bytes(*k)))
    }

    /// Whether `key` is listed.
    #[must_use]
    pub fn contains(&self, key: SvcParamKey) -> bool {
        self.iter().any(|k| k == key)
    }

    /// The wire-format value.
    #[inline]
    #[must_use]
    pub const fn as_wire(&self) -> &'a [u8] {
        self.0
    }
}

impl fmt::Display for Mandatory<'_> {
    /// Comma-separated key names (RFC 9460 §8).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_comma_separated(f, self.iter())
    }
}

debug_as_list!(Mandatory);

/// The `alpn` value: one or more ALPN protocol IDs of 1–255 octets
/// (RFC 9460 §7.1.1).
///
/// ```
/// use dnsbox::rdata::svcparam::Alpn;
///
/// let alpn = Alpn::new(b"\x02h2\x08http/1.1")?;
/// assert!(alpn.contains(b"http/1.1"));
/// assert_eq!(alpn.to_string(), r#""h2,http/1.1""#);
/// assert!(Alpn::new(b"").is_err());
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Alpn<'a>(&'a [u8]);

impl<'a> Alpn<'a> {
    /// Validates a wire-format `alpn` value.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRdata`] for an empty list, an empty ID, or an ID
    /// running past the value.
    pub fn new(value: &'a [u8]) -> Result<Self> {
        if value.is_empty() {
            return Err(Error::InvalidRdata);
        }
        length_prefixed_items(value)?;
        Ok(Alpn(value))
    }

    /// The protocol IDs, in record order.
    pub fn iter(&self) -> impl Iterator<Item = &'a [u8]> + Clone + use<'a> {
        ItemIter(self.0)
    }

    /// Whether `id` is listed.
    #[must_use]
    pub fn contains(&self, id: &[u8]) -> bool {
        self.iter().any(|i| i == id)
    }

    /// The wire-format value.
    #[inline]
    #[must_use]
    pub const fn as_wire(&self) -> &'a [u8] {
        self.0
    }
}

impl fmt::Display for Alpn<'_> {
    /// A quoted comma-separated list with RFC 9460 Appendix A.1 escaping.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_quoted_list(f, self.iter())
    }
}

impl fmt::Debug for Alpn<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.iter().map(crate::CharStr::from_wire_unchecked))
            .finish()
    }
}

/// The `ipv4hint` value: one or more IPv4 addresses (RFC 9460 §7.3).
///
/// ```
/// use dnsbox::rdata::svcparam::Ipv4Hint;
///
/// let hint = Ipv4Hint::new(&[192, 0, 2, 1])?;
/// assert_eq!(hint.iter().next(), Some([192, 0, 2, 1].into()));
/// assert!(Ipv4Hint::new(&[192, 0, 2]).is_err());
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Hint<'a>(&'a [u8]);

impl<'a> Ipv4Hint<'a> {
    /// Validates a wire-format `ipv4hint` value.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRdata`] unless the value is a non-empty multiple of
    /// 4 bytes.
    pub const fn new(value: &'a [u8]) -> Result<Self> {
        match fixed_items::<4>(value) {
            Ok(()) => Ok(Ipv4Hint(value)),
            Err(e) => Err(e),
        }
    }

    /// The addresses, in record order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = Ipv4Addr> + Clone + use<'a> {
        self.0
            .as_chunks::<4>()
            .0
            .iter()
            .map(|a| Ipv4Addr::from(*a))
    }

    /// The wire-format value.
    #[inline]
    #[must_use]
    pub const fn as_wire(&self) -> &'a [u8] {
        self.0
    }
}

impl fmt::Display for Ipv4Hint<'_> {
    /// Comma-separated addresses.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_comma_separated(f, self.iter())
    }
}

debug_as_list!(Ipv4Hint);

/// The `ipv6hint` value: one or more IPv6 addresses (RFC 9460 §7.3).
///
/// ```
/// use dnsbox::rdata::svcparam::Ipv6Hint;
///
/// let addr: core::net::Ipv6Addr = "2001:db8::53".parse().unwrap();
/// let octets = addr.octets();
/// let hint = Ipv6Hint::new(&octets)?;
/// assert_eq!(hint.to_string(), "2001:db8::53");
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6Hint<'a>(&'a [u8]);

impl<'a> Ipv6Hint<'a> {
    /// Validates a wire-format `ipv6hint` value.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRdata`] unless the value is a non-empty multiple of
    /// 16 bytes.
    pub const fn new(value: &'a [u8]) -> Result<Self> {
        match fixed_items::<16>(value) {
            Ok(()) => Ok(Ipv6Hint(value)),
            Err(e) => Err(e),
        }
    }

    /// The addresses, in record order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = Ipv6Addr> + Clone + use<'a> {
        self.0
            .as_chunks::<16>()
            .0
            .iter()
            .map(|a| Ipv6Addr::from(*a))
    }

    /// The wire-format value.
    #[inline]
    #[must_use]
    pub const fn as_wire(&self) -> &'a [u8] {
        self.0
    }
}

impl fmt::Display for Ipv6Hint<'_> {
    /// Comma-separated addresses (RFC 5952 text form).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_comma_separated(f, self.iter())
    }
}

debug_as_list!(Ipv6Hint);

/// The `ech` value: an ECHConfigList, length prefix included
/// (RFC 9848 §3). It is kept opaque.
///
/// ```
/// use dnsbox::rdata::svcparam::Ech;
///
/// let ech = Ech(&[0, 2, 0xfe, 0x0d]);
/// assert_eq!(ech.as_bytes().len(), 4);
/// assert_eq!(ech.to_string(), "AAL+DQ==");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ech<'a>(pub &'a [u8]);

impl<'a> Ech<'a> {
    /// The ECHConfigList bytes.
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.0
    }
}

impl fmt::Display for Ech<'_> {
    /// Base64 (RFC 4648 §4), as RFC 9848 §3 specifies.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Base64(self.0), f)
    }
}

impl fmt::Debug for Ech<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ech({})", Base64(self.0))
    }
}

/// The `dohpath` value: a relative URI template in UTF-8 (RFC 9461 §5).
///
/// ```
/// use dnsbox::rdata::svcparam::DohPath;
///
/// let path = DohPath::new(b"/dns-query{?dns}")?;
/// assert_eq!(path.as_str(), "/dns-query{?dns}");
/// assert_eq!(path.to_string(), r#""/dns-query{?dns}""#);
/// assert!(DohPath::new(&[0xff]).is_err()); // not UTF-8
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DohPath<'a>(&'a str);

impl<'a> DohPath<'a> {
    /// Validates a wire-format `dohpath` value (it must be UTF-8).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRdata`] if it is not UTF-8.
    pub const fn new(value: &'a [u8]) -> Result<Self> {
        match core::str::from_utf8(value) {
            Ok(s) => Ok(DohPath(s)),
            Err(_) => Err(Error::InvalidRdata),
        }
    }

    /// The URI template.
    #[inline]
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        self.0
    }
}

impl fmt::Display for DohPath<'_> {
    /// A quoted character-string.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::text::fmt_quoted(f, self.0.as_bytes())
    }
}

/// The `tls-supported-groups` value: a non-empty list of TLS NamedGroup
/// code points without duplicates, in order of decreasing preference
/// (draft-ietf-tls-key-share-prediction §3.1).
///
/// ```
/// use dnsbox::rdata::svcparam::TlsSupportedGroups;
///
/// // X25519MLKEM768 (4588), then X25519 (29).
/// let groups = TlsSupportedGroups::new(&[0x11, 0xec, 0x00, 0x1d])?;
/// assert_eq!(groups.iter().collect::<Vec<_>>(), [4588, 29]);
/// assert_eq!(groups.to_string(), "4588,29");
/// assert!(TlsSupportedGroups::new(&[0, 29, 0, 29]).is_err()); // duplicate
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TlsSupportedGroups<'a>(&'a [u8]);

impl<'a> TlsSupportedGroups<'a> {
    /// Validates a wire-format `tls-supported-groups` value.
    ///
    /// The duplicate check is linear in the list length (a 8 KiB bitmap on
    /// the stack for lists longer than 32 groups), so hostile values cannot
    /// cause quadratic work.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRdata`] for an empty or odd-length list, or a
    /// repeated group.
    pub fn new(value: &'a [u8]) -> Result<Self> {
        fixed_items::<2>(value)?;
        let groups = value.as_chunks::<2>().0;
        if groups.len() <= 32 {
            for (i, g) in groups.iter().enumerate() {
                if groups.get(i + 1..).unwrap_or(&[]).contains(g) {
                    return Err(Error::InvalidRdata);
                }
            }
        } else {
            let mut seen = [0u64; 1024];
            for g in groups {
                let g = u16::from_be_bytes(*g);
                let (word, bit) = (usize::from(g >> 6), 1u64 << (g & 63));
                let slot = seen.get_mut(word).ok_or(Error::InvalidRdata)?;
                if *slot & bit != 0 {
                    return Err(Error::InvalidRdata);
                }
                *slot |= bit;
            }
        }
        Ok(TlsSupportedGroups(value))
    }

    /// The group code points, most preferred first.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = u16> + Clone + use<'a> {
        self.0
            .as_chunks::<2>()
            .0
            .iter()
            .map(|g| u16::from_be_bytes(*g))
    }

    /// The wire-format value.
    #[inline]
    #[must_use]
    pub const fn as_wire(&self) -> &'a [u8] {
        self.0
    }
}

impl fmt::Display for TlsSupportedGroups<'_> {
    /// Comma-separated decimal code points.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_comma_separated(f, self.iter())
    }
}

debug_as_list!(TlsSupportedGroups);

/// The `docpath` value: zero or more path segments of 1–255 octets; no
/// segments is the root path `/` (RFC 9953 §3).
///
/// ```
/// use dnsbox::rdata::svcparam::DocPath;
///
/// let path = DocPath::new(b"\x03dns")?;
/// assert_eq!(path.iter().collect::<Vec<_>>(), [&b"dns"[..]]);
/// assert_eq!(DocPath::new(b"")?.iter().count(), 0); // the root path
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DocPath<'a>(&'a [u8]);

impl<'a> DocPath<'a> {
    /// Validates a wire-format `docpath` value.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRdata`] for an empty segment or one running past
    /// the value.
    pub fn new(value: &'a [u8]) -> Result<Self> {
        length_prefixed_items(value)?;
        Ok(DocPath(value))
    }

    /// The path segments, outermost first.
    pub fn iter(&self) -> impl Iterator<Item = &'a [u8]> + Clone + use<'a> {
        ItemIter(self.0)
    }

    /// The wire-format value.
    #[inline]
    #[must_use]
    pub const fn as_wire(&self) -> &'a [u8] {
        self.0
    }
}

impl fmt::Display for DocPath<'_> {
    /// A quoted comma-separated list with RFC 9460 Appendix A.1 escaping.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_quoted_list(f, self.iter())
    }
}

impl fmt::Debug for DocPath<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.iter().map(crate::CharStr::from_wire_unchecked))
            .finish()
    }
}

/// The `oots` value: one or more (transport protocol, weight) entries, each
/// a length-prefixed identifier of 1–255 octets followed by a weight of
/// 0–100 (draft-johani-dnsop-svcb-oots §2.1).
///
/// ```
/// use dnsbox::rdata::svcparam::Oots;
///
/// let oots = Oots::new(b"\x03dot\x50\x03doh\x14")?;
/// assert_eq!(oots.iter().collect::<Vec<_>>(), [(&b"dot"[..], 80), (&b"doh"[..], 20)]);
/// assert!(Oots::new(b"\x03dot\x65").is_err()); // weight 101
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Oots<'a>(&'a [u8]);

impl<'a> Oots<'a> {
    /// The largest valid weight (a percentage).
    pub const MAX_WEIGHT: u8 = 100;

    /// Validates a wire-format `oots` value.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRdata`] for an empty list, an empty or truncated
    /// identifier, or a weight above [`MAX_WEIGHT`](Self::MAX_WEIGHT).
    pub fn new(value: &'a [u8]) -> Result<Self> {
        if value.is_empty() {
            return Err(Error::InvalidRdata);
        }
        let mut rest = value;
        while let [len, tail @ ..] = rest {
            let len = usize::from(*len);
            match tail.get(len..) {
                Some([weight, tail @ ..]) if len > 0 && *weight <= Self::MAX_WEIGHT => {
                    rest = tail;
                }
                _ => return Err(Error::InvalidRdata),
            }
        }
        Ok(Oots(value))
    }

    /// The `(protocol identifier, weight)` entries, in record order.
    pub fn iter(&self) -> impl Iterator<Item = (&'a [u8], u8)> + Clone + use<'a> {
        let mut rest = self.0;
        core::iter::from_fn(move || {
            let (len, tail) = rest.split_first()?;
            let (proto, tail) = tail.split_at_checked(usize::from(*len))?;
            let (weight, tail) = tail.split_first()?;
            rest = tail;
            Some((proto, *weight))
        })
    }

    /// The wire-format value.
    #[inline]
    #[must_use]
    pub const fn as_wire(&self) -> &'a [u8] {
        self.0
    }
}

impl fmt::Display for Oots<'_> {
    /// A quoted list of `proto:weight` entries.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"")?;
        for (i, (proto, weight)) in self.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            for &b in proto {
                if b == b',' || b == b'\\' {
                    f.write_str("\\\\")?;
                }
                fmt_quoted_byte(f, b)?;
            }
            write!(f, ":{weight}")?;
        }
        f.write_str("\"")
    }
}

impl fmt::Debug for Oots<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(
                self.iter()
                    .map(|(p, w)| (crate::CharStr::from_wire_unchecked(p), w)),
            )
            .finish()
    }
}
