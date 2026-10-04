//! The SvcParams list of SVCB/HTTPS record data (RFC 9460 §2.2).

use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr};

use super::SvcParamKey;
use super::value::{
    Alpn, DocPath, DohPath, Ech, Ipv4Hint, Ipv6Hint, Mandatory, Oots, SvcParamValue,
    TlsSupportedGroups,
};
use crate::{Error, Result};

/// One SvcParam: a key and its (validated) wire-format value
/// (RFC 9460 §2.2).
///
/// `Display` gives the presentation form: `key=value`, or just `key` when
/// the value is empty (RFC 9460 §2.1).
///
/// ```
/// use dnsbox::rdata::{SvcParam, SvcParamKey, SvcParamValue};
///
/// let param = SvcParam::new(SvcParamKey::PORT, &[0x20, 0xfb])?;
/// assert_eq!(param.value(), SvcParamValue::Port(8443));
/// assert_eq!(param.to_string(), "port=8443");
/// // A value of the wrong size for its key is rejected.
/// assert!(SvcParam::new(SvcParamKey::PORT, &[1]).is_err());
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SvcParam<'a> {
    key: SvcParamKey,
    value: &'a [u8],
}

impl<'a> SvcParam<'a> {
    /// Pairs `key` with a wire-format `value`, checking that the value
    /// has the format the key requires.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRdata`] if it does not.
    pub fn new(key: SvcParamKey, value: &'a [u8]) -> Result<Self> {
        SvcParamValue::parse(key, value)?;
        Ok(SvcParam { key, value })
    }

    /// The key.
    #[inline]
    #[must_use]
    pub const fn key(&self) -> SvcParamKey {
        self.key
    }

    /// The wire-format value.
    #[inline]
    #[must_use]
    pub const fn raw_value(&self) -> &'a [u8] {
        self.value
    }

    /// The typed value.
    #[must_use]
    pub fn value(&self) -> SvcParamValue<'a> {
        // Validated on construction; the fallback is unreachable.
        SvcParamValue::parse(self.key, self.value).unwrap_or(SvcParamValue::Unknown(self.value))
    }
}

impl fmt::Display for SvcParam<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.key, f)?;
        if self.value.is_empty() {
            return Ok(());
        }
        write!(f, "={}", self.value())
    }
}

impl fmt::Debug for SvcParam<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {:?}", self.key, self.value())
    }
}

/// The SvcParams of a SVCB/HTTPS record: a validated view over their wire
/// form (RFC 9460 §2.2).
///
/// Construction ([`SvcParams::new`], or parsing the record) guarantees:
///
/// - every SvcParam is complete (no truncation inside one);
/// - keys are in strictly increasing order, so none is repeated;
/// - the reserved "Invalid key" 65535 ([`SvcParamKey::INVALID`],
///   RFC 9460 §14.3.2) does not appear;
/// - every value has the format its key requires ([`SvcParamValue`]);
/// - the RR is self-consistent (RFC 9460 §2.4.3): every key listed in
///   `mandatory` is present (§8), and `no-default-alpn` comes with `alpn`
///   (§7.1.1).
///
/// Iterating yields [`SvcParam`]s in key order; there are also typed
/// accessors for the registered keys. Lookups walk the list (it is sorted,
/// so they stop early) and allocate nothing.
///
/// ```
/// use dnsbox::rdata::{SvcParamKey, SvcParams};
///
/// // port=53, then ipv4hint=192.0.2.53 (keys in increasing order).
/// let params = SvcParams::new(b"\x00\x03\x00\x02\x00\x35\x00\x04\x00\x04\xc0\x00\x02\x35")?;
/// assert_eq!(params.len(), 2);
/// assert_eq!(params.port(), Some(53));
/// assert_eq!(params.ipv4_hints().collect::<Vec<_>>(), [core::net::Ipv4Addr::new(192, 0, 2, 53)]);
/// assert!(!params.contains(SvcParamKey::ALPN));
/// assert_eq!(params.to_string(), "port=53 ipv4hint=192.0.2.53");
///
/// // Out of order: malformed.
/// assert!(SvcParams::new(b"\x00\x04\x00\x04\xc0\x00\x02\x35\x00\x03\x00\x02\x00\x35").is_err());
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SvcParams<'a>(&'a [u8]);

impl<'a> SvcParams<'a> {
    /// No SvcParams.
    pub const EMPTY: SvcParams<'static> = SvcParams(&[]);

    /// Validates wire-format SvcParams (the part of the RDATA after the
    /// TargetName).
    ///
    /// The work is linear in the length of `wire`.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedEof`] if the data ends inside a
    /// SvcParam and [`Error::InvalidRdata`] if the keys are not
    /// strictly increasing, the reserved key 65535 is used (RFC 9460
    /// §14.3.2), a value is malformed, or the parameters are not
    /// self-consistent.
    pub fn new(wire: &'a [u8]) -> Result<Self> {
        let mut prev: Option<u16> = None;
        let mut iter = RawIter(wire);
        let mut mandatory: Option<Mandatory<'a>> = None;
        let mut alpn = false;
        let mut no_default_alpn = false;
        while !iter.0.is_empty() {
            let (key, value) = iter.next_checked()?;
            if prev.is_some_and(|p| key.get() <= p) || key == SvcParamKey::INVALID {
                return Err(Error::InvalidRdata);
            }
            prev = Some(key.get());
            match SvcParamValue::parse(key, value)? {
                SvcParamValue::Mandatory(m) => mandatory = Some(m),
                SvcParamValue::Alpn(_) => alpn = true,
                SvcParamValue::NoDefaultAlpn => no_default_alpn = true,
                _ => {}
            }
        }
        if no_default_alpn && !alpn {
            return Err(Error::InvalidRdata);
        }
        let params = SvcParams(wire);
        if let Some(m) = mandatory {
            // Both lists are sorted: one merge pass checks that every
            // mandatory key is present.
            let mut keys = params.iter().map(|p| p.key());
            for wanted in m.iter() {
                if !keys.by_ref().any(|k| k == wanted) {
                    return Err(Error::InvalidRdata);
                }
            }
        }
        Ok(params)
    }

    /// The wire form.
    #[inline]
    #[must_use]
    pub const fn as_wire(&self) -> &'a [u8] {
        self.0
    }

    /// Whether there are no SvcParams.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The number of SvcParams (walks the list).
    #[must_use]
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    /// Iterates over the SvcParams in (increasing) key order.
    #[inline]
    pub fn iter(&self) -> SvcParamIter<'a> {
        SvcParamIter(RawIter(self.0))
    }

    /// The SvcParam with `key`, if present.
    #[must_use]
    pub fn get(&self, key: SvcParamKey) -> Option<SvcParam<'a>> {
        self.iter()
            .find(|p| p.key() >= key)
            .filter(|p| p.key() == key)
    }

    /// Whether a SvcParam with `key` is present.
    #[inline]
    #[must_use]
    pub fn contains(&self, key: SvcParamKey) -> bool {
        self.get(key).is_some()
    }

    /// The typed value of `key`, if present.
    #[inline]
    #[must_use]
    pub fn value(&self, key: SvcParamKey) -> Option<SvcParamValue<'a>> {
        self.get(key).map(|p| p.value())
    }

    /// The `mandatory` keys (RFC 9460 §8).
    #[must_use]
    pub fn mandatory(&self) -> Option<Mandatory<'a>> {
        match self.value(SvcParamKey::MANDATORY)? {
            SvcParamValue::Mandatory(v) => Some(v),
            _ => None,
        }
    }

    /// The `alpn` IDs (RFC 9460 §7.1).
    #[must_use]
    pub fn alpn(&self) -> Option<Alpn<'a>> {
        match self.value(SvcParamKey::ALPN)? {
            SvcParamValue::Alpn(v) => Some(v),
            _ => None,
        }
    }

    /// Whether `no-default-alpn` is present (RFC 9460 §7.1).
    #[inline]
    #[must_use]
    pub fn no_default_alpn(&self) -> bool {
        self.contains(SvcParamKey::NO_DEFAULT_ALPN)
    }

    /// The `port` (RFC 9460 §7.2).
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        match self.value(SvcParamKey::PORT)? {
            SvcParamValue::Port(v) => Some(v),
            _ => None,
        }
    }

    /// The `ipv4hint` addresses (RFC 9460 §7.3).
    #[must_use]
    pub fn ipv4hint(&self) -> Option<Ipv4Hint<'a>> {
        match self.value(SvcParamKey::IPV4HINT)? {
            SvcParamValue::Ipv4Hint(v) => Some(v),
            _ => None,
        }
    }

    /// The `ech` configuration list (RFC 9848).
    #[must_use]
    pub fn ech(&self) -> Option<Ech<'a>> {
        match self.value(SvcParamKey::ECH)? {
            SvcParamValue::Ech(v) => Some(v),
            _ => None,
        }
    }

    /// The `ipv6hint` addresses (RFC 9460 §7.3).
    #[must_use]
    pub fn ipv6hint(&self) -> Option<Ipv6Hint<'a>> {
        match self.value(SvcParamKey::IPV6HINT)? {
            SvcParamValue::Ipv6Hint(v) => Some(v),
            _ => None,
        }
    }

    /// The `dohpath` URI template (RFC 9461 §5).
    #[must_use]
    pub fn dohpath(&self) -> Option<DohPath<'a>> {
        match self.value(SvcParamKey::DOHPATH)? {
            SvcParamValue::DohPath(v) => Some(v),
            _ => None,
        }
    }

    /// Whether `ohttp` is present (RFC 9540 §4).
    #[inline]
    #[must_use]
    pub fn ohttp(&self) -> bool {
        self.contains(SvcParamKey::OHTTP)
    }

    /// The `tls-supported-groups` (draft-ietf-tls-key-share-prediction).
    #[must_use]
    pub fn tls_supported_groups(&self) -> Option<TlsSupportedGroups<'a>> {
        match self.value(SvcParamKey::TLS_SUPPORTED_GROUPS)? {
            SvcParamValue::TlsSupportedGroups(v) => Some(v),
            _ => None,
        }
    }

    /// The `docpath` segments (RFC 9953 §3).
    #[must_use]
    pub fn docpath(&self) -> Option<DocPath<'a>> {
        match self.value(SvcParamKey::DOCPATH)? {
            SvcParamValue::DocPath(v) => Some(v),
            _ => None,
        }
    }

    /// Whether `pvd` is present (draft-ietf-intarea-proxy-config).
    #[inline]
    #[must_use]
    pub fn pvd(&self) -> bool {
        self.contains(SvcParamKey::PVD)
    }

    /// The `oots` entries (draft-johani-dnsop-svcb-oots).
    #[must_use]
    pub fn oots(&self) -> Option<Oots<'a>> {
        match self.value(SvcParamKey::OOTS)? {
            SvcParamValue::Oots(v) => Some(v),
            _ => None,
        }
    }

    /// Convenience: the IPv4 hints, or an empty iterator.
    pub fn ipv4_hints(&self) -> impl Iterator<Item = Ipv4Addr> + use<'a> {
        self.ipv4hint().into_iter().flat_map(|h| h.iter())
    }

    /// Convenience: the IPv6 hints, or an empty iterator.
    pub fn ipv6_hints(&self) -> impl Iterator<Item = Ipv6Addr> + use<'a> {
        self.ipv6hint().into_iter().flat_map(|h| h.iter())
    }
}

impl<'a> IntoIterator for SvcParams<'a> {
    type Item = SvcParam<'a>;
    type IntoIter = SvcParamIter<'a>;

    #[inline]
    fn into_iter(self) -> SvcParamIter<'a> {
        self.iter()
    }
}

impl<'a> IntoIterator for &SvcParams<'a> {
    type Item = SvcParam<'a>;
    type IntoIter = SvcParamIter<'a>;
    #[inline]
    fn into_iter(self) -> SvcParamIter<'a> {
        self.iter()
    }
}

impl fmt::Display for SvcParams<'_> {
    /// Space-separated SvcParams in presentation format (RFC 9460 §2.1).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, p) in self.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            fmt::Display::fmt(&p, f)?;
        }
        Ok(())
    }
}

impl fmt::Debug for SvcParams<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// Splits raw `key, length, value` triples.
#[derive(Clone, Debug)]
pub(super) struct RawIter<'a>(pub(super) &'a [u8]);

impl<'a> RawIter<'a> {
    /// Reads the next triple, failing with [`Error::UnexpectedEof`] if it is
    /// incomplete (and then leaving the iterator unchanged).
    pub(super) fn next_checked(&mut self) -> Result<(SvcParamKey, &'a [u8])> {
        match self.0 {
            [k0, k1, l0, l1, rest @ ..] => {
                let len = usize::from(u16::from_be_bytes([*l0, *l1]));
                let (value, rest) = rest.split_at_checked(len).ok_or(Error::UnexpectedEof)?;
                self.0 = rest;
                Ok((SvcParamKey::new(u16::from_be_bytes([*k0, *k1])), value))
            }
            _ => Err(Error::UnexpectedEof),
        }
    }
}

/// Iterator over [`SvcParams`], in key order.
///
/// ```
/// use dnsbox::rdata::{SvcParamKey, Svcb};
///
/// let mut buf = [0u8; 64];
/// let svcb = Svcb::from_text("1 . port=443 alpn=h2 no-default-alpn", &mut buf)?;
/// let keys: Vec<SvcParamKey> = svcb.params.iter().map(|p| p.key()).collect();
/// assert_eq!(keys, [SvcParamKey::ALPN, SvcParamKey::NO_DEFAULT_ALPN, SvcParamKey::PORT]);
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Debug)]
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct SvcParamIter<'a>(RawIter<'a>);

impl<'a> Iterator for SvcParamIter<'a> {
    type Item = SvcParam<'a>;

    fn next(&mut self) -> Option<SvcParam<'a>> {
        match self.0.next_checked() {
            Ok((key, value)) => Some(SvcParam { key, value }),
            Err(_) => {
                // Unreachable for validated params; end the iteration.
                self.0.0 = &[];
                None
            }
        }
    }
}

impl core::iter::FusedIterator for SvcParamIter<'_> {}
