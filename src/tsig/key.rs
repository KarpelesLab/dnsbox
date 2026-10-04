//! The pluggable MAC interface: [`TsigKey`], [`TsigMac`], [`KeyStore`].

use core::fmt;

use crate::name::Name;
use crate::{Error, Result};

/// The longest MAC dnsbox handles, in bytes (HMAC-SHA512).
pub const MAX_MAC_LEN: usize = 64;

/// A running MAC computation (one per signed or verified message).
///
/// Implementations wrap a real MAC from a crypto library; dnsbox only
/// feeds bytes in the order RFC 8945 §4.3 prescribes.
pub trait TsigMac {
    /// Feeds message bytes.
    fn update(&mut self, data: &[u8]);

    /// Finishes the computation and writes the full-length MAC to the start
    /// of `out`, returning its length (at most [`MAX_MAC_LEN`]).
    fn finalize(self, out: &mut [u8; MAX_MAC_LEN]) -> usize;

    /// Finishes the computation and checks `expected` against the first
    /// `expected.len()` bytes of the MAC (a truncated MAC, RFC 8945
    /// §5.2.2.1), **in constant time**. dnsbox has already checked that
    /// `expected` is between the truncation floor and the full length.
    fn verify(self, expected: &[u8]) -> bool;
}

/// A TSIG key: its name, its algorithm, and a factory for keyed MACs.
pub trait TsigKey {
    /// The MAC computation this key produces.
    type Mac: TsigMac;

    /// The key name (the owner name of the TSIG record, RFC 8945 §4.2).
    fn name(&self) -> Name<'_>;

    /// The algorithm name (e.g. `hmac-sha256.`).
    fn algorithm(&self) -> Name<'_>;

    /// Full output length of the MAC function, in bytes (at most
    /// [`MAX_MAC_LEN`]).
    fn digest_len(&self) -> usize;

    /// Length of the MAC this key generates (a truncation, RFC 8945
    /// §5.2.2.1, when shorter than [`digest_len`](Self::digest_len)). It is
    /// also the local truncation policy: a received MAC shorter than this
    /// is rejected with BADTRUNC (§5.2.4). Defaults to the full length.
    fn mac_len(&self) -> usize {
        self.digest_len()
    }

    /// Starts a new MAC computation keyed with this key.
    fn new_mac(&self) -> Self::Mac;
}

impl<K: TsigKey + ?Sized> TsigKey for &K {
    type Mac = K::Mac;

    #[inline]
    fn name(&self) -> Name<'_> {
        (**self).name()
    }

    #[inline]
    fn algorithm(&self) -> Name<'_> {
        (**self).algorithm()
    }

    #[inline]
    fn digest_len(&self) -> usize {
        (**self).digest_len()
    }

    #[inline]
    fn mac_len(&self) -> usize {
        (**self).mac_len()
    }

    #[inline]
    fn new_mac(&self) -> Self::Mac {
        (**self).new_mac()
    }
}

/// A set of keys a server accepts, looked up by key name and algorithm
/// (RFC 8945 §5.2.1).
///
/// Implemented by every [`TsigKey`] (a single key) and by slices and arrays
/// of keys.
pub trait KeyStore {
    /// The key type.
    type Key: TsigKey;

    /// Finds the key with this name and algorithm (both compared
    /// ASCII-case-insensitively).
    fn find_key(&self, name: Name<'_>, algorithm: Name<'_>) -> Option<&Self::Key>;
}

fn key_matches<K: TsigKey>(key: &K, name: Name<'_>, algorithm: Name<'_>) -> bool {
    key.name() == name && key.algorithm() == algorithm
}

impl<K: TsigKey> KeyStore for K {
    type Key = K;

    fn find_key(&self, name: Name<'_>, algorithm: Name<'_>) -> Option<&K> {
        key_matches(self, name, algorithm).then_some(self)
    }
}

impl<K: TsigKey> KeyStore for [K] {
    type Key = K;

    fn find_key(&self, name: Name<'_>, algorithm: Name<'_>) -> Option<&K> {
        self.iter().find(|k| key_matches(*k, name, algorithm))
    }
}

impl<K: TsigKey, const N: usize> KeyStore for [K; N] {
    type Key = K;

    fn find_key(&self, name: Name<'_>, algorithm: Name<'_>) -> Option<&K> {
        self.as_slice().find_key(name, algorithm)
    }
}

/// A MAC value of up to [`MAX_MAC_LEN`] bytes, stored inline (no
/// allocation). Returned by signing, and used as the "prior MAC" of
/// responses and stream messages (RFC 8945 §4.3.1, §5.3.1).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacBuf {
    buf: [u8; MAX_MAC_LEN],
    len: u8,
}

impl MacBuf {
    /// Copies a MAC; fails with [`Error::BadMacSize`] beyond
    /// [`MAX_MAC_LEN`] bytes.
    pub fn new(mac: &[u8]) -> Result<Self> {
        let mut buf = [0u8; MAX_MAC_LEN];
        buf.get_mut(..mac.len())
            .ok_or(Error::BadMacSize)?
            .copy_from_slice(mac);
        Ok(MacBuf {
            buf,
            len: mac.len() as u8,
        })
    }

    /// The MAC bytes.
    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.buf.get(..self.len as usize).unwrap_or(&[])
    }

    /// The MAC length.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether the MAC is empty.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl AsRef<[u8]> for MacBuf {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl fmt::Debug for MacBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacBuf({})", crate::text::Hex(self.as_slice()))
    }
}
