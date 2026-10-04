//! The pluggable MAC interface: [`TsigKey`], [`TsigMac`], [`KeyStore`].

use core::fmt;

use crate::name::Name;
use crate::{Error, Result};

/// The longest MAC dnsbox handles, in bytes (HMAC-SHA512).
pub const MAX_MAC_LEN: usize = 64;

/// A running MAC computation (one per signed or verified message).
///
/// Implementations wrap a real MAC from a crypto library; dnsbox only
/// feeds bytes in the order RFC 8945 §4.3 prescribes. See [`TsigKey`] for
/// an implementation, and [`HmacState`] (feature `tsig`)
/// for the `purecrypto` one.
///
/// ```
/// use dnsbox::tsig::{MAX_MAC_LEN, TsigMac};
///
/// // dnsbox drives a MAC like this: feed, then finalize or verify.
/// fn mac_of<M: TsigMac>(mut mac: M, parts: &[&[u8]]) -> ([u8; MAX_MAC_LEN], usize) {
///     for part in parts {
///         mac.update(part);
///     }
///     let mut out = [0u8; MAX_MAC_LEN];
///     let len = mac.finalize(&mut out);
///     (out, len)
/// }
/// ```
///
#[cfg_attr(feature = "tsig", doc = "[`HmacState`]: super::HmacState")]
#[cfg_attr(not(feature = "tsig"), doc = "[`HmacState`]: crate#cargo-features")]
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
///
/// [`HmacKey`] (feature `tsig`) implements it with
/// `purecrypto`. Other backends implement both traits:
///
/// ```
/// use dnsbox::tsig::{MAX_MAC_LEN, TsigKey, TsigMac};
/// use dnsbox::{Name, NameBuf};
///
/// /// A (deliberately insecure) toy MAC: XOR of all bytes, as a sketch of
/// /// the shape. Wrap a real HMAC from your crypto library instead.
/// struct XorMac(u8);
///
/// impl TsigMac for XorMac {
///     fn update(&mut self, data: &[u8]) {
///         self.0 = data.iter().fold(self.0, |a, b| a ^ b);
///     }
///     fn finalize(self, out: &mut [u8; MAX_MAC_LEN]) -> usize {
///         out[..16].fill(self.0);
///         16
///     }
///     fn verify(self, expected: &[u8]) -> bool {
///         expected.iter().all(|&b| b == self.0) // use a constant-time compare
///     }
/// }
///
/// struct XorKey(NameBuf);
///
/// impl TsigKey for XorKey {
///     type Mac = XorMac;
///     fn name(&self) -> Name<'_> {
///         self.0.as_name()
///     }
///     fn algorithm(&self) -> Name<'_> {
///         Name::from_wire(b"\x07xor-mac\x00").unwrap()
///     }
///     fn digest_len(&self) -> usize {
///         16
///     }
///     fn new_mac(&self) -> XorMac {
///         XorMac(0)
///     }
/// }
/// ```
///
#[cfg_attr(feature = "tsig", doc = "[`HmacKey`]: super::HmacKey")]
#[cfg_attr(not(feature = "tsig"), doc = "[`HmacKey`]: crate#cargo-features")]
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
///
/// ```
/// # #[cfg(feature = "tsig")] {
/// use dnsbox::NameBuf;
/// use dnsbox::tsig::{HmacKey, KeyStore, TsigAlgorithm, TsigKey};
///
/// let (a, b): (NameBuf, NameBuf) = ("xfr-key".parse()?, "update-key".parse()?);
/// let keys = [
///     HmacKey::new(&a, TsigAlgorithm::HmacSha256, b"secret one"),
///     HmacKey::new(&b, TsigAlgorithm::HmacSha512, b"secret two"),
/// ];
/// let found = keys.find_key(b.as_name(), TsigAlgorithm::HmacSha512.name()).expect("known key");
/// assert_eq!(found.name(), b.as_name());
/// assert!(keys.find_key(b.as_name(), TsigAlgorithm::HmacSha256.name()).is_none());
/// # }
/// # Ok::<(), dnsbox::Error>(())
/// ```
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
///
/// ```
/// # #[cfg(feature = "tsig")] {
/// use dnsbox::tsig::{HmacKey, MacBuf, TsigAlgorithm, TsigSigner};
/// use dnsbox::{Class, MessageBuilder, NameBuf, Rtype};
///
/// let key_name: NameBuf = "k".parse()?;
/// let key = HmacKey::new(&key_name, TsigAlgorithm::HmacSha384, b"secret");
/// let zone: NameBuf = "example.com".parse()?;
/// let mut buf = [0u8; 256];
/// let mut b = MessageBuilder::query(&mut buf, 1, &zone, Rtype::SOA, Class::IN)?;
/// let mac: MacBuf = TsigSigner::request(&key).sign(&mut b, 1_700_000_000)?;
/// assert_eq!(mac.len(), 48);
/// // Keep it to verify the response: `TsigVerifier::new(&key, mac.as_slice())`.
/// # }
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacBuf {
    buf: [u8; MAX_MAC_LEN],
    len: u8,
}

impl MacBuf {
    /// Copies a MAC.
    ///
    /// # Errors
    ///
    /// [`Error::BadMacSize`] beyond [`MAX_MAC_LEN`] bytes.
    ///
    /// ```
    /// use dnsbox::tsig::MacBuf;
    ///
    /// let mac = MacBuf::new(&[0xab; 32])?;
    /// assert_eq!(mac.len(), 32);
    /// assert!(MacBuf::new(&[0; 65]).is_err());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
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
