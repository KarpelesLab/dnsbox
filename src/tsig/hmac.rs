//! HMAC TSIG keys backed by `purecrypto` (feature `tsig`).
//!
//! dnsbox never implements a digest or HMAC: this module only adapts
//! `purecrypto::hash::Hmac` to the [`TsigKey`] / [`TsigMac`] traits.

use core::fmt;

use purecrypto::ct::ConstantTimeEq;
use purecrypto::hash::{Hmac, Md5, Sha1, Sha224, Sha256, Sha384, Sha512};

use super::algorithm::TsigAlgorithm;
use super::key::{MAX_MAC_LEN, TsigKey, TsigMac};
use super::verify::check_mac_size;
use crate::Result;
use crate::name::{Name, NameBuf, ToName};

/// A TSIG key for one of the HMAC algorithms of RFC 8945 §6, computed
/// with `purecrypto`.
///
/// The secret is borrowed (no allocation); decode it from base64 yourself
/// (e.g. from a BIND `key` statement).
///
/// ```
/// use dnsbox::NameBuf;
/// use dnsbox::tsig::{HmacKey, TsigAlgorithm, TsigKey};
///
/// let name: NameBuf = "tsig-key".parse()?;
/// let key = HmacKey::new(&name, TsigAlgorithm::HmacSha256, b"secret bytes");
/// assert_eq!(key.mac_len(), 32);
/// // Emit (and require) MACs truncated to 16 bytes, like BIND's
/// // `hmac-sha256-128` key option.
/// let short = key.with_mac_len(16)?;
/// assert_eq!(short.mac_len(), 16);
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone)]
pub struct HmacKey<'s> {
    name: NameBuf,
    algorithm: TsigAlgorithm,
    secret: &'s [u8],
    mac_len: usize,
}

impl<'s> HmacKey<'s> {
    /// A key named `name` using `algorithm` with the shared `secret`.
    ///
    /// The truncated algorithms (`hmac-sha256-128`, ...) generate and
    /// require MACs of their truncated length.
    pub fn new(name: impl ToName, algorithm: TsigAlgorithm, secret: &'s [u8]) -> Self {
        HmacKey {
            name: name.to_name().to_buf(),
            algorithm,
            secret,
            mac_len: algorithm.mac_len(),
        }
    }

    /// Sets the generated MAC length (truncation, RFC 8945 §5.2.2.1); it
    /// is also the shortest MAC accepted (BADTRUNC policy, §5.2.4). Fails
    /// with [`Error::BadMacSize`] outside the range the RFC allows.
    pub fn with_mac_len(mut self, len: usize) -> Result<Self> {
        check_mac_size(len, self.algorithm.digest_len())?;
        self.mac_len = len;
        Ok(self)
    }

    /// The algorithm.
    #[inline]
    pub const fn algorithm_id(&self) -> TsigAlgorithm {
        self.algorithm
    }
}

impl fmt::Debug for HmacKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the secret.
        f.debug_struct("HmacKey")
            .field("name", &self.name)
            .field("algorithm", &self.algorithm)
            .field("mac_len", &self.mac_len)
            .finish_non_exhaustive()
    }
}

/// A running HMAC computation for an [`HmacKey`].
#[derive(Clone)]
pub struct HmacState(State);

#[derive(Clone)]
enum State {
    Md5(Hmac<Md5>),
    Sha1(Hmac<Sha1>),
    Sha224(Hmac<Sha224>),
    Sha256(Hmac<Sha256>),
    Sha384(Hmac<Sha384>),
    Sha512(Hmac<Sha512>),
}

impl fmt::Debug for HmacState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HmacState(..)")
    }
}

fn copy_out(digest: &[u8], out: &mut [u8; MAX_MAC_LEN]) -> usize {
    let len = digest.len().min(MAX_MAC_LEN);
    if let (Some(dst), Some(src)) = (out.get_mut(..len), digest.get(..len)) {
        dst.copy_from_slice(src);
    }
    len
}

impl TsigMac for HmacState {
    fn update(&mut self, data: &[u8]) {
        match &mut self.0 {
            State::Md5(h) => h.update(data),
            State::Sha1(h) => h.update(data),
            State::Sha224(h) => h.update(data),
            State::Sha256(h) => h.update(data),
            State::Sha384(h) => h.update(data),
            State::Sha512(h) => h.update(data),
        }
    }

    fn finalize(self, out: &mut [u8; MAX_MAC_LEN]) -> usize {
        match self.0 {
            State::Md5(h) => copy_out(&h.finalize(), out),
            State::Sha1(h) => copy_out(&h.finalize(), out),
            State::Sha224(h) => copy_out(&h.finalize(), out),
            State::Sha256(h) => copy_out(&h.finalize(), out),
            State::Sha384(h) => copy_out(&h.finalize(), out),
            State::Sha512(h) => copy_out(&h.finalize(), out),
        }
    }

    fn verify(self, expected: &[u8]) -> bool {
        let mut full = [0u8; MAX_MAC_LEN];
        let len = self.finalize(&mut full);
        let ok = match full.get(..expected.len()) {
            Some(prefix) if !expected.is_empty() && expected.len() <= len => {
                bool::from(prefix.ct_eq(expected))
            }
            _ => false,
        };
        full.fill(0);
        ok
    }
}

impl TsigKey for HmacKey<'_> {
    type Mac = HmacState;

    fn name(&self) -> Name<'_> {
        self.name.as_name()
    }

    fn algorithm(&self) -> Name<'_> {
        self.algorithm.name()
    }

    fn digest_len(&self) -> usize {
        self.algorithm.digest_len()
    }

    fn mac_len(&self) -> usize {
        self.mac_len
    }

    fn new_mac(&self) -> HmacState {
        let k = self.secret;
        HmacState(match self.algorithm {
            TsigAlgorithm::HmacMd5 => State::Md5(Hmac::new(k)),
            TsigAlgorithm::HmacSha1 => State::Sha1(Hmac::new(k)),
            TsigAlgorithm::HmacSha224 => State::Sha224(Hmac::new(k)),
            TsigAlgorithm::HmacSha256 | TsigAlgorithm::HmacSha256_128 => {
                State::Sha256(Hmac::new(k))
            }
            TsigAlgorithm::HmacSha384 | TsigAlgorithm::HmacSha384_192 => {
                State::Sha384(Hmac::new(k))
            }
            TsigAlgorithm::HmacSha512 | TsigAlgorithm::HmacSha512_256 => {
                State::Sha512(Hmac::new(k))
            }
        })
    }
}
