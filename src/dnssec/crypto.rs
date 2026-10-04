//! Pluggable signature backends: the [`Verifier`] and [`Signer`] traits.
//!
//! dnsbox builds the data to be signed (RFC 4034 §3.1.8.1) and checks
//! everything that is not cryptography; a backend only verifies or creates
//! the raw signature. The `dnssec` feature provides one backed by
//! `purecrypto` ([`PurecryptoVerifier`](super::PurecryptoVerifier),
//! [`SigningKey`](super::SigningKey)); other crypto libraries can be
//! plugged in by implementing these traits.

use super::Algorithm;
use crate::Result;
use crate::rdata::Dnskey;

/// Verifies DNSSEC signatures.
///
/// Implementations receive the public key in its DNSKEY wire format
/// (RFC 3110 §2 for RSA, `x || y` for ECDSA per RFC 6605 §4, the raw
/// point for EdDSA per RFC 8080 §3), the signed data, and the signature in
/// its RRSIG wire format (RFC 3110 §3, RFC 5702 §3, RFC 6605 §4,
/// RFC 8080 §4).
///
/// # Examples
///
/// A backend that delegates to another one but no longer accepts the
/// SHA-1-based algorithms (a local policy; RFC 8624 §3.1 already advises
/// against signing with them):
///
/// ```
/// use dnsbox::dnssec::{Algorithm, Verifier};
/// use dnsbox::{Error, Result};
///
/// struct NoSha1<V>(V);
///
/// impl<V: Verifier> Verifier for NoSha1<V> {
///     fn supports(&self, algorithm: Algorithm) -> bool {
///         !matches!(algorithm, Algorithm::RSASHA1 | Algorithm::RSASHA1_NSEC3_SHA1)
///             && self.0.supports(algorithm)
///     }
///     fn verify(&self, algorithm: Algorithm, key: &[u8], data: &[u8], sig: &[u8]) -> Result<()> {
///         if !self.supports(algorithm) {
///             return Err(Error::UnsupportedAlgorithm);
///         }
///         self.0.verify(algorithm, key, data, sig)
///     }
/// }
/// # #[cfg(feature = "dnssec")]
/// assert!(!NoSha1(dnsbox::dnssec::PurecryptoVerifier).supports(Algorithm::RSASHA1));
/// ```
pub trait Verifier {
    /// Whether signatures of `algorithm` can be verified. Data signed only
    /// with unsupported algorithms is treated as insecure, not bogus
    /// (RFC 4035 §5.2).
    fn supports(&self, algorithm: Algorithm) -> bool;

    /// Verifies `signature` over `data` with `public_key`.
    ///
    /// # Errors
    ///
    /// Must fail with [`Error::UnsupportedAlgorithm`] for unsupported
    /// algorithms, [`Error::InvalidKey`] for malformed keys and
    /// [`Error::BadSignature`] when the signature does not verify.
    ///
    /// [`Error::UnsupportedAlgorithm`]: crate::Error::UnsupportedAlgorithm
    /// [`Error::InvalidKey`]: crate::Error::InvalidKey
    /// [`Error::BadSignature`]: crate::Error::BadSignature
    fn verify(
        &self,
        algorithm: Algorithm,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<()>;
}

impl<V: Verifier + ?Sized> Verifier for &V {
    #[inline]
    fn supports(&self, algorithm: Algorithm) -> bool {
        (**self).supports(algorithm)
    }

    #[inline]
    fn verify(
        &self,
        algorithm: Algorithm,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        (**self).verify(algorithm, public_key, data, signature)
    }
}

/// Creates DNSSEC signatures with one private key.
///
/// [`SigningKey`] implements it with `purecrypto`;
/// implement it to sign with a key held elsewhere (an HSM, a KMS, ...).
///
/// ```
/// # #[cfg(feature = "dnssec")] {
/// use dnsbox::dnssec::{Algorithm, Signer, SigningKey};
/// use dnsbox::rdata::Dnskey;
///
/// let key = SigningKey::from_private_bytes(Algorithm::ED25519, &[3; 32])?;
/// assert_eq!(key.algorithm(), Algorithm::ED25519);
/// assert_eq!(key.signature_len(), 64);
/// let dnskey = key.dnskey(Dnskey::ZONE);
/// assert_eq!(dnskey.public_key, key.public_key());
/// # }
/// # Ok::<(), dnsbox::Error>(())
/// ```
///
#[cfg_attr(feature = "dnssec", doc = "[`SigningKey`]: super::SigningKey")]
#[cfg_attr(not(feature = "dnssec"), doc = "[`SigningKey`]: crate#cargo-features")]
pub trait Signer {
    /// The key's algorithm.
    fn algorithm(&self) -> Algorithm;

    /// The public key in its DNSKEY wire format (see [`Verifier`]).
    fn public_key(&self) -> &[u8];

    /// The maximum length of a signature (exact for every algorithm
    /// supported by the `purecrypto` backend).
    fn signature_len(&self) -> usize;

    /// Signs `data`, writing the signature in its RRSIG wire format to the
    /// start of `out` and returning its length.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::BufferTooSmall`](crate::Error::BufferTooSmall)
    /// if `out` is shorter than [`signature_len`](Self::signature_len).
    fn sign(&self, data: &[u8], out: &mut [u8]) -> Result<usize>;

    /// The DNSKEY record data for this key, with `flags` (e.g.
    /// [`Dnskey::ZONE`], plus [`Dnskey::SEP`] for a key-signing key) and
    /// protocol 3 (RFC 4034 §2.1).
    fn dnskey(&self, flags: u16) -> Dnskey<'_> {
        Dnskey::new(flags, 3, self.algorithm(), self.public_key())
    }
}

impl<S: Signer + ?Sized> Signer for &S {
    #[inline]
    fn algorithm(&self) -> Algorithm {
        (**self).algorithm()
    }

    #[inline]
    fn public_key(&self) -> &[u8] {
        (**self).public_key()
    }

    #[inline]
    fn signature_len(&self) -> usize {
        (**self).signature_len()
    }

    #[inline]
    fn sign(&self, data: &[u8], out: &mut [u8]) -> Result<usize> {
        (**self).sign(data, out)
    }
}
