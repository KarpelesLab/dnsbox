//! The `purecrypto`-backed signature backend (feature `dnssec`).
//!
//! Supported algorithms, for both verification and signing:
//! RSASHA1 (5), RSASHA1-NSEC3-SHA1 (7), RSASHA256 (8), RSASHA512 (10)
//! (RFC 3110, RFC 5702), ECDSAP256SHA256 (13), ECDSAP384SHA384 (14)
//! (RFC 6605), ED25519 (15) and ED448 (16) (RFC 8080). RSA/MD5, DSA and
//! GOST are not supported (RFC 8624 §3.1 forbids validating RSAMD5).

use alloc::vec::Vec;
use core::fmt;

use purecrypto::bignum::BoxedUint;
use purecrypto::ec::ecdsa::{EcdsaPrivateKey, EcdsaPublicKey, Signature as P256Signature};
use purecrypto::ec::{
    BoxedEcdsaPrivateKey, BoxedEcdsaPublicKey, BoxedEcdsaSignature, CurveId, Ed448PrivateKey,
    Ed448PublicKey, Ed448Signature, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature,
};
use purecrypto::hash::{Sha1, Sha256, Sha384, Sha512};
use purecrypto::rng::{CryptoRng, RngCore};
use purecrypto::rsa::{BoxedRsaPrivateKey, BoxedRsaPublicKey, Pkcs1Digest};

use super::{Algorithm, RsaPublicKey, Signer, Verifier};
use crate::{Error, Result};

/// Smallest RSA modulus accepted, in bits (RFC 3110 §2, RFC 5702 §2).
const MIN_RSA_BITS: usize = 512;
/// Smallest RSA modulus accepted for RSASHA512, in bits (RFC 5702 §2).
const MIN_RSASHA512_BITS: usize = 1024;
/// Largest RSA modulus accepted, in bits (RFC 3110 §2, RFC 5702 §2).
const MAX_RSA_BITS: usize = 4096;
/// Largest RSA public exponent accepted, in octets. RFC 3110 allows up to
/// 4096 bits, but verification cost grows with the exponent size and real
/// keys use 3 or 65537, so exponents are capped at 256 bits (the FIPS
/// 186-5 bound) to keep the work per signature small.
const MAX_RSA_EXPONENT_LEN: usize = 32;
/// Default RSA key size for [`SigningKey::generate`].
const DEFAULT_RSA_BITS: usize = 2048;

/// Whether the backend handles `algorithm`.
const fn supported(algorithm: Algorithm) -> bool {
    matches!(algorithm.get(), 5 | 7 | 8 | 10 | 13 | 14 | 15 | 16)
}

/// The minimum RSA modulus size for `algorithm`.
fn min_rsa_bits(algorithm: Algorithm) -> usize {
    if algorithm == Algorithm::RSASHA512 {
        MIN_RSASHA512_BITS
    } else {
        MIN_RSA_BITS
    }
}

/// A [`Verifier`] backed by `purecrypto`.
///
/// RSA keys are accepted with moduli of 512 to 4096 bits (1024 to 4096
/// for RSASHA512) and exponents of at most 256 bits; ECDSA points must be
/// on the curve.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PurecryptoVerifier;

impl Verifier for PurecryptoVerifier {
    fn supports(&self, algorithm: Algorithm) -> bool {
        supported(algorithm)
    }

    fn verify(
        &self,
        algorithm: Algorithm,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        match algorithm {
            Algorithm::RSASHA1 | Algorithm::RSASHA1_NSEC3_SHA1 => {
                verify_rsa::<Sha1>(algorithm, public_key, data, signature)
            }
            Algorithm::RSASHA256 => verify_rsa::<Sha256>(algorithm, public_key, data, signature),
            Algorithm::RSASHA512 => verify_rsa::<Sha512>(algorithm, public_key, data, signature),
            Algorithm::ECDSAP256SHA256 => {
                let key = p256_public(public_key)?;
                let sig: &[u8; 64] = signature.try_into().map_err(|_| Error::BadSignature)?;
                key.verify::<Sha256>(data, &P256Signature::from_bytes(sig))
                    .map_err(|_| Error::BadSignature)
            }
            Algorithm::ECDSAP384SHA384 => {
                let key = p384_public(public_key)?;
                if signature.len() != 96 {
                    return Err(Error::BadSignature);
                }
                let (r, s) = signature.split_at(48);
                let sig = BoxedEcdsaSignature::from_components(
                    BoxedUint::from_be_bytes(r),
                    BoxedUint::from_be_bytes(s),
                );
                key.verify::<Sha384>(data, &sig)
                    .map_err(|_| Error::BadSignature)
            }
            Algorithm::ED25519 => {
                let key: [u8; 32] = public_key.try_into().map_err(|_| Error::InvalidKey)?;
                let sig: [u8; 64] = signature.try_into().map_err(|_| Error::BadSignature)?;
                Ed25519PublicKey::from_bytes(key)
                    .verify(data, &Ed25519Signature::from_bytes(sig))
                    .map_err(|_| Error::BadSignature)
            }
            Algorithm::ED448 => {
                let key: [u8; 57] = public_key.try_into().map_err(|_| Error::InvalidKey)?;
                let sig: [u8; 114] = signature.try_into().map_err(|_| Error::BadSignature)?;
                Ed448PublicKey::from_bytes(key)
                    .verify(data, &Ed448Signature::from_bytes(sig))
                    .map_err(|_| Error::BadSignature)
            }
            _ => Err(Error::UnsupportedAlgorithm),
        }
    }
}

/// Parses and checks an RFC 3110 RSA public key.
fn rsa_public(algorithm: Algorithm, public_key: &[u8]) -> Result<BoxedRsaPublicKey> {
    let key = RsaPublicKey::from_dnskey(public_key)?;
    let bits = key.modulus_bits();
    if !(min_rsa_bits(algorithm)..=MAX_RSA_BITS).contains(&bits)
        || key.exponent.len() > MAX_RSA_EXPONENT_LEN
    {
        return Err(Error::InvalidKey);
    }
    let n = BoxedUint::from_be_bytes(key.modulus);
    let e = BoxedUint::from_be_bytes(key.exponent);
    // An even modulus is never a product of two odd primes (and would make
    // the Montgomery setup panic); e must be odd, >= 3 and below n.
    if !n.is_odd() || !e.is_odd() || e.bit_len() < 2 || !e.lt(&n) {
        return Err(Error::InvalidKey);
    }
    Ok(BoxedRsaPublicKey::new(n, e))
}

fn verify_rsa<D: Pkcs1Digest>(
    algorithm: Algorithm,
    public_key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<()> {
    let key = rsa_public(algorithm, public_key)?;
    let k = key.modulus().bit_len().div_ceil(8);
    // The signature is as long as the modulus (RFC 3110 §3); tolerate
    // signers that strip leading zero octets.
    let mut padded = alloc::vec![0u8; k];
    let pad = k.checked_sub(signature.len()).ok_or(Error::BadSignature)?;
    padded
        .get_mut(pad..)
        .ok_or(Error::BadSignature)?
        .copy_from_slice(signature);
    key.verify_pkcs1v15::<D>(data, &padded)
        .map_err(|_| Error::BadSignature)
}

/// Builds the uncompressed SEC1 encoding `0x04 || x || y` of a DNSKEY
/// ECDSA key (RFC 6605 §4).
fn sec1<const N: usize>(public_key: &[u8]) -> Result<[u8; N]> {
    let mut out = [0u8; N];
    let (tag, rest) = out.split_first_mut().ok_or(Error::InvalidKey)?;
    if rest.len() != public_key.len() {
        return Err(Error::InvalidKey);
    }
    *tag = 0x04;
    rest.copy_from_slice(public_key);
    Ok(out)
}

fn p256_public(public_key: &[u8]) -> Result<EcdsaPublicKey> {
    EcdsaPublicKey::from_sec1(&sec1::<65>(public_key)?).map_err(|_| Error::InvalidKey)
}

fn p384_public(public_key: &[u8]) -> Result<BoxedEcdsaPublicKey> {
    BoxedEcdsaPublicKey::from_sec1(CurveId::P384, &sec1::<97>(public_key)?)
        .map_err(|_| Error::InvalidKey)
}

/// A private key usable by [`SigningKey`] (`purecrypto` types).
#[derive(Clone)]
#[non_exhaustive]
pub enum PrivateKey {
    /// An RSA key, for RSASHA1, RSASHA1-NSEC3-SHA1, RSASHA256 and
    /// RSASHA512.
    Rsa(BoxedRsaPrivateKey),
    /// A P-256 key, for ECDSAP256SHA256.
    EcdsaP256(EcdsaPrivateKey),
    /// A P-384 key, for ECDSAP384SHA384.
    EcdsaP384(BoxedEcdsaPrivateKey),
    /// An Ed25519 key.
    Ed25519(Ed25519PrivateKey),
    /// An Ed448 key.
    Ed448(Ed448PrivateKey),
}

impl fmt::Debug for PrivateKey {
    /// Names the key type without revealing secret material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PrivateKey::Rsa(_) => "PrivateKey::Rsa(..)",
            PrivateKey::EcdsaP256(_) => "PrivateKey::EcdsaP256(..)",
            PrivateKey::EcdsaP384(_) => "PrivateKey::EcdsaP384(..)",
            PrivateKey::Ed25519(_) => "PrivateKey::Ed25519(..)",
            PrivateKey::Ed448(_) => "PrivateKey::Ed448(..)",
        })
    }
}

/// A DNSSEC private key backed by `purecrypto`: a [`Signer`] for RRSIG
/// generation, and the source of the matching DNSKEY (and, through
/// [`ZoneKey::ds`](super::ZoneKey::ds), DS) records.
///
/// Every supported algorithm signs deterministically (PKCS#1 v1.5,
/// RFC 6979 ECDSA, EdDSA), so no random number generator is needed after
/// key generation.
///
/// ```
/// use dnsbox::dnssec::{Algorithm, Signer, SigningKey, PurecryptoVerifier, Verifier};
/// use dnsbox::rdata::Dnskey;
///
/// // The RFC 8080 §6.1 example key.
/// let seed = [
///     0x38, 0x32, 0x32, 0x36, 0x30, 0x33, 0x38, 0x34, 0x36, 0x32, 0x38, 0x30, 0x38, 0x30, 0x31, 0x32,
///     0x32, 0x36, 0x34, 0x35, 0x31, 0x39, 0x30, 0x32, 0x30, 0x34, 0x31, 0x34, 0x32, 0x32, 0x36, 0x32,
/// ];
/// let key = SigningKey::from_private_bytes(Algorithm::ED25519, &seed)?;
/// assert_eq!(key.dnskey(Dnskey::ZONE | Dnskey::SEP).key_tag(), 3613);
///
/// let mut sig = [0u8; 64];
/// let len = key.sign(b"data", &mut sig)?;
/// PurecryptoVerifier.verify(Algorithm::ED25519, key.public_key(), b"data", &sig[..len])?;
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone)]
pub struct SigningKey {
    algorithm: Algorithm,
    key: PrivateKey,
    public_key: Vec<u8>,
}

impl SigningKey {
    /// Wraps a `purecrypto` private key for `algorithm`.
    ///
    /// Fails with [`Error::UnsupportedAlgorithm`] if the key type does not
    /// match the algorithm (or the algorithm is not supported), and with
    /// [`Error::InvalidKey`] for an RSA modulus outside 512–4096 bits
    /// (1024–4096 for RSASHA512) or exponent above 256 bits, or a
    /// non-P-384 key for ECDSAP384SHA384.
    pub fn new(algorithm: Algorithm, key: PrivateKey) -> Result<Self> {
        let public_key = match (&key, algorithm) {
            (
                PrivateKey::Rsa(k),
                Algorithm::RSASHA1
                | Algorithm::RSASHA1_NSEC3_SHA1
                | Algorithm::RSASHA256
                | Algorithm::RSASHA512,
            ) => {
                let n = k.modulus();
                let public = k.public_key();
                let e = public.exponent();
                let bits = n.bit_len();
                if !(min_rsa_bits(algorithm)..=MAX_RSA_BITS).contains(&bits)
                    || e.bit_len() > MAX_RSA_EXPONENT_LEN * 8
                    || e.bit_len() < 2
                {
                    return Err(Error::InvalidKey);
                }
                let n = n.to_be_bytes(bits.div_ceil(8));
                let e = e.to_be_bytes(e.bit_len().div_ceil(8));
                let mut out = Vec::new();
                RsaPublicKey {
                    exponent: &e,
                    modulus: &n,
                }
                .compose(&mut out)?;
                out
            }
            (PrivateKey::EcdsaP256(k), Algorithm::ECDSAP256SHA256) => {
                k.public_key().to_sec1().get(1..).unwrap_or(&[]).to_vec()
            }
            (PrivateKey::EcdsaP384(k), Algorithm::ECDSAP384SHA384) => {
                if k.curve() != CurveId::P384 {
                    return Err(Error::InvalidKey);
                }
                k.public_key().to_sec1().get(1..).unwrap_or(&[]).to_vec()
            }
            (PrivateKey::Ed25519(k), Algorithm::ED25519) => k.public_key().to_bytes().to_vec(),
            (PrivateKey::Ed448(k), Algorithm::ED448) => k.public_key().to_bytes().to_vec(),
            _ => return Err(Error::UnsupportedAlgorithm),
        };
        Ok(SigningKey {
            algorithm,
            key,
            public_key,
        })
    }

    /// Builds a key for an ECDSA or EdDSA `algorithm` from its private key
    /// octets: the big-endian scalar for ECDSA (32 octets for P-256, 48 for
    /// P-384, RFC 6605 §6) or the seed for EdDSA (32 octets for Ed25519,
    /// 57 for Ed448, RFC 8080 §6) — the `PrivateKey:` field of BIND's
    /// private key format.
    ///
    /// Fails with [`Error::InvalidKey`] for a wrong length or an
    /// out-of-range scalar, and [`Error::UnsupportedAlgorithm`] for other
    /// algorithms (use [`SigningKey::from_rsa_components`] for RSA).
    pub fn from_private_bytes(algorithm: Algorithm, bytes: &[u8]) -> Result<Self> {
        let key = match algorithm {
            Algorithm::ECDSAP256SHA256 => {
                let b: &[u8; 32] = bytes.try_into().map_err(|_| Error::InvalidKey)?;
                PrivateKey::EcdsaP256(
                    EcdsaPrivateKey::from_bytes(b).map_err(|_| Error::InvalidKey)?,
                )
            }
            Algorithm::ECDSAP384SHA384 => {
                if bytes.len() != 48 {
                    return Err(Error::InvalidKey);
                }
                PrivateKey::EcdsaP384(
                    BoxedEcdsaPrivateKey::from_bytes(CurveId::P384, bytes)
                        .map_err(|_| Error::InvalidKey)?,
                )
            }
            Algorithm::ED25519 => {
                let b: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidKey)?;
                PrivateKey::Ed25519(Ed25519PrivateKey::from_bytes(b))
            }
            Algorithm::ED448 => {
                let b: [u8; 57] = bytes.try_into().map_err(|_| Error::InvalidKey)?;
                PrivateKey::Ed448(Ed448PrivateKey::from_bytes(b))
            }
            _ => return Err(Error::UnsupportedAlgorithm),
        };
        SigningKey::new(algorithm, key)
    }

    /// Builds an RSA key from its big-endian components: modulus `n`,
    /// public exponent `e`, private exponent `d` and, optionally (pass
    /// empty slices otherwise), the primes `p` and `q`, which enable the
    /// faster and blinded CRT path — the `Modulus`, `PublicExponent`,
    /// `PrivateExponent`, `Prime1` and `Prime2` fields of BIND's private
    /// key format (RFC 5702 §6).
    ///
    /// The components are trusted to form a valid key; inconsistent ones
    /// produce signatures that do not verify. Fails with
    /// [`Error::InvalidKey`] for an even or out-of-range modulus, an
    /// unusable exponent, or only one prime.
    pub fn from_rsa_components(
        algorithm: Algorithm,
        n: &[u8],
        e: &[u8],
        d: &[u8],
        p: &[u8],
        q: &[u8],
    ) -> Result<Self> {
        if !algorithm.is_rsa() || algorithm == Algorithm::RSAMD5 {
            return Err(Error::UnsupportedAlgorithm);
        }
        let n = BoxedUint::from_be_bytes(n);
        let e = BoxedUint::from_be_bytes(e);
        let d = BoxedUint::from_be_bytes(d);
        if !n.is_odd() || !e.is_odd() || !e.lt(&n) || d.is_zero() || !d.lt(&n) {
            return Err(Error::InvalidKey);
        }
        let key = match (p.is_empty(), q.is_empty()) {
            (true, true) => BoxedRsaPrivateKey::from_components(n, e, d),
            (false, false) => BoxedRsaPrivateKey::from_components_with_primes(
                n,
                e,
                d,
                BoxedUint::from_be_bytes(p),
                BoxedUint::from_be_bytes(q),
            ),
            _ => return Err(Error::InvalidKey),
        };
        SigningKey::new(algorithm, PrivateKey::Rsa(key))
    }

    /// Generates a new key for `algorithm` (RSA keys get a 2048-bit
    /// modulus and exponent 65537). `rng` must be a cryptographically
    /// secure generator, e.g. `purecrypto::rng::OsRng` with the `std`
    /// feature.
    pub fn generate<R: RngCore + CryptoRng>(algorithm: Algorithm, rng: &mut R) -> Result<Self> {
        let key = match algorithm {
            a if a.is_rsa() => return Self::generate_rsa(algorithm, DEFAULT_RSA_BITS, rng),
            Algorithm::ECDSAP256SHA256 => PrivateKey::EcdsaP256(EcdsaPrivateKey::generate(rng)),
            Algorithm::ECDSAP384SHA384 => {
                PrivateKey::EcdsaP384(BoxedEcdsaPrivateKey::generate(CurveId::P384, rng))
            }
            Algorithm::ED25519 => PrivateKey::Ed25519(Ed25519PrivateKey::generate(rng)),
            Algorithm::ED448 => PrivateKey::Ed448(Ed448PrivateKey::generate(rng)),
            _ => return Err(Error::UnsupportedAlgorithm),
        };
        SigningKey::new(algorithm, key)
    }

    /// Generates a new RSA key with a `bits`-bit modulus (an even number
    /// from 1024 to 4096) and exponent 65537.
    pub fn generate_rsa<R: RngCore + CryptoRng>(
        algorithm: Algorithm,
        bits: usize,
        rng: &mut R,
    ) -> Result<Self> {
        if !algorithm.is_rsa() || algorithm == Algorithm::RSAMD5 {
            return Err(Error::UnsupportedAlgorithm);
        }
        if !(1024..=MAX_RSA_BITS).contains(&bits) || !bits.is_multiple_of(2) {
            return Err(Error::InvalidKey);
        }
        // purecrypto raises the Miller-Rabin count to the FIPS 186-5
        // minimum for the size when given fewer rounds.
        let key = BoxedRsaPrivateKey::generate(bits, BoxedUint::from_u64(65537), rng, 0);
        SigningKey::new(algorithm, PrivateKey::Rsa(key))
    }

    /// The private key.
    #[inline]
    pub fn private_key(&self) -> &PrivateKey {
        &self.key
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("algorithm", &self.algorithm)
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl Signer for SigningKey {
    #[inline]
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    #[inline]
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn signature_len(&self) -> usize {
        match &self.key {
            PrivateKey::Rsa(k) => k.modulus().bit_len().div_ceil(8),
            PrivateKey::EcdsaP256(_) => 64,
            PrivateKey::EcdsaP384(_) => 96,
            PrivateKey::Ed25519(_) => 64,
            PrivateKey::Ed448(_) => 114,
        }
    }

    fn sign(&self, data: &[u8], out: &mut [u8]) -> Result<usize> {
        let len = self.signature_len();
        let out = out.get_mut(..len).ok_or(Error::BufferTooSmall)?;
        match &self.key {
            PrivateKey::Rsa(k) => {
                let sig = match self.algorithm {
                    Algorithm::RSASHA256 => k.sign_pkcs1v15::<Sha256>(data),
                    Algorithm::RSASHA512 => k.sign_pkcs1v15::<Sha512>(data),
                    _ => k.sign_pkcs1v15::<Sha1>(data),
                }
                .map_err(|_| Error::InvalidKey)?;
                if sig.len() != len {
                    return Err(Error::InvalidKey);
                }
                out.copy_from_slice(&sig);
            }
            PrivateKey::EcdsaP256(k) => {
                let sig = k.sign::<Sha256>(data).map_err(|_| Error::InvalidKey)?;
                out.copy_from_slice(&sig.to_bytes());
            }
            PrivateKey::EcdsaP384(k) => {
                let sig = k.sign::<Sha384>(data).map_err(|_| Error::InvalidKey)?;
                let sig = sig.to_bytes(CurveId::P384);
                if sig.len() != len {
                    return Err(Error::InvalidKey);
                }
                out.copy_from_slice(&sig);
            }
            PrivateKey::Ed25519(k) => out.copy_from_slice(&k.sign(data).to_bytes()),
            PrivateKey::Ed448(k) => out.copy_from_slice(&k.sign(data).to_bytes()),
        }
        Ok(len)
    }
}

#[cfg(test)]
mod tests;
