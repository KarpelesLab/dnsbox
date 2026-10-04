//! DS digests (RFC 4034 §5.1.4, RFC 4509, RFC 6605 §6.2).

use super::canonical_name;
use crate::name::{MAX_NAME_LEN, Name};
use crate::rdata::{ComposeRdata, Dnskey};
use crate::wire::Composer;
use crate::Result;
#[cfg(feature = "dnssec-digest")]
use {
    super::{Algorithm, DigestType},
    crate::Error,
    crate::rdata::Ds,
};

/// Writes the data a DS digest is computed over: the DNSKEY owner name in
/// canonical form followed by the DNSKEY RDATA (RFC 4034 §5.1.4).
///
/// ```
/// use dnsbox::dnssec::{Algorithm, ds_digest_input};
/// use dnsbox::rdata::Dnskey;
/// use dnsbox::{NameBuf, WireWriter};
///
/// let owner: NameBuf = "Example.".parse()?;
/// let key = Dnskey::new(257, 3, Algorithm::ED25519, &[7; 32]);
/// let mut buf = [0u8; 64];
/// let mut w = WireWriter::new(&mut buf);
/// ds_digest_input(owner.as_name(), &key, &mut w)?;
/// assert!(w.written().starts_with(b"\x07example\x00\x01\x01\x03\x0f\x07"));
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn ds_digest_input<C: Composer + ?Sized>(
    owner: Name<'_>,
    key: &Dnskey<'_>,
    c: &mut C,
) -> Result<()> {
    let mut buf = [0u8; MAX_NAME_LEN];
    let len = canonical_name(owner, &mut buf);
    c.put_bytes(buf.get(..len).unwrap_or(&[]))?;
    key.compose_rdata(c)
}

/// A computed DS digest, with the key tag and algorithm of its DNSKEY: a
/// complete DS RDATA (RFC 4034 §5.1).
///
/// Supported digest types are SHA-1, SHA-256 and SHA-384, computed by
/// `purecrypto`.
///
/// ```
/// use dnsbox::dnssec::{Algorithm, DigestType, DsDigest};
/// use dnsbox::rdata::Dnskey;
/// use dnsbox::NameBuf;
///
/// let owner: NameBuf = "example.com".parse()?;
/// let key = Dnskey::new(257, 3, Algorithm::ED25519, &[7; 32]);
/// let ds = DsDigest::compute(owner.as_name(), &key, DigestType::SHA256)?;
/// assert_eq!(ds.digest().len(), 32);
/// assert_eq!(ds.to_ds().key_tag, key.key_tag());
/// assert!(ds.matches(&ds.to_ds()));
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[cfg(feature = "dnssec-digest")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec-digest")))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DsDigest {
    key_tag: u16,
    algorithm: Algorithm,
    digest_type: DigestType,
    digest: [u8; 48],
    len: u8,
}

#[cfg(feature = "dnssec-digest")]
impl DsDigest {
    /// Computes the DS digest of `key`, owned by `owner`, with
    /// `digest_type` (RFC 4034 §5.1.4).
    ///
    /// Fails with [`Error::UnsupportedAlgorithm`] for digest types other
    /// than SHA-1, SHA-256 and SHA-384.
    pub fn compute(owner: Name<'_>, key: &Dnskey<'_>, digest_type: DigestType) -> Result<Self> {
        use purecrypto::hash::{Sha1, Sha256, Sha384};
        let mut name = [0u8; MAX_NAME_LEN];
        let name_len = canonical_name(owner, &mut name);
        let [f0, f1] = key.flags.to_be_bytes();
        let parts: [&[u8]; 3] = [
            name.get(..name_len).unwrap_or(&[]),
            &[f0, f1, key.protocol, key.algorithm.get()],
            key.public_key,
        ];
        let mut digest = [0u8; 48];
        let len = match digest_type {
            DigestType::SHA1 => digest_parts::<Sha1>(&parts, &mut digest),
            DigestType::SHA256 => digest_parts::<Sha256>(&parts, &mut digest),
            DigestType::SHA384 => digest_parts::<Sha384>(&parts, &mut digest),
            _ => return Err(Error::UnsupportedAlgorithm),
        };
        Ok(DsDigest {
            key_tag: key.key_tag(),
            algorithm: key.algorithm,
            digest_type,
            digest,
            len: len as u8,
        })
    }

    /// The digest.
    #[inline]
    pub fn digest(&self) -> &[u8] {
        self.digest.get(..usize::from(self.len)).unwrap_or(&[])
    }

    /// The DS record data for this digest (convert with `.into()` for CDS).
    #[inline]
    pub fn to_ds(&self) -> Ds<'_> {
        Ds::new(self.key_tag, self.algorithm, self.digest_type, self.digest())
    }

    /// Whether `ds` matches this digest: same key tag, algorithm, digest
    /// type and digest (RFC 4035 §5.2).
    pub fn matches(&self, ds: &Ds<'_>) -> bool {
        ds.key_tag == self.key_tag
            && ds.algorithm == self.algorithm
            && ds.digest_type == self.digest_type
            && ds.digest == self.digest()
    }
}

/// Checks that `ds` authenticates `key`, owned by `owner`
/// (RFC 4035 §5.2): key tag, algorithm and digest must match.
///
/// Fails with [`Error::UnsupportedAlgorithm`] for unsupported digest
/// types, [`Error::KeyMismatch`] if the key tag or algorithm differ, and
/// [`Error::BadSignature`] if the digest does not match.
#[cfg(feature = "dnssec-digest")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec-digest")))]
pub fn verify_ds(ds: &Ds<'_>, owner: Name<'_>, key: &Dnskey<'_>) -> Result<()> {
    if ds.algorithm != key.algorithm || ds.key_tag != key.key_tag() {
        return Err(Error::KeyMismatch);
    }
    let digest = DsDigest::compute(owner, key, ds.digest_type)?;
    if digest.matches(ds) {
        Ok(())
    } else {
        Err(Error::BadSignature)
    }
}

/// Hashes the concatenation of `parts` with `D` into `out`, returning the
/// digest length.
#[cfg(feature = "dnssec-digest")]
pub(crate) fn digest_parts<D: purecrypto::hash::Digest>(parts: &[&[u8]], out: &mut [u8]) -> usize {
    let mut h = D::new();
    for p in parts {
        h.update(p);
    }
    let d = h.finalize();
    let d = d.as_ref();
    let len = d.len().min(out.len());
    if let (Some(dst), Some(src)) = (out.get_mut(..len), d.get(..len)) {
        dst.copy_from_slice(src);
    }
    len
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnssec::testvec;
    use crate::rdata::ParseRdata;
    use crate::testutil::hex;
    use crate::{NameBuf, WireReader};
    use std::vec::Vec;

    #[test]
    fn digest_input() {
        // RFC 4034 §5.4: DS for dskey.example.com.
        let key_wire = hex(testvec::RFC4034_DSKEY);
        let key = Dnskey::parse_rdata(&mut WireReader::new(&key_wire)).unwrap();
        assert_eq!(key.key_tag(), 60485);
        let owner = NameBuf::from_text(b"DSKEY.example.COM").unwrap();
        let mut out = Vec::new();
        ds_digest_input(owner.as_name(), &key, &mut out).unwrap();
        let mut expected = b"\x05dskey\x07example\x03com\x00".to_vec();
        expected.extend(&key_wire);
        assert_eq!(out, expected);
    }

    #[cfg(feature = "dnssec-digest")]
    #[test]
    fn digests() {
        use crate::dnssec::DigestType;
        let key_wire = hex(testvec::RFC4034_DSKEY);
        let key = Dnskey::parse_rdata(&mut WireReader::new(&key_wire)).unwrap();
        let owner = NameBuf::from_text(b"dskey.example.com").unwrap();
        // RFC 4034 §5.4.
        let d = DsDigest::compute(owner.as_name(), &key, DigestType::SHA1).unwrap();
        assert_eq!(d.digest(), hex("2BB183AF5F22588179A53B0A98631FAD1A292118"));
        let ds_wire = hex("ec45 05 01 2BB183AF5F22588179A53B0A98631FAD1A292118");
        let ds = Ds::parse_rdata(&mut WireReader::new(&ds_wire)).unwrap();
        assert_eq!(d.to_ds(), ds);
        assert!(d.matches(&ds));
        assert_eq!(verify_ds(&ds, owner.as_name(), &key), Ok(()));
        // Case of the owner name does not matter.
        let upper = NameBuf::from_text(b"DSKEY.EXAMPLE.COM").unwrap();
        assert_eq!(verify_ds(&ds, upper.as_name(), &key), Ok(()));
        let other = NameBuf::from_text(b"other.example.com").unwrap();
        assert_eq!(verify_ds(&ds, other.as_name(), &key), Err(Error::BadSignature));
        let wrong_tag = Ds { key_tag: 1, ..ds };
        assert_eq!(verify_ds(&wrong_tag, owner.as_name(), &key), Err(Error::KeyMismatch));
        let wrong_alg = Ds {
            algorithm: Algorithm::RSASHA256,
            ..ds
        };
        assert_eq!(verify_ds(&wrong_alg, owner.as_name(), &key), Err(Error::KeyMismatch));
        let gost = Ds {
            digest_type: DigestType::GOST,
            ..ds
        };
        assert_eq!(
            verify_ds(&gost, owner.as_name(), &key),
            Err(Error::UnsupportedAlgorithm)
        );
        assert!(!d.matches(&Ds { digest: &[], ..ds }));
        assert!(!d.matches(&Ds { digest_type: DigestType::SHA256, ..ds }));
    }
}
