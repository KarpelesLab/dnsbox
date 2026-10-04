//! NSEC3 hashing (RFC 5155 §5) and hashed owner names (RFC 5155 §3).

use core::fmt;

#[cfg(feature = "dnssec-digest")]
use super::Nsec3HashAlgorithm;
use crate::name::{Name, NameBuf};
use crate::text::Base32Hex;
use crate::{Error, Result};

/// The largest hash an NSEC3 owner label can hold: 63 base32hex
/// characters decode to at most 39 octets.
const MAX_HASH_LEN: usize = 39;

/// An NSEC3 hash value (RFC 5155 §5), as computed by [`nsec3_hash`] or
/// decoded from a hashed owner name with [`Nsec3Hash::from_owner`].
///
/// `Display` writes unpadded base32hex (RFC 4648 §7), uppercase, as in
/// the NSEC3 next-hashed-owner field (RFC 5155 §3.3).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Nsec3Hash {
    len: u8,
    bytes: [u8; MAX_HASH_LEN],
}

impl Nsec3Hash {
    /// Wraps raw hash octets (at most 39, as fits a 63-character label).
    pub fn new(hash: &[u8]) -> Result<Self> {
        let mut bytes = [0u8; MAX_HASH_LEN];
        let dst = bytes.get_mut(..hash.len()).ok_or(Error::InvalidRdata)?;
        dst.copy_from_slice(hash);
        if hash.is_empty() {
            return Err(Error::InvalidRdata);
        }
        Ok(Nsec3Hash {
            len: hash.len() as u8,
            bytes,
        })
    }

    /// Decodes the hash from the first label of an NSEC3 owner name
    /// (base32hex, case-insensitive, RFC 5155 §3).
    ///
    /// Fails with [`Error::InvalidText`] if the label is not valid unpadded
    /// base32hex, and with [`Error::InvalidRdata`] for the root name.
    pub fn from_owner(owner: Name<'_>) -> Result<Self> {
        let label = owner.first_label().ok_or(Error::InvalidRdata)?;
        let mut bytes = [0u8; MAX_HASH_LEN];
        let len = decode_base32hex(label.as_bytes(), &mut bytes)?;
        if len == 0 {
            return Err(Error::InvalidText);
        }
        Ok(Nsec3Hash {
            len: len as u8,
            bytes,
        })
    }

    /// The hash octets.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }

    /// The hashed owner name: the lowercase base32hex label followed by
    /// `zone` (RFC 5155 §3).
    pub fn owner_name(&self, zone: Name<'_>) -> Result<NameBuf> {
        let mut label = [0u8; 63];
        let mut w = SliceWriter {
            buf: &mut label,
            len: 0,
        };
        fmt::write(&mut w, format_args!("{}", Base32Hex(self.as_bytes())))
            .map_err(|_| Error::LabelTooLong)?;
        let len = w.len;
        let label = label.get_mut(..len).ok_or(Error::LabelTooLong)?;
        label.make_ascii_lowercase();
        let mut name = NameBuf::from_name(zone);
        name.prepend_label(label)?;
        Ok(name)
    }
}

impl fmt::Display for Nsec3Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Base32Hex(self.as_bytes()), f)
    }
}

impl fmt::Debug for Nsec3Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nsec3Hash({self})")
    }
}

/// A `fmt::Write` over a fixed slice.
struct SliceWriter<'b> {
    buf: &'b mut [u8],
    len: usize,
}

impl fmt::Write for SliceWriter<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len + s.len();
        self.buf
            .get_mut(self.len..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// Decodes unpadded base32hex (RFC 4648 §7), case-insensitively, into
/// `out`, returning the decoded length. Rejects non-canonical input
/// (impossible lengths or non-zero trailing bits).
fn decode_base32hex(input: &[u8], out: &mut [u8]) -> Result<usize> {
    if matches!(input.len() % 8, 1 | 3 | 6) {
        return Err(Error::InvalidText);
    }
    let mut acc: u64 = 0;
    let mut bits = 0u32;
    let mut len = 0usize;
    for &c in input {
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'v' => c - b'a' + 10,
            b'A'..=b'V' => c - b'A' + 10,
            _ => return Err(Error::InvalidText),
        };
        acc = (acc << 5) | u64::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            *out.get_mut(len).ok_or(Error::InvalidText)? = (acc >> bits) as u8;
            len += 1;
            acc &= (1 << bits) - 1;
        }
    }
    if acc != 0 {
        return Err(Error::InvalidText);
    }
    Ok(len)
}

/// Computes the NSEC3 hash of `name` (RFC 5155 §5):
/// `IH(salt, x, 0) = H(x || salt)`, `IH(salt, x, k) = H(IH(salt, x, k-1)
/// || salt)`, with `x` the canonical (lowercase, uncompressed) wire form
/// of `name` (see [`canonical_name`](super::canonical_name)) and `k` =
/// `iterations`.
///
/// The work is `iterations + 1` hash computations; validators should
/// refuse to hash for records with iteration counts above their policy
/// limit (RFC 9276 §3.2 recommends treating large counts as insecure).
///
/// Fails with [`Error::UnsupportedAlgorithm`] for hash algorithms other
/// than SHA-1.
///
/// ```
/// use dnsbox::NameBuf;
/// use dnsbox::dnssec::{Nsec3HashAlgorithm, nsec3_hash};
///
/// // RFC 5155 Appendix A: H(example) = 0p9mhaveqvm6t7vbl5lop2u3t2rp3tom
/// let name: NameBuf = "example".parse()?;
/// let h = nsec3_hash(name.as_name(), Nsec3HashAlgorithm::SHA1, 12, &[0xaa, 0xbb, 0xcc, 0xdd])?;
/// assert_eq!(h.to_string(), "0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM");
/// assert_eq!(h.owner_name(name.as_name())?.to_string(), "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.");
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[cfg(feature = "dnssec-digest")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec-digest")))]
pub fn nsec3_hash(
    name: Name<'_>,
    algorithm: Nsec3HashAlgorithm,
    iterations: u16,
    salt: &[u8],
) -> Result<Nsec3Hash> {
    use super::ds::digest_parts;
    use purecrypto::hash::Sha1;
    if algorithm != Nsec3HashAlgorithm::SHA1 {
        return Err(Error::UnsupportedAlgorithm);
    }
    let mut wire = [0u8; crate::name::MAX_NAME_LEN];
    let len = super::canonical_name(name, &mut wire);
    let mut hash = [0u8; 20];
    digest_parts::<Sha1>(&[wire.get(..len).unwrap_or(&[]), salt], &mut hash);
    for _ in 0..iterations {
        let prev = hash;
        digest_parts::<Sha1>(&[&prev, salt], &mut hash);
    }
    Nsec3Hash::new(&hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::ToString;

    #[test]
    fn base32hex() {
        let mut out = [0u8; 40];
        assert_eq!(decode_base32hex(b"", &mut out), Ok(0));
        for (enc, dec) in [
            ("CO", "f"),
            ("CPNG", "fo"),
            ("cpnmu", "foo"),
            ("CPNMUOG", "foob"),
            ("CPNMUOJ1", "fooba"),
            ("CPNMUOJ1E8", "foobar"),
        ] {
            let n = decode_base32hex(enc.as_bytes(), &mut out).unwrap();
            assert_eq!(&out[..n], dec.as_bytes(), "{enc}");
        }
        for bad in ["C", "CPN", "CPNMUO", "CP", "W0", "C=", "CPNMUOJ1E9"] {
            assert_eq!(
                decode_base32hex(bad.as_bytes(), &mut out),
                Err(Error::InvalidText),
                "{bad}"
            );
        }
        assert_eq!(
            decode_base32hex(b"00", &mut [0u8; 0]),
            Err(Error::InvalidText)
        );
    }

    #[test]
    fn hashes() {
        let zone = NameBuf::from_text(b"example").unwrap();
        let owner = NameBuf::from_text(b"0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM.example").unwrap();
        let h = Nsec3Hash::from_owner(owner.as_name()).unwrap();
        assert_eq!(h.as_bytes().len(), 20);
        assert_eq!(h.to_string(), "0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM");
        assert_eq!(
            std::format!("{h:?}"),
            "Nsec3Hash(0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM)"
        );
        assert_eq!(
            h.owner_name(zone.as_name()).unwrap().to_string(),
            "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example."
        );
        assert_eq!(Nsec3Hash::from_owner(Name::ROOT), Err(Error::InvalidRdata));
        let bad = NameBuf::from_text(b"xyz.example").unwrap();
        assert_eq!(
            Nsec3Hash::from_owner(bad.as_name()),
            Err(Error::InvalidText)
        );
        assert_eq!(Nsec3Hash::new(&[]), Err(Error::InvalidRdata));
        assert_eq!(Nsec3Hash::new(&[0; 40]), Err(Error::InvalidRdata));
        assert_eq!(Nsec3Hash::new(&[0; 39]).unwrap().to_string().len(), 63);
        assert!(
            Nsec3Hash::new(&[1; 39])
                .unwrap()
                .owner_name(zone.as_name())
                .is_ok()
        );
    }

    #[cfg(feature = "dnssec-digest")]
    #[test]
    fn rfc5155_hashes() {
        // RFC 5155 Appendix A, salt aabbccdd, 12 iterations.
        let salt = [0xaa, 0xbb, 0xcc, 0xdd];
        for (name, hash) in [
            ("example", "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"),
            ("a.example", "35mthgpgcu1qg68fab165klnsnk3dpvl"),
            ("ai.example", "gjeqe526plbf1g8mklp59enfd789njgi"),
            ("ns1.example", "2t7b4g4vsa5smi47k61mv5bv1a22bojr"),
            ("ns2.example", "q04jkcevqvmu85r014c7dkba38o0ji5r"),
            ("w.example", "k8udemvp1j2f7eg6jebps17vp3n8i58h"),
            ("*.w.example", "r53bq7cc2uvmubfu5ocmm6pers9tk9en"),
            ("x.w.example", "b4um86eghhds6nea196smvmlo4ors995"),
            ("y.w.example", "ji6neoaepv8b5o6k4ev33abha8ht9fgc"),
            ("x.y.w.example", "2vptu5timamqttgl4luu9kg21e0aor3s"),
            ("xx.example", "t644ebqk9bibcna874givr6joj62mlhv"),
            (
                "2t7b4g4vsa5smi47k61mv5bv1a22bojr.example",
                "kohar7mbb8dc2ce8a9qvl8hon4k53uhi",
            ),
            ("X.W.Example", "b4um86eghhds6nea196smvmlo4ors995"),
        ] {
            let n = NameBuf::from_text(name.as_bytes()).unwrap();
            let h = nsec3_hash(n.as_name(), Nsec3HashAlgorithm::SHA1, 12, &salt).unwrap();
            assert_eq!(h.to_string().to_ascii_lowercase(), hash, "{name}");
            let owner = NameBuf::from_text(std::format!("{hash}.example").as_bytes()).unwrap();
            assert_eq!(Nsec3Hash::from_owner(owner.as_name()).unwrap(), h);
        }
        assert_eq!(
            nsec3_hash(Name::ROOT, Nsec3HashAlgorithm::new(2), 0, &[]),
            Err(Error::UnsupportedAlgorithm)
        );
        // Zero iterations, empty salt: plain SHA-1 of the wire name.
        let h = nsec3_hash(Name::ROOT, Nsec3HashAlgorithm::SHA1, 0, &[]).unwrap();
        assert_eq!(
            h.as_bytes(),
            crate::testutil::hex("5ba93c9db0cff93f52b521d7420e43f6eda2784f")
        );
    }
}
