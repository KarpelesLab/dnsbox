//! Key tags (RFC 4034 Appendix B) and the RSA public key format
//! (RFC 3110 §2).

use super::Algorithm;
use crate::wire::Composer;
use crate::{Error, Result};

/// Computes the key tag of a DNSKEY (or KEY/CDNSKEY) from its RDATA fields
/// (RFC 4034 Appendix B).
///
/// For RSA/MD5 (algorithm 1) the tag is the most significant 16 bits of the
/// least significant 24 bits of the modulus (RFC 4034 §B.1); for every
/// other algorithm it is the ones-complement-style checksum of the RDATA.
///
/// ```
/// use dnsbox::dnssec::{Algorithm, key_tag};
///
/// assert_eq!(key_tag(257, 3, Algorithm::ED25519, &[0; 32]), 1040);
/// ```
pub fn key_tag(flags: u16, protocol: u8, algorithm: Algorithm, public_key: &[u8]) -> u16 {
    if algorithm == Algorithm::RSAMD5 {
        // RFC 4034 §B.1: the modulus ends the public key field (RFC 3110),
        // so these are its third- and second-to-last octets.
        let n = public_key.len();
        return match (n.checked_sub(3), n.checked_sub(2)) {
            (Some(hi), Some(lo)) => u16::from_be_bytes([
                public_key.get(hi).copied().unwrap_or(0),
                public_key.get(lo).copied().unwrap_or(0),
            ]),
            _ => 0,
        };
    }
    let [f0, f1] = flags.to_be_bytes();
    let mut acc: u64 = (u64::from(f0) << 8) + u64::from(f1);
    acc += (u64::from(protocol) << 8) + u64::from(algorithm.get());
    let (pairs, rest) = public_key.as_chunks::<2>();
    for [hi, lo] in pairs {
        acc += (u64::from(*hi) << 8) + u64::from(*lo);
    }
    if let [last] = rest {
        acc += u64::from(*last) << 8;
    }
    acc += (acc >> 16) & 0xffff;
    (acc & 0xffff) as u16
}

/// An RSA public key in the DNSKEY/KEY format of RFC 3110 §2: exponent
/// length (one octet, or zero followed by two octets), exponent, modulus.
///
/// Both numbers are big-endian without leading zero octets.
///
/// ```
/// use dnsbox::dnssec::RsaPublicKey;
///
/// let key = RsaPublicKey::from_dnskey(&[3, 1, 0, 1, 0xc1, 0x5c])?;
/// assert_eq!(key.exponent, [1, 0, 1]);
/// assert_eq!(key.modulus, [0xc1, 0x5c]);
/// assert_eq!(key.modulus_bits(), 16);
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RsaPublicKey<'a> {
    /// The public exponent.
    pub exponent: &'a [u8],
    /// The modulus.
    pub modulus: &'a [u8],
}

impl<'a> RsaPublicKey<'a> {
    /// Parses the public key field of an RSA DNSKEY.
    ///
    /// Fails with [`Error::InvalidKey`] if it is truncated, if either number
    /// is empty, or if either has a leading zero octet (RFC 3110 §2).
    pub fn from_dnskey(public_key: &'a [u8]) -> Result<Self> {
        let (exp_len, rest) = match public_key {
            [0, hi, lo, rest @ ..] => (usize::from(u16::from_be_bytes([*hi, *lo])), rest),
            [len, rest @ ..] => (usize::from(*len), rest),
            [] => return Err(Error::InvalidKey),
        };
        if exp_len == 0 || rest.len() <= exp_len {
            return Err(Error::InvalidKey);
        }
        let (exponent, modulus) = rest.split_at(exp_len);
        if exponent.first() == Some(&0) || modulus.first() == Some(&0) {
            return Err(Error::InvalidKey);
        }
        Ok(RsaPublicKey { exponent, modulus })
    }

    /// The size of the modulus in bits.
    pub fn modulus_bits(&self) -> usize {
        match self.modulus.first() {
            Some(&b) => self.modulus.len() * 8 - b.leading_zeros() as usize,
            None => 0,
        }
    }

    /// The length of the encoded public key field.
    pub const fn wire_len(&self) -> usize {
        let prefix = if self.exponent.len() > 255 { 3 } else { 1 };
        prefix + self.exponent.len() + self.modulus.len()
    }

    /// Writes the RFC 3110 encoding (the DNSKEY public key field).
    ///
    /// Fails with [`Error::InvalidKey`] if a number is empty, has a leading
    /// zero octet, or the exponent is longer than 65535 octets.
    pub fn compose<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        let bad = |n: &[u8]| n.first().is_none_or(|&b| b == 0);
        if bad(self.exponent) || bad(self.modulus) {
            return Err(Error::InvalidKey);
        }
        let len = u16::try_from(self.exponent.len()).map_err(|_| Error::InvalidKey)?;
        if let Ok(short) = u8::try_from(len) {
            c.put_u8(short)?;
        } else {
            c.put_u8(0)?;
            c.put_u16(len)?;
        }
        c.put_bytes(self.exponent)?;
        c.put_bytes(self.modulus)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WireWriter;
    use crate::testutil::hex;
    use std::vec::Vec;

    #[test]
    fn key_tags() {
        // RFC 4034 §2.3 / §5.4 example key.
        let rdata = hex(crate::dnssec::testvec::RFC4034_KEY);
        let tag = key_tag(
            u16::from_be_bytes([rdata[0], rdata[1]]),
            rdata[2],
            Algorithm::new(rdata[3]),
            &rdata[4..],
        );
        assert_eq!(tag, 2642);
        // Odd-length key: the last octet is the high half of a pair.
        assert_eq!(key_tag(0, 0, Algorithm::new(0), &[1]), 0x100);
        assert_eq!(key_tag(0, 0, Algorithm::new(0), &[1, 2, 3]), 0x0402);
        // Carry folding.
        assert_eq!(
            key_tag(0xffff, 0xff, Algorithm::new(0xff), &[0xff; 4]),
            0xffff
        );
        // RSA/MD5 special case: bits 8..24 from the end of the modulus.
        assert_eq!(
            key_tag(256, 3, Algorithm::RSAMD5, &[1, 3, 0xaa, 0xbb, 0xcc, 0xdd]),
            0xbbcc
        );
        assert_eq!(key_tag(256, 3, Algorithm::RSAMD5, &[1, 3]), 0);
        assert_eq!(key_tag(256, 3, Algorithm::RSAMD5, &[1, 3, 7]), 0x0103);
    }

    #[test]
    fn rsa_format() {
        let k = RsaPublicKey::from_dnskey(&[1, 3, 0xab, 0xcd]).unwrap();
        assert_eq!((k.exponent, k.modulus), (&[3][..], &[0xab, 0xcd][..]));
        assert_eq!(k.modulus_bits(), 16);
        assert_eq!(k.wire_len(), 4);

        // Long exponent form.
        let mut long = std::vec![0, 1, 0];
        long.extend([0x55; 256]);
        long.extend([0x80, 0]);
        let k = RsaPublicKey::from_dnskey(&long).unwrap();
        assert_eq!((k.exponent.len(), k.modulus.len()), (256, 2));
        assert_eq!(k.wire_len(), long.len());
        let mut buf = [0u8; 300];
        let mut w = WireWriter::new(&mut buf);
        k.compose(&mut w).unwrap();
        assert_eq!(w.written(), &long[..]);

        for bad in [
            &[][..],
            &[0],
            &[0, 0],
            &[0, 0, 0, 1],
            &[1, 3],
            &[2, 3],
            &[0, 0, 1, 3],
            &[1, 0, 5],
            &[1, 3, 0, 5],
        ] {
            assert_eq!(
                RsaPublicKey::from_dnskey(bad),
                Err(Error::InvalidKey),
                "{bad:?}"
            );
        }
        let mut w = WireWriter::new(&mut buf);
        for (e, n) in [
            (&[][..], &[1][..]),
            (&[1], &[]),
            (&[0, 1], &[1]),
            (&[1], &[0, 1]),
        ] {
            let k = RsaPublicKey {
                exponent: e,
                modulus: n,
            };
            assert_eq!(k.compose(&mut w), Err(Error::InvalidKey));
        }
        let huge: Vec<u8> = std::vec![1; 65536];
        let k = RsaPublicKey {
            exponent: &huge,
            modulus: &[1],
        };
        assert_eq!(k.compose(&mut w), Err(Error::InvalidKey));
        assert_eq!(
            RsaPublicKey {
                exponent: &[],
                modulus: &[]
            }
            .modulus_bits(),
            0
        );
    }
}
