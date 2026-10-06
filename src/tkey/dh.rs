//! The Diffie-Hellman KEY format (RFC 2539), without cryptography.

use crate::wire::{Composer, WireReader};
use crate::{Error, Result};

/// Well-known group 1 (RFC 2539 Appendix A.1, the 768-bit prime of
/// RFC 2409 §6.1): `2^768 - 2^704 - 1 + 2^64 * { [2^638 pi] + 149686 }`.
const PRIME_768: [u8; 96] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x3A, 0x36, 0x20, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// Well-known group 2 (RFC 2539 Appendix A.2, the 1024-bit prime of
/// RFC 2409 §6.2): `2^1024 - 2^960 - 1 + 2^64 * { [2^894 pi] + 129093 }`.
const PRIME_1024: [u8; 128] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// BIND's well-known group 3: the 1536-bit prime of RFC 3526 §2 (MODP
/// group 5), `2^1536 - 2^1472 - 1 + 2^64 * { [2^1406 pi] + 741804 }`.
const PRIME_1536: [u8; 192] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
    0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
    0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
    0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x23, 0x73, 0x27, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// The generator of every well-known group (RFC 2539 Appendix A).
const GENERATOR_2: &[u8] = &[2];

/// The prime of a well-known Diffie-Hellman group (RFC 2539 §2,
/// Appendix A), most significant octet first: 1 is the 768-bit prime of
/// Appendix A.1, 2 the 1024-bit prime of A.2, and 3 the 1536-bit prime
/// of RFC 3526 §2, which BIND assigns that index (RFC 2539 itself defines
/// only 1 and 2). The generator of all three is 2. `None` for any other
/// index.
///
/// These groups are weak by today's standards (the 768- and 1024-bit
/// discrete logarithm problems are within reach of well-funded
/// attackers); they are here for interoperability.
///
/// ```
/// use dnsbox::tkey::well_known_prime;
///
/// assert_eq!(well_known_prime(1).map(<[u8]>::len), Some(96));
/// assert_eq!(well_known_prime(2).map(<[u8]>::len), Some(128));
/// assert_eq!(well_known_prime(3).map(<[u8]>::len), Some(192));
/// assert_eq!(well_known_prime(4), None);
/// ```
#[must_use]
pub const fn well_known_prime(index: u16) -> Option<&'static [u8]> {
    match index {
        1 => Some(&PRIME_768),
        2 => Some(&PRIME_1024),
        3 => Some(&PRIME_1536),
        _ => None,
    }
}

/// `n` without its leading zero octets (the same integer).
pub(crate) fn trim(n: &[u8]) -> &[u8] {
    let zeros = n.iter().take_while(|&&b| b == 0).count();
    n.get(zeros..).unwrap_or(&[])
}

/// The prime field of a Diffie-Hellman KEY (RFC 2539 §2).
///
/// ```
/// use dnsbox::tkey::{DhKey, DhPrime};
///
/// // Prime length 1: a one-octet index into the well-known groups.
/// let key = DhKey::parse(&[0, 1, 2, 0, 0, 0, 1, 5])?;
/// assert_eq!(key.prime, DhPrime::WellKnown(2));
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DhPrime<'a> {
    /// An index into the table of well-known prime/generator pairs (a
    /// prime length of 1 or 2, then that many octets; RFC 2539 §2, §4,
    /// Appendix A; see [`well_known_prime`]).
    WellKnown(u16),
    /// The prime itself, most significant octet first (a prime length of
    /// 16 or more).
    Explicit(&'a [u8]),
}

/// The public key field of a Diffie-Hellman KEY record (algorithm 2,
/// RFC 2539 §2): the group (a prime and a generator) and the public value
/// `g^x mod p`, each most significant octet first.
///
/// This is the wire format only; the key agreement of RFC 2930 §4.1 is
/// [`DhKeyPair`] (feature `tkey`). Parsing allocates nothing.
///
/// ```
/// use dnsbox::tkey::{DhKey, DhPrime};
/// use dnsbox::WireWriter;
///
/// let wire = [0, 1, 2, 0, 0, 0, 2, 0x12, 0x34];
/// let key = DhKey::parse(&wire)?;
/// assert_eq!((key.prime, key.generator, key.public_value), (DhPrime::WellKnown(2), &[][..], &[0x12, 0x34][..]));
/// let (prime, generator) = key.group().unwrap();
/// assert_eq!((prime.len(), generator), (128, &[2][..]));
///
/// let mut buf = [0u8; 16];
/// let mut w = WireWriter::new(&mut buf);
/// key.compose(&mut w)?;
/// assert_eq!(w.as_bytes(), wire);
/// assert_eq!(key.wire_len(), wire.len());
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[cfg_attr(feature = "tkey", doc = "[`DhKeyPair`]: super::DhKeyPair")]
#[cfg_attr(not(feature = "tkey"), doc = "[`DhKeyPair`]: crate#cargo-features")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DhKey<'a> {
    /// The prime: a well-known group or the prime itself.
    pub prime: DhPrime<'a>,
    /// The generator; usually empty with a well-known prime, whose
    /// generator is 2 (RFC 2539 §2: the length "SHOULD be zero").
    pub generator: &'a [u8],
    /// The public value `g^x mod p`.
    pub public_value: &'a [u8],
}

impl<'a> DhKey<'a> {
    /// Parses the public key field of a Diffie-Hellman KEY (RFC 2539 §2).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKey`] if the field is truncated or has octets left
    /// over, if the prime length is 0 or 3 to 15 (reserved), if an
    /// explicit prime comes without a generator, or if the public value is
    /// empty.
    ///
    /// ```
    /// use dnsbox::tkey::{DhKey, DhPrime};
    /// use dnsbox::Error;
    ///
    /// let key = DhKey::parse(&[0, 16, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ///                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x61, 0, 1, 5, 0, 1, 3])?;
    /// assert!(matches!(key.prime, DhPrime::Explicit(p) if p.len() == 16));
    /// assert_eq!(DhKey::parse(&[0, 3, 1, 2, 3, 0, 0, 0, 1, 1]), Err(Error::InvalidKey));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn parse(public_key: &'a [u8]) -> Result<Self> {
        Self::read(public_key).map_err(|_| Error::InvalidKey)
    }

    fn read(public_key: &'a [u8]) -> Result<Self> {
        let mut r = WireReader::new(public_key);
        let prime = match r.read_u16()? {
            1 => DhPrime::WellKnown(r.read_u8()?.into()),
            2 => DhPrime::WellKnown(r.read_u16()?),
            0 | 3..=15 => return Err(Error::InvalidKey),
            len => DhPrime::Explicit(r.read_bytes(len.into())?),
        };
        let len = r.read_u16()?;
        let generator = r.read_bytes(len.into())?;
        let len = r.read_u16()?;
        let public_value = r.read_bytes(len.into())?;
        r.finish()?;
        if public_value.is_empty() || matches!(prime, DhPrime::Explicit(_)) && generator.is_empty()
        {
            return Err(Error::InvalidKey);
        }
        Ok(DhKey {
            prime,
            generator,
            public_value,
        })
    }

    /// The length of the encoded field.
    ///
    /// ```
    /// use dnsbox::tkey::{DhKey, DhPrime};
    ///
    /// let key = DhKey { prime: DhPrime::WellKnown(1), generator: &[], public_value: &[9; 96] };
    /// assert_eq!(key.wire_len(), 2 + 1 + 2 + 2 + 96);
    /// ```
    #[must_use]
    pub const fn wire_len(&self) -> usize {
        let prime = match self.prime {
            DhPrime::WellKnown(i) if i <= 0xff => 1,
            DhPrime::WellKnown(_) => 2,
            DhPrime::Explicit(p) => p.len(),
        };
        6 + prime + self.generator.len() + self.public_value.len()
    }

    /// Writes the field (RFC 2539 §2). A well-known index is written in
    /// one octet when it fits (prime length 1, as BIND writes it), in two
    /// otherwise.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKey`] if a field is longer than 65535 octets, an
    /// explicit prime is shorter than 16 octets or has no generator, or
    /// the public value is empty; the composer's error if it is full.
    ///
    /// ```
    /// use dnsbox::tkey::{DhKey, DhPrime};
    /// use dnsbox::{Error, WireWriter};
    ///
    /// let mut buf = [0u8; 16];
    /// let mut w = WireWriter::new(&mut buf);
    /// let key = DhKey { prime: DhPrime::WellKnown(0x1234), generator: &[], public_value: &[5] };
    /// key.compose(&mut w)?;
    /// assert_eq!(w.as_bytes(), [0, 2, 0x12, 0x34, 0, 0, 0, 1, 5]);
    /// let short = DhKey { prime: DhPrime::Explicit(&[23]), generator: &[5], public_value: &[8] };
    /// assert_eq!(short.compose(&mut w), Err(Error::InvalidKey));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn compose<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        let len = |n: &[u8]| u16::try_from(n.len()).map_err(|_| Error::InvalidKey);
        let (generator, public_value) = (len(self.generator)?, len(self.public_value)?);
        if public_value == 0 {
            return Err(Error::InvalidKey);
        }
        match self.prime {
            DhPrime::WellKnown(i) => match u8::try_from(i) {
                Ok(i) => {
                    c.put_u16(1)?;
                    c.put_u8(i)?;
                }
                Err(_) => {
                    c.put_u16(2)?;
                    c.put_u16(i)?;
                }
            },
            DhPrime::Explicit(p) => {
                let n = len(p)?;
                if n < 16 || generator == 0 {
                    return Err(Error::InvalidKey);
                }
                c.put_u16(n)?;
                c.put_bytes(p)?;
            }
        }
        c.put_u16(generator)?;
        c.put_bytes(self.generator)?;
        c.put_u16(public_value)?;
        c.put_bytes(self.public_value)
    }

    /// The group's prime and generator, with a well-known index resolved
    /// through [`well_known_prime`] and an absent generator of a
    /// well-known group read as 2. `None` for an unknown well-known index.
    ///
    /// ```
    /// use dnsbox::tkey::{DhKey, DhPrime};
    ///
    /// let key = DhKey { prime: DhPrime::WellKnown(9), generator: &[], public_value: &[5] };
    /// assert_eq!(key.group(), None);
    /// let key = DhKey { prime: DhPrime::Explicit(&[0xfb; 16]), generator: &[5], public_value: &[5] };
    /// assert_eq!(key.group(), Some((&[0xfb; 16][..], &[5][..])));
    /// ```
    #[must_use]
    pub fn group(&self) -> Option<(&'a [u8], &'a [u8])> {
        match self.prime {
            DhPrime::WellKnown(i) => {
                let generator = if self.generator.is_empty() {
                    GENERATOR_2
                } else {
                    self.generator
                };
                Some((well_known_prime(i)?, generator))
            }
            DhPrime::Explicit(p) => Some((p, self.generator)),
        }
    }

    /// Whether both keys are in the same group: equal primes and
    /// generators as integers, however they are written (a well-known
    /// index or the explicit prime, with or without leading zeros). Both
    /// parties of an exchange must use the same group (RFC 2930 §4.1);
    /// a server answers BADKEY otherwise. `false` when either group is
    /// unknown.
    ///
    /// ```
    /// use dnsbox::tkey::{DhKey, DhPrime, well_known_prime};
    ///
    /// let p = well_known_prime(1).unwrap();
    /// let a = DhKey { prime: DhPrime::WellKnown(1), generator: &[], public_value: &[5] };
    /// let b = DhKey { prime: DhPrime::Explicit(p), generator: &[0, 2], public_value: &[7] };
    /// let c = DhKey { prime: DhPrime::WellKnown(2), generator: &[], public_value: &[5] };
    /// assert!(a.same_group(&b) && !a.same_group(&c));
    /// ```
    #[must_use]
    pub fn same_group(&self, other: &DhKey<'_>) -> bool {
        match (self.group(), other.group()) {
            (Some((p, g)), Some((q, h))) => trim(p) == trim(q) && trim(g) == trim(h),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WireWriter;

    #[test]
    fn primes_are_the_rfc_ones() {
        // RFC 2539 Appendix A and RFC 3526 §2 give the primes in hex; the
        // tables above were checked against the pi formulas (and as safe
        // primes) with an independent script; here their shape: all start
        // and end with 64 one bits and share the pi prefix.
        for (i, bits) in [(1, 768), (2, 1024), (3, 1536)] {
            let p = well_known_prime(i).unwrap();
            assert_eq!(p.len() * 8, bits);
            assert_eq!(&p[..8], &[0xff; 8]);
            assert_eq!(&p[p.len() - 8..], &[0xff; 8]);
            assert_eq!(&p[8..16], &PRIME_768[8..16]);
        }
        assert_eq!(&PRIME_1024[..84], &PRIME_1536[..84]);
        assert_eq!(well_known_prime(0), None);
        assert_eq!(well_known_prime(u16::MAX), None);
    }

    #[test]
    fn parse_and_compose() {
        let cases: &[&[u8]] = &[
            &[0, 1, 1, 0, 0, 0, 1, 7],
            &[0, 2, 0x12, 0x34, 0, 1, 2, 0, 2, 0, 7],
            &[
                0, 16, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 5, 0, 1, 3,
            ],
        ];
        for &wire in cases {
            let key = DhKey::parse(wire).unwrap();
            let mut buf = [0u8; 64];
            let mut w = WireWriter::new(&mut buf);
            key.compose(&mut w).unwrap();
            assert_eq!(w.as_bytes(), wire);
            assert_eq!(key.wire_len(), wire.len());
            // Every truncation and any extra octet is rejected.
            for end in 0..wire.len() {
                assert_eq!(DhKey::parse(&wire[..end]), Err(Error::InvalidKey), "{end}");
            }
            let mut long = wire.to_vec();
            long.push(0);
            assert_eq!(DhKey::parse(&long), Err(Error::InvalidKey));
        }
        // A two-octet index that fits in one is written in one.
        let key = DhKey::parse(&[0, 2, 0, 2, 0, 0, 0, 1, 7]).unwrap();
        assert_eq!(key.prime, DhPrime::WellKnown(2));
        assert_eq!(key.wire_len(), 8);
    }

    #[test]
    fn malformed() {
        for bad in [
            &[0, 0, 0, 0, 0, 1, 7][..],
            // Reserved prime lengths.
            &[0, 3, 1, 1, 1, 0, 0, 0, 1, 7],
            &[
                0, 15, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 7,
            ],
            // No public value.
            &[0, 1, 1, 0, 0, 0, 0],
            // An explicit prime without a generator.
            &[
                0, 16, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 7,
            ],
            // Lengths beyond the field.
            &[0xff, 0xff, 1],
            &[0, 1, 1, 0xff, 0xff],
        ] {
            assert_eq!(DhKey::parse(bad), Err(Error::InvalidKey), "{bad:?}");
        }
        let mut buf = [0u8; 64];
        let mut w = WireWriter::new(&mut buf);
        let empty = DhKey {
            prime: DhPrime::WellKnown(1),
            generator: &[],
            public_value: &[],
        };
        assert_eq!(empty.compose(&mut w), Err(Error::InvalidKey));
        let no_generator = DhKey {
            prime: DhPrime::Explicit(&[1; 16]),
            generator: &[],
            public_value: &[1],
        };
        assert_eq!(no_generator.compose(&mut w), Err(Error::InvalidKey));
        let huge = std::vec![1u8; 70_000];
        let big = DhKey {
            prime: DhPrime::WellKnown(1),
            generator: &[],
            public_value: &huge,
        };
        assert_eq!(big.compose(&mut w), Err(Error::InvalidKey));
        assert!(w.as_bytes().is_empty());
    }

    #[test]
    fn groups() {
        let p2 = well_known_prime(2).unwrap();
        let mut padded = std::vec![0u8, 0];
        padded.extend_from_slice(p2);
        let a = DhKey {
            prime: DhPrime::WellKnown(2),
            generator: &[],
            public_value: &[5],
        };
        let b = DhKey {
            prime: DhPrime::Explicit(&padded),
            generator: &[2],
            public_value: &[5],
        };
        let c = DhKey {
            prime: DhPrime::WellKnown(2),
            generator: &[5],
            public_value: &[5],
        };
        let unknown = DhKey {
            prime: DhPrime::WellKnown(0),
            generator: &[],
            public_value: &[5],
        };
        assert!(a.same_group(&b) && b.same_group(&a));
        assert!(!a.same_group(&c) && !unknown.same_group(&unknown));
        assert_eq!(c.group(), Some((p2, &[5][..])));
        assert_eq!(trim(&[0, 0]), &[] as &[u8]);
        assert_eq!(trim(&[0, 1, 0]), &[1, 0]);
    }
}
