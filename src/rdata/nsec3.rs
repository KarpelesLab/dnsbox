//! NSEC3 (RFC 5155 §3) and NSEC3PARAM (RFC 5155 §4) record data.

use core::cmp::Ordering;
use core::fmt;

use super::{ComposeRdata, ParseRdata, TypeBitmap};
use crate::dnssec::Nsec3HashAlgorithm;
use crate::text::{Base32Hex, Hex};
use crate::wire::{Composer, WireReader};
use crate::{Error, Result, Rtype};

/// Writes a salt in presentation format: hex, or `-` when empty
/// (RFC 5155 §3.3).
fn fmt_salt(f: &mut fmt::Formatter<'_>, salt: &[u8]) -> fmt::Result {
    if salt.is_empty() {
        f.write_str("-")
    } else {
        fmt::Display::fmt(&Hex(salt), f)
    }
}

/// Writes a length-prefixed field (salt, hash) of at most 255 octets.
fn put_u8_prefixed<C: Composer + ?Sized>(c: &mut C, data: &[u8]) -> Result<()> {
    let len = u8::try_from(data.len()).map_err(|_| Error::InvalidRdata)?;
    c.put_u8(len)?;
    c.put_bytes(data)
}

/// `NSEC3` record data: hashed authenticated denial of existence
/// (RFC 5155 §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Nsec3<'a> {
    /// The hash algorithm (RFC 5155 §3.1.1).
    pub hash_algorithm: Nsec3HashAlgorithm,
    /// Flags; bit 0 is Opt-Out (RFC 5155 §3.1.2).
    pub flags: u8,
    /// Additional hash iterations (RFC 5155 §3.1.3).
    pub iterations: u16,
    /// The salt, 0–255 octets (RFC 5155 §3.1.5).
    pub salt: &'a [u8],
    /// The next hashed owner name in hash order, unencoded, 1–255 octets
    /// (RFC 5155 §3.1.7).
    pub next_hashed_owner: &'a [u8],
    /// The types present at the original owner name (RFC 5155 §3.1.8).
    pub types: TypeBitmap<'a>,
}

impl Nsec3<'_> {
    /// The Opt-Out flag (RFC 5155 §3.1.2.1).
    pub const OPT_OUT: u8 = 0x01;

    /// Whether the Opt-Out flag is set.
    #[inline]
    pub const fn is_opt_out(&self) -> bool {
        self.flags & Self::OPT_OUT != 0
    }

    /// Whether this NSEC3 record, whose owner name's first label decodes
    /// to `owner_hash`, covers `hash`: `owner_hash < hash < next`, or, for
    /// the last NSEC3 of the chain, `hash > owner_hash` or `hash < next`
    /// (RFC 5155 §8.3, §7.2.1).
    ///
    /// Use [`dnssec::Nsec3Hash::from_owner`](crate::dnssec) to decode the
    /// owner's hash and [`dnssec::nsec3_hash`](crate::dnssec) to hash a name.
    pub fn covers(&self, owner_hash: &[u8], hash: &[u8]) -> bool {
        let next = self.next_hashed_owner;
        let after_owner = owner_hash.cmp(hash) == Ordering::Less;
        let before_next = hash.cmp(next) == Ordering::Less;
        if owner_hash.cmp(next) == Ordering::Less {
            after_owner && before_next
        } else {
            after_owner || before_next
        }
    }
}

impl super::ParseRdataText for Nsec3<'_> {}

impl<'a> ParseRdata<'a> for Nsec3<'a> {
    const RTYPE: Rtype = Rtype::NSEC3;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        let hash_algorithm = Nsec3HashAlgorithm::new(rdata.read_u8()?);
        let flags = rdata.read_u8()?;
        let iterations = rdata.read_u16()?;
        let salt_len = rdata.read_u8()?;
        let salt = rdata.read_bytes(salt_len.into())?;
        let hash_len = rdata.read_u8()?;
        // Every hash algorithm has a non-empty output; a zero-length hash
        // would make the record useless (RFC 5155 §3.1.6).
        if hash_len == 0 {
            return Err(Error::InvalidRdata);
        }
        let next_hashed_owner = rdata.read_bytes(hash_len.into())?;
        Ok(Nsec3 {
            hash_algorithm,
            flags,
            iterations,
            salt,
            next_hashed_owner,
            types: TypeBitmap::parse(rdata)?,
        })
    }
}

impl ComposeRdata for Nsec3<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::NSEC3
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        if self.next_hashed_owner.is_empty() {
            return Err(Error::InvalidRdata);
        }
        c.put_u8(self.hash_algorithm.get())?;
        c.put_u8(self.flags)?;
        c.put_u16(self.iterations)?;
        put_u8_prefixed(c, self.salt)?;
        put_u8_prefixed(c, self.next_hashed_owner)?;
        c.put_bytes(self.types.as_wire())
    }
}

impl fmt::Display for Nsec3<'_> {
    /// `algorithm flags iterations salt next-hashed-owner type...`
    /// (RFC 5155 §3.3), with the hash in unpadded base32hex.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} ",
            self.hash_algorithm.get(),
            self.flags,
            self.iterations
        )?;
        fmt_salt(f, self.salt)?;
        write!(f, " {}", Base32Hex(self.next_hashed_owner))?;
        if !self.types.is_empty() {
            write!(f, " {}", self.types)?;
        }
        Ok(())
    }
}

/// `NSEC3PARAM` record data: the NSEC3 parameters of a zone, for
/// authoritative servers (RFC 5155 §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Nsec3param<'a> {
    /// The hash algorithm (RFC 5155 §4.1.1).
    pub hash_algorithm: Nsec3HashAlgorithm,
    /// Flags; must be zero in zone data (RFC 5155 §4.1.2).
    pub flags: u8,
    /// Additional hash iterations (RFC 5155 §4.1.3).
    pub iterations: u16,
    /// The salt, 0–255 octets (RFC 5155 §4.1.5).
    pub salt: &'a [u8],
}

impl super::ParseRdataText for Nsec3param<'_> {}

impl<'a> ParseRdata<'a> for Nsec3param<'a> {
    const RTYPE: Rtype = Rtype::NSEC3PARAM;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        let hash_algorithm = Nsec3HashAlgorithm::new(rdata.read_u8()?);
        let flags = rdata.read_u8()?;
        let iterations = rdata.read_u16()?;
        let salt_len = rdata.read_u8()?;
        Ok(Nsec3param {
            hash_algorithm,
            flags,
            iterations,
            salt: rdata.read_bytes(salt_len.into())?,
        })
    }
}

impl ComposeRdata for Nsec3param<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::NSEC3PARAM
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_u8(self.hash_algorithm.get())?;
        c.put_u8(self.flags)?;
        c.put_u16(self.iterations)?;
        put_u8_prefixed(c, self.salt)
    }
}

impl fmt::Display for Nsec3param<'_> {
    /// `algorithm flags iterations salt` (RFC 5155 §4.3).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} ",
            self.hash_algorithm.get(),
            self.flags,
            self.iterations
        )?;
        fmt_salt(f, self.salt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdata::RData;
    use crate::rdata::tests::{compose, parse, round_trip};
    use crate::testutil::hex;
    use crate::{Class, WireWriter};

    #[test]
    fn rfc5155_examples() {
        // RFC 5155 Appendix A: 0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.
        //   NSEC3 1 1 12 aabbccdd 2t7b4g4vsa5smi47k61mv5bv1a22bojr MX DNSKEY NS
        //   SOA NSEC3PARAM RRSIG
        let mut wire = hex("01 01 000c 04 aabbccdd 14");
        wire.extend(hex("174eb2409fe28bcb4887a1836f957f0a8425e27b"));
        wire.extend(hex("0007 22010000000290"));
        let s = round_trip(
            Rtype::NSEC3,
            &wire,
            "1 1 12 AABBCCDD 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR NS SOA MX RRSIG DNSKEY NSEC3PARAM",
        );
        assert!(s.contains(" NSEC3PARAM"));
        let RData::Nsec3(n) = parse(Rtype::NSEC3, Class::IN, &wire).unwrap() else {
            panic!()
        };
        assert!(n.is_opt_out());
        assert_eq!(n.hash_algorithm, Nsec3HashAlgorithm::SHA1);
        assert!(n.types.contains(Rtype::DNSKEY));

        // example. NSEC3PARAM 1 0 12 aabbccdd
        round_trip(Rtype::NSEC3PARAM, &hex("01 00 000c 04 aabbccdd"), "1 0 12 AABBCCDD");
        // Empty salt and empty bitmap.
        round_trip(Rtype::NSEC3PARAM, &hex("01 00 0000 00"), "1 0 0 -");
        round_trip(Rtype::NSEC3, &hex("01 00 0000 00 01 ff"), "1 0 0 - VS");
    }

    #[test]
    fn covers() {
        let n = Nsec3 {
            hash_algorithm: Nsec3HashAlgorithm::SHA1,
            flags: 0,
            iterations: 0,
            salt: &[],
            next_hashed_owner: &[0x50],
            types: TypeBitmap::default(),
        };
        assert!(n.covers(&[0x10], &[0x20]));
        assert!(!n.covers(&[0x10], &[0x10]));
        assert!(!n.covers(&[0x10], &[0x50]));
        assert!(!n.covers(&[0x10], &[0x60]));
        // Last in the chain.
        assert!(n.covers(&[0x60], &[0x70]));
        assert!(n.covers(&[0x60], &[0x01]));
        assert!(!n.covers(&[0x60], &[0x55]));
    }

    #[test]
    fn malformed() {
        // Zero-length hash.
        assert_eq!(
            parse(Rtype::NSEC3, Class::IN, &hex("01 00 0000 00 00")),
            Err(Error::InvalidRdata)
        );
        // Salt longer than the RDATA.
        assert_eq!(
            parse(Rtype::NSEC3PARAM, Class::IN, &hex("01 00 0000 05 aabb")),
            Err(Error::UnexpectedEof)
        );
        assert_eq!(
            parse(Rtype::NSEC3PARAM, Class::IN, &hex("01 00 0000 01 aabb")),
            Err(Error::TrailingData)
        );
        // Bad bitmap.
        assert_eq!(
            parse(Rtype::NSEC3, Class::IN, &hex("01 00 0000 00 01 ff 00 00")),
            Err(Error::InvalidRdata)
        );
        // Composing rejects oversized fields and an empty hash.
        let long = [0u8; 256];
        let mut buf = [0u8; 600];
        let p = Nsec3param {
            hash_algorithm: Nsec3HashAlgorithm::SHA1,
            flags: 0,
            iterations: 0,
            salt: &long,
        };
        assert_eq!(
            p.compose_rdata(&mut WireWriter::new(&mut buf)),
            Err(Error::InvalidRdata)
        );
        let n = Nsec3 {
            hash_algorithm: Nsec3HashAlgorithm::SHA1,
            flags: 0,
            iterations: 0,
            salt: &[],
            next_hashed_owner: &[],
            types: TypeBitmap::default(),
        };
        assert_eq!(
            n.compose_rdata(&mut WireWriter::new(&mut buf)),
            Err(Error::InvalidRdata)
        );
        let n = Nsec3 {
            next_hashed_owner: &long,
            ..n
        };
        assert_eq!(
            n.compose_rdata(&mut WireWriter::new(&mut buf)),
            Err(Error::InvalidRdata)
        );
        let n = Nsec3 {
            next_hashed_owner: &[1],
            ..n
        };
        assert_eq!(compose(&n), hex("01 00 0000 00 01 01"));
    }
}
