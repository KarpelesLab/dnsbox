//! ZONEMD record data (RFC 8976 §2) and its scheme and hash-algorithm
//! registries.

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::text::Hex;
use crate::wire::{Composer, WireReader};
use crate::{Error, Result, Rtype};

// IANA "ZONEMD Schemes" (RFC 8976 §5.2), as of 2026-10: 0 and 255 are
// reserved, 240–254 private use.
open_enum! {
    /// A ZONEMD scheme (RFC 8976 §2.2.2, IANA "ZONEMD Schemes").
    /// Presented as a bare number.
    pub struct ZonemdScheme(u8), generic "";
    /// Simple ZONEMD collation (RFC 8976 §3.3.1).
    SIMPLE = 1 => "SIMPLE",
}

// IANA "ZONEMD Hash Algorithms" (RFC 8976 §5.3), as of 2026-10: 0 and 255
// are reserved, 240–254 private use.
open_enum! {
    /// A ZONEMD hash algorithm (RFC 8976 §2.2.3, IANA "ZONEMD Hash
    /// Algorithms"). Presented as a bare number.
    pub struct ZonemdHashAlg(u8), generic "";
    /// SHA-384 (RFC 8976 §2.2.3).
    SHA384 = 1 => "SHA384",
    /// SHA-512 (RFC 8976 §2.2.3).
    SHA512 = 2 => "SHA512",
}

impl ZonemdHashAlg {
    /// The digest length of a registered algorithm, in octets.
    pub const fn digest_len(self) -> Option<usize> {
        match self.0 {
            1 => Some(48),
            2 => Some(64),
            _ => None,
        }
    }
}

/// `ZONEMD` record data: a message digest over the zone's contents
/// (RFC 8976 §2).
///
/// The digest must be at least 12 octets (RFC 8976 §2.2.4) and, for the
/// registered hash algorithms, exactly the algorithm's output length
/// (as BIND enforces). Computing the digest needs the whole zone in
/// canonical order and is out of scope for this view.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Zonemd<'a> {
    /// The SOA serial of the zone the digest was computed over.
    pub serial: u32,
    /// How the zone data is collated.
    pub scheme: ZonemdScheme,
    /// The hash algorithm.
    pub hash_alg: ZonemdHashAlg,
    /// The digest.
    pub digest: &'a [u8],
}

impl Zonemd<'_> {
    /// Minimum digest length (RFC 8976 §2.2.4).
    pub const MIN_DIGEST_LEN: usize = 12;

    /// Checks the digest length (RFC 8976 §2.2.4).
    pub const fn validate(&self) -> Result<()> {
        let len = self.digest.len();
        let ok = match self.hash_alg.digest_len() {
            Some(n) => len == n,
            None => len >= Self::MIN_DIGEST_LEN,
        };
        if ok { Ok(()) } else { Err(Error::InvalidRdata) }
    }
}

impl super::ParseRdataText for Zonemd<'_> {}

impl<'a> ParseRdata<'a> for Zonemd<'a> {
    const RTYPE: Rtype = Rtype::ZONEMD;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        let mut r = *rdata;
        let serial = r.read_u32()?;
        let [scheme, hash_alg] = r.read_array()?;
        let zonemd = Zonemd {
            serial,
            scheme: ZonemdScheme::new(scheme),
            hash_alg: ZonemdHashAlg::new(hash_alg),
            digest: r.read_rest(),
        };
        zonemd.validate()?;
        *rdata = r;
        Ok(zonemd)
    }
}

impl ComposeRdata for Zonemd<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::ZONEMD
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        self.validate()?;
        c.put_u32(self.serial)?;
        c.put_u8(self.scheme.get())?;
        c.put_u8(self.hash_alg.get())?;
        c.put_bytes(self.digest)
    }
}

impl fmt::Display for Zonemd<'_> {
    /// `serial scheme hash-algorithm hex-digest` (RFC 8976 §2.3).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.serial,
            self.scheme.get(),
            self.hash_alg.get(),
            Hex(self.digest)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{Zonemd, ZonemdHashAlg, ZonemdScheme};
    use crate::rdata::tests::{parse, round_trip};
    use crate::rdata::RData;
    use crate::{Class, ComposeRdata, Error, Rtype};
    use std::string::ToString;

    const DIGEST: &str = "C68090D90A7AED716BC459F9340E3D7C1370D4D24B7E2FC3\
                          A1DDC0B9A87153B9A9713B3C9AE5CC27777F98B8E730044C";

    #[test]
    fn rfc8976_example() {
        // RFC 8976 Appendix A.1: example. ZONEMD 2018031900 1 1 c68090...
        let mut wire = crate::testutil::hex("7848B91C0101");
        wire.extend_from_slice(&crate::testutil::hex(DIGEST));
        round_trip(
            Rtype::ZONEMD,
            &wire,
            &std::format!("2018031900 1 1 {DIGEST}"),
        );
        let RData::Zonemd(z) = parse(Rtype::ZONEMD, Class::IN, &wire).unwrap() else {
            panic!()
        };
        assert_eq!(z.scheme, ZonemdScheme::SIMPLE);
        assert_eq!(z.hash_alg, ZonemdHashAlg::SHA384);
        assert_eq!(z.hash_alg.to_string(), "SHA384");
        assert_eq!(ZonemdHashAlg::SHA512.digest_len(), Some(64));
        // Unknown algorithm with the minimum length (named-rrchecker).
        round_trip(
            Rtype::ZONEMD,
            &crate::testutil::hex("000000010303001122334455667788990011"),
            "1 3 3 001122334455667788990011",
        );
    }

    #[test]
    fn malformed() {
        for bad in [
            "00000001010100112233",                   // SHA384, 4 octets
            "000000010101001122334455667788990011",   // SHA384, 12 octets
            "0000000103030011223344556677889900",     // unknown, 11 octets
        ] {
            assert_eq!(
                parse(Rtype::ZONEMD, Class::IN, &crate::testutil::hex(bad)),
                Err(Error::InvalidRdata),
                "{bad}"
            );
        }
        assert_eq!(
            parse(Rtype::ZONEMD, Class::IN, b"\x00\x00\x00\x01\x01"),
            Err(Error::UnexpectedEof)
        );
        let bad = Zonemd {
            serial: 1,
            scheme: ZonemdScheme::SIMPLE,
            hash_alg: ZonemdHashAlg::SHA512,
            digest: &[0; 48],
        };
        let mut buf = [0u8; 128];
        let mut w = crate::WireWriter::new(&mut buf);
        assert_eq!(bad.compose_rdata(&mut w), Err(Error::InvalidRdata));
    }
}
