//! ZONEMD record data (RFC 8976 §2) and its scheme and hash-algorithm
//! registries.

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::text::Hex;
use crate::wire::{Composer, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Error, Result, Rtype};

// IANA "ZONEMD Schemes" (RFC 8976 §5.2), as of 2026-10: 0 and 255 are
// reserved, 240–254 private use.
open_enum! {
    /// A ZONEMD scheme (RFC 8976 §2.2.2, IANA "ZONEMD Schemes").
    /// Presented as a bare number.
    ///
    /// ```
    /// use dnsbox::rdata::ZonemdScheme;
    ///
    /// assert_eq!(ZonemdScheme::SIMPLE.get(), 1);
    /// assert_eq!(ZonemdScheme::new(240).to_string(), "240");
    /// ```
    pub struct ZonemdScheme(u8), generic "";
    /// Simple ZONEMD collation (RFC 8976 §3.3.1).
    SIMPLE = 1 => "SIMPLE",
}

// IANA "ZONEMD Hash Algorithms" (RFC 8976 §5.3), as of 2026-10: 0 and 255
// are reserved, 240–254 private use.
open_enum! {
    /// A ZONEMD hash algorithm (RFC 8976 §2.2.3, IANA "ZONEMD Hash
    /// Algorithms"). Presented as a bare number.
    ///
    /// ```
    /// use dnsbox::rdata::ZonemdHashAlg;
    ///
    /// assert_eq!(ZonemdHashAlg::SHA384.digest_len(), Some(48));
    /// assert_eq!(ZonemdHashAlg::SHA512.digest_len(), Some(64));
    /// assert_eq!(ZonemdHashAlg::new(240).digest_len(), None);
    /// ```
    pub struct ZonemdHashAlg(u8), generic "";
    /// SHA-384 (RFC 8976 §2.2.3).
    SHA384 = 1 => "SHA384",
    /// SHA-512 (RFC 8976 §2.2.3).
    SHA512 = 2 => "SHA512",
}

impl ZonemdHashAlg {
    /// The digest length of a registered algorithm, in octets.
    #[must_use]
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
/// canonical order: see `dnssec::ZoneCollation` (feature `alloc`) and
/// `dnssec::zonemd_digest` / `dnssec::verify_zonemd` (features `alloc`
/// and `dnssec-digest`).
///
/// ```
/// use dnsbox::rdata::{ParseRdataText, Zonemd, ZonemdHashAlg, ZonemdScheme};
///
/// let mut buf = [0u8; 64];
/// let zonemd = Zonemd::from_text("2018031900 1 1 ( c68090d90a7aed716bc459f9340e3d7c1370d4d24b7e2fc3
///     a1ddc0b9a87153b9a9713b3c9ae5cc27777f98b8e730044c )", &mut buf)?;
/// assert_eq!(zonemd.serial, 2018031900);
/// assert_eq!((zonemd.scheme, zonemd.hash_alg), (ZonemdScheme::SIMPLE, ZonemdHashAlg::SHA384));
/// assert_eq!(zonemd.digest.len(), 48);
/// zonemd.validate()?;
/// # Ok::<(), dnsbox::Error>(())
/// ```
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
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRdata`] if the digest does not have the length of
    /// its hash algorithm, or, for an unknown algorithm, is shorter than
    /// [`MIN_DIGEST_LEN`](Self::MIN_DIGEST_LEN).
    pub const fn validate(&self) -> Result<()> {
        let len = self.digest.len();
        let ok = match self.hash_alg.digest_len() {
            Some(n) => len == n,
            None => len >= Self::MIN_DIGEST_LEN,
        };
        if ok { Ok(()) } else { Err(Error::InvalidRdata) }
    }
}

impl ParseRdataText for Zonemd<'_> {
    /// `serial scheme hash-algorithm digest` (RFC 8976 §2.3): decimal
    /// serial, scheme and algorithm, then the digest in hexadecimal, which
    /// may be split by blanks. The digest length is checked as on the
    /// wire.
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        out.put_u32(s.u32()?)?;
        out.put_u8(s.u8()?)?;
        out.put_u8(s.u8()?)?;
        if s.hex_rest_into(out)? == 0 {
            return Err(Error::UnexpectedEof);
        }
        Ok(())
    }
}

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
    use crate::rdata::tests::{parse, round_trip, text_error, text_round_trip};
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

    #[test]
    fn text() {
        // RFC 8976 Appendix A.1 (digest split as in the RFC; wire from
        // named-rrchecker).
        let mut wire = crate::testutil::hex("7848B91C0101");
        wire.extend_from_slice(&crate::testutil::hex(DIGEST));
        text_round_trip(
            Rtype::ZONEMD,
            "2018031900 1 1 (\n c68090d90a7aed716bc459f9340e3d7c1370d4d24b7e2fc3\n \
             a1ddc0b9a87153b9a9713b3c9ae5cc27777f98b8e730044c )",
            &wire,
            &std::format!("2018031900 1 1 {DIGEST}"),
        );
        // An unassigned (private-use) algorithm with the minimum digest
        // length (named-rrchecker).
        text_round_trip(
            Rtype::ZONEMD,
            "1 1 240 001122334455667788990011",
            &crate::testutil::hex("0000000101F0001122334455667788990011"),
            "1 1 240 001122334455667788990011",
        );
        // SHA-512 needs exactly 64 octets, here given as four tokens.
        let quarter = "00112233445566778899AABBCCDDEEFF";
        let text = std::format!("7 1 2 {quarter} {quarter} {quarter} {quarter}");
        let mut wire = crate::testutil::hex("000000070102");
        for _ in 0..4 {
            wire.extend_from_slice(&crate::testutil::hex(quarter));
        }
        text_round_trip(
            Rtype::ZONEMD,
            &text,
            &wire,
            &std::format!("7 1 2 {}", quarter.repeat(4)),
        );
        for (text, err) in [
            // Digest length (BIND: "unexpected end of input").
            ("1 1 1 0011", Error::InvalidRdata),
            ("1 1 3 0011223344556677889900", Error::InvalidRdata),
            ("1 1 3", Error::UnexpectedEof),
            // Numbers only (BIND: "not a valid number").
            ("1 SIMPLE SHA384 001122334455667788990011", Error::InvalidText),
            ("1 1 256 001122334455667788990011", Error::InvalidText),
            ("1 1 3 00112233445566778899001", Error::InvalidText),
            ("1 1 3 0011223344556677889900xx", Error::InvalidText),
            ("1 1", Error::UnexpectedEof),
        ] {
            assert_eq!(text_error(Rtype::ZONEMD, text), err, "{text:?}");
        }
    }
}
