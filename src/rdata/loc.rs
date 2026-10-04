//! LOC record data (RFC 1876).

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::wire::{Composer, OutBuf, WireReader};
use crate::zone::{Scanner, Token};
use crate::{Error, Result, Rtype};

/// Raw latitude/longitude value of the equator and the prime meridian:
/// 2^31 (RFC 1876 §2).
const EQUATOR: u32 = 1 << 31;
/// 90° in thousandths of an arcsecond.
const MAX_LATITUDE: u32 = 90 * 3_600_000;
/// 180° in thousandths of an arcsecond.
const MAX_LONGITUDE: u32 = 180 * 3_600_000;
/// The altitude reference point, 100 000 m below the WGS 84 spheroid, in
/// centimetres (RFC 1876 §2).
const ALTITUDE_BASE: i64 = 10_000_000;

/// Powers of ten for the precision encoding (exponents 0–9).
const POWERS: [u64; 10] = [
    1,
    10,
    100,
    1_000,
    10_000,
    100_000,
    1_000_000,
    10_000_000,
    100_000_000,
    1_000_000_000,
];

/// `LOC` record data: a geographical location, with its size and the
/// precision of the position (RFC 1876 §2).
///
/// Only version 0 of the format exists; RDATA with another version is
/// rejected with [`Error::InvalidRdata`] (RFC 1876 §2: "make no assumptions
/// about the format of unrecognized versions").
///
/// The fields hold the raw wire values; the accessors convert them:
///
/// - `size`, `horiz_pre` and `vert_pre` use the RFC's base-10 "mantissa ×
///   10^exponent centimetres" octet ([`Loc::encode_precision`],
///   [`Loc::decode_precision`]);
/// - `latitude` and `longitude` are thousandths of an arcsecond offset by
///   2^31 ([`Loc::latitude_mas`], [`Loc::longitude_mas`]);
/// - `altitude` is centimetres above a base 100 000 m below the WGS 84
///   reference spheroid ([`Loc::altitude_cm`]).
///
/// ```
/// use dnsbox::rdata::Loc;
///
/// // RFC 1876 §3: 42 21 54 N 71 06 18 W -24m 30m
/// let north = (42 * 3600 + 21 * 60 + 54) * 1000;
/// let west = -(71 * 3600 + 6 * 60 + 18) * 1000;
/// let loc = Loc::new(north, west, -2400, 3000, 1_000_000, 1000)?;
/// assert_eq!(loc.to_string(), "42 21 54.000 N 71 6 18.000 W -24.00m 30m 10000m 10m");
/// assert_eq!(loc.size, 0x33);
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Loc {
    /// Diameter of a sphere enclosing the entity (encoded precision octet).
    pub size: u8,
    /// Horizontal precision: diameter of the circle of error (encoded
    /// precision octet).
    pub horiz_pre: u8,
    /// Vertical precision (encoded precision octet).
    pub vert_pre: u8,
    /// Latitude: thousandths of an arcsecond, 2^31 being the equator
    /// (larger is north).
    pub latitude: u32,
    /// Longitude: thousandths of an arcsecond, 2^31 being the prime
    /// meridian (larger is east).
    pub longitude: u32,
    /// Altitude in centimetres above a base 100 000 m below the WGS 84
    /// reference spheroid.
    pub altitude: u32,
}

impl Loc {
    /// The only defined format version (RFC 1876 §2).
    pub const VERSION: u8 = 0;
    /// Default `size` when the master file omits it: 1 m (RFC 1876 §3).
    pub const DEFAULT_SIZE: u8 = 0x12;
    /// Default `horiz_pre`: 10 000 m (RFC 1876 §3).
    pub const DEFAULT_HORIZ_PRE: u8 = 0x16;
    /// Default `vert_pre`: 10 m (RFC 1876 §3).
    pub const DEFAULT_VERT_PRE: u8 = 0x13;

    /// Builds a location from signed values: latitude and longitude in
    /// thousandths of an arcsecond (positive north / east), altitude in
    /// centimetres relative to the WGS 84 spheroid, and size and
    /// precisions in centimetres (rounded down to the representable
    /// "one digit × power of ten" values, see
    /// [`encode_precision`](Self::encode_precision)).
    ///
    /// Fails with [`Error::InvalidRdata`] if the latitude exceeds ±90°, the
    /// longitude ±180°, or the altitude is below −100 000 m or above
    /// 42 849 672.95 m.
    pub const fn new(
        latitude_mas: i32,
        longitude_mas: i32,
        altitude_cm: i64,
        size_cm: u64,
        horiz_pre_cm: u64,
        vert_pre_cm: u64,
    ) -> Result<Self> {
        if latitude_mas.unsigned_abs() > MAX_LATITUDE
            || longitude_mas.unsigned_abs() > MAX_LONGITUDE
            || altitude_cm < -ALTITUDE_BASE
            || altitude_cm > u32::MAX as i64 - ALTITUDE_BASE
        {
            return Err(Error::InvalidRdata);
        }
        Ok(Loc {
            size: Self::encode_precision(size_cm),
            horiz_pre: Self::encode_precision(horiz_pre_cm),
            vert_pre: Self::encode_precision(vert_pre_cm),
            latitude: EQUATOR.wrapping_add_signed(latitude_mas),
            longitude: EQUATOR.wrapping_add_signed(longitude_mas),
            altitude: (altitude_cm + ALTITUDE_BASE) as u32,
        })
    }

    /// Encodes a size or precision in centimetres as the RFC 1876 §2
    /// octet: the high nibble is a mantissa (0–9), the low nibble a power
    /// of ten. Values that are not "one digit × power of ten" are rounded
    /// down; values of 9 × 10^9 cm or more saturate to `0x99` (the
    /// algorithm of RFC 1876 Appendix A, `precsize_aton`).
    #[must_use]
    pub const fn encode_precision(cm: u64) -> u8 {
        let mut exponent = 0;
        while exponent < 9 && cm >= POWERS[exponent + 1] {
            exponent += 1;
        }
        let mantissa = cm / POWERS[exponent];
        let mantissa = if mantissa > 9 { 9 } else { mantissa };
        ((mantissa as u8) << 4) | exponent as u8
    }

    /// Decodes a size or precision octet into centimetres, or `None` if
    /// the mantissa or exponent exceeds 9 (RFC 1876 §2) or if a zero
    /// mantissa has a non-zero exponent (a non-canonical zero that BIND
    /// also rejects, and that [`encode_precision`](Self::encode_precision)
    /// never produces).
    #[must_use]
    pub const fn decode_precision(octet: u8) -> Option<u64> {
        let mantissa = (octet >> 4) as u64;
        let exponent = (octet & 0x0f) as usize;
        if mantissa > 9 || exponent > 9 || (mantissa == 0 && exponent != 0) {
            return None;
        }
        Some(mantissa * POWERS[exponent])
    }

    /// The size in centimetres (`None` if the octet is invalid).
    #[inline]
    #[must_use]
    pub const fn size_cm(&self) -> Option<u64> {
        Self::decode_precision(self.size)
    }

    /// The horizontal precision in centimetres (`None` if invalid).
    #[inline]
    #[must_use]
    pub const fn horiz_pre_cm(&self) -> Option<u64> {
        Self::decode_precision(self.horiz_pre)
    }

    /// The vertical precision in centimetres (`None` if invalid).
    #[inline]
    #[must_use]
    pub const fn vert_pre_cm(&self) -> Option<u64> {
        Self::decode_precision(self.vert_pre)
    }

    /// The latitude in thousandths of an arcsecond, positive north.
    #[inline]
    #[must_use]
    pub const fn latitude_mas(&self) -> i64 {
        self.latitude as i64 - EQUATOR as i64
    }

    /// The longitude in thousandths of an arcsecond, positive east.
    #[inline]
    #[must_use]
    pub const fn longitude_mas(&self) -> i64 {
        self.longitude as i64 - EQUATOR as i64
    }

    /// The altitude in centimetres relative to the WGS 84 spheroid.
    #[inline]
    #[must_use]
    pub const fn altitude_cm(&self) -> i64 {
        self.altitude as i64 - ALTITUDE_BASE
    }

    /// Checks the field invariants enforced on parsing: valid precision
    /// octets, latitude within ±90° and longitude within ±180°.
    pub const fn validate(&self) -> Result<()> {
        if Self::decode_precision(self.size).is_none()
            || Self::decode_precision(self.horiz_pre).is_none()
            || Self::decode_precision(self.vert_pre).is_none()
            || self.latitude_mas().unsigned_abs() > MAX_LATITUDE as u64
            || self.longitude_mas().unsigned_abs() > MAX_LONGITUDE as u64
        {
            return Err(Error::InvalidRdata);
        }
        Ok(())
    }

    /// The 16-byte wire form.
    #[must_use]
    pub const fn to_wire(&self) -> [u8; 16] {
        let [a0, a1, a2, a3] = self.latitude.to_be_bytes();
        let [o0, o1, o2, o3] = self.longitude.to_be_bytes();
        let [h0, h1, h2, h3] = self.altitude.to_be_bytes();
        [
            Self::VERSION,
            self.size,
            self.horiz_pre,
            self.vert_pre,
            a0,
            a1,
            a2,
            a3,
            o0,
            o1,
            o2,
            o3,
            h0,
            h1,
            h2,
            h3,
        ]
    }
}

/// Parses an unsigned fixed-point decimal `int[.frac]` with at most
/// `places` fraction digits (either part may be empty, not both, as in
/// BIND: `54.`, `.5`) and returns it scaled by 10^`places`.
fn parse_fixed(raw: &[u8], places: usize) -> Result<u64> {
    let (int, frac) = match raw.iter().position(|&c| c == b'.') {
        Some(dot) => (
            raw.get(..dot).unwrap_or(&[]),
            raw.get(dot + 1..).unwrap_or(&[]),
        ),
        None => (raw, &[][..]),
    };
    if (int.is_empty() && frac.is_empty()) || frac.len() > places {
        return Err(Error::InvalidText);
    }
    let digits = int.iter().chain(frac).map(|&c| {
        if c.is_ascii_digit() {
            Ok(u64::from(c - b'0'))
        } else {
            Err(Error::InvalidText)
        }
    });
    let mut v: u64 = 0;
    for d in digits {
        v = v
            .checked_mul(10)
            .and_then(|v| v.checked_add(d.ok()?))
            .ok_or(Error::InvalidText)?;
    }
    for _ in frac.len()..places {
        v = v.checked_mul(10).ok_or(Error::InvalidText)?;
    }
    Ok(v)
}

/// Strips the optional `m` unit of a distance (RFC 1876 §3).
fn strip_metres(raw: &[u8]) -> &[u8] {
    raw.strip_suffix(b"m").unwrap_or(raw)
}

/// Whether `t` is a hemisphere letter (`N`, `S`, `E` or `W`, either
/// case), which ends an angle.
fn is_hemisphere(t: &Token<'_>) -> bool {
    ["N", "S", "E", "W"].iter().any(|h| t.is(h))
}

/// Reads an angle `d [m [s[.fff]]] H` (RFC 1876 §3) of at most `max_deg`
/// degrees, `pos` / `neg` being the hemisphere letters, and returns the
/// raw wire value (thousandths of an arcsecond offset by 2^31).
fn read_angle(s: &mut Scanner<'_>, max_deg: u32, pos: &str, neg: &str) -> Result<u32> {
    let degrees = s.u32()?;
    let mut minutes = 0;
    let mut thousandths = 0;
    let mut t = s.word()?;
    if !is_hemisphere(&t) {
        minutes = t.u8()?;
        t = s.word()?;
        if !is_hemisphere(&t) {
            thousandths = parse_fixed(t.as_bytes(), 3)?;
            t = s.word()?;
        }
    }
    if degrees > max_deg || minutes > 59 || thousandths > 59_999 {
        return Err(Error::InvalidText);
    }
    let abs = (u64::from(degrees) * 60 + u64::from(minutes)) * 60_000 + thousandths;
    if abs > u64::from(max_deg) * 3_600_000 {
        return Err(Error::InvalidText);
    }
    // At most 180° = 648 000 000 < 2^31.
    let abs = abs as u32;
    if t.is(pos) {
        Ok(EQUATOR + abs)
    } else if t.is(neg) {
        Ok(EQUATOR - abs)
    } else {
        Err(Error::InvalidText)
    }
}

/// Reads an altitude `[-]m[.cc][m]` (RFC 1876 §3: −100000.00 to
/// 42849672.95 metres; BIND also accepts a `+` sign) and returns the raw
/// wire value.
fn read_altitude(s: &mut Scanner<'_>) -> Result<u32> {
    let raw = s.word()?.as_bytes();
    let (negative, raw) = match raw.split_first() {
        Some((b'-', rest)) => (true, rest),
        Some((b'+', rest)) => (false, rest),
        _ => (false, raw),
    };
    let cm = i64::try_from(parse_fixed(strip_metres(raw), 2)?).map_err(|_| Error::InvalidText)?;
    let cm = if negative { -cm } else { cm };
    cm.checked_add(ALTITUDE_BASE)
        .and_then(|raw| u32::try_from(raw).ok())
        .ok_or(Error::InvalidText)
}

/// Largest size or precision BIND accepts, in centimetres: up to
/// 90 000 000 whole metres (RFC 1876 §3), which saturates the encoding.
const MAX_PRECISION_CM: u64 = 90_000_000 * 100 + 99;

impl ParseRdataText for Loc {
    /// `d1 [m1 [s1]] {N|S} d2 [m2 [s2]] {E|W} alt[m] [siz[m] [hp[m]
    /// [vp[m]]]]` (RFC 1876 §3): degrees, minutes and seconds (up to three
    /// decimals) with the hemisphere, the altitude in metres (up to two
    /// decimals), then optionally the size and the horizontal and vertical
    /// precisions in metres (defaults 1 m, 10 000 m and 10 m), rounded
    /// down to the "digit × power of ten" values the encoding can hold,
    /// as BIND does.
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        let latitude = read_angle(s, 90, "N", "S")?;
        let longitude = read_angle(s, 180, "E", "W")?;
        let altitude = read_altitude(s)?;
        let mut precisions = [
            Loc::DEFAULT_SIZE,
            Loc::DEFAULT_HORIZ_PRE,
            Loc::DEFAULT_VERT_PRE,
        ];
        for p in &mut precisions {
            let Some(t) = s.next_token()? else { break };
            if t.is_quoted() {
                return Err(Error::InvalidText);
            }
            let cm = parse_fixed(strip_metres(t.as_bytes()), 2)?;
            if cm > MAX_PRECISION_CM {
                return Err(Error::InvalidText);
            }
            *p = Loc::encode_precision(cm);
        }
        let [size, horiz_pre, vert_pre] = precisions;
        let loc = Loc {
            size,
            horiz_pre,
            vert_pre,
            latitude,
            longitude,
            altitude,
        };
        out.put_bytes(&loc.to_wire())
    }
}

impl<'a> ParseRdata<'a> for Loc {
    const RTYPE: Rtype = Rtype::LOC;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        if rdata.peek_u8()? != Self::VERSION {
            return Err(Error::InvalidRdata);
        }
        // Work on a copy so the caller's reader is untouched on failure.
        let mut r = *rdata;
        r.skip(1)?;
        let loc = Loc {
            size: r.read_u8()?,
            horiz_pre: r.read_u8()?,
            vert_pre: r.read_u8()?,
            latitude: r.read_u32()?,
            longitude: r.read_u32()?,
            altitude: r.read_u32()?,
        };
        loc.validate()?;
        *rdata = r;
        Ok(loc)
    }
}

impl ComposeRdata for Loc {
    fn rtype(&self) -> Rtype {
        Rtype::LOC
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        self.validate()?;
        c.put_bytes(&self.to_wire())
    }
}

/// Writes an angle as `d m s.fff H` (RFC 1876 §3), BIND style.
fn fmt_angle(f: &mut fmt::Formatter<'_>, raw: u32, pos: char, neg: char) -> fmt::Result {
    let (abs, hemisphere) = if raw >= EQUATOR {
        (raw - EQUATOR, pos)
    } else {
        (EQUATOR - raw, neg)
    };
    let thousandths = abs % 1000;
    let seconds = abs / 1000;
    write!(
        f,
        "{} {} {}.{:03} {}",
        seconds / 3600,
        (seconds / 60) % 60,
        seconds % 60,
        thousandths,
        hemisphere
    )
}

/// Writes a size or precision in metres: whole metres from 1 m up,
/// `0.xx` below.
fn fmt_precision(f: &mut fmt::Formatter<'_>, octet: u8) -> fmt::Result {
    let cm = Loc::decode_precision(octet).unwrap_or(0);
    if cm >= 100 {
        write!(f, "{}m", cm / 100)
    } else {
        write!(f, "0.{cm:02}m")
    }
}

impl fmt::Display for Loc {
    /// `d1 [m1 [s1]] {N|S} d2 [m2 [s2]] {E|W} alt[m] [siz[m] [hp[m]
    /// [vp[m]]]]` (RFC 1876 §3), always with every field, e.g.
    /// `42 21 54.000 N 71 6 18.000 W -24.00m 30m 10000m 10m`. Invalid
    /// field values (only possible for hand-built values) fall back to the
    /// generic RFC 3597 form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.validate().is_err() {
            return crate::text::fmt_generic_rdata(f, &self.to_wire());
        }
        fmt_angle(f, self.latitude, 'N', 'S')?;
        f.write_str(" ")?;
        fmt_angle(f, self.longitude, 'E', 'W')?;
        let alt = self.altitude_cm();
        let sign = if alt < 0 { "-" } else { "" };
        let alt = alt.unsigned_abs();
        write!(f, " {sign}{}.{:02}m ", alt / 100, alt % 100)?;
        fmt_precision(f, self.size)?;
        f.write_str(" ")?;
        fmt_precision(f, self.horiz_pre)?;
        f.write_str(" ")?;
        fmt_precision(f, self.vert_pre)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdata::tests::{
        compose, parse, round_trip, text_error, text_parse, text_round_trip,
    };
    use crate::{Class, Error, Rtype};
    use std::string::ToString;

    #[test]
    fn rfc1876_example() {
        // cambridge-net.kei.com. LOC 42 21 54 N 71 06 18 W -24m 30m
        // (wire form cross-checked with BIND's named-rrchecker).
        let wire = crate::testutil::hex("0033161389172DD070BE15F000988D20");
        round_trip(
            Rtype::LOC,
            &wire,
            "42 21 54.000 N 71 6 18.000 W -24.00m 30m 10000m 10m",
        );
        let north = (42 * 3600 + 21 * 60 + 54) * 1000;
        let west = -(71 * 3600 + 6 * 60 + 18) * 1000;
        let loc = Loc::new(north, west, -2400, 3000, 1_000_000, 1000).unwrap();
        assert_eq!(compose(&loc), wire);
        assert_eq!(loc.latitude_mas(), i64::from(north));
        assert_eq!(loc.longitude_mas(), i64::from(west));
        assert_eq!(loc.altitude_cm(), -2400);
        assert_eq!(
            (loc.size_cm(), loc.horiz_pre_cm(), loc.vert_pre_cm()),
            (Some(3000), Some(1_000_000), Some(1000))
        );
    }

    #[test]
    fn extremes() {
        // 0 0 0 N 0 0 0 E 0m 0.05m 0.5m 90000000m (named-rrchecker).
        round_trip(
            Rtype::LOC,
            &crate::testutil::hex("00505199800000008000000000989680"),
            "0 0 0.000 N 0 0 0.000 E 0.00m 0.05m 0.50m 90000000m",
        );
        // 90 S 180 W, highest altitude.
        round_trip(
            Rtype::LOC,
            &crate::testutil::hex("001212126CB0270059604E00FFFFFFFF"),
            "90 0 0.000 S 180 0 0.000 W 42849672.95m 1m 1m 1m",
        );
        let lowest = Loc::new(
            90 * 3_600_000,
            180 * 3_600_000,
            -10_000_000,
            0,
            100,
            9_000_000_000,
        )
        .unwrap();
        assert_eq!(
            lowest.to_string(),
            "90 0 0.000 N 180 0 0.000 E -100000.00m 0.00m 1m 90000000m"
        );
        for bad in [
            Loc::new(90 * 3_600_000 + 1, 0, 0, 0, 0, 0),
            Loc::new(0, -180 * 3_600_000 - 1, 0, 0, 0, 0),
            Loc::new(0, 0, -10_000_001, 0, 0, 0),
            Loc::new(0, 0, i64::from(u32::MAX) - 10_000_000 + 1, 0, 0, 0),
            Loc::new(i32::MIN, 0, 0, 0, 0, 0),
        ] {
            assert_eq!(bad, Err(Error::InvalidRdata));
        }
    }

    #[test]
    fn precision_encoding() {
        for (cm, octet) in [
            (0, 0x00),
            (5, 0x50),
            (9, 0x90),
            (10, 0x11),
            (99, 0x91),
            (100, 0x12),
            (150, 0x12),
            (3000, 0x33),
            (1_000_000, 0x16),
            (9_000_000_000, 0x99),
            (u64::MAX, 0x99),
        ] {
            assert_eq!(Loc::encode_precision(cm), octet, "{cm}");
        }
        assert_eq!(Loc::decode_precision(0x99), Some(9_000_000_000));
        assert_eq!(Loc::decode_precision(0x12), Some(100));
        assert_eq!(Loc::decode_precision(0xa0), None);
        assert_eq!(Loc::decode_precision(0x0a), None);
        assert_eq!(Loc::decode_precision(0x05), None);
        assert_eq!(Loc::decode_precision(0x00), Some(0));
        // Every encoding decodes back to a value that re-encodes the same.
        for cm in (0..2000).chain([10u64.pow(9), 123_456_789_012]) {
            let octet = Loc::encode_precision(cm);
            let back = Loc::decode_precision(octet).unwrap();
            assert!(back <= cm);
            assert_eq!(Loc::encode_precision(back), octet);
        }
    }

    #[test]
    fn malformed() {
        let good = crate::testutil::hex("0033161389172DD070BE15F000988D20");
        let with = |i: usize, b: u8| {
            let mut w = good.clone();
            w[i] = b;
            parse(Rtype::LOC, Class::IN, &w).map(|_| ())
        };
        // Version 1 is unknown; precision nibbles above 9.
        assert_eq!(with(0, 1), Err(Error::InvalidRdata));
        assert_eq!(with(1, 0xa0), Err(Error::InvalidRdata));
        assert_eq!(with(2, 0x1a), Err(Error::InvalidRdata));
        assert_eq!(with(3, 0xff), Err(Error::InvalidRdata));
        // Non-canonical zero (BIND: out of range).
        assert_eq!(with(1, 0x01), Err(Error::InvalidRdata));
        // Latitude beyond 90° (BIND: out of range).
        assert_eq!(with(4, 0x99), Err(Error::InvalidRdata));
        // Longitude beyond 180°.
        assert_eq!(with(8, 0xf0), Err(Error::InvalidRdata));
        assert_eq!(
            parse(Rtype::LOC, Class::IN, &good[..15]),
            Err(Error::UnexpectedEof)
        );
        let mut long = good.clone();
        long.push(0);
        assert_eq!(
            parse(Rtype::LOC, Class::IN, &long),
            Err(Error::TrailingData)
        );
        // An invalid hand-built value refuses to compose, displays
        // generically.
        let mut loc = Loc::new(0, 0, 0, 100, 100, 100).unwrap();
        loc.size = 0xab;
        let mut buf = [0u8; 32];
        let mut w = crate::WireWriter::new(&mut buf);
        assert_eq!(loc.compose_rdata(&mut w), Err(Error::InvalidRdata));
        assert!(loc.to_string().starts_with("\\# 16 00AB1212"));
        assert_eq!(loc.size_cm(), None);
    }

    #[test]
    fn text() {
        // RFC 1876 §3 examples; wire forms from named-rrchecker.
        text_round_trip(
            Rtype::LOC,
            "42 21 54 N 71 06 18 W -24m 30m",
            &crate::testutil::hex("0033161389172DD070BE15F000988D20"),
            "42 21 54.000 N 71 6 18.000 W -24.00m 30m 10000m 10m",
        );
        text_round_trip(
            Rtype::LOC,
            "52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m",
            &crate::testutil::hex("000016138B3CF018810CBCE0009895B8"),
            "52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m",
        );
        text_round_trip(
            Rtype::LOC,
            "32 7 19 S 116 2 25 E 10m",
            &crate::testutil::hex("00121613791B7D2898E6486800989A68"),
            "32 7 19.000 S 116 2 25.000 E 10.00m 1m 10000m 10m",
        );
        text_round_trip(
            Rtype::LOC,
            "60 9 0.000 N 24 39 0.000 E ( 10.00m 20.00m\n 2000.00m 20.00m )",
            &crate::testutil::hex("002325238CE82360854A10A000989A68"),
            "60 9 0.000 N 24 39 0.000 E 10.00m 20m 2000m 20m",
        );
        // Omitted minutes and seconds, no unit.
        text_round_trip(
            Rtype::LOC,
            "42 N 71 W 0",
            &crate::testutil::hex("001216138903210070C3DA8000989680"),
            "42 0 0.000 N 71 0 0.000 W 0.00m 1m 10000m 10m",
        );
        // Extremes.
        text_round_trip(
            Rtype::LOC,
            "90 0 0 N 180 0 0 W 42849672.95m",
            &crate::testutil::hex("00121613934FD90059604E00FFFFFFFF"),
            "90 0 0.000 N 180 0 0.000 W 42849672.95m 1m 10000m 10m",
        );
        text_round_trip(
            Rtype::LOC,
            "90 S 180 E -100000m 0 0.05m 90000000m",
            &crate::testutil::hex("000050996CB02700A69FB20000000000"),
            "90 0 0.000 S 180 0 0.000 E -100000.00m 0.00m 0.05m 90000000m",
        );
        // BIND's lenient forms (named-rrchecker).
        for (text, wire) in [
            ("42 21 .5 n 71 06 18 w 0", "0012161389165CD470BE15F000989680"),
            ("42 21 54.5 N 71 06 18 W -.5", "0012161389172FC470BE15F00098964E"),
            ("42 21 54.5 N 71 06 18 W +1.", "0012161389172FC470BE15F0009896E4"),
            ("42 21 54.5 N 71 06 18 W 1.55m 1.", "0012161389172FC470BE15F00098971B"),
            ("0 0 59.999 N 0 E 0", "001216138000EA5F8000000000989680"),
            ("00 0 N 0 E 0 0.", "00001613800000008000000000989680"),
            // Precisions are rounded down: 0.15m, 99m, 1.5m.
            ("0 N 0 E 0 0.15m 99m 1.5m", "00119312800000008000000000989680"),
            // 90000000.01m saturates.
            ("0 N 0 E 0 90000000.01m", "00991613800000008000000000989680"),
        ] {
            assert_eq!(
                text_parse(Rtype::LOC, text),
                Ok(crate::testutil::hex(wire)),
                "{text}"
            );
        }
    }

    #[test]
    fn text_malformed() {
        for (text, err) in [
            // Out of range (BIND: "out of range").
            ("91 N 0 E 0", Error::InvalidText),
            ("90 1 N 0 E 0", Error::InvalidText),
            ("90 0 0.001 S 0 E 0", Error::InvalidText),
            ("0 60 N 0 E 0", Error::InvalidText),
            ("0 0 60 N 0 E 0", Error::InvalidText),
            ("0 N 181 E 0", Error::InvalidText),
            ("0 N 0 E 42849672.96m", Error::InvalidText),
            ("0 N 0 E -100000.01m", Error::InvalidText),
            ("0 N 0 E 0 90000001m", Error::InvalidText),
            ("0 N 0 E 0 99999999999999999999999m", Error::InvalidText),
            ("0 N 0 E 99999999999999999999999m", Error::InvalidText),
            ("4294967296 N 0 E 0", Error::InvalidText),
            // Syntax (BIND: "syntax error", "not a valid number").
            ("0 0 59.9999 N 0 E 0", Error::InvalidText),
            ("0 N 0 E 1.555m", Error::InvalidText),
            ("0 N 0 E 0M", Error::InvalidText),
            ("0 N 0 E 0 1M", Error::InvalidText),
            ("0 N 0 E .", Error::InvalidText),
            ("0 N 0 E -", Error::InvalidText),
            ("0 N 0 E m", Error::InvalidText),
            ("0 N 0 E 1.2.3", Error::InvalidText),
            ("-1 N 0 E 0", Error::InvalidText),
            ("0 E 0 N 0", Error::InvalidText),
            ("0 N 0 N 0", Error::InvalidText),
            ("0 1 2 3 N 0 E 0", Error::InvalidText),
            ("0 N 0 E 0 \"1m\"", Error::InvalidText),
            ("\"0\" N 0 E 0", Error::InvalidText),
            ("0 N 0 E 0 1m 2m 3m 4m", Error::InvalidText),
            // Missing fields.
            ("", Error::UnexpectedEof),
            ("0 N", Error::UnexpectedEof),
            ("0 N 0 E", Error::UnexpectedEof),
            ("0 0 0", Error::UnexpectedEof),
        ] {
            assert_eq!(text_error(Rtype::LOC, text), err, "{text:?}");
        }
    }
}
