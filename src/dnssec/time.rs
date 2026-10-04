//! DNSSEC time values: RFC 1982 serial-number arithmetic and the
//! `YYYYMMDDHHmmSS` presentation format of RRSIG/SIG timestamps
//! (RFC 4034 §3.1.5, §3.2).

use core::cmp::Ordering;
use core::fmt;
use core::str::FromStr;

use crate::{Error, Result};

/// Compares two 32-bit serial numbers with RFC 1982 §3.2 arithmetic, as
/// required for RRSIG validity times (RFC 4034 §3.1.5).
///
/// Returns `None` when the comparison is undefined (the values are exactly
/// 2^31 apart).
///
/// ```
/// use core::cmp::Ordering;
/// use dnsbox::dnssec::serial_cmp;
///
/// assert_eq!(serial_cmp(1, 2), Some(Ordering::Less));
/// // Wrap-around: 0xffff_fff0 comes just before 5.
/// assert_eq!(serial_cmp(0xffff_fff0, 5), Some(Ordering::Less));
/// assert_eq!(serial_cmp(0, 0x8000_0000), None);
/// ```
#[must_use]
pub const fn serial_cmp(a: u32, b: u32) -> Option<Ordering> {
    let diff = b.wrapping_sub(a);
    if diff == 0 {
        Some(Ordering::Equal)
    } else if diff < 0x8000_0000 {
        Some(Ordering::Less)
    } else if diff > 0x8000_0000 {
        Some(Ordering::Greater)
    } else {
        None
    }
}

/// Checks that `now` lies within `[inception, expiration]` using serial
/// arithmetic (RFC 4035 §5.3.1, RFC 4034 §3.1.5).
///
/// Fails with [`Error::SignatureNotYetValid`] if `now` is before the
/// inception time and [`Error::SignatureExpired`] if it is after the
/// expiration time (including undefined comparisons, and windows whose
/// expiration precedes their inception).
pub const fn check_validity(inception: u32, expiration: u32, now: u32) -> Result<()> {
    if !matches!(
        serial_cmp(inception, expiration),
        Some(Ordering::Less | Ordering::Equal)
    ) {
        return Err(Error::SignatureExpired);
    }
    if !matches!(
        serial_cmp(inception, now),
        Some(Ordering::Less | Ordering::Equal)
    ) {
        return Err(Error::SignatureNotYetValid);
    }
    if !matches!(
        serial_cmp(now, expiration),
        Some(Ordering::Less | Ordering::Equal)
    ) {
        return Err(Error::SignatureExpired);
    }
    Ok(())
}

/// An RRSIG/SIG timestamp: seconds since 1970-01-01T00:00:00Z modulo 2^32
/// (RFC 4034 §3.1.5).
///
/// `Display` writes the `YYYYMMDDHHmmSS` UTC form (RFC 4034 §3.2), reading
/// the value as a time between 1970 and 2106. `FromStr` accepts that form
/// or a plain decimal number of seconds; dates past 2106 wrap modulo 2^32.
///
/// ```
/// use dnsbox::dnssec::Timestamp;
///
/// let t: Timestamp = "20300101000000".parse()?;
/// assert_eq!(t.get(), 1_893_456_000);
/// assert_eq!(Timestamp::new(1_440_021_600).to_string(), "20150819220000");
/// assert_eq!(Timestamp::from_utc(2000, 1, 1, 0, 0, 0), Some(Timestamp::new(946_684_800)));
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Timestamp(u32);

impl Timestamp {
    /// Wraps a raw value.
    #[inline]
    #[must_use]
    pub const fn new(secs: u32) -> Self {
        Timestamp(secs)
    }

    /// The raw value.
    #[inline]
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Builds a timestamp from a UTC calendar date and time (year 1970 or
    /// later; later than 2106 wraps modulo 2^32). Returns `None` for an
    /// invalid date or time.
    #[must_use]
    pub const fn from_utc(year: u32, month: u32, day: u32, h: u32, m: u32, s: u32) -> Option<Self> {
        if year < 1970 || year > 9999 || month < 1 || month > 12 || day < 1 || h > 23 || m > 59 {
            return None;
        }
        // RFC 4034 does not mention leap seconds; accept :60 like strptime.
        if s > 60 || day > days_in_month(year, month) {
            return None;
        }
        let days = days_from_civil(year, month, day);
        let secs = days * 86_400 + (h as u64) * 3600 + (m as u64) * 60 + s as u64;
        Some(Timestamp(secs as u32))
    }

    /// The UTC calendar date and time `(year, month, day, hour, minute,
    /// second)`, reading the value as seconds since 1970.
    #[must_use]
    pub const fn to_utc(self) -> (u32, u32, u32, u32, u32, u32) {
        let secs = self.0 as u64;
        let days = secs / 86_400;
        let rem = (secs % 86_400) as u32;
        let (y, mo, d) = civil_from_days(days);
        (y, mo, d, rem / 3600, rem / 60 % 60, rem % 60)
    }
}

impl From<u32> for Timestamp {
    #[inline]
    fn from(v: u32) -> Self {
        Timestamp(v)
    }
}

impl From<Timestamp> for u32 {
    #[inline]
    fn from(v: Timestamp) -> Self {
        v.0
    }
}

impl PartialOrd for Timestamp {
    /// RFC 1982 serial-number order; `None` when undefined.
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        serial_cmp(self.0, other.0)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (y, mo, d, h, mi, s) = self.to_utc();
        write!(f, "{y:04}{mo:02}{d:02}{h:02}{mi:02}{s:02}")
    }
}

impl FromStr for Timestamp {
    type Err = Error;

    /// Parses `YYYYMMDDHHmmSS` (UTC) or a decimal number of seconds
    /// (RFC 4034 §3.2).
    fn from_str(s: &str) -> Result<Self> {
        let b = s.as_bytes();
        if b.is_empty() || !b.iter().all(u8::is_ascii_digit) {
            return Err(Error::InvalidText);
        }
        if b.len() == 14 {
            let num = |r: core::ops::Range<usize>| -> u32 {
                b.get(r)
                    .unwrap_or(&[])
                    .iter()
                    .fold(0, |acc, &d| acc * 10 + u32::from(d - b'0'))
            };
            return Timestamp::from_utc(
                num(0..4),
                num(4..6),
                num(6..8),
                num(8..10),
                num(10..12),
                num(12..14),
            )
            .ok_or(Error::InvalidText);
        }
        s.parse::<u32>()
            .map(Timestamp)
            .map_err(|_| Error::InvalidText)
    }
}

const fn is_leap(y: u32) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

const fn days_in_month(y: u32, m: u32) -> u32 {
    match m {
        2 if is_leap(y) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (year >= 1970).
const fn days_from_civil(y: u32, m: u32, d: u32) -> u64 {
    let y = if m <= 2 { y - 1 } else { y } as u64;
    let era = y / 400;
    let yoe = y - era * 400;
    let mp = ((m + 9) % 12) as u64;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date of a day count since 1970-01-01.
const fn civil_from_days(days: u64) -> (u32, u32, u32) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = (yoe + era * 400) as u32 + if m <= 2 { 1 } else { 0 };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::ToString;

    #[test]
    fn serial_arithmetic() {
        assert_eq!(serial_cmp(5, 5), Some(Ordering::Equal));
        assert_eq!(serial_cmp(5, 6), Some(Ordering::Less));
        assert_eq!(serial_cmp(6, 5), Some(Ordering::Greater));
        assert_eq!(serial_cmp(u32::MAX, 0), Some(Ordering::Less));
        assert_eq!(serial_cmp(0, u32::MAX), Some(Ordering::Greater));
        assert_eq!(serial_cmp(0, 0x7fff_ffff), Some(Ordering::Less));
        assert_eq!(serial_cmp(0, 0x8000_0001), Some(Ordering::Greater));
        assert_eq!(serial_cmp(7, 0x8000_0007), None);
        assert_eq!(
            Timestamp::new(1).partial_cmp(&Timestamp::new(2)),
            Some(Ordering::Less)
        );
    }

    #[test]
    fn validity() {
        assert_eq!(check_validity(10, 20, 15), Ok(()));
        assert_eq!(check_validity(10, 20, 10), Ok(()));
        assert_eq!(check_validity(10, 20, 20), Ok(()));
        assert_eq!(check_validity(10, 20, 9), Err(Error::SignatureNotYetValid));
        assert_eq!(check_validity(10, 20, 21), Err(Error::SignatureExpired));
        // Inverted window.
        assert_eq!(check_validity(20, 10, 15), Err(Error::SignatureExpired));
        // A window spanning the 2^32 wrap (RFC 4034 §3.1.5).
        assert_eq!(check_validity(0xffff_ff00, 0x100, 5), Ok(()));
        assert_eq!(
            check_validity(0xffff_ff00, 0x100, 0x200),
            Err(Error::SignatureExpired)
        );
        // Undefined comparisons fail.
        assert_eq!(
            check_validity(0, 0x8000_0000, 1),
            Err(Error::SignatureExpired)
        );
        assert_eq!(
            check_validity(0x10, 0x20, 0x8000_0010),
            Err(Error::SignatureNotYetValid)
        );
    }

    #[test]
    fn dates() {
        // RFC 4034 §3.3 example times.
        let t: Timestamp = "20030322173103".parse().unwrap();
        assert_eq!(t.get(), 1_048_354_263);
        assert_eq!(t.to_string(), "20030322173103");
        assert_eq!(Timestamp::new(0).to_string(), "19700101000000");
        assert_eq!(Timestamp::new(u32::MAX).to_string(), "21060207062815");
        assert_eq!(
            "20000229000000".parse::<Timestamp>().unwrap().get(),
            951_782_400
        );
        assert_eq!("1048354263".parse(), Ok(t));
        // 2106-02-07 06:28:16 wraps to 0.
        assert_eq!("21060207062816".parse(), Ok(Timestamp::new(0)));
        for bad in [
            "",
            "x",
            "-1",
            "4294967296",
            "20030230000000",
            "20031301000000",
            "20030100000000",
            "20030101240000",
            "20030101006000",
            "19691231235959",
            "2003032217310",
        ] {
            assert_eq!(bad.parse::<Timestamp>(), Err(Error::InvalidText), "{bad}");
        }
        // Every day for a few centuries round-trips.
        let mut secs = 0u64;
        while secs <= u64::from(u32::MAX) {
            let t = Timestamp::new(secs as u32);
            let (y, mo, d, h, mi, s) = t.to_utc();
            assert_eq!(Timestamp::from_utc(y, mo, d, h, mi, s), Some(t));
            secs += 86_400 * 7 + 3_661;
        }
        assert_eq!(u32::from(Timestamp::from(9)), 9);
    }
}
