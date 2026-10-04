//! ATMA record data (ATM Forum AF-DANS-0152.000, "ATM Name System
//! Specification Version 1.0").

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::wire::{Composer, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Class, Error, Result, Rtype};

/// `ATMA` record data: an ATM address (ATM Forum AF-DANS-0152.000).
/// Class IN only, as in BIND.
///
/// The address is kept as received. Its presentation depends on the
/// format: AESA addresses (format 0) are hexadecimal digits, E.164
/// addresses (format 1, which must be ASCII digits) are written with a
/// leading `+`. Unknown formats are accepted and displayed in the generic
/// RFC 3597 form.
///
/// ```
/// use dnsbox::rdata::{Atma, ParseRdataText};
///
/// // An E.164 ATM address.
/// let mut buf = [0u8; 16];
/// let atma = Atma::from_text("+1.2345", &mut buf)?;
/// assert_eq!((atma.format, atma.address), (Atma::E164, &b"12345"[..]));
/// assert_eq!(atma.to_string(), "+12345");
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Atma<'a> {
    /// The address format: [`Atma::AESA`], [`Atma::E164`] or another value.
    pub format: u8,
    /// The address (at least one octet).
    pub address: &'a [u8],
}

impl Atma<'_> {
    /// ATM End System Address format (binary, shown as hex).
    pub const AESA: u8 = 0;
    /// E.164 format (ASCII digits).
    pub const E164: u8 = 1;

    /// Checks that the address is non-empty and, for E.164, all digits.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedEof`] for an empty address,
    /// [`Error::InvalidRdata`] for a non-digit in an E.164 address.
    pub fn validate(&self) -> Result<()> {
        if self.address.is_empty() {
            return Err(Error::UnexpectedEof);
        }
        if self.format == Self::E164 && !self.address.iter().all(u8::is_ascii_digit) {
            return Err(Error::InvalidRdata);
        }
        Ok(())
    }
}

impl ParseRdataText for Atma<'_> {
    /// One token (ATM Forum AF-DANS-0152.000 §4, as BIND reads it): `+`
    /// and decimal digits for an E.164 address, otherwise hexadecimal
    /// digits for an AESA address; `.` separators may appear anywhere.
    /// Other formats have no presentation form (generic form only).
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        let t = s.word()?;
        match t.as_bytes() {
            [b'+', digits @ ..] => {
                out.put_u8(Atma::E164)?;
                for &c in digits.iter().filter(|&&c| c != b'.') {
                    if !c.is_ascii_digit() {
                        return Err(Error::InvalidText);
                    }
                    out.put_u8(c)?;
                }
                Ok(())
            }
            hex => {
                out.put_u8(Atma::AESA)?;
                super::nsap::put_dotted_hex(hex, out).map(drop)
            }
        }
    }
}

impl<'a> ParseRdata<'a> for Atma<'a> {
    const RTYPE: Rtype = Rtype::ATMA;
    const CLASS: Option<Class> = Some(Class::IN);

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        let mut r = *rdata;
        let atma = Atma {
            format: r.read_u8()?,
            address: r.read_rest(),
        };
        atma.validate()?;
        *rdata = r;
        Ok(atma)
    }
}

impl ComposeRdata for Atma<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::ATMA
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        self.validate().map_err(|_| Error::InvalidRdata)?;
        c.put_u8(self.format)?;
        c.put_bytes(self.address)
    }
}

impl fmt::Display for Atma<'_> {
    /// AESA: lowercase hex digits; E.164: `+` and the digits; other
    /// formats: `\# <len> <hex>`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.format {
            Self::AESA => self
                .address
                .iter()
                .try_for_each(|b| write!(f, "{b:02x}")),
            Self::E164 if self.validate().is_ok() => {
                f.write_str("+")?;
                self.address
                    .iter()
                    .try_for_each(|&b| fmt::Write::write_char(f, b as char))
            }
            _ => {
                write!(f, "\\# {} {:02X}", self.address.len() + 1, self.format)?;
                fmt::Display::fmt(&crate::text::Hex(self.address), f)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Atma;
    use crate::rdata::tests::{parse, round_trip, text_error, text_round_trip};
    use crate::{Class, ComposeRdata, Error, Rtype};
    use std::string::ToString;

    #[test]
    fn round_trips() {
        // ATMA 47000580ffde0000000000ffffffffffffffff00 and ATMA +12345
        // (named-rrchecker).
        round_trip(
            Rtype::ATMA,
            &crate::testutil::hex("0047000580FFDE0000000000FFFFFFFFFFFFFFFF00"),
            "47000580ffde0000000000ffffffffffffffff00",
        );
        round_trip(Rtype::ATMA, b"\x0112345", "+12345");
        round_trip(Rtype::ATMA, b"\x00\x01", "01");
        // Unknown format: generic form, as BIND prints it.
        round_trip(Rtype::ATMA, b"\x021", "\\# 2 0231");
    }

    #[test]
    fn malformed() {
        assert_eq!(
            parse(Rtype::ATMA, Class::IN, b"\x00"),
            Err(Error::UnexpectedEof)
        );
        assert_eq!(
            parse(Rtype::ATMA, Class::IN, b"\x01a"),
            Err(Error::InvalidRdata)
        );
        let bad = Atma {
            format: Atma::E164,
            address: b"1-2",
        };
        assert_eq!(bad.to_string(), "\\# 4 01312D32");
        let mut buf = [0u8; 8];
        let mut w = crate::WireWriter::new(&mut buf);
        assert_eq!(bad.compose_rdata(&mut w), Err(Error::InvalidRdata));
    }

    #[test]
    fn text() {
        // named-rrchecker.
        text_round_trip(
            Rtype::ATMA,
            "47.0005.80.ffde00.0000.0000.ffff.ffffffffffff.00",
            &crate::testutil::hex("0047000580FFDE0000000000FFFFFFFFFFFFFFFF00"),
            "47000580ffde0000000000ffffffffffffffff00",
        );
        text_round_trip(Rtype::ATMA, "+1.2345", b"\x0112345", "+12345");
        text_round_trip(Rtype::ATMA, "01", b"\x00\x01", "01");
        // Unknown formats only in the generic form.
        text_round_trip(Rtype::ATMA, "\\# 2 0231", b"\x021", "\\# 2 0231");
        for (text, err) in [
            // BIND: "unexpected end of input", "extra input text".
            ("4", Error::InvalidText),
            ("47 00", Error::InvalidText),
            ("+12a", Error::InvalidText),
            ("+-1", Error::InvalidText),
            ("4g", Error::InvalidText),
            ("\"47\"", Error::InvalidText),
            ("+", Error::UnexpectedEof),
            ("..", Error::UnexpectedEof),
            ("", Error::UnexpectedEof),
        ] {
            assert_eq!(text_error(Rtype::ATMA, text), err, "{text:?}");
        }
    }
}
