//! X25 record data (RFC 1183 §3.1).

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::charstr::CharStr;
use crate::wire::{Composer, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Error, Result, Rtype};

/// `X25` record data: an X.121 PSDN address (RFC 1183 §3.1).
///
/// ```
/// use dnsbox::rdata::{ParseRdataText, X25};
/// use dnsbox::CharStr;
///
/// let mut buf = [0u8; 16];
/// let x25 = X25::from_text("311061700956", &mut buf)?;
/// assert_eq!(x25, X25::new(CharStr::new(b"311061700956")?)?);
/// assert!(X25::new(CharStr::new(b"12")?).is_err()); // too short
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct X25<'a> {
    /// The PSDN address: at least four decimal digits (RFC 1183 §3.1).
    pub psdn_address: CharStr<'a>,
}

impl<'a> X25<'a> {
    /// Wraps a PSDN address.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRdata`] unless it is at least four ASCII decimal
    /// digits.
    pub fn new(psdn_address: CharStr<'a>) -> Result<Self> {
        let x = X25 { psdn_address };
        x.validate()?;
        Ok(x)
    }

    /// Checks that the address is at least four decimal digits
    /// (RFC 1183 §3.1).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRdata`] if it is not.
    pub fn validate(&self) -> Result<()> {
        let digits = self.psdn_address.as_bytes();
        if digits.len() < 4 || !digits.iter().all(u8::is_ascii_digit) {
            return Err(Error::InvalidRdata);
        }
        Ok(())
    }
}

impl ParseRdataText for X25<'_> {
    /// `<PSDN-address>` (RFC 1183 §3.1): one `<character-string>`, quoted
    /// or not, of at least four decimal digits.
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        s.char_string_into(out)
    }
}

impl<'a> ParseRdata<'a> for X25<'a> {
    const RTYPE: Rtype = Rtype::X25;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        let mut r = *rdata;
        let x = X25::new(r.read_char_string()?)?;
        *rdata = r;
        Ok(x)
    }
}

impl ComposeRdata for X25<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::X25
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        self.validate()?;
        self.psdn_address.compose(c)
    }
}

impl fmt::Display for X25<'_> {
    /// The address as a quoted `<character-string>`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.psdn_address, f)
    }
}

#[cfg(test)]
mod tests {
    use super::X25;
    use crate::rdata::tests::{parse, round_trip, text_error, text_round_trip};
    use crate::{CharStr, Class, Error, Rtype};

    #[test]
    fn rfc1183_example() {
        // X25 311061700956 (named-rrchecker).
        round_trip(Rtype::X25, b"\x0c311061700956", "\"311061700956\"");
        round_trip(Rtype::X25, b"\x041234", "\"1234\"");
    }

    #[test]
    fn malformed() {
        for bad in [&b"\x03123"[..], b"\x04123a", b"\x00"] {
            assert_eq!(
                parse(Rtype::X25, Class::IN, bad),
                Err(Error::InvalidRdata),
                "{bad:?}"
            );
        }
        assert_eq!(
            X25::new(CharStr::new(b"12 34").unwrap()),
            Err(Error::InvalidRdata)
        );
        assert_eq!(
            parse(Rtype::X25, Class::IN, b"\x041234\x00"),
            Err(Error::TrailingData)
        );
    }

    #[test]
    fn text() {
        // RFC 1183 §3.1: "Relay.Prime.COM.  X25  311061700956".
        text_round_trip(Rtype::X25, "311061700956", b"\x0c311061700956", "\"311061700956\"");
        text_round_trip(Rtype::X25, "\"1234\"", b"\x041234", "\"1234\"");
        text_round_trip(Rtype::X25, "\\0491234", b"\x0511234", "\"11234\"");
    }

    #[test]
    fn text_malformed() {
        for (text, err) in [
            ("", Error::UnexpectedEof),
            ("311061700956 1", Error::InvalidText),
            // RFC 1183 §3.1: at least four decimal digits.
            ("123", Error::InvalidRdata),
            ("\"\"", Error::InvalidRdata),
            ("1234a", Error::InvalidRdata),
            ("\"12 34\"", Error::InvalidRdata),
        ] {
            assert_eq!(text_error(Rtype::X25, text), err, "{text:?}");
        }
        let long = "1".repeat(256);
        assert_eq!(text_error(Rtype::X25, &long), Error::CharStringTooLong);
    }
}
