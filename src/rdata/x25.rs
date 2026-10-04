//! X25 record data (RFC 1183 §3.1).

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::charstr::CharStr;
use crate::wire::{Composer, WireReader};
use crate::{Error, Result, Rtype};

/// `X25` record data: an X.121 PSDN address (RFC 1183 §3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct X25<'a> {
    /// The PSDN address: at least four decimal digits (RFC 1183 §3.1).
    pub psdn_address: CharStr<'a>,
}

impl<'a> X25<'a> {
    /// Wraps a PSDN address, which must be at least four ASCII decimal
    /// digits ([`Error::InvalidRdata`] otherwise).
    pub fn new(psdn_address: CharStr<'a>) -> Result<Self> {
        let x = X25 { psdn_address };
        x.validate()?;
        Ok(x)
    }

    /// Checks that the address is at least four decimal digits
    /// (RFC 1183 §3.1).
    pub fn validate(&self) -> Result<()> {
        let digits = self.psdn_address.as_bytes();
        if digits.len() < 4 || !digits.iter().all(u8::is_ascii_digit) {
            return Err(Error::InvalidRdata);
        }
        Ok(())
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
    use crate::rdata::tests::{parse, round_trip};
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
}
