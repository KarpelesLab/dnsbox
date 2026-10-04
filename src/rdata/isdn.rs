//! ISDN record data (RFC 1183 §3.2).

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::charstr::CharStr;
use crate::wire::{Composer, WireReader};
use crate::{Result, Rtype};

/// `ISDN` record data: an ISDN telephone number and optional
/// subaddress (RFC 1183 §3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Isdn<'a> {
    /// The ISDN address (country code, area code, number).
    pub address: CharStr<'a>,
    /// The optional subaddress.
    pub subaddress: Option<CharStr<'a>>,
}

impl super::ParseRdataText for Isdn<'_> {}

impl<'a> ParseRdata<'a> for Isdn<'a> {
    const RTYPE: Rtype = Rtype::ISDN;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        let mut r = *rdata;
        let address = r.read_char_string()?;
        let subaddress = if r.is_empty() {
            None
        } else {
            Some(r.read_char_string()?)
        };
        *rdata = r;
        Ok(Isdn {
            address,
            subaddress,
        })
    }
}

impl ComposeRdata for Isdn<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::ISDN
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        self.address.compose(c)?;
        match self.subaddress {
            Some(sa) => sa.compose(c),
            None => Ok(()),
        }
    }
}

impl fmt::Display for Isdn<'_> {
    /// `"address" ["subaddress"]` (RFC 1183 §3.2).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.address, f)?;
        if let Some(sa) = self.subaddress {
            write!(f, " {sa}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::rdata::tests::{parse, round_trip};
    use crate::{Class, Error, Rtype};

    #[test]
    fn rfc1183_examples() {
        // ISDN 150862028003217 [004] (named-rrchecker).
        round_trip(
            Rtype::ISDN,
            b"\x0f150862028003217",
            "\"150862028003217\"",
        );
        round_trip(
            Rtype::ISDN,
            b"\x0f150862028003217\x03004",
            "\"150862028003217\" \"004\"",
        );
        round_trip(Rtype::ISDN, b"\x00\x00", "\"\" \"\"");
    }

    #[test]
    fn malformed() {
        assert_eq!(
            parse(Rtype::ISDN, Class::IN, b"\x011\x01"),
            Err(Error::UnexpectedEof)
        );
        assert_eq!(
            parse(Rtype::ISDN, Class::IN, b"\x011\x011\x00"),
            Err(Error::TrailingData)
        );
    }
}
