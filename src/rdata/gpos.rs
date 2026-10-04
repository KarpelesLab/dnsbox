//! GPOS record data (RFC 1712 §3).

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::charstr::CharStr;
use crate::wire::{Composer, WireReader};
use crate::{Result, Rtype};

/// `GPOS` record data: a geographical position as three decimal strings
/// (RFC 1712 §3). Superseded by [`Loc`](super::Loc).
///
/// The strings are kept as received; RFC 1712 expects real numbers
/// (longitude −180..180, latitude −90..90, altitude in metres).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Gpos<'a> {
    /// Longitude in decimal degrees, positive east.
    pub longitude: CharStr<'a>,
    /// Latitude in decimal degrees, positive north.
    pub latitude: CharStr<'a>,
    /// Altitude in metres.
    pub altitude: CharStr<'a>,
}

impl super::ParseRdataText for Gpos<'_> {}

impl<'a> ParseRdata<'a> for Gpos<'a> {
    const RTYPE: Rtype = Rtype::GPOS;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        let mut r = *rdata;
        let gpos = Gpos {
            longitude: r.read_char_string()?,
            latitude: r.read_char_string()?,
            altitude: r.read_char_string()?,
        };
        *rdata = r;
        Ok(gpos)
    }
}

impl ComposeRdata for Gpos<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::GPOS
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        self.longitude.compose(c)?;
        self.latitude.compose(c)?;
        self.altitude.compose(c)
    }
}

impl fmt::Display for Gpos<'_> {
    /// Three quoted strings: longitude, latitude, altitude.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.longitude, self.latitude, self.altitude)
    }
}

#[cfg(test)]
mod tests {
    use crate::rdata::tests::{parse, round_trip};
    use crate::{Class, Error, Rtype};

    #[test]
    fn rfc1712_example() {
        // GPOS -32.6882 116.8652 10.0 (named-rrchecker).
        round_trip(
            Rtype::GPOS,
            b"\x08-32.6882\x08116.8652\x0410.0",
            "\"-32.6882\" \"116.8652\" \"10.0\"",
        );
        round_trip(Rtype::GPOS, b"\x00\x00\x00", "\"\" \"\" \"\"");
        assert_eq!(
            parse(Rtype::GPOS, Class::IN, b"\x00\x00"),
            Err(Error::UnexpectedEof)
        );
    }
}
