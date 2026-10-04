//! MX record data (RFC 1035 §3.3.9).

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Result, Rtype};

/// `MX` record data: a mail exchange (RFC 1035 §3.3.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Mx<'a> {
    /// Preference; lower values are preferred.
    pub preference: u16,
    /// The mail exchange host.
    pub exchange: Name<'a>,
}

impl<'a> ParseRdata<'a> for Mx<'a> {
    const RTYPE: Rtype = Rtype::MX;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        Ok(Mx {
            preference: rdata.read_u16()?,
            exchange: rdata.read_name()?,
        })
    }
}

impl ComposeRdata for Mx<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::MX
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_u16(self.preference)?;
        c.put_name(self.exchange, NameEncoding::Compressible)
    }
}

impl fmt::Display for Mx<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.preference, self.exchange)
    }
}

impl ParseRdataText for Mx<'_> {
    /// `<preference> <exchange>` (RFC 1035 §3.3.9).
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        out.put_u16(s.u16()?)?;
        s.name_into(out, NameEncoding::Compressible)
    }
}

#[cfg(test)]
mod tests {
    use crate::rdata::tests::{text_error, text_round_trip};
    use crate::{Error, Rtype};

    #[test]
    fn text() {
        // RFC 1035 §5.3: "MX 10 VENERA" with origin ISI.EDU.
        text_round_trip(
            Rtype::MX,
            "10 VENERA",
            b"\x00\x0a\x06VENERA\x07example\x00",
            "10 VENERA.example.",
        );
        text_round_trip(Rtype::MX, "0 .", b"\x00\x00\x00", "0 .");
        text_round_trip(
            Rtype::MX,
            "( 65535\n mx.example.net. ) ; comment",
            b"\xff\xff\x02mx\x07example\x03net\x00",
            "65535 mx.example.net.",
        );
        assert_eq!(text_error(Rtype::MX, "65536 a."), Error::InvalidText);
        assert_eq!(text_error(Rtype::MX, "-1 a."), Error::InvalidText);
        assert_eq!(text_error(Rtype::MX, "10"), Error::UnexpectedEof);
        assert_eq!(text_error(Rtype::MX, "10 a. b."), Error::InvalidText);
        assert_eq!(text_error(Rtype::MX, "10 a..b"), Error::EmptyLabel);
        assert_eq!(text_error(Rtype::MX, "x a."), Error::InvalidText);
    }
}
