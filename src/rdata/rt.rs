//! RT record data (RFC 1183 §3.3).

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Result, Rtype};

/// `RT` record data: a route-through intermediate host
/// (RFC 1183 §3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Rt<'a> {
    /// Preference; lower values are preferred.
    pub preference: u16,
    /// The intermediate host, which should have A, X25 or ISDN records.
    pub intermediate: Name<'a>,
}

impl ParseRdataText for Rt<'_> {
    /// `<preference> <intermediate-host>` (RFC 1183 §3.3): a decimal
    /// number and a domain name, relative to the origin unless it ends in
    /// a dot.
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        out.put_u16(s.u16()?)?;
        s.name_into(out, NameEncoding::Lowercase)
    }
}

impl<'a> ParseRdata<'a> for Rt<'a> {
    const RTYPE: Rtype = Rtype::RT;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        Ok(Rt {
            preference: rdata.read_u16()?,
            // RFC 3597 §4 lists RT among the types receivers decompress.
            intermediate: rdata.read_name()?,
        })
    }
}

impl ComposeRdata for Rt<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::RT
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_u16(self.preference)?;
        // Never compressed (RFC 3597 §4), lowercased in canonical form
        // (RFC 4034 §6.2).
        c.put_name(self.intermediate, NameEncoding::Lowercase)
    }
}

impl fmt::Display for Rt<'_> {
    /// `preference intermediate-host` (RFC 1183 §3.3).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.preference, self.intermediate)
    }
}

#[cfg(test)]
mod tests {
    use crate::rdata::tests::{round_trip, text_error, text_round_trip};
    use crate::{Error, Rtype};

    #[test]
    fn rfc1183_example() {
        // RT 2 relay.prime.com. (named-rrchecker).
        round_trip(
            Rtype::RT,
            b"\x00\x02\x05relay\x05prime\x03com\x00",
            "2 relay.prime.com.",
        );
    }

    #[test]
    fn text() {
        // RFC 1183 §3.3 examples.
        text_round_trip(
            Rtype::RT,
            "2    Relay.Prime.COM.",
            b"\x00\x02\x05Relay\x05Prime\x03COM\x00",
            "2 Relay.Prime.COM.",
        );
        text_round_trip(
            Rtype::RT,
            "10   NET.Prime.COM.",
            b"\x00\x0a\x03NET\x05Prime\x03COM\x00",
            "10 NET.Prime.COM.",
        );
        text_round_trip(
            Rtype::RT,
            "( 90\n relay )",
            b"\x00\x5a\x05relay\x07example\x00",
            "90 relay.example.",
        );
    }

    #[test]
    fn text_malformed() {
        for (text, err) in [
            ("", Error::UnexpectedEof),
            ("2", Error::UnexpectedEof),
            ("65536 a.", Error::InvalidText),
            ("2 a. b.", Error::InvalidText),
            ("2 \"a.\"", Error::InvalidText),
        ] {
            assert_eq!(text_error(Rtype::RT, text), err, "{text:?}");
        }
    }
}
