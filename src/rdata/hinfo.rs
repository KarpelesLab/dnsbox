//! HINFO record data (RFC 1035 §3.3.2, RFC 8482 §4.2).

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::charstr::CharStr;
use crate::wire::{Composer, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Result, Rtype};

/// `HINFO` record data: host information (RFC 1035 §3.3.2). Also used in
/// minimal responses to ANY queries (RFC 8482 §4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Hinfo<'a> {
    /// CPU type.
    pub cpu: CharStr<'a>,
    /// Operating system.
    pub os: CharStr<'a>,
}

impl<'a> ParseRdata<'a> for Hinfo<'a> {
    const RTYPE: Rtype = Rtype::HINFO;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        Ok(Hinfo {
            cpu: rdata.read_char_string()?,
            os: rdata.read_char_string()?,
        })
    }
}

impl ComposeRdata for Hinfo<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::HINFO
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        self.cpu.compose(c)?;
        self.os.compose(c)
    }
}

impl fmt::Display for Hinfo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.cpu, self.os)
    }
}

impl ParseRdataText for Hinfo<'_> {
    /// `<cpu> <os>`, two `<character-string>`s (RFC 1035 §3.3.2).
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        s.char_string_into(out)?;
        s.char_string_into(out)
    }
}

#[cfg(test)]
mod tests {
    use crate::rdata::tests::{text_error, text_round_trip};
    use crate::{Error, Rtype};

    #[test]
    fn text() {
        // RFC 1035 §5.3 style, and RFC 8482 §4.2's minimal ANY answer.
        text_round_trip(Rtype::HINFO, "DEC-2060 TOPS20", b"\x08DEC-2060\x06TOPS20", r#""DEC-2060" "TOPS20""#);
        text_round_trip(Rtype::HINFO, "\"RFC8482\" \"\"", b"\x07RFC8482\x00", r#""RFC8482" """#);
        assert_eq!(text_error(Rtype::HINFO, "x86"), Error::UnexpectedEof);
        assert_eq!(text_error(Rtype::HINFO, "a b c"), Error::InvalidText);
    }
}
