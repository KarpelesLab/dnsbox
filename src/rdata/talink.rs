//! TALINK record data (draft-wijngaards-dnsop-trust-history-02).

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Result, Rtype};

/// `TALINK` record data: a link in a trust-anchor history chain
/// (draft-wijngaards-dnsop-trust-history-02). Never standardised.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Talink<'a> {
    /// The previous name in the chain (`.` at the start).
    pub previous: Name<'a>,
    /// The next name in the chain (`.` at the end).
    pub next: Name<'a>,
}

impl ParseRdataText for Talink<'_> {
    /// `<previous name> <next name>`, as BIND writes them
    /// (draft-wijngaards-dnsop-trust-history-02).
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        s.name_into(out, NameEncoding::Plain)?;
        s.name_into(out, NameEncoding::Plain)
    }
}

impl<'a> ParseRdata<'a> for Talink<'a> {
    const RTYPE: Rtype = Rtype::TALINK;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        // Not among the RFC 3597 §4 decompressible types.
        let mut r = *rdata;
        let previous = r.read_name_uncompressed()?;
        let next = r.read_name_uncompressed()?;
        *rdata = r;
        Ok(Talink { previous, next })
    }
}

impl ComposeRdata for Talink<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::TALINK
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_name(self.previous, NameEncoding::Plain)?;
        c.put_name(self.next, NameEncoding::Plain)
    }
}

impl fmt::Display for Talink<'_> {
    /// `previous-name next-name`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.previous, self.next)
    }
}

#[cfg(test)]
mod tests {
    use crate::rdata::tests::{parse, round_trip, text_error, text_round_trip};
    use crate::{Class, Error, Rtype};

    #[test]
    fn text() {
        // TALINK prev. next. (named-rrchecker), and relative names with
        // `.` for the ends of the chain.
        text_round_trip(Rtype::TALINK, "prev. next.", b"\x04prev\x00\x04next\x00", "prev. next.");
        text_round_trip(Rtype::TALINK, ". Next", b"\x00\x04Next\x07example\x00", ". Next.example.");
        assert_eq!(text_error(Rtype::TALINK, "prev."), Error::UnexpectedEof);
        assert_eq!(text_error(Rtype::TALINK, "a..b. c."), Error::EmptyLabel);
        assert_eq!(text_error(Rtype::TALINK, "a..b. c."), Error::EmptyLabel);
    }

    #[test]
    fn round_trips() {
        // TALINK prev. next. (named-rrchecker).
        round_trip(Rtype::TALINK, b"\x04prev\x00\x04next\x00", "prev. next.");
        // BIND: "disallowed (by application policy)".
        assert_eq!(
            parse(Rtype::TALINK, Class::IN, b"\xc0\x00"),
            Err(Error::UnexpectedPointer)
        );
    }

    #[test]
    fn text_examples() {
        // named-rrchecker.
        text_round_trip(
            Rtype::TALINK,
            "prev next.",
            b"\x04prev\x07example\x00\x04next\x00",
            "prev.example. next.",
        );
        text_round_trip(Rtype::TALINK, ". .", b"\x00\x00", ". .");
        assert_eq!(text_error(Rtype::TALINK, "prev"), Error::UnexpectedEof);
        assert_eq!(text_error(Rtype::TALINK, "a. b. c."), Error::InvalidText);
    }
}
