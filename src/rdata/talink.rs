//! TALINK record data (draft-wijngaards-dnsop-trust-history-02).

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, WireReader};
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

impl super::ParseRdataText for Talink<'_> {}

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
    use crate::rdata::tests::{parse, round_trip};
    use crate::{Class, Error, Rtype};

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
}
