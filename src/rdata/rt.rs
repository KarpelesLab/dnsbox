//! RT record data (RFC 1183 §3.3).

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, WireReader};
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
    use crate::Rtype;
    use crate::rdata::tests::round_trip;

    #[test]
    fn rfc1183_example() {
        // RT 2 relay.prime.com. (named-rrchecker).
        round_trip(
            Rtype::RT,
            b"\x00\x02\x05relay\x05prime\x03com\x00",
            "2 relay.prime.com.",
        );
    }
}
