//! AFSDB record data (RFC 1183 §1, RFC 5864).

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, WireReader};
use crate::{Result, Rtype};

/// `AFSDB` record data: an AFS cell database or DCE authenticated name
/// server (RFC 1183 §1; deprecated for AFS by RFC 5864 in favour of SRV).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Afsdb<'a> {
    /// Subtype: 1 = AFS version 3 volume location server, 2 = DCE/NCA
    /// root cell directory node (RFC 1183 §1).
    pub subtype: u16,
    /// The server host.
    pub hostname: Name<'a>,
}

impl Afsdb<'_> {
    /// Subtype 1: AFS cell database server (RFC 1183 §1).
    pub const AFS: u16 = 1;
    /// Subtype 2: DCE authenticated name server (RFC 1183 §1).
    pub const DCE: u16 = 2;
}

impl super::ParseRdataText for Afsdb<'_> {}

impl<'a> ParseRdata<'a> for Afsdb<'a> {
    const RTYPE: Rtype = Rtype::AFSDB;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        Ok(Afsdb {
            subtype: rdata.read_u16()?,
            // RFC 3597 §4 lists AFSDB among the types receivers decompress.
            hostname: rdata.read_name()?,
        })
    }
}

impl ComposeRdata for Afsdb<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::AFSDB
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_u16(self.subtype)?;
        // Never compressed (RFC 3597 §4), lowercased in canonical form
        // (RFC 4034 §6.2).
        c.put_name(self.hostname, NameEncoding::Lowercase)
    }
}

impl fmt::Display for Afsdb<'_> {
    /// `subtype hostname` (RFC 1183 §1).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.subtype, self.hostname)
    }
}

#[cfg(test)]
mod tests {
    use crate::Rtype;
    use crate::rdata::tests::round_trip;

    #[test]
    fn rfc1183_example() {
        // AFSDB 1 bigbird.toto.com. (named-rrchecker).
        round_trip(
            Rtype::AFSDB,
            b"\x00\x01\x07bigbird\x04toto\x03com\x00",
            "1 bigbird.toto.com.",
        );
        round_trip(Rtype::AFSDB, b"\x00\x02\x00", "2 .");
    }
}
