//! PX record data (RFC 2163 §4).

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, WireReader};
use crate::{Class, Result, Rtype};

/// `PX` record data: X.400 / RFC 822 address mapping information
/// (RFC 2163 §4). Class IN only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Px<'a> {
    /// Preference; lower values are preferred.
    pub preference: u16,
    /// The RFC 822 part of the mapping.
    pub map822: Name<'a>,
    /// The X.400 part of the mapping.
    pub mapx400: Name<'a>,
}

impl super::ParseRdataText for Px<'_> {}

impl<'a> ParseRdata<'a> for Px<'a> {
    const RTYPE: Rtype = Rtype::PX;
    const CLASS: Option<Class> = Some(Class::IN);

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        // RFC 3597 §4 lists PX among the types receivers decompress.
        Ok(Px {
            preference: rdata.read_u16()?,
            map822: rdata.read_name()?,
            mapx400: rdata.read_name()?,
        })
    }
}

impl ComposeRdata for Px<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::PX
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_u16(self.preference)?;
        // Never compressed (RFC 3597 §4), lowercased in canonical form
        // (RFC 4034 §6.2).
        c.put_name(self.map822, NameEncoding::Lowercase)?;
        c.put_name(self.mapx400, NameEncoding::Lowercase)
    }
}

impl fmt::Display for Px<'_> {
    /// `preference map822 mapx400` (RFC 2163 §4).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.preference, self.map822, self.mapx400)
    }
}

#[cfg(test)]
mod tests {
    use crate::Rtype;
    use crate::rdata::tests::round_trip;

    #[test]
    fn rfc2163_example() {
        // PX 50 it. ADMD-garr.C-it. (named-rrchecker).
        round_trip(
            Rtype::PX,
            b"\x00\x32\x02it\x00\x09ADMD-garr\x04C-it\x00",
            "50 it. ADMD-garr.C-it.",
        );
    }
}
