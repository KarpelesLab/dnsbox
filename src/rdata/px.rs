//! PX record data (RFC 2163 §4).

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, OutBuf, WireReader};
use crate::zone::Scanner;
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

impl ParseRdataText for Px<'_> {
    /// `preference map822 mapx400` (RFC 2163 §4).
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        out.put_u16(s.u16()?)?;
        s.name_into(out, NameEncoding::Lowercase)?;
        s.name_into(out, NameEncoding::Lowercase)
    }
}

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
    use crate::rdata::tests::{round_trip, text_error, text_round_trip};
    use crate::{Error, Rtype};

    #[test]
    fn rfc2163_example() {
        // PX 50 it. ADMD-garr.C-it. (named-rrchecker).
        round_trip(
            Rtype::PX,
            b"\x00\x32\x02it\x00\x09ADMD-garr\x04C-it\x00",
            "50 it. ADMD-garr.C-it.",
        );
    }

    #[test]
    fn text() {
        // RFC 2163 §4 examples (named-rrchecker).
        text_round_trip(
            Rtype::PX,
            "50 it. ADMD-garr.C-it.",
            b"\x00\x32\x02it\x00\x09ADMD-garr\x04C-it\x00",
            "50 it. ADMD-garr.C-it.",
        );
        text_round_trip(
            Rtype::PX,
            "50 cnr.it. O-cnr.PRMD-infn.ADMD-garr.C-it.",
            b"\x00\x32\x03cnr\x02it\x00\x05O-cnr\x09PRMD-infn\x09ADMD-garr\x04C-it\x00",
            "50 cnr.it. O-cnr.PRMD-infn.ADMD-garr.C-it.",
        );
        // Relative names.
        text_round_trip(
            Rtype::PX,
            "50 it ADMD-garr.C-it.",
            b"\x00\x32\x02it\x07example\x00\x09ADMD-garr\x04C-it\x00",
            "50 it.example. ADMD-garr.C-it.",
        );
        for (text, err) in [
            ("50 it.", Error::UnexpectedEof),
            ("65536 it. it.", Error::InvalidText),
            ("50 it. it. it.", Error::InvalidText),
        ] {
            assert_eq!(text_error(Rtype::PX, text), err, "{text:?}");
        }
    }
}
