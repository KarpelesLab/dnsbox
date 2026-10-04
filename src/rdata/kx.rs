//! KX record data (RFC 2230 §3).

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, WireReader};
use crate::{Class, Result, Rtype};

/// `KX` record data: a key exchanger for the owner name (RFC 2230 §3).
/// Class IN only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Kx<'a> {
    /// Preference; lower values are preferred.
    pub preference: u16,
    /// The key exchanger host.
    pub exchanger: Name<'a>,
}

impl<'a> ParseRdata<'a> for Kx<'a> {
    const RTYPE: Rtype = Rtype::KX;
    const CLASS: Option<Class> = Some(Class::IN);

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        Ok(Kx {
            preference: rdata.read_u16()?,
            // KX is not among the RFC 3597 §4 decompressible types.
            exchanger: rdata.read_name_uncompressed()?,
        })
    }
}

impl ComposeRdata for Kx<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::KX
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_u16(self.preference)?;
        // Lowercased in canonical form (RFC 4034 §6.2).
        c.put_name(self.exchanger, NameEncoding::Lowercase)
    }
}

impl fmt::Display for Kx<'_> {
    /// `preference exchanger` (RFC 2230 §3).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.preference, self.exchanger)
    }
}

#[cfg(test)]
mod tests {
    use crate::rdata::tests::{parse, round_trip};
    use crate::{Class, Error, Rtype};

    #[test]
    fn rfc2230_example() {
        // KX 10 kx1.foo.example. (named-rrchecker).
        round_trip(
            Rtype::KX,
            b"\x00\x0a\x03kx1\x03foo\x07example\x00",
            "10 kx1.foo.example.",
        );
        assert_eq!(
            parse(Rtype::KX, Class::IN, b"\x00\x0a\xc0\x00"),
            Err(Error::UnexpectedPointer)
        );
    }
}
