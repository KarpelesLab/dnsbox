//! SRV record data (RFC 2782).

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, WireReader};
use crate::{Result, Rtype};

/// `SRV` record data: the location of a service (RFC 2782).
///
/// RFC 2782 forbids compressing the target, but RFC 3597 §4 lists SRV among
/// the types whose RDATA names receivers should decompress, so a compressed
/// target is accepted when parsing. It is always written uncompressed, and
/// lowercased in canonical form (RFC 4034 §6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Srv<'a> {
    /// Priority; lower values are tried first (RFC 2782 "Priority").
    pub priority: u16,
    /// Relative weight among records of equal priority (RFC 2782
    /// "Weight").
    pub weight: u16,
    /// Port of the service (RFC 2782 "Port").
    pub port: u16,
    /// Host providing the service; `.` means the service is decidedly not
    /// available (RFC 2782 "Target").
    pub target: Name<'a>,
}

impl<'a> Srv<'a> {
    /// Builds SRV data from its fields (RFC 2782).
    #[inline]
    pub const fn new(priority: u16, weight: u16, port: u16, target: Name<'a>) -> Self {
        Srv {
            priority,
            weight,
            port,
            target,
        }
    }

    /// Whether the service is "decidedly not available" at this domain:
    /// a target of `.` (RFC 2782).
    #[inline]
    pub const fn is_unavailable(&self) -> bool {
        self.target.is_root()
    }
}

impl super::ParseRdataText for Srv<'_> {}

impl<'a> ParseRdata<'a> for Srv<'a> {
    const RTYPE: Rtype = Rtype::SRV;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        Ok(Srv {
            priority: rdata.read_u16()?,
            weight: rdata.read_u16()?,
            port: rdata.read_u16()?,
            // RFC 3597 §4 lists SRV among the types receivers decompress.
            target: rdata.read_name()?,
        })
    }
}

impl ComposeRdata for Srv<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::SRV
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_u16(self.priority)?;
        c.put_u16(self.weight)?;
        c.put_u16(self.port)?;
        // Never compressed (RFC 2782), lowercased in canonical form
        // (RFC 4034 §6.2).
        c.put_name(self.target, NameEncoding::Lowercase)
    }
}

impl fmt::Display for Srv<'_> {
    /// `priority weight port target` (RFC 2782).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.priority, self.weight, self.port, self.target
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdata::tests::{parse, round_trip};
    use crate::{Class, Error, RData};

    #[test]
    fn rfc2782_examples() {
        // _ftp._tcp.example.com. SRV 0 1 21 ftp1.example.com.
        round_trip(
            Rtype::SRV,
            b"\x00\x00\x00\x01\x00\x15\x04ftp1\x07example\x03com\x00",
            "0 1 21 ftp1.example.com.",
        );
        // "Decidedly not available": target `.`.
        let wire = b"\x00\x00\x00\x00\x00\x00\x00";
        round_trip(Rtype::SRV, wire, "0 0 0 .");
        let Ok(RData::Srv(srv)) = parse(Rtype::SRV, Class::IN, wire) else {
            panic!("not SRV")
        };
        assert!(srv.is_unavailable());
        assert_eq!(srv, Srv::new(0, 0, 0, Name::ROOT));
        // Maximum field values.
        round_trip(
            Rtype::SRV,
            b"\xff\xff\xff\xff\xff\xff\x01a\x00",
            "65535 65535 65535 a.",
        );
    }

    #[test]
    fn malformed() {
        assert_eq!(
            parse(Rtype::SRV, Class::IN, b"\x00\x00\x00\x01\x00\x15"),
            Err(Error::UnexpectedEof)
        );
        assert_eq!(
            parse(Rtype::SRV, Class::IN, b"\x00\x00\x00\x01\x00\x15\x00\x00"),
            Err(Error::TrailingData)
        );
        // A pointer to itself.
        assert_eq!(
            parse(Rtype::SRV, Class::IN, b"\x00\x00\x00\x01\x00\x15\xc0\x06"),
            Err(Error::BadPointer)
        );
    }
}
