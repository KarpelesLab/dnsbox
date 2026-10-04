//! SRV record data (RFC 2782).

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Result, Rtype};

/// `SRV` record data: the location of a service (RFC 2782).
///
/// RFC 2782 forbids compressing the target, but RFC 3597 §4 lists SRV among
/// the types whose RDATA names receivers should decompress, so a compressed
/// target is accepted when parsing. It is always written uncompressed, and
/// lowercased in canonical form (RFC 4034 §6.2).
///
/// ```
/// use dnsbox::rdata::{ParseRdataText, Srv};
///
/// let mut buf = [0u8; 64];
/// let srv = Srv::from_text("10 60 5060 bigbox.example.com.", &mut buf)?;
/// assert_eq!((srv.priority, srv.weight, srv.port), (10, 60, 5060));
/// assert!(!srv.is_unavailable());
/// // "." as target: the service is decidedly not available (RFC 2782).
/// let mut buf = [0u8; 8];
/// assert!(Srv::from_text("0 0 0 .", &mut buf)?.is_unavailable());
/// # Ok::<(), dnsbox::Error>(())
/// ```
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
    #[must_use]
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
    #[must_use]
    pub const fn is_unavailable(&self) -> bool {
        self.target.is_root()
    }
}

impl ParseRdataText for Srv<'_> {
    /// `<priority> <weight> <port> <target>` (RFC 2782); the target is a
    /// domain name, relative to the origin unless it ends in a dot.
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        out.put_u16(s.u16()?)?;
        out.put_u16(s.u16()?)?;
        out.put_u16(s.u16()?)?;
        s.name_into(out, NameEncoding::Lowercase)
    }
}

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
    use crate::rdata::tests::{parse, round_trip, text_error, text_round_trip};
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

    #[test]
    fn text() {
        // RFC 2782 example zone ($ORIGIN example.com. there, `example.`
        // here): "_ldap._tcp SRV 0 1 389 old-slow-box.example.com.".
        text_round_trip(
            Rtype::SRV,
            "0 1 389 old-slow-box",
            b"\x00\x00\x00\x01\x01\x85\x0cold-slow-box\x07example\x00",
            "0 1 389 old-slow-box.example.",
        );
        text_round_trip(
            Rtype::SRV,
            "0 0 21 server.example.com.",
            b"\x00\x00\x00\x00\x00\x15\x06server\x07example\x03com\x00",
            "0 0 21 server.example.com.",
        );
        // "Decidedly not available": "SRV 0 0 0 .".
        text_round_trip(Rtype::SRV, "0 0 0 .", b"\0\0\0\0\0\0\0", "0 0 0 .");
        // Split over lines, maximum values, case preserved.
        text_round_trip(
            Rtype::SRV,
            "( 65535 65535\n 65535 Host ) ; comment",
            b"\xff\xff\xff\xff\xff\xff\x04Host\x07example\x00",
            "65535 65535 65535 Host.example.",
        );
    }

    #[test]
    fn text_malformed() {
        assert_eq!(text_error(Rtype::SRV, ""), Error::UnexpectedEof);
        assert_eq!(text_error(Rtype::SRV, "0 1 21"), Error::UnexpectedEof);
        assert_eq!(text_error(Rtype::SRV, "0 1 65536 a."), Error::InvalidText);
        assert_eq!(text_error(Rtype::SRV, "-1 1 21 a."), Error::InvalidText);
        assert_eq!(text_error(Rtype::SRV, "0 x 21 a."), Error::InvalidText);
        assert_eq!(text_error(Rtype::SRV, "\"0\" 1 21 a."), Error::InvalidText);
        assert_eq!(text_error(Rtype::SRV, "0 1 21 a. b."), Error::InvalidText);
        assert_eq!(text_error(Rtype::SRV, "0 1 21 a..b."), Error::EmptyLabel);
        assert_eq!(text_error(Rtype::SRV, "0 1 21 \"a.\""), Error::InvalidText);
    }
}
