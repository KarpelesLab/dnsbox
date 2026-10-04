//! AFSDB record data (RFC 1183 §1, RFC 5864).

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Result, Rtype};

/// `AFSDB` record data: an AFS cell database or DCE authenticated name
/// server (RFC 1183 §1; deprecated for AFS by RFC 5864 in favour of SRV).
///
/// ```
/// use dnsbox::rdata::{Afsdb, ParseRdataText};
///
/// // RFC 1183 §1: an AFS cell database server.
/// let mut buf = [0u8; 32];
/// let afsdb = Afsdb::from_text("1 jack.toaster.com.", &mut buf)?;
/// assert_eq!(afsdb.subtype, 1);
/// assert_eq!(afsdb.hostname.to_string(), "jack.toaster.com.");
/// # Ok::<(), dnsbox::Error>(())
/// ```
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

impl ParseRdataText for Afsdb<'_> {
    /// `<subtype> <hostname>` (RFC 1183 §1): a decimal number and a domain
    /// name, relative to the origin unless it ends in a dot.
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        out.put_u16(s.u16()?)?;
        s.name_into(out, NameEncoding::Lowercase)
    }
}

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
    use crate::rdata::tests::{round_trip, text_error, text_round_trip};
    use crate::{Error, Rtype};

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

    #[test]
    fn text() {
        // RFC 1183 §1 example (toaster.com's AFS and DCE servers).
        text_round_trip(
            Rtype::AFSDB,
            "1 jack.toaster.com.",
            b"\x00\x01\x04jack\x07toaster\x03com\x00",
            "1 jack.toaster.com.",
        );
        text_round_trip(
            Rtype::AFSDB,
            "2 tracy",
            b"\x00\x02\x05tracy\x07example\x00",
            "2 tracy.example.",
        );
        text_round_trip(
            Rtype::AFSDB,
            "( 65535\n BIGBIRD.TOTO.COM. )",
            b"\xff\xff\x07BIGBIRD\x04TOTO\x03COM\x00",
            "65535 BIGBIRD.TOTO.COM.",
        );
    }

    #[test]
    fn text_malformed() {
        for (text, err) in [
            ("", Error::UnexpectedEof),
            ("1", Error::UnexpectedEof),
            ("65536 a.", Error::InvalidText),
            ("AFS a.", Error::InvalidText),
            ("1 a. b.", Error::InvalidText),
            ("1 a..", Error::EmptyLabel),
        ] {
            assert_eq!(text_error(Rtype::AFSDB, text), err, "{text:?}");
        }
    }
}
