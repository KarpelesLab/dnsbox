//! SOA record data (RFC 1035 §3.3.13).

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Result, Rtype};

/// `SOA` record data: start of a zone of authority (RFC 1035 §3.3.13).
///
/// ```
/// use dnsbox::rdata::{ParseRdataText, Soa};
///
/// // TTL-style units are accepted for the timers (as BIND does).
/// let mut buf = [0u8; 64];
/// let soa = Soa::from_text("ns1.example. hostmaster.example. 2024010101 2h 15m 2w 1h", &mut buf)?;
/// assert_eq!(soa.serial, 2_024_010_101);
/// assert_eq!((soa.refresh, soa.retry, soa.expire, soa.minimum), (7200, 900, 1_209_600, 3600));
/// assert_eq!(soa.rname.to_string(), "hostmaster.example.");
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Soa<'a> {
    /// The primary name server for the zone.
    pub mname: Name<'a>,
    /// The mailbox of the person responsible for the zone.
    pub rname: Name<'a>,
    /// Zone serial number (RFC 1982 arithmetic).
    pub serial: u32,
    /// Seconds before the zone should be refreshed.
    pub refresh: u32,
    /// Seconds before a failed refresh should be retried.
    pub retry: u32,
    /// Seconds after which the zone is no longer authoritative.
    pub expire: u32,
    /// Negative-caching TTL (RFC 2308 §4).
    pub minimum: u32,
}

impl<'a> ParseRdata<'a> for Soa<'a> {
    const RTYPE: Rtype = Rtype::SOA;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        Ok(Soa {
            mname: rdata.read_name()?,
            rname: rdata.read_name()?,
            serial: rdata.read_u32()?,
            refresh: rdata.read_u32()?,
            retry: rdata.read_u32()?,
            expire: rdata.read_u32()?,
            minimum: rdata.read_u32()?,
        })
    }
}

impl ComposeRdata for Soa<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::SOA
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_name(self.mname, NameEncoding::Compressible)?;
        c.put_name(self.rname, NameEncoding::Compressible)?;
        for v in [
            self.serial,
            self.refresh,
            self.retry,
            self.expire,
            self.minimum,
        ] {
            c.put_u32(v)?;
        }
        Ok(())
    }
}

impl fmt::Display for Soa<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} {}",
            self.mname, self.rname, self.serial, self.refresh, self.retry, self.expire, self.minimum
        )
    }
}

impl ParseRdataText for Soa<'_> {
    /// `<mname> <rname> <serial> <refresh> <retry> <expire> <minimum>`
    /// (RFC 1035 §3.3.13, §5.3). The four timers accept TTL units
    /// (`1h30m`, as BIND does); the serial is a plain number.
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        s.name_into(out, NameEncoding::Compressible)?;
        s.name_into(out, NameEncoding::Compressible)?;
        out.put_u32(s.u32()?)?;
        for _ in 0..4 {
            out.put_u32(s.ttl()?)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::rdata::tests::{text_error, text_round_trip};
    use crate::{Error, Rtype};

    #[test]
    fn text() {
        // RFC 1035 §5.3, with origin "example." instead of ISI.EDU.
        text_round_trip(
            Rtype::SOA,
            "VENERA      Action\\.domains (\n\
             \x20                            20     ; SERIAL\n\
             \x20                            7200   ; REFRESH\n\
             \x20                            600    ; RETRY\n\
             \x20                            3600000; EXPIRE\n\
             \x20                            60)    ; MINIMUM",
            b"\x06VENERA\x07example\x00\x0eAction.domains\x07example\x00\
              \x00\x00\x00\x14\x00\x00\x1c\x20\x00\x00\x02\x58\x00\x36\xee\x80\x00\x00\x00\x3c",
            "VENERA.example. Action\\.domains.example. 20 7200 600 3600000 60",
        );
        text_round_trip(
            Rtype::SOA,
            "ns. host. 4294967295 1h 15M 2w 1d1s",
            b"\x02ns\x00\x04host\x00\xff\xff\xff\xff\x00\x00\x0e\x10\x00\x00\x03\x84\
              \x00\x12\x75\x00\x00\x01\x51\x81",
            "ns. host. 4294967295 3600 900 1209600 86401",
        );
        assert_eq!(text_error(Rtype::SOA, "ns. host. 1h 1 2 3 4"), Error::InvalidText);
        assert_eq!(text_error(Rtype::SOA, "ns. host. 1 2 3 4"), Error::UnexpectedEof);
        assert_eq!(text_error(Rtype::SOA, "ns. host. 1 2 3 4 5 6"), Error::InvalidText);
        assert_eq!(text_error(Rtype::SOA, "ns. host. 4294967296 2 3 4 5"), Error::InvalidText);
    }
}
