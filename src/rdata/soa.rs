//! SOA record data (RFC 1035 §3.3.13).

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, WireReader};
use crate::{Result, Rtype};

/// `SOA` record data: start of a zone of authority (RFC 1035 §3.3.13).
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
