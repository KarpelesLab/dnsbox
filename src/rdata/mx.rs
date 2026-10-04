//! MX record data (RFC 1035 §3.3.9).

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, WireReader};
use crate::{Result, Rtype};

/// `MX` record data: a mail exchange (RFC 1035 §3.3.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Mx<'a> {
    /// Preference; lower values are preferred.
    pub preference: u16,
    /// The mail exchange host.
    pub exchange: Name<'a>,
}

impl<'a> ParseRdata<'a> for Mx<'a> {
    const RTYPE: Rtype = Rtype::MX;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        Ok(Mx {
            preference: rdata.read_u16()?,
            exchange: rdata.read_name()?,
        })
    }
}

impl ComposeRdata for Mx<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::MX
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_u16(self.preference)?;
        c.put_name(self.exchange, NameEncoding::Compressible)
    }
}

impl fmt::Display for Mx<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.preference, self.exchange)
    }
}
