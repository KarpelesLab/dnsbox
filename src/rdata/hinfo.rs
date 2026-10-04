//! HINFO record data (RFC 1035 §3.3.2, RFC 8482 §4.2).

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::charstr::CharStr;
use crate::wire::{Composer, WireReader};
use crate::{Result, Rtype};

/// `HINFO` record data: host information (RFC 1035 §3.3.2). Also used in
/// minimal responses to ANY queries (RFC 8482 §4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Hinfo<'a> {
    /// CPU type.
    pub cpu: CharStr<'a>,
    /// Operating system.
    pub os: CharStr<'a>,
}

impl<'a> ParseRdata<'a> for Hinfo<'a> {
    const RTYPE: Rtype = Rtype::HINFO;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        Ok(Hinfo {
            cpu: rdata.read_char_string()?,
            os: rdata.read_char_string()?,
        })
    }
}

impl ComposeRdata for Hinfo<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::HINFO
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        self.cpu.compose(c)?;
        self.os.compose(c)
    }
}

impl fmt::Display for Hinfo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.cpu, self.os)
    }
}
