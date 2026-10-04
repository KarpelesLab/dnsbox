//! MINFO record data (RFC 1035 §3.3.7).

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, WireReader};
use crate::{Result, Rtype};

/// `MINFO` record data: mailbox or mail list information — experimental
/// (RFC 1035 §3.3.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Minfo<'a> {
    /// Mailbox responsible for the mailing list.
    pub rmailbx: Name<'a>,
    /// Mailbox that receives error messages.
    pub emailbx: Name<'a>,
}

impl<'a> ParseRdata<'a> for Minfo<'a> {
    const RTYPE: Rtype = Rtype::MINFO;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        Ok(Minfo {
            rmailbx: rdata.read_name()?,
            emailbx: rdata.read_name()?,
        })
    }
}

impl ComposeRdata for Minfo<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::MINFO
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_name(self.rmailbx, NameEncoding::Compressible)?;
        c.put_name(self.emailbx, NameEncoding::Compressible)
    }
}

impl fmt::Display for Minfo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.rmailbx, self.emailbx)
    }
}
