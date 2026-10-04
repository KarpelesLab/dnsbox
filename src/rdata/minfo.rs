//! MINFO record data (RFC 1035 §3.3.7).

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, OutBuf, WireReader};
use crate::zone::Scanner;
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

impl ParseRdataText for Minfo<'_> {
    /// `<rmailbx> <emailbx>` (RFC 1035 §3.3.7).
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        s.name_into(out, NameEncoding::Compressible)?;
        s.name_into(out, NameEncoding::Compressible)
    }
}

#[cfg(test)]
mod tests {
    use crate::Rtype;
    use crate::rdata::tests::{text_error, text_round_trip};

    #[test]
    fn text() {
        text_round_trip(
            Rtype::MINFO,
            "admins errors.example.",
            b"\x06admins\x07example\x00\x06errors\x07example\x00",
            "admins.example. errors.example.",
        );
        text_round_trip(Rtype::MINFO, "@ .", b"\x07example\x00\x00", "example. .");
        for bad in ["a", "a b c", "a \"b\""] {
            text_error(Rtype::MINFO, bad);
        }
    }
}
