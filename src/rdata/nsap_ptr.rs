//! NSAP-PTR record data (RFC 1706 §6).

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, WireReader};
use crate::{Class, Result, Rtype};

/// `NSAP-PTR` record data: the domain name for an NSAP address, the
/// NSAP counterpart of PTR (RFC 1706 §6). Class IN only; deprecated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NsapPtr<'a> {
    /// The owner of the NSAP address.
    pub ptrdname: Name<'a>,
}

impl super::ParseRdataText for NsapPtr<'_> {}

impl<'a> ParseRdata<'a> for NsapPtr<'a> {
    const RTYPE: Rtype = Rtype::NSAP_PTR;
    const CLASS: Option<Class> = Some(Class::IN);

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        // Not among the RFC 3597 §4 types that may be decompressed.
        Ok(NsapPtr {
            ptrdname: rdata.read_name_uncompressed()?,
        })
    }
}

impl ComposeRdata for NsapPtr<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::NSAP_PTR
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        // Not in the RFC 4034 §6.2 lowercasing list.
        c.put_name(self.ptrdname, NameEncoding::Plain)
    }
}

impl fmt::Display for NsapPtr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.ptrdname, f)
    }
}

#[cfg(test)]
mod tests {
    use crate::rdata::tests::{parse, round_trip};
    use crate::{Class, Error, Rtype};

    #[test]
    fn round_trips() {
        // NSAP-PTR foo.bar. (named-rrchecker).
        round_trip(Rtype::NSAP_PTR, b"\x03foo\x03bar\x00", "foo.bar.");
        assert_eq!(
            parse(Rtype::NSAP_PTR, Class::IN, b"\xc0\x00"),
            Err(Error::UnexpectedPointer)
        );
    }
}
