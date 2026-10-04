//! NSAP record data (RFC 1706 §5).

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::wire::{Composer, WireReader};
use crate::{Class, Error, Result, Rtype};

/// `NSAP` record data: an OSI network service access point address
/// (RFC 1706 §5). Class IN only; deprecated in practice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Nsap<'a> {
    /// The binary NSAP address (at least one octet).
    pub address: &'a [u8],
}

impl super::ParseRdataText for Nsap<'_> {}

impl<'a> ParseRdata<'a> for Nsap<'a> {
    const RTYPE: Rtype = Rtype::NSAP;
    const CLASS: Option<Class> = Some(Class::IN);

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        if rdata.is_empty() {
            return Err(Error::UnexpectedEof);
        }
        Ok(Nsap {
            address: rdata.read_rest(),
        })
    }
}

impl ComposeRdata for Nsap<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::NSAP
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        if self.address.is_empty() {
            return Err(Error::InvalidRdata);
        }
        c.put_bytes(self.address)
    }
}

impl fmt::Display for Nsap<'_> {
    /// `0x` followed by the address in lowercase hexadecimal, without the
    /// optional `.` separators (RFC 1706 §5).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("0x")?;
        self.address.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

#[cfg(test)]
mod tests {
    use crate::rdata::tests::{parse, round_trip};
    use crate::rdata::{RData, UnknownRdata};
    use crate::{Class, Error, Rtype};

    #[test]
    fn rfc1706_example() {
        // NSAP 0x47.0005.80.005a00.0000.0001.e133.ffffff000161.00
        // (named-rrchecker).
        round_trip(
            Rtype::NSAP,
            &crate::testutil::hex("47000580005A0000000001E133FFFFFF00016100"),
            "0x47000580005a0000000001e133ffffff00016100",
        );
    }

    #[test]
    fn malformed_and_class() {
        assert_eq!(
            parse(Rtype::NSAP, Class::IN, b""),
            Err(Error::UnexpectedEof)
        );
        assert_eq!(
            parse(Rtype::NSAP, Class::CH, b"\x47").unwrap(),
            RData::Unknown(UnknownRdata::new(Rtype::NSAP, b"\x47"))
        );
    }
}
