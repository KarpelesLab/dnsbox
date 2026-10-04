//! NULL record data (RFC 1035 §3.3.10).

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::wire::{Composer, WireReader};
use crate::{Result, Rtype};

/// `NULL` record data: up to 65535 arbitrary octets — experimental
/// (RFC 1035 §3.3.10).
///
/// NULL has no presentation format; it displays in the generic RFC 3597
/// form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Null<'a> {
    /// The payload.
    pub data: &'a [u8],
}

impl<'a> ParseRdata<'a> for Null<'a> {
    const RTYPE: Rtype = Rtype::NULL;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        Ok(Null {
            data: rdata.read_rest(),
        })
    }
}

impl ComposeRdata for Null<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::NULL
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_bytes(self.data)
    }
}

impl fmt::Display for Null<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::text::fmt_generic_rdata(f, self.data)
    }
}
