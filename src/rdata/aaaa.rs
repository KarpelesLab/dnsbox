//! AAAA record data (RFC 3596 §2.2).

use core::fmt;
use core::net::Ipv6Addr;

use super::{ComposeRdata, ParseRdata};
use crate::wire::{Composer, WireReader};
use crate::{Class, Result, Rtype};

/// `AAAA` record data: an IPv6 host address (RFC 3596 §2.2). Class IN only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Aaaa {
    /// The address.
    pub addr: Ipv6Addr,
}

impl Aaaa {
    /// Wraps an address.
    #[inline]
    pub const fn new(addr: Ipv6Addr) -> Self {
        Aaaa { addr }
    }
}

impl From<Ipv6Addr> for Aaaa {
    #[inline]
    fn from(addr: Ipv6Addr) -> Self {
        Aaaa { addr }
    }
}

impl ParseRdata<'_> for Aaaa {
    const RTYPE: Rtype = Rtype::AAAA;
    const CLASS: Option<Class> = Some(Class::IN);

    #[inline]
    fn parse_rdata(rdata: &mut WireReader<'_>) -> Result<Self> {
        rdata.read_array::<16>().map(|o| Aaaa::new(Ipv6Addr::from(o)))
    }
}

impl ComposeRdata for Aaaa {
    #[inline]
    fn rtype(&self) -> Rtype {
        Rtype::AAAA
    }

    #[inline]
    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_bytes(&self.addr.octets())
    }
}

impl fmt::Display for Aaaa {
    /// RFC 5952 text form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.addr, f)
    }
}
