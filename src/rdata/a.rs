//! A record data (RFC 1035 §3.4.1).

use core::fmt;
use core::net::Ipv4Addr;

use super::{ComposeRdata, ParseRdata};
use crate::wire::{Composer, WireReader};
use crate::{Class, Result, Rtype};

/// `A` record data: an IPv4 host address (RFC 1035 §3.4.1). Class IN only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct A {
    /// The address.
    pub addr: Ipv4Addr,
}

impl A {
    /// Wraps an address.
    #[inline]
    pub const fn new(addr: Ipv4Addr) -> Self {
        A { addr }
    }
}

impl From<Ipv4Addr> for A {
    #[inline]
    fn from(addr: Ipv4Addr) -> Self {
        A { addr }
    }
}

impl ParseRdata<'_> for A {
    const RTYPE: Rtype = Rtype::A;
    const CLASS: Option<Class> = Some(Class::IN);

    #[inline]
    fn parse_rdata(rdata: &mut WireReader<'_>) -> Result<Self> {
        rdata.read_array::<4>().map(|o| A::new(Ipv4Addr::from(o)))
    }
}

impl ComposeRdata for A {
    #[inline]
    fn rtype(&self) -> Rtype {
        Rtype::A
    }

    #[inline]
    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_bytes(&self.addr.octets())
    }
}

impl fmt::Display for A {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.addr, f)
    }
}
