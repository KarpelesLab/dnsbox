//! A record data (RFC 1035 §3.4.1).

use core::fmt;
use core::net::Ipv4Addr;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::wire::{Composer, OutBuf, WireReader};
use crate::zone::Scanner;
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

impl ParseRdataText for A {
    /// A dotted-decimal IPv4 address (RFC 1035 §3.4.1).
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        out.put_bytes(&s.ipv4()?.octets())
    }
}

#[cfg(test)]
mod tests {
    use crate::Rtype;
    use crate::rdata::tests::{text_error, text_round_trip};

    #[test]
    fn text() {
        text_round_trip(Rtype::A, "192.0.2.1", &[192, 0, 2, 1], "192.0.2.1");
        text_round_trip(Rtype::A, "\\# 4 0a000001", &[10, 0, 0, 1], "10.0.0.1");
        for bad in ["192.0.2", "192.0.2.256", "192.0.2.1 x", "\"192.0.2.1\"", "::1", ""] {
            text_error(Rtype::A, bad);
        }
    }
}
