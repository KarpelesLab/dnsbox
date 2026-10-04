//! AAAA record data (RFC 3596 §2.2).

use core::fmt;
use core::net::Ipv6Addr;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::wire::{Composer, OutBuf, WireReader};
use crate::zone::Scanner;
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

impl ParseRdataText for Aaaa {
    /// An IPv6 address in any RFC 4291 §2.2 text form (RFC 3596 §2.4).
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        out.put_bytes(&s.ipv6()?.octets())
    }
}

#[cfg(test)]
mod tests {
    use crate::Rtype;
    use crate::rdata::tests::{text_error, text_round_trip};

    #[test]
    fn text() {
        let mut wire = [0u8; 16];
        wire[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        wire[15] = 1;
        text_round_trip(Rtype::AAAA, "2001:DB8:0:0::1", &wire, "2001:db8::1");
        // RFC 4291 §2.2 form 3: embedded IPv4.
        let mut mapped = [0u8; 16];
        mapped[10..].copy_from_slice(&[0xff, 0xff, 192, 0, 2, 1]);
        text_round_trip(Rtype::AAAA, "::ffff:192.0.2.1", &mapped, "::ffff:192.0.2.1");
        for bad in ["192.0.2.1", "2001:db8::1::2", "2001:db8::1%eth0", "2001:db8::/32", ""] {
            text_error(Rtype::AAAA, bad);
        }
    }
}
