//! WKS record data (RFC 1035 §3.4.2).

use core::fmt;
use core::net::Ipv4Addr;

use super::{ComposeRdata, ParseRdata};
use crate::wire::{Composer, WireReader};
use crate::{Class, Result, Rtype};

/// `WKS` record data: well-known services offered by a host
/// (RFC 1035 §3.4.2). Class IN only. Deprecated in practice (RFC 1123
/// §2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Wks<'a> {
    /// The host address.
    pub address: Ipv4Addr,
    /// IP protocol number (6 = TCP, 17 = UDP).
    pub protocol: u8,
    /// Port bitmap: bit *n* (MSB-first) set means port *n* is offered.
    pub bitmap: &'a [u8],
}

impl<'a> Wks<'a> {
    /// Iterates over the ports set in the bitmap, ascending.
    pub fn ports(&self) -> impl Iterator<Item = u16> + 'a {
        let bitmap = self.bitmap;
        bitmap.iter().enumerate().flat_map(|(i, &byte)| {
            (0..8u16).filter_map(move |bit| {
                let port = u16::try_from(i * 8).ok()?.checked_add(bit)?;
                (byte & (0x80 >> bit) != 0).then_some(port)
            })
        })
    }
}

impl<'a> ParseRdata<'a> for Wks<'a> {
    const RTYPE: Rtype = Rtype::WKS;
    const CLASS: Option<Class> = Some(Class::IN);

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        Ok(Wks {
            address: Ipv4Addr::from(rdata.read_array::<4>()?),
            protocol: rdata.read_u8()?,
            bitmap: rdata.read_rest(),
        })
    }
}

impl ComposeRdata for Wks<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::WKS
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_bytes(&self.address.octets())?;
        c.put_u8(self.protocol)?;
        c.put_bytes(self.bitmap)
    }
}

impl fmt::Display for Wks<'_> {
    /// `address protocol port...`, with numeric protocol and ports.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.address, self.protocol)?;
        for port in self.ports() {
            write!(f, " {port}")?;
        }
        Ok(())
    }
}
