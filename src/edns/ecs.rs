//! Client Subnet option (RFC 7871).

use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{ComposeOption, OptionCode, ParseOption};
use crate::wire::{Composer, WireReader};
use crate::{Error, Result};

/// `ECS` option: the client subnet a query is made on behalf of, and the
/// scope an answer is valid for (RFC 7871 §6).
///
/// Only the IPv4 and IPv6 families are defined; anything else is rejected
/// with [`Error::InvalidOption`] (RFC 7871 §7.2.1). The address is always
/// held truncated to the source prefix, which is what goes on the wire.
/// Parsing is strict (§6): the ADDRESS field must have exactly
/// `ceil(SOURCE PREFIX-LENGTH / 8)` octets with no bit set beyond the
/// prefix, and neither prefix length may exceed the address width.
///
/// ```
/// use dnsbox::edns::ClientSubnet;
///
/// let ecs = ClientSubnet::new("198.51.100.77".parse().unwrap(), 24, 0)?;
/// assert_eq!(ecs.addr().to_string(), "198.51.100.0");
/// assert_eq!(ecs.to_string(), "ECS=198.51.100.0/24/0");
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ClientSubnet {
    addr: IpAddr,
    source_prefix: u8,
    scope_prefix: u8,
}

impl ClientSubnet {
    /// Address family number for IPv4 (IANA "Address Family Numbers").
    pub const FAMILY_IPV4: u16 = 1;
    /// Address family number for IPv6 (IANA "Address Family Numbers").
    pub const FAMILY_IPV6: u16 = 2;

    /// Builds the option, truncating `addr` to `source_prefix` bits
    /// (RFC 7871 §6). In queries the scope prefix must be 0 (§6).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidOption`] if a prefix length exceeds the address
    /// width (32 or 128).
    pub fn new(addr: IpAddr, source_prefix: u8, scope_prefix: u8) -> Result<Self> {
        let max = max_prefix(&addr);
        if source_prefix > max || scope_prefix > max {
            return Err(Error::InvalidOption);
        }
        Ok(ClientSubnet {
            addr: mask(addr, source_prefix),
            source_prefix,
            scope_prefix,
        })
    }

    /// FAMILY: 1 for IPv4, 2 for IPv6.
    #[inline]
    #[must_use]
    pub const fn family(&self) -> u16 {
        match self.addr {
            IpAddr::V4(_) => Self::FAMILY_IPV4,
            IpAddr::V6(_) => Self::FAMILY_IPV6,
        }
    }

    /// The address, truncated to the source prefix.
    #[inline]
    #[must_use]
    pub const fn addr(&self) -> IpAddr {
        self.addr
    }

    /// SOURCE PREFIX-LENGTH: the significant bits of the address.
    #[inline]
    #[must_use]
    pub const fn source_prefix(&self) -> u8 {
        self.source_prefix
    }

    /// SCOPE PREFIX-LENGTH: the bits the answer covers (0 in queries).
    #[inline]
    #[must_use]
    pub const fn scope_prefix(&self) -> u8 {
        self.scope_prefix
    }

    /// Returns a copy with the scope prefix replaced, as an authoritative
    /// server does when answering (RFC 7871 §7.2.1).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidOption`] if `scope_prefix` exceeds the address
    /// width.
    ///
    /// ```
    /// use dnsbox::edns::ClientSubnet;
    ///
    /// let query = ClientSubnet::new("2001:db8:1234::1".parse().unwrap(), 56, 0)?;
    /// let answer = query.with_scope_prefix(48)?;
    /// assert_eq!(answer.to_string(), "ECS=2001:db8:1234::/56/48");
    /// assert!(query.with_scope_prefix(129).is_err());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn with_scope_prefix(self, scope_prefix: u8) -> Result<Self> {
        if scope_prefix > max_prefix(&self.addr) {
            return Err(Error::InvalidOption);
        }
        Ok(ClientSubnet {
            scope_prefix,
            ..self
        })
    }

    /// The significant address octets as sent on the wire, and their
    /// count.
    fn address_octets(&self) -> ([u8; 16], usize) {
        let mut out = [0u8; 16];
        let len = (self.source_prefix as usize).div_ceil(8);
        match self.addr {
            IpAddr::V4(a) => out[..4].copy_from_slice(&a.octets()),
            IpAddr::V6(a) => out = a.octets(),
        }
        (out, len)
    }
}

/// The address width in bits.
const fn max_prefix(addr: &IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// Clears every bit of `addr` beyond `prefix` (at most the width).
fn mask(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(a) => {
            let m = u32::MAX.checked_shl(32u32.saturating_sub(u32::from(prefix))).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(a) & m))
        }
        IpAddr::V6(a) => {
            let m = u128::MAX.checked_shl(128u32.saturating_sub(u32::from(prefix))).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(a) & m))
        }
    }
}

impl ParseOption<'_> for ClientSubnet {
    const CODE: OptionCode = OptionCode::ECS;

    fn parse_option(data: &mut WireReader<'_>) -> Result<Self> {
        let mut r = *data;
        let family = r.read_u16()?;
        let source_prefix = r.read_u8()?;
        let scope_prefix = r.read_u8()?;
        let addr = r.read_rest();
        let width = match family {
            Self::FAMILY_IPV4 => 4,
            Self::FAMILY_IPV6 => 16,
            _ => return Err(Error::InvalidOption),
        };
        if source_prefix as usize > width * 8
            || scope_prefix as usize > width * 8
            || addr.len() != (source_prefix as usize).div_ceil(8)
        {
            return Err(Error::InvalidOption);
        }
        let mut octets = [0u8; 16];
        octets
            .get_mut(..addr.len())
            .ok_or(Error::InvalidOption)?
            .copy_from_slice(addr);
        let full = if width == 4 {
            IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
        } else {
            IpAddr::V6(Ipv6Addr::from(octets))
        };
        let ecs = ClientSubnet {
            addr: mask(full, source_prefix),
            source_prefix,
            scope_prefix,
        };
        if ecs.addr != full {
            // Non-zero bits beyond the source prefix (RFC 7871 §6).
            return Err(Error::InvalidOption);
        }
        *data = r;
        Ok(ecs)
    }
}

impl ComposeOption for ClientSubnet {
    #[inline]
    fn code(&self) -> OptionCode {
        OptionCode::ECS
    }

    fn compose_option<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_u16(self.family())?;
        c.put_u8(self.source_prefix)?;
        c.put_u8(self.scope_prefix)?;
        let (octets, len) = self.address_octets();
        c.put_bytes(octets.get(..len).ok_or(Error::InvalidOption)?)
    }
}

impl fmt::Display for ClientSubnet {
    /// `ECS=<address>/<source prefix>/<scope prefix>`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ECS={}/{}/{}",
            self.addr, self.source_prefix, self.scope_prefix
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edns::tests::{parse, round_trip};

    #[test]
    fn wire_forms() {
        // As echoed by ns1.google.com (captured October 2026).
        round_trip(
            OptionCode::ECS,
            b"\x00\x01\x18\x00\xc6\x33\x64",
            "ECS=198.51.100.0/24/0",
        );
        // A response scoped to the /24.
        round_trip(
            OptionCode::ECS,
            b"\x00\x01\x18\x18\xc6\x33\x64",
            "ECS=198.51.100.0/24/24",
        );
        round_trip(OptionCode::ECS, b"\x00\x01\x00\x00", "ECS=0.0.0.0/0/0");
        round_trip(
            OptionCode::ECS,
            b"\x00\x02\x38\x00\x20\x01\x0d\xb8\x12\x34\x56",
            "ECS=2001:db8:1234:5600::/56/0",
        );
        round_trip(
            OptionCode::ECS,
            b"\x00\x01\x15\x00\xc0\x00\x08",
            "ECS=192.0.8.0/21/0",
        );
        round_trip(
            OptionCode::ECS,
            &[0, 2, 128, 64, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            "ECS=2001:db8::1/128/64",
        );
    }

    #[test]
    fn strictness() {
        for bad in [
            &b"\x00\x03\x00\x00"[..],     // unknown family
            b"\x00\x00\x00\x00",          // family 0
            b"\x00\x01\x21\x00\x01\x02\x03\x04\x05", // source prefix > 32
            b"\x00\x01\x18\x21\x01\x02\x03",         // scope prefix > 32
            b"\x00\x01\x18\x00\x01\x02",             // too few octets
            b"\x00\x01\x18\x00\x01\x02\x03\x04",     // too many octets
            b"\x00\x01\x17\x00\x01\x02\x03",         // bit set beyond /23
            b"\x00\x02\x81\x00",                     // source prefix > 128
        ] {
            assert_eq!(parse(OptionCode::ECS, bad), Err(Error::InvalidOption), "{bad:?}");
        }
        assert_eq!(parse(OptionCode::ECS, b"\x00\x01\x00"), Err(Error::UnexpectedEof));
    }

    #[test]
    fn construction() {
        let v6: IpAddr = "2001:db8:ffff::1".parse().unwrap();
        let e = ClientSubnet::new(v6, 33, 0).unwrap();
        assert_eq!(e.addr(), "2001:db8:8000::".parse::<IpAddr>().unwrap());
        assert_eq!(e.family(), 2);
        assert_eq!((e.source_prefix(), e.scope_prefix()), (33, 0));
        let e = e.with_scope_prefix(48).unwrap();
        assert_eq!(e.scope_prefix(), 48);
        assert_eq!(e.with_scope_prefix(129), Err(Error::InvalidOption));
        let v4: IpAddr = "10.1.2.3".parse().unwrap();
        assert_eq!(ClientSubnet::new(v4, 33, 0), Err(Error::InvalidOption));
        assert_eq!(ClientSubnet::new(v4, 0, 33), Err(Error::InvalidOption));
        let e = ClientSubnet::new(v4, 32, 0).unwrap();
        assert_eq!(e.addr(), v4);
        assert_eq!(e.family(), 1);
        assert_eq!(crate::edns::tests::compose_tlv(&e), b"\x00\x08\x00\x08\x00\x01\x20\x00\x0a\x01\x02\x03");
        assert_eq!(ClientSubnet::new(v4, 0, 0).unwrap().addr(), IpAddr::from([0, 0, 0, 0]));
    }
}
