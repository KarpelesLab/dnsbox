//! ILNP record data: NID, L32, L64 and LP (RFC 6742 §2).

use core::fmt;
use core::net::Ipv4Addr;

use super::{ComposeRdata, ParseRdata};
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, WireReader};
use crate::{Result, Rtype};

/// Writes a 64-bit value as four colon-separated groups of four lowercase
/// hex digits (RFC 6742 §2.1, §2.3).
fn fmt_u64_groups(f: &mut fmt::Formatter<'_>, v: u64) -> fmt::Result {
    write!(
        f,
        "{:04x}:{:04x}:{:04x}:{:04x}",
        v >> 48,
        (v >> 32) & 0xffff,
        (v >> 16) & 0xffff,
        v & 0xffff
    )
}

/// Defines a `preference` + 64-bit value type (NID, L64).
macro_rules! pref_u64_rdata {
    ($(#[$doc:meta])* $ty:ident, $rt:ident, $(#[$fdoc:meta])* $field:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $ty {
            /// Preference; lower values are preferred.
            pub preference: u16,
            $(#[$fdoc])*
            pub $field: u64,
        }

        impl<'a> ParseRdata<'a> for $ty {
            const RTYPE: Rtype = Rtype::$rt;

            fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
                let mut r = *rdata;
                let preference = r.read_u16()?;
                let $field = r.read_u64()?;
                *rdata = r;
                Ok($ty { preference, $field })
            }
        }

        impl ComposeRdata for $ty {
            fn rtype(&self) -> Rtype {
                Rtype::$rt
            }

            fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
                c.put_u16(self.preference)?;
                c.put_u64(self.$field)
            }
        }

        impl fmt::Display for $ty {
            /// `preference xxxx:xxxx:xxxx:xxxx`.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{} ", self.preference)?;
                fmt_u64_groups(f, self.$field)
            }
        }
    };
}

pref_u64_rdata! {
    /// `NID` record data: an ILNP node identifier (RFC 6742 §2.1).
    Nid, NID,
    /// The 64-bit node identifier.
    node_id
}

pref_u64_rdata! {
    /// `L64` record data: a 64-bit ILNPv6 locator (RFC 6742 §2.3).
    L64, L64,
    /// The 64-bit locator.
    locator
}

/// `L32` record data: a 32-bit ILNPv4 locator (RFC 6742 §2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct L32 {
    /// Preference; lower values are preferred.
    pub preference: u16,
    /// The 32-bit locator, presented like an IPv4 address.
    pub locator: Ipv4Addr,
}

impl<'a> ParseRdata<'a> for L32 {
    const RTYPE: Rtype = Rtype::L32;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        let mut r = *rdata;
        let preference = r.read_u16()?;
        let locator = Ipv4Addr::from(r.read_array::<4>()?);
        *rdata = r;
        Ok(L32 {
            preference,
            locator,
        })
    }
}

impl ComposeRdata for L32 {
    fn rtype(&self) -> Rtype {
        Rtype::L32
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_u16(self.preference)?;
        c.put_bytes(&self.locator.octets())
    }
}

impl fmt::Display for L32 {
    /// `preference a.b.c.d` (RFC 6742 §2.2).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.preference, self.locator)
    }
}

/// `LP` record data: a pointer to the name holding L32/L64 records
/// (RFC 6742 §2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Lp<'a> {
    /// Preference; lower values are preferred.
    pub preference: u16,
    /// The name with the locator records.
    pub fqdn: Name<'a>,
}

impl<'a> ParseRdata<'a> for Lp<'a> {
    const RTYPE: Rtype = Rtype::LP;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        let mut r = *rdata;
        let preference = r.read_u16()?;
        // Not among the RFC 3597 §4 decompressible types.
        let fqdn = r.read_name_uncompressed()?;
        *rdata = r;
        Ok(Lp { preference, fqdn })
    }
}

impl ComposeRdata for Lp<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::LP
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_u16(self.preference)?;
        // Not in the RFC 4034 §6.2 lowercasing list.
        c.put_name(self.fqdn, NameEncoding::Plain)
    }
}

impl fmt::Display for Lp<'_> {
    /// `preference fqdn` (RFC 6742 §2.4).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.preference, self.fqdn)
    }
}

#[cfg(test)]
mod tests {
    use super::{L32, Nid};
    use crate::rdata::tests::{compose, parse, round_trip};
    use crate::{Class, Error, Rtype};

    #[test]
    fn rfc6742_examples() {
        // RFC 6742 examples (wire from named-rrchecker; BIND omits the
        // leading zeros of each group, the RFC keeps them).
        round_trip(
            Rtype::NID,
            &crate::testutil::hex("000A00144FFFFF20EE64"),
            "10 0014:4fff:ff20:ee64",
        );
        round_trip(Rtype::L32, &crate::testutil::hex("000A0A010200"), "10 10.1.2.0");
        round_trip(
            Rtype::L64,
            &crate::testutil::hex("000A20010DB811401000"),
            "10 2001:0db8:1140:1000",
        );
        round_trip(
            Rtype::LP,
            b"\x00\x0a\x0bl64-subnet1\x07example\x03com\x00",
            "10 l64-subnet1.example.com.",
        );
        let nid = Nid {
            preference: 1,
            node_id: 0x0001_0002_0003_0004,
        };
        assert_eq!(compose(&nid), b"\x00\x01\x00\x01\x00\x02\x00\x03\x00\x04");
        let l32 = L32 {
            preference: 2,
            locator: [192, 0, 2, 1].into(),
        };
        assert_eq!(compose(&l32), b"\x00\x02\xc0\x00\x02\x01");
    }

    #[test]
    fn malformed() {
        assert_eq!(
            parse(Rtype::NID, Class::IN, b"\x00\x0a\x00"),
            Err(Error::UnexpectedEof)
        );
        assert_eq!(
            parse(Rtype::L32, Class::IN, b"\x00\x0a\x01\x02\x03\x04\x05"),
            Err(Error::TrailingData)
        );
        assert_eq!(
            parse(Rtype::LP, Class::IN, b"\x00\x0a\xc0\x00"),
            Err(Error::UnexpectedPointer)
        );
    }
}
