//! ILNP record data: NID, L32, L64 and LP (RFC 6742 §2).

use core::fmt;
use core::net::Ipv4Addr;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Result, Rtype};

/// Reads a 64-bit value written as four colon-separated groups of one to
/// four hex digits (RFC 6742 §2.1, §2.3; no `::` shorthand) and writes it.
fn put_u64_groups<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
    let mut groups = [0u16; 4];
    super::eui::parse_hex_groups(s.word()?.as_bytes(), b':', 4, &mut groups)?;
    groups.iter().try_for_each(|&g| out.put_u16(g))
}

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

        impl ParseRdataText for $ty {
            /// `preference xxxx:xxxx:xxxx:xxxx` (RFC 6742 §2.1, §2.3).
            fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
                out.put_u16(s.u16()?)?;
                put_u64_groups(s, out)
            }
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
    ///
    /// ```
    /// use dnsbox::rdata::{Nid, ParseRdataText};
    ///
    /// let mut buf = [0u8; 10];
    /// let nid = Nid::from_text("20 14:4FFF:FF20:EE64", &mut buf)?;
    /// assert_eq!((nid.preference, nid.node_id), (20, 0x0014_4fff_ff20_ee64));
    /// assert_eq!(nid.to_string(), "20 0014:4fff:ff20:ee64");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    Nid, NID,
    /// The 64-bit node identifier.
    node_id
}

pref_u64_rdata! {
    /// `L64` record data: a 64-bit ILNPv6 locator (RFC 6742 §2.3).
    ///
    /// ```
    /// use dnsbox::rdata::{L64, ParseRdataText};
    ///
    /// let mut buf = [0u8; 10];
    /// let l64 = L64::from_text("10 2001:0DB8:1140:1000", &mut buf)?;
    /// assert_eq!(l64.locator, 0x2001_0db8_1140_1000);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    L64, L64,
    /// The 64-bit locator.
    locator
}

/// `L32` record data: a 32-bit ILNPv4 locator (RFC 6742 §2.2).
///
/// ```
/// use dnsbox::rdata::{L32, ParseRdataText};
///
/// let mut buf = [0u8; 6];
/// let l32 = L32::from_text("10 10.1.2.0", &mut buf)?;
/// assert_eq!(l32.locator, core::net::Ipv4Addr::new(10, 1, 2, 0));
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct L32 {
    /// Preference; lower values are preferred.
    pub preference: u16,
    /// The 32-bit locator, presented like an IPv4 address.
    pub locator: Ipv4Addr,
}

impl ParseRdataText for L32 {
    /// `preference a.b.c.d` (RFC 6742 §2.2).
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        out.put_u16(s.u16()?)?;
        out.put_bytes(&s.ipv4()?.octets())
    }
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
///
/// ```
/// use dnsbox::rdata::{Lp, ParseRdataText};
///
/// let mut buf = [0u8; 32];
/// let lp = Lp::from_text("10 l64-subnet1.example.com.", &mut buf)?;
/// assert_eq!(lp.fqdn.to_string(), "l64-subnet1.example.com.");
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Lp<'a> {
    /// Preference; lower values are preferred.
    pub preference: u16,
    /// The name with the locator records.
    pub fqdn: Name<'a>,
}

impl ParseRdataText for Lp<'_> {
    /// `preference fqdn` (RFC 6742 §2.4).
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        out.put_u16(s.u16()?)?;
        s.name_into(out, NameEncoding::Plain)
    }
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
    use crate::rdata::tests::{compose, parse, round_trip, text_error, text_round_trip};
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

    #[test]
    fn text() {
        // RFC 6742 §2 examples (named-rrchecker).
        text_round_trip(
            Rtype::NID,
            "10 0014:4fff:ff20:ee64",
            &crate::testutil::hex("000A00144FFFFF20EE64"),
            "10 0014:4fff:ff20:ee64",
        );
        text_round_trip(
            Rtype::NID,
            "20 14:4FFF:FF20:EE64",
            &crate::testutil::hex("001400144FFFFF20EE64"),
            "20 0014:4fff:ff20:ee64",
        );
        text_round_trip(
            Rtype::L64,
            "10 2001:0DB8:1140:1000",
            &crate::testutil::hex("000A20010DB811401000"),
            "10 2001:0db8:1140:1000",
        );
        text_round_trip(
            Rtype::L32,
            "10 10.1.2.0",
            &crate::testutil::hex("000A0A010200"),
            "10 10.1.2.0",
        );
        text_round_trip(
            Rtype::LP,
            "10 l64-subnet1.example.com.",
            b"\x00\x0a\x0bl64-subnet1\x07example\x03com\x00",
            "10 l64-subnet1.example.com.",
        );
        // Relative to the origin (`example.`).
        text_round_trip(
            Rtype::LP,
            "20 l32-subnet1",
            b"\x00\x14\x0bl32-subnet1\x07example\x00",
            "20 l32-subnet1.example.",
        );
        for (t, text, err) in [
            // BIND: "syntax error", "out of range", "bad dotted quad".
            (Rtype::NID, "10 0014:4fff:ff20:ee64:1", Error::InvalidText),
            (Rtype::NID, "10 0014:4fff:ff20", Error::InvalidText),
            (Rtype::NID, "10 00014:4fff:ff20:ee64", Error::InvalidText),
            (Rtype::NID, "10 ::4fff:ff20:ee64", Error::InvalidText),
            (Rtype::NID, "10 1::2:3", Error::InvalidText),
            (Rtype::NID, "10 g:1:2:3", Error::InvalidText),
            (Rtype::L64, "65536 1:2:3:4", Error::InvalidText),
            (Rtype::L64, "10", Error::UnexpectedEof),
            (Rtype::L32, "10 10.1.2", Error::InvalidText),
            (Rtype::L32, "10 010.1.2.3", Error::InvalidText),
            (Rtype::L32, "10 2001:db8::1", Error::InvalidText),
            (Rtype::L32, "10", Error::UnexpectedEof),
            (Rtype::LP, "10", Error::UnexpectedEof),
            (Rtype::LP, "x foo.", Error::InvalidText),
            (Rtype::LP, "10 foo. bar.", Error::InvalidText),
        ] {
            assert_eq!(text_error(t, text), err, "{t} {text:?}");
        }
    }
}
