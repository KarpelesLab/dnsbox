//! A6 record data (RFC 2874 §3.1) — historic (RFC 6563).

use core::fmt;
use core::net::Ipv6Addr;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Class, Error, Result, Rtype};

/// `A6` record data: an IPv6 address given as a suffix plus the name of a
/// prefix to look up (RFC 2874 §3.1). Moved to historic by RFC 6563; class
/// IN only.
///
/// `suffix` holds the full 128-bit address with the first `prefix_len`
/// bits zero; only the `16 - prefix_len / 8` low octets are transmitted,
/// and the pad bits in the first transmitted octet must be zero.
///
/// ```
/// use dnsbox::rdata::{A6, ParseRdataText};
///
/// // RFC 2874 §3.1.1: 64 prefix bits come from subnet-1.ip6.a.net.
/// let mut buf = [0u8; 64];
/// let a6 = A6::from_text("64 ::2:3:4:5 subnet-1.ip6.a.net.", &mut buf)?;
/// assert_eq!(a6.prefix_len, 64);
/// assert_eq!(a6.prefix.map(|n| n.to_string()).as_deref(), Some("subnet-1.ip6.a.net."));
/// a6.validate()?;
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct A6<'a> {
    /// Number of leading address bits taken from the prefix name (0–128).
    pub prefix_len: u8,
    /// The address suffix (leading `prefix_len` bits zero).
    pub suffix: Ipv6Addr,
    /// The prefix name; present exactly when `prefix_len > 0`.
    pub prefix: Option<Name<'a>>,
}

impl A6<'_> {
    /// Checks `prefix_len <= 128`, that the first `prefix_len` bits of
    /// `suffix` are zero, and that `prefix` is present iff
    /// `prefix_len > 0` (RFC 2874 §3.1).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRdata`] if a check fails.
    pub fn validate(&self) -> Result<()> {
        if self.prefix_len > 128 || (self.prefix_len > 0) != self.prefix.is_some() {
            return Err(Error::InvalidRdata);
        }
        let bits = u128::from(self.suffix);
        if self.prefix_len > 0 && bits >> (128 - u32::from(self.prefix_len)) != 0 {
            return Err(Error::InvalidRdata);
        }
        Ok(())
    }

    /// Number of suffix octets on the wire for `prefix_len`.
    const fn suffix_octets(prefix_len: u8) -> usize {
        16 - (prefix_len as usize / 8)
    }
}

impl ParseRdataText for A6<'_> {
    /// `prefix-len [address-suffix] [prefix-name]` (RFC 2874 §3.1.1): the
    /// suffix is present unless `prefix-len` is 128, the name unless it is
    /// 0. As in BIND, the address bits covered by the prefix are ignored
    /// (cleared), so `64 2001:db8::1 name` keeps only `::1`.
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        let prefix_len = s.u8()?;
        if prefix_len > 128 {
            return Err(Error::InvalidRdata);
        }
        out.put_u8(prefix_len)?;
        if prefix_len < 128 {
            let bits = u128::from(s.ipv6()?) & (u128::MAX >> prefix_len);
            let n = Self::suffix_octets(prefix_len);
            out.put_bytes(bits.to_be_bytes().get(16 - n..).unwrap_or(&[]))?;
        }
        if prefix_len > 0 {
            // Lowercased in canonical form (RFC 4034 §6.2).
            s.name_into(out, NameEncoding::Lowercase)?;
        }
        Ok(())
    }
}

impl<'a> ParseRdata<'a> for A6<'a> {
    const RTYPE: Rtype = Rtype::A6;
    const CLASS: Option<Class> = Some(Class::IN);

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        let mut r = *rdata;
        let prefix_len = r.read_u8()?;
        if prefix_len > 128 {
            return Err(Error::InvalidRdata);
        }
        let n = Self::suffix_octets(prefix_len);
        let mut octets = [0u8; 16];
        octets[16 - n..].copy_from_slice(r.read_bytes(n)?);
        let prefix = if prefix_len > 0 {
            // A6 is not among the RFC 3597 §4 decompressible types.
            Some(r.read_name_uncompressed()?)
        } else {
            None
        };
        let a6 = A6 {
            prefix_len,
            suffix: Ipv6Addr::from(octets),
            prefix,
        };
        a6.validate()?;
        *rdata = r;
        Ok(a6)
    }
}

impl ComposeRdata for A6<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::A6
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        self.validate()?;
        c.put_u8(self.prefix_len)?;
        let octets = self.suffix.octets();
        let n = Self::suffix_octets(self.prefix_len);
        c.put_bytes(octets.get(16 - n..).unwrap_or(&[]))?;
        match self.prefix {
            // Lowercased in canonical form (RFC 4034 §6.2), never
            // compressed.
            Some(name) => c.put_name(name, NameEncoding::Lowercase),
            None => Ok(()),
        }
    }
}

impl fmt::Display for A6<'_> {
    /// `prefix-len [address-suffix] [prefix-name]` (RFC 2874 §3.1.1): the
    /// suffix is omitted when `prefix_len` is 128, the name when it is 0.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.prefix_len)?;
        if self.prefix_len < 128 {
            write!(f, " {}", self.suffix)?;
        }
        if let Some(name) = self.prefix {
            write!(f, " {name}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::A6;
    use crate::rdata::tests::{parse, round_trip, text_error, text_round_trip};
    use crate::{Class, ComposeRdata, Error, Name, Rtype};

    #[test]
    fn rfc2874_examples() {
        // A6 64 ::2:3:4:5 subnet-1.ip6.a.net. (named-rrchecker).
        round_trip(
            Rtype::A6,
            &crate::testutil::hex(
                "400002000300040005087375626E65742D31036970360161036E657400",
            ),
            "64 ::2:3:4:5 subnet-1.ip6.a.net.",
        );
        // A6 0 2001:db8::1.
        round_trip(
            Rtype::A6,
            &crate::testutil::hex("0020010DB8000000000000000000000001"),
            "0 2001:db8::1",
        );
        // A6 128 foo. (BIND prints a double space).
        round_trip(Rtype::A6, b"\x80\x03foo\x00", "128 foo.");
        // Prefix length not a multiple of 8: 16 - 65/8 = 8 octets, the top
        // bit of the first is padding.
        round_trip(
            Rtype::A6,
            b"\x41\x7f\x00\x00\x00\x00\x00\x00\x01\x00",
            "65 ::7f00:0:0:1 .",
        );
    }

    #[test]
    fn malformed() {
        for bad in [
            &b"\x81\x00"[..],                               // prefix > 128
            b"\x41\xff\x02\x03\x04\x05\x06\x07\x08\x00", // pad bit set
        ] {
            assert_eq!(
                parse(Rtype::A6, Class::IN, bad),
                Err(Error::InvalidRdata),
                "{bad:?}"
            );
        }
        assert_eq!(
            parse(Rtype::A6, Class::IN, b"\x40\x00\x00\x00\x00\x00\x00\x00\x00\xc0\x00"),
            Err(Error::UnexpectedPointer)
        );
        let mut buf = [0u8; 64];
        let mut w = crate::WireWriter::new(&mut buf);
        for bad in [
            A6 {
                prefix_len: 64,
                suffix: "::1".parse().unwrap(),
                prefix: None,
            },
            A6 {
                prefix_len: 0,
                suffix: "::1".parse().unwrap(),
                prefix: Some(Name::ROOT),
            },
            A6 {
                prefix_len: 64,
                suffix: "1::1".parse().unwrap(),
                prefix: Some(Name::ROOT),
            },
            A6 {
                prefix_len: 129,
                suffix: "::".parse().unwrap(),
                prefix: Some(Name::ROOT),
            },
        ] {
            assert_eq!(bad.compose_rdata(&mut w), Err(Error::InvalidRdata));
        }
    }

    #[test]
    fn text() {
        // RFC 2874 §3.1.1 / §5 examples (named-rrchecker).
        text_round_trip(
            Rtype::A6,
            "64 ::2:3:4:5 subnet-1.ip6.a.net.",
            &crate::testutil::hex("400002000300040005087375626E65742D31036970360161036E657400"),
            "64 ::2:3:4:5 subnet-1.ip6.a.net.",
        );
        text_round_trip(
            Rtype::A6,
            "0 2001:db8::1",
            &crate::testutil::hex("0020010DB8000000000000000000000001"),
            "0 2001:db8::1",
        );
        text_round_trip(Rtype::A6, "128 foo.", b"\x80\x03foo\x00", "128 foo.");
        // BIND prints "128  foo." (two blanks), which reads the same.
        assert_eq!(
            crate::rdata::tests::text_parse(Rtype::A6, "128  foo."),
            Ok(b"\x80\x03foo\x00".to_vec())
        );
        // Relative prefix name; 16 - 48/8 = 10 suffix octets.
        let mut wire = crate::testutil::hex("300000123456789ABCDEF0");
        wire.extend_from_slice(b"\x06SUBNET\x03ip6\x07example\x00");
        text_round_trip(
            Rtype::A6,
            "48 0::0:1234:5678:9abc:def0 SUBNET.ip6",
            &wire,
            "48 ::1234:5678:9abc:def0 SUBNET.ip6.example.",
        );
        // Prefix bits and pad bits are cleared (named-rrchecker).
        text_round_trip(
            Rtype::A6,
            "65 ::ff00:0:0:1 .",
            &crate::testutil::hex("417F0000000000000100"),
            "65 ::7f00:0:0:1 .",
        );
        assert_eq!(
            crate::rdata::tests::text_parse(Rtype::A6, "64 1::2:3:4:5 foo."),
            Ok(crate::testutil::hex("40000200030004000503666F6F00"))
        );
        for (text, err) in [
            // BIND: "out of range", "extra input text", "unexpected end".
            ("129 foo.", Error::InvalidRdata),
            ("256 foo.", Error::InvalidText),
            ("0 2001:db8::1 foo.", Error::InvalidText),
            ("128", Error::UnexpectedEof),
            ("64 ::1", Error::UnexpectedEof),
            ("64 192.0.2.1 foo.", Error::InvalidText),
            ("0", Error::UnexpectedEof),
        ] {
            assert_eq!(text_error(Rtype::A6, text), err, "{text:?}");
        }
    }
}
