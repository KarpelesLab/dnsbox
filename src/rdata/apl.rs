//! APL record data (RFC 3123 §4).

use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::wire::{Composer, OutBuf, WireReader};
use crate::zone::{Scanner, decimal};
use crate::{Class, Error, Result, Rtype};

/// `APL` record data: a list of address prefixes (RFC 3123 §4). Class IN
/// only, as in BIND.
///
/// The view wraps the validated items; iterate them with
/// [`items`](Self::items). To build one from separate items, use
/// [`AplItems`].
///
/// ```
/// use dnsbox::rdata::{Apl, AplItem};
///
/// let apl = Apl::from_wire(b"\x00\x01\x15\x03\xc0\xa8\x20\x00\x01\x1c\x83\xc0\xa8\x26")?;
/// assert_eq!(apl.to_string(), "1:192.168.32.0/21 !1:192.168.38.0/28");
/// let first: AplItem<'_> = apl.items().next().unwrap();
/// assert_eq!(first.address(), Some([192, 168, 32, 0].into()));
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Apl<'a>(&'a [u8]);

/// One APL item: an address prefix, possibly negated (RFC 3123 §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AplItem<'a> {
    /// Address family (IANA "Address Family Numbers": 1 = IPv4,
    /// 2 = IPv6).
    pub family: u16,
    /// Prefix length in bits.
    pub prefix: u8,
    /// The negation flag (`!` in presentation format).
    pub negation: bool,
    /// The leading address octets. On the wire trailing zero octets are
    /// omitted (RFC 3123 §4); when composing they are trimmed, so a full
    /// address may be given here.
    pub afdpart: &'a [u8],
}

impl AplItem<'_> {
    /// IPv4 address family.
    pub const IPV4: u16 = 1;
    /// IPv6 address family.
    pub const IPV6: u16 = 2;

    /// `afdpart` without its trailing zero octets.
    fn trimmed(&self) -> &[u8] {
        let len = self.afdpart.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
        self.afdpart.get(..len).unwrap_or(&[])
    }

    /// Checks the family-specific limits (RFC 3123 §4.1–4.2): IPv4
    /// prefixes are at most 32 bits with at most 4 address octets, IPv6
    /// at most 128 bits and 16 octets; any family carries at most 127
    /// octets.
    fn validate_trimmed(&self, afd: &[u8]) -> Result<()> {
        let (max_prefix, max_len) = match self.family {
            Self::IPV4 => (32, 4),
            Self::IPV6 => (128, 16),
            _ => (u8::MAX, 0x7f),
        };
        if self.prefix > max_prefix || afd.len() > max_len {
            return Err(Error::InvalidRdata);
        }
        Ok(())
    }

    /// The full address (zero-filled) for the IPv4 and IPv6 families.
    #[must_use]
    pub fn address(&self) -> Option<IpAddr> {
        let afd = self.trimmed();
        match self.family {
            Self::IPV4 if afd.len() <= 4 => {
                let mut o = [0u8; 4];
                o[..afd.len()].copy_from_slice(afd);
                Some(IpAddr::V4(Ipv4Addr::from(o)))
            }
            Self::IPV6 if afd.len() <= 16 => {
                let mut o = [0u8; 16];
                o[..afd.len()].copy_from_slice(afd);
                Some(IpAddr::V6(Ipv6Addr::from(o)))
            }
            _ => None,
        }
    }

    /// Writes the item, trimming trailing zero octets from `afdpart`.
    /// Fails with [`Error::InvalidRdata`] if it exceeds the family limits.
    pub fn compose<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        let afd = self.trimmed();
        self.validate_trimmed(afd)?;
        c.put_u16(self.family)?;
        c.put_u8(self.prefix)?;
        // afd.len() <= 127 was checked above.
        c.put_u8(u8::from(self.negation) << 7 | afd.len() as u8)?;
        c.put_bytes(afd)
    }
}

impl fmt::Display for AplItem<'_> {
    /// `[!]family:address/prefix` (RFC 3123 §5); families other than IPv4
    /// and IPv6 have no presentation format and are written as
    /// `[!]family:\#<hex>/prefix`, which only [`Apl`]'s generic fallback
    /// avoids.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.negation {
            f.write_str("!")?;
        }
        match self.address() {
            Some(addr) => write!(f, "{}:{}/{}", self.family, addr, self.prefix),
            None => write!(
                f,
                "{}:\\#{}/{}",
                self.family,
                crate::text::Hex(self.afdpart),
                self.prefix
            ),
        }
    }
}

impl<'a> Apl<'a> {
    /// Validates `wire` as a sequence of APL items: complete items, family
    /// limits respected, no trailing zero address octets (RFC 3123 §4). An
    /// empty list is valid.
    pub fn from_wire(wire: &'a [u8]) -> Result<Self> {
        let mut rest = wire;
        while !rest.is_empty() {
            let (item, tail) = split_item(rest)?;
            if item.afdpart.last() == Some(&0) {
                return Err(Error::InvalidRdata);
            }
            item.validate_trimmed(item.afdpart)?;
            rest = tail;
        }
        Ok(Apl(wire))
    }

    /// The encoded items.
    #[inline]
    #[must_use]
    pub const fn as_wire(&self) -> &'a [u8] {
        self.0
    }

    /// Whether the list is empty.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterates over the items.
    #[inline]
    pub fn items(&self) -> AplIter<'a> {
        AplIter(self.0)
    }
}

impl<'a> IntoIterator for Apl<'a> {
    type Item = AplItem<'a>;
    type IntoIter = AplIter<'a>;
    #[inline]
    fn into_iter(self) -> AplIter<'a> {
        self.items()
    }
}

impl<'a> IntoIterator for &Apl<'a> {
    type Item = AplItem<'a>;
    type IntoIter = AplIter<'a>;
    #[inline]
    fn into_iter(self) -> AplIter<'a> {
        self.items()
    }
}

/// Splits one item off the front of `wire`.
fn split_item(wire: &[u8]) -> Result<(AplItem<'_>, &[u8])> {
    let [f0, f1, prefix, n, rest @ ..] = wire else {
        return Err(Error::UnexpectedEof);
    };
    let len = usize::from(n & 0x7f);
    if rest.len() < len {
        return Err(Error::UnexpectedEof);
    }
    let (afdpart, tail) = rest.split_at(len);
    let item = AplItem {
        family: u16::from_be_bytes([*f0, *f1]),
        prefix: *prefix,
        negation: n & 0x80 != 0,
        afdpart,
    };
    Ok((item, tail))
}

/// Iterator over the items of an [`Apl`].
#[derive(Clone, Debug)]
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct AplIter<'a>(&'a [u8]);

impl<'a> Iterator for AplIter<'a> {
    type Item = AplItem<'a>;

    fn next(&mut self) -> Option<AplItem<'a>> {
        match split_item(self.0) {
            Ok((item, tail)) => {
                self.0 = tail;
                Some(item)
            }
            // Unreachable for a validated list; stay panic-free anyway.
            Err(_) => {
                self.0 = &[];
                None
            }
        }
    }
}

impl core::iter::FusedIterator for AplIter<'_> {}

/// Parses one `[!]afi:address/prefix` item (RFC 3123 §5) and writes it.
fn put_item_text<B: OutBuf + ?Sized>(text: &[u8], out: &mut B) -> Result<()> {
    let (negation, text) = match text.split_first() {
        Some((b'!', rest)) => (true, rest),
        _ => (false, text),
    };
    let colon = text
        .iter()
        .position(|&c| c == b':')
        .ok_or(Error::InvalidText)?;
    let slash = text
        .iter()
        .rposition(|&c| c == b'/')
        .filter(|&p| p > colon)
        .ok_or(Error::InvalidText)?;
    let field = |range: core::ops::Range<usize>| {
        text.get(range)
            .and_then(|f| core::str::from_utf8(f).ok())
            .ok_or(Error::InvalidText)
    };
    let family: u16 = decimal(field(0..colon)?.as_bytes())?;
    let prefix: u8 = decimal(field(slash + 1..text.len())?.as_bytes())?;
    let address = field(colon + 1..slash)?;
    let (octets, len) = match family {
        AplItem::IPV4 => {
            let a: Ipv4Addr = address.parse().map_err(|_| Error::InvalidText)?;
            (a.to_ipv6_compatible().octets(), 4)
        }
        AplItem::IPV6 => {
            let a: Ipv6Addr = address.parse().map_err(|_| Error::InvalidText)?;
            (a.octets(), 16)
        }
        // No presentation format is defined for other families.
        _ => return Err(Error::InvalidText),
    };
    let item = AplItem {
        family,
        prefix,
        negation,
        // IPv4 is in the last four octets of the compatible address.
        afdpart: octets.get(16 - len..).unwrap_or(&[]),
    };
    item.compose(out).map_err(|e| match e {
        // A prefix longer than the address (BIND: "out of range").
        Error::InvalidRdata => Error::InvalidText,
        e => e,
    })
}

impl ParseRdataText for Apl<'_> {
    /// Zero or more blank-separated `[!]afi:address/prefix` items
    /// (RFC 3123 §5): address family 1 with a dotted-quad IPv4 address or
    /// 2 with an IPv6 address, then the prefix length. Trailing zero
    /// octets are dropped from the encoded address; host bits beyond the
    /// prefix are kept, as BIND does. Other families have no presentation
    /// format and must use the generic form.
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        while let Some(t) = s.next_token()? {
            if t.is_quoted() {
                return Err(Error::InvalidText);
            }
            put_item_text(t.as_bytes(), out)?;
        }
        Ok(())
    }
}

impl<'a> ParseRdata<'a> for Apl<'a> {
    const RTYPE: Rtype = Rtype::APL;
    const CLASS: Option<Class> = Some(Class::IN);

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        let apl = Apl::from_wire(rdata.peek_rest())?;
        rdata.read_rest();
        Ok(apl)
    }
}

impl ComposeRdata for Apl<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::APL
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_bytes(self.0)
    }
}

impl fmt::Display for Apl<'_> {
    /// Space-separated items (RFC 3123 §5). A list holding a family other
    /// than IPv4 or IPv6, which has no presentation format, is written in
    /// the generic RFC 3597 form, as BIND does.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.items().any(|i| i.address().is_none()) {
            return crate::text::fmt_generic_rdata(f, self.0);
        }
        for (i, item) in self.items().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            fmt::Display::fmt(&item, f)?;
        }
        Ok(())
    }
}

/// Compose-only `APL` data built from separate items (trailing zero
/// address octets are trimmed).
///
/// ```
/// use dnsbox::rdata::{AplItem, AplItems};
/// use dnsbox::{ComposeRdata, WireWriter};
///
/// let net = [192, 168, 32, 0];
/// let items = [AplItem { family: AplItem::IPV4, prefix: 21, negation: false, afdpart: &net }];
/// let mut buf = [0u8; 32];
/// let mut w = WireWriter::new(&mut buf);
/// AplItems(&items).compose_rdata(&mut w)?;
/// assert_eq!(w.as_bytes(), b"\x00\x01\x15\x03\xc0\xa8\x20");
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct AplItems<'s>(pub &'s [AplItem<'s>]);

impl ComposeRdata for AplItems<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::APL
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        self.0.iter().try_for_each(|i| i.compose(c))
    }
}

#[cfg(test)]
mod tests {
    use super::{Apl, AplItem, AplItems};
    use crate::rdata::tests::{compose, parse, round_trip, text_error, text_round_trip};
    use crate::{Class, ComposeRdata, Error, Rtype};
    use std::string::ToString;
    use std::vec::Vec;

    #[test]
    fn rfc3123_examples() {
        // APL 1:192.168.32.0/21 !1:192.168.38.0/28 2:ff00::/8
        // (named-rrchecker).
        round_trip(
            Rtype::APL,
            &crate::testutil::hex("00011503C0A82000011C83C0A82600020801FF"),
            "1:192.168.32.0/21 !1:192.168.38.0/28 2:ff00::/8",
        );
        round_trip(Rtype::APL, b"", "");
        round_trip(
            Rtype::APL,
            b"\x00\x01\x00\x00\x00\x02\x00\x00",
            "1:0.0.0.0/0 2:::/0",
        );
        // Unknown family: generic form, as BIND prints it.
        round_trip(Rtype::APL, b"\x00\x03\x01\x00", "\\# 4 00030100");
    }

    #[test]
    fn items_and_building() {
        let wire = crate::testutil::hex("00011503C0A82000011C83C0A82600020801FF");
        let apl = Apl::from_wire(&wire).unwrap();
        let items: Vec<AplItem<'_>> = apl.items().collect();
        assert_eq!(items.len(), 3);
        assert!(items[1].negation && !items[0].negation);
        assert_eq!(items[2].address(), Some("ff00::".parse().unwrap()));
        assert_eq!(compose(&AplItems(&items)), apl.as_wire());
        // Full addresses are trimmed when composing.
        let full = [192, 168, 0, 0];
        let item = AplItem {
            family: AplItem::IPV4,
            prefix: 16,
            negation: true,
            afdpart: &full,
        };
        assert_eq!(compose(&AplItems(&[item])), b"\x00\x01\x10\x82\xc0\xa8");
        assert_eq!(item.to_string(), "!1:192.168.0.0/16");
        let odd = AplItem {
            family: 3,
            prefix: 1,
            negation: false,
            afdpart: &[1],
        };
        assert_eq!(odd.address(), None);
        assert_eq!(odd.to_string(), "3:\\#01/1");
        assert!(Apl::default().is_empty());
    }

    #[test]
    fn malformed() {
        for (bad, err) in [
            (&b"\x00\x01\x15\x04\xc0\xa8\x20\x00"[..], Error::InvalidRdata), // trailing zero
            (b"\x00\x01\x15\x05\xc0\xa8\x20\x00\x01", Error::InvalidRdata), // IPv4 > 4 octets
            (b"\x00\x01\x21\x01\xc0", Error::InvalidRdata),                 // IPv4 /33
            (b"\x00\x02\x81\x01\xff", Error::InvalidRdata),                 // IPv6 /129
            (b"\x00\x01\x15", Error::UnexpectedEof),
            (b"\x00\x01\x15\x03\xc0\xa8", Error::UnexpectedEof),
        ] {
            assert_eq!(parse(Rtype::APL, Class::IN, bad), Err(err), "{bad:?}");
        }
        let mut buf = [0u8; 64];
        let mut w = crate::WireWriter::new(&mut buf);
        let too_long = AplItem {
            family: AplItem::IPV4,
            prefix: 8,
            negation: false,
            afdpart: &[1, 2, 3, 4, 5],
        };
        assert_eq!(
            AplItems(&[too_long]).compose_rdata(&mut w),
            Err(Error::InvalidRdata)
        );
        let huge = [1u8; 128];
        let other = AplItem {
            family: 9,
            prefix: 8,
            negation: false,
            afdpart: &huge,
        };
        assert_eq!(other.compose(&mut w), Err(Error::InvalidRdata));
    }

    #[test]
    fn text() {
        // RFC 3123 §5 examples (named-rrchecker).
        text_round_trip(
            Rtype::APL,
            "1:192.168.32.0/21 !1:192.168.38.0/28",
            &crate::testutil::hex("00011503C0A82000011C83C0A826"),
            "1:192.168.32.0/21 !1:192.168.38.0/28",
        );
        text_round_trip(
            Rtype::APL,
            "1:224.0.0.0/4 2:FF00:0:0:0:0:0:0:0/8",
            &crate::testutil::hex("00010401E000020801FF"),
            "1:224.0.0.0/4 2:ff00::/8",
        );
        text_round_trip(
            Rtype::APL,
            "1:192.168.32.0/21 !1:192.168.38.0/28 2:ff00::/8",
            &crate::testutil::hex("00011503C0A82000011C83C0A82600020801FF"),
            "1:192.168.32.0/21 !1:192.168.38.0/28 2:ff00::/8",
        );
        // RFC 3123 §5: "an empty list is allowed".
        text_round_trip(Rtype::APL, "", b"", "");
        // Host bits beyond the prefix are kept, all-zero addresses are
        // empty (named-rrchecker).
        text_round_trip(
            Rtype::APL,
            "1:192.168.32.1/21 1:0.0.0.0/32 !2:::/0",
            &crate::testutil::hex("00011504C0A820010001200000020080"),
            "1:192.168.32.1/21 1:0.0.0.0/32 !2:::/0",
        );
        text_round_trip(
            Rtype::APL,
            "2:2001:db8::1:0/128",
            &crate::testutil::hex("0002800E20010DB800000000000000000001"),
            "2:2001:db8::1:0/128",
        );
        for (text, err) in [
            // BIND: "out of range", "not implemented", "syntax error",
            // "bad dotted quad", "bad IPv6 address", "unexpected token".
            ("1:192.168.32.0/33", Error::InvalidText),
            ("2:ff00::/129", Error::InvalidText),
            ("1:1.2.3.4/256", Error::InvalidText),
            ("3:1/1", Error::InvalidText),
            ("65536:1.2.3.4/32", Error::InvalidText),
            ("1:192.168.32.0", Error::InvalidText),
            ("192.168.32.0/24", Error::InvalidText),
            ("!!1:1.2.3.4/32", Error::InvalidText),
            ("+1:1.2.3.4/32", Error::InvalidText),
            ("1:1.2.3.4/+32", Error::InvalidText),
            ("1:1.2.3/24", Error::InvalidText),
            ("1:1.2.3.4/", Error::InvalidText),
            (":1.2.3.4/32", Error::InvalidText),
            ("2:1.2.3.4/32", Error::InvalidText),
            ("1:::/0", Error::InvalidText),
            ("1/8:1.2.3.4", Error::InvalidText),
            ("\"1:1.2.3.4/32\"", Error::InvalidText),
            ("1:1.2.3.4/32 x", Error::InvalidText),
        ] {
            assert_eq!(text_error(Rtype::APL, text), err, "{text:?}");
        }
    }
}
