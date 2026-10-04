//! NXT record data (RFC 2535 §5.2) — obsolete, replaced by NSEC
//! (RFC 3755).

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Error, Result, Rtype};

/// Maximum NXT bitmap length: types 0–127 (RFC 2535 §5.2).
const MAX_BITMAP: usize = 16;

/// `NXT` record data: the next name in the zone and the types present at
/// the owner name (RFC 2535 §5.2). Obsolete (RFC 3755 §3).
///
/// The bitmap is the original flat form covering types 1–127: bit *n*
/// (most significant bit first) set means type *n* is present. Bit 0 set
/// announces an extended format that was never defined, so it is rejected,
/// as is a trailing zero octet (the bitmap must be minimal, as BIND
/// requires).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Nxt<'a> {
    /// The next owner name in canonical order.
    pub next: Name<'a>,
    /// The type bitmap, at most 16 octets.
    pub bitmap: &'a [u8],
}

impl<'a> Nxt<'a> {
    /// Encodes `types` (in any order, duplicates ignored; each 1–127) as a
    /// minimal NXT bitmap into `out`, returning the used prefix.
    ///
    /// ```
    /// use dnsbox::rdata::Nxt;
    /// use dnsbox::{Name, Rtype};
    ///
    /// let mut buf = [0u8; 16];
    /// let bitmap = Nxt::encode_bitmap(&[Rtype::SOA, Rtype::A, Rtype::NS], &mut buf)?;
    /// let nxt = Nxt { next: Name::ROOT, bitmap };
    /// assert_eq!(nxt.to_string(), ". A NS SOA");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn encode_bitmap<'b>(types: &[Rtype], out: &'b mut [u8; MAX_BITMAP]) -> Result<&'b [u8]> {
        *out = [0; MAX_BITMAP];
        for t in types {
            let n = t.get();
            if n == 0 || n as usize >= MAX_BITMAP * 8 {
                return Err(Error::InvalidRdata);
            }
            out[n as usize / 8] |= 0x80 >> (n % 8);
        }
        let len = out.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
        Ok(&out[..len])
    }

    /// Checks the bitmap: at most 16 octets, bit 0 clear, no trailing
    /// zero octet.
    pub fn validate(&self) -> Result<()> {
        let b = self.bitmap;
        if b.len() > MAX_BITMAP
            || b.first().is_some_and(|f| f & 0x80 != 0)
            || b.last() == Some(&0)
        {
            return Err(Error::InvalidRdata);
        }
        Ok(())
    }

    /// Whether `rtype` is present in the bitmap.
    #[must_use]
    pub fn contains(&self, rtype: Rtype) -> bool {
        let n = rtype.get() as usize;
        self.bitmap
            .get(n / 8)
            .is_some_and(|b| b & (0x80 >> (n % 8)) != 0)
    }

    /// Iterates over the types present, ascending.
    pub fn types(&self) -> impl Iterator<Item = Rtype> + 'a {
        let bitmap = self.bitmap;
        (0..bitmap.len().min(MAX_BITMAP) * 8).filter_map(move |i| {
            let set = bitmap.get(i / 8).is_some_and(|b| b & (0x80 >> (i % 8)) != 0);
            (set && i != 0).then_some(Rtype::new(i as u16))
        })
    }
}

impl ParseRdataText for Nxt<'_> {
    /// `<next domain name> <type>...` (RFC 2535 §5.2): the types as
    /// mnemonics or `TYPEnnn`, in any order, each 1–127 (the flat bitmap
    /// cannot hold others: [`Error::InvalidRdata`]).
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        s.name_into(out, NameEncoding::Lowercase)?;
        let mut bitmap = [0u8; MAX_BITMAP];
        while let Some(t) = s.next_token()? {
            if t.is_quoted() {
                return Err(Error::InvalidText);
            }
            let n = usize::from(t.as_str()?.parse::<Rtype>()?.get());
            if n == 0 {
                return Err(Error::InvalidRdata);
            }
            *bitmap.get_mut(n / 8).ok_or(Error::InvalidRdata)? |= 0x80 >> (n % 8);
        }
        let len = bitmap.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
        out.put_bytes(bitmap.get(..len).unwrap_or(&[]))
    }
}

impl<'a> ParseRdata<'a> for Nxt<'a> {
    const RTYPE: Rtype = Rtype::NXT;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        let mut r = *rdata;
        // RFC 3597 §4 lists NXT among the types receivers decompress.
        let next = r.read_name()?;
        let nxt = Nxt {
            next,
            bitmap: r.read_rest(),
        };
        nxt.validate()?;
        *rdata = r;
        Ok(nxt)
    }
}

impl ComposeRdata for Nxt<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::NXT
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        self.validate()?;
        // Lowercased in canonical form (RFC 4034 §6.2), never compressed.
        c.put_name(self.next, NameEncoding::Lowercase)?;
        c.put_bytes(self.bitmap)
    }
}

impl fmt::Display for Nxt<'_> {
    /// `next-name type...` (RFC 2535 §5.2).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.next, f)?;
        for t in self.types() {
            write!(f, " {t}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Nxt;
    use crate::rdata::tests::{parse, round_trip, text_error, text_round_trip};
    use crate::{Class, Error, Name, Rtype};
    use std::vec::Vec;

    #[test]
    fn round_trips() {
        // NXT next.example. A NS SOA MX (named-rrchecker).
        round_trip(
            Rtype::NXT,
            b"\x04next\x07example\x00\x62\x01",
            "next.example. A NS SOA MX",
        );
        round_trip(Rtype::NXT, b"\x00", ".");
        let mut wire = b"\x00".to_vec();
        wire.extend_from_slice(&[0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        round_trip(Rtype::NXT, &wire, ". A TYPE127");
    }

    #[test]
    fn text() {
        // RFC 2535 §5.4: big.foo.tld. NXT medium.foo.tld. A MX SIG NXT.
        text_round_trip(
            Rtype::NXT,
            "medium.foo.tld. A MX SIG NXT",
            b"\x06medium\x03foo\x03tld\x00\x40\x01\x00\x82",
            "medium.foo.tld. A MX SIG NXT",
        );
        // Any order, duplicates, generic mnemonics, relative names.
        text_round_trip(
            Rtype::NXT,
            "next soa TYPE2 a SOA MX",
            b"\x04next\x07example\x00\x62\x01",
            "next.example. A NS SOA MX",
        );
        text_round_trip(Rtype::NXT, ".", b"\x00", ".");
        let mut wire = b"\x00".to_vec();
        wire.extend_from_slice(&[0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        text_round_trip(Rtype::NXT, ". TYPE127 A", &wire, ". A TYPE127");
    }

    #[test]
    fn text_malformed() {
        assert_eq!(text_error(Rtype::NXT, ""), Error::UnexpectedEof);
        // Types the flat bitmap cannot hold (RFC 2535 §5.2).
        assert_eq!(text_error(Rtype::NXT, ". TYPE0"), Error::InvalidRdata);
        assert_eq!(text_error(Rtype::NXT, ". TYPE128"), Error::InvalidRdata);
        assert_eq!(text_error(Rtype::NXT, ". CAA"), Error::InvalidRdata);
        assert_eq!(text_error(Rtype::NXT, ". NOSUCHTYPE"), Error::UnknownMnemonic);
        assert_eq!(text_error(Rtype::NXT, ". \"A\""), Error::InvalidText);
    }

    #[test]
    fn bitmap_helpers() {
        let mut buf = [0u8; 16];
        let bm = Nxt::encode_bitmap(&[Rtype::MX, Rtype::A, Rtype::NS, Rtype::SOA], &mut buf)
            .unwrap();
        assert_eq!(bm, b"\x62\x01");
        let nxt = Nxt {
            next: Name::ROOT,
            bitmap: bm,
        };
        assert!(nxt.contains(Rtype::MX) && !nxt.contains(Rtype::TXT));
        assert!(!nxt.contains(Rtype::new(1000)));
        let types: Vec<Rtype> = nxt.types().collect();
        assert_eq!(types, [Rtype::A, Rtype::NS, Rtype::SOA, Rtype::MX]);
        let mut buf = [0u8; 16];
        assert_eq!(
            Nxt::encode_bitmap(&[Rtype::new(128)], &mut buf),
            Err(Error::InvalidRdata)
        );
        assert_eq!(
            Nxt::encode_bitmap(&[Rtype::new(0)], &mut buf),
            Err(Error::InvalidRdata)
        );
        assert_eq!(Nxt::encode_bitmap(&[], &mut buf), Ok(&[][..]));
    }

    #[test]
    fn malformed() {
        for bad in [
            &b"\x01a\x00\x80"[..], // bit 0 set (BIND: bad bitmap)
            b"\x00\x62\x00",       // trailing zero octet
            b"\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", // 17 octets
        ] {
            assert_eq!(
                parse(Rtype::NXT, Class::IN, bad),
                Err(Error::InvalidRdata),
                "{bad:?}"
            );
        }
        let bad = Nxt {
            next: Name::ROOT,
            bitmap: b"\x80",
        };
        let mut buf = [0u8; 8];
        let mut w = crate::WireWriter::new(&mut buf);
        assert_eq!(
            crate::ComposeRdata::compose_rdata(&bad, &mut w),
            Err(Error::InvalidRdata)
        );
    }
}
