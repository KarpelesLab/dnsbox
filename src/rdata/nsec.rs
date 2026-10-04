//! NSEC record data (RFC 4034 §4).

use core::cmp::Ordering;
use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText, TypeBitmap};
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Result, Rtype};

/// `NSEC` record data: authenticated denial of existence (RFC 4034 §4).
///
/// To build one, encode the type list with [`TypeBitmap::compose`] into a
/// buffer and wrap it with [`TypeBitmap::new`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Nsec<'a> {
    /// The next owner name in canonical order (RFC 4034 §4.1.1). Never
    /// compressed, and not lowercased in canonical form (RFC 6840 §5.1).
    pub next_domain_name: Name<'a>,
    /// The types present at the owner name (RFC 4034 §4.1.2).
    pub types: TypeBitmap<'a>,
}

impl<'a> Nsec<'a> {
    /// Builds the record data.
    #[inline]
    pub const fn new(next_domain_name: Name<'a>, types: TypeBitmap<'a>) -> Self {
        Nsec {
            next_domain_name,
            types,
        }
    }

    /// Whether this NSEC record, owned by `owner`, proves that `name` does
    /// not exist: `owner < name < next` in canonical order, or, for the last
    /// NSEC of the zone (whose next name wraps around to the apex),
    /// `name > owner` or `name < next` (RFC 4035 §5.4).
    ///
    /// The caller must still check that `name` is inside the zone and that
    /// the record is authentic.
    pub fn covers(&self, owner: &Name<'_>, name: &Name<'_>) -> bool {
        let next = &self.next_domain_name;
        let after_owner = owner.cmp_canonical(name) == Ordering::Less;
        let before_next = name.cmp_canonical(next) == Ordering::Less;
        if owner.cmp_canonical(next) == Ordering::Less {
            after_owner && before_next
        } else {
            after_owner || before_next
        }
    }
}

impl ParseRdataText for Nsec<'_> {
    /// `<next domain name> <type>...` (RFC 4034 §4.2): the types as
    /// mnemonics or `TYPEnnn`, in any order; none gives an empty bitmap.
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        s.name_into(out, NameEncoding::Plain)?;
        s.type_bitmap_into(out)
    }
}

impl<'a> ParseRdata<'a> for Nsec<'a> {
    const RTYPE: Rtype = Rtype::NSEC;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        Ok(Nsec {
            next_domain_name: rdata.read_name_uncompressed()?,
            types: TypeBitmap::parse(rdata)?,
        })
    }
}

impl ComposeRdata for Nsec<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::NSEC
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_name(self.next_domain_name, NameEncoding::Plain)?;
        c.put_bytes(self.types.as_wire())
    }
}

impl fmt::Display for Nsec<'_> {
    /// `next-name type...` (RFC 4034 §4.2).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.next_domain_name, f)?;
        if !self.types.is_empty() {
            write!(f, " {}", self.types)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdata::RData;
    use crate::rdata::tests::{parse, round_trip, text_error, text_parse, text_round_trip};
    use crate::testutil::hex;
    use crate::wire::{Canonical, WireWriter};
    use crate::{Class, Error, NameBuf};

    #[test]
    fn rfc4034_example() {
        // RFC 4034 §4.3: alfa.example.com. NSEC host.example.com. (
        //     A MX RRSIG NSEC TYPE1234 )
        let mut wire = b"\x04host\x07example\x03com\x00".to_vec();
        wire.extend(hex("0006 40010000 0003 041b"));
        wire.extend([0; 26]);
        wire.push(0x20);
        round_trip(
            Rtype::NSEC,
            &wire,
            "host.example.com. A MX RRSIG NSEC TYPE1234",
        );
        let RData::Nsec(n) = parse(Rtype::NSEC, Class::IN, &wire).unwrap() else {
            panic!()
        };
        assert!(n.types.contains(Rtype::MX));
        // An empty bitmap is allowed on the wire.
        round_trip(Rtype::NSEC, b"\x01a\x00", "a.");
    }

    #[test]
    fn text() {
        // RFC 4034 §4.3, as printed there.
        let mut wire = b"\x04host\x07example\x03com\x00".to_vec();
        wire.extend(hex("0006 40010000 0003 041b"));
        wire.extend([0; 26]);
        wire.push(0x20);
        text_round_trip(
            Rtype::NSEC,
            "host.example.com. (\n A MX RRSIG NSEC TYPE1234 )",
            &wire,
            "host.example.com. A MX RRSIG NSEC TYPE1234",
        );
        // Any order, duplicates, lowercase and generic mnemonics, a
        // relative name (origin `example.`); the case of the name is kept.
        let mut want = b"\x04Host\x07example\x03com\x07example\x00".to_vec();
        want.extend_from_slice(&wire[18..]);
        assert_eq!(
            text_parse(Rtype::NSEC, "Host.example.com TYPE1234 nsec rrsig MX a TYPE15 A")
                .as_deref(),
            Ok(&want[..])
        );
        // RFC 4035 Appendix A: the last NSEC of the chain, and an empty
        // bitmap.
        let mut wire = b"\x07example\x00".to_vec();
        wire.extend(hex("0006 400400080003"));
        text_round_trip(
            Rtype::NSEC,
            "@ A HINFO AAAA RRSIG NSEC",
            &wire,
            "example. A HINFO AAAA RRSIG NSEC",
        );
        text_round_trip(Rtype::NSEC, "a.", b"\x01a\x00", "a.");
        // Types in the last window (TYPE65535).
        text_round_trip(
            Rtype::NSEC,
            ". TYPE65535",
            &[&[0u8, 0xff, 0x20][..], &[0; 31], &[0x01]].concat(),
            ". TYPE65535",
        );
    }

    #[test]
    fn text_malformed() {
        assert_eq!(text_error(Rtype::NSEC, ""), Error::UnexpectedEof);
        assert_eq!(text_error(Rtype::NSEC, "a. NOSUCHTYPE"), Error::UnknownMnemonic);
        assert_eq!(text_error(Rtype::NSEC, "a. TYPE65536"), Error::InvalidText);
        assert_eq!(text_error(Rtype::NSEC, "a. \"A\""), Error::InvalidText);
        assert_eq!(text_error(Rtype::NSEC, "\"a.\" A"), Error::InvalidText);
        assert_eq!(text_error(Rtype::NSEC, "a. A (MX"), Error::InvalidText);
    }

    #[test]
    fn canonical_keeps_case() {
        // RFC 6840 §5.1: the next name is not lowercased.
        let next = NameBuf::from_text(b"Host.Example").unwrap();
        let n = Nsec::new(next.as_name(), TypeBitmap::default());
        let mut buf = [0u8; 32];
        let mut w = WireWriter::new(&mut buf);
        n.compose_rdata(&mut Canonical::new(&mut w)).unwrap();
        assert_eq!(w.as_bytes(), b"\x04Host\x07Example\x00");
    }

    #[test]
    fn malformed() {
        assert_eq!(
            parse(Rtype::NSEC, Class::IN, b"\xc0\x00"),
            Err(Error::UnexpectedPointer)
        );
        assert_eq!(
            parse(Rtype::NSEC, Class::IN, b"\x01a\x00\x00\x00"),
            Err(Error::InvalidRdata)
        );
    }

    #[test]
    fn covers() {
        let n = |s: &str| NameBuf::from_text(s.as_bytes()).unwrap();
        let (a, b, c, z) = (n("a.example"), n("b.example"), n("c.example"), n("example"));
        let nsec = Nsec::new(c.as_name(), TypeBitmap::default());
        assert!(nsec.covers(&a.as_name(), &b.as_name()));
        assert!(!nsec.covers(&a.as_name(), &a.as_name()));
        assert!(!nsec.covers(&a.as_name(), &c.as_name()));
        assert!(nsec.covers(&a.as_name(), &n("B.a.example").as_name()));
        // Last NSEC: next name is the apex.
        let last = Nsec::new(z.as_name(), TypeBitmap::default());
        assert!(last.covers(&c.as_name(), &n("d.example").as_name()));
        assert!(!last.covers(&c.as_name(), &b.as_name()));
        assert!(!last.covers(&c.as_name(), &c.as_name()));
    }
}
