//! CSYNC record data (RFC 7477 §2.1).

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText, TypeBitmap};
use crate::wire::{Composer, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Result, Rtype};

/// `CSYNC` record data: child-to-parent synchronization instructions
/// (RFC 7477 §2.1).
///
/// To build one from a list of types, use [`CsyncParts`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Csync<'a> {
    /// The child zone's SOA serial the data was taken at (RFC 7477
    /// §2.1.1.1).
    pub serial: u32,
    /// Flags ([`Csync::IMMEDIATE`], [`Csync::SOA_MINIMUM`]).
    pub flags: u16,
    /// The types the parent should synchronize (RFC 7477 §2.1.1.3).
    pub types: TypeBitmap<'a>,
}

impl Csync<'_> {
    /// The "immediate" flag: process without waiting for the serial
    /// (RFC 7477 §2.1.1.2.1).
    pub const IMMEDIATE: u16 = 0x0001;
    /// The "soaminimum" flag: only act if the SOA serial is at least
    /// `serial` (RFC 7477 §2.1.1.2.2).
    pub const SOA_MINIMUM: u16 = 0x0002;

    /// Whether the immediate flag is set.
    #[inline]
    pub const fn immediate(&self) -> bool {
        self.flags & Self::IMMEDIATE != 0
    }

    /// Whether the soaminimum flag is set.
    #[inline]
    pub const fn soa_minimum(&self) -> bool {
        self.flags & Self::SOA_MINIMUM != 0
    }
}

impl ParseRdataText for Csync<'_> {
    /// `serial flags type...` (RFC 7477 §2.1.2): decimal SOA serial and
    /// flags, then the type mnemonics (`TYPEnnn` too), possibly none.
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        out.put_u32(s.u32()?)?;
        out.put_u16(s.u16()?)?;
        s.type_bitmap_into(out)
    }
}

impl<'a> ParseRdata<'a> for Csync<'a> {
    const RTYPE: Rtype = Rtype::CSYNC;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        let mut r = *rdata;
        let serial = r.read_u32()?;
        let flags = r.read_u16()?;
        let types = TypeBitmap::parse(&mut r)?;
        *rdata = r;
        Ok(Csync {
            serial,
            flags,
            types,
        })
    }
}

impl ComposeRdata for Csync<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::CSYNC
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_u32(self.serial)?;
        c.put_u16(self.flags)?;
        c.put_bytes(self.types.as_wire())
    }
}

impl fmt::Display for Csync<'_> {
    /// `serial flags type...` (RFC 7477 §2.1.2).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.serial, self.flags)?;
        for t in self.types.iter() {
            write!(f, " {t}")?;
        }
        Ok(())
    }
}

/// Compose-only `CSYNC` data with the types given as a list.
///
/// ```
/// use dnsbox::rdata::{Csync, CsyncParts};
/// use dnsbox::{ComposeRdata, Rtype, WireWriter};
///
/// let csync = CsyncParts {
///     serial: 66,
///     flags: Csync::IMMEDIATE | Csync::SOA_MINIMUM,
///     types: &[Rtype::A, Rtype::NS, Rtype::AAAA],
/// };
/// let mut buf = [0u8; 32];
/// let mut w = WireWriter::new(&mut buf);
/// csync.compose_rdata(&mut w)?;
/// assert_eq!(w.as_bytes(), b"\x00\x00\x00\x42\x00\x03\x00\x04\x60\x00\x00\x08");
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct CsyncParts<'s> {
    /// SOA serial.
    pub serial: u32,
    /// Flags.
    pub flags: u16,
    /// The types to synchronize (any order).
    pub types: &'s [Rtype],
}

impl ComposeRdata for CsyncParts<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::CSYNC
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_u32(self.serial)?;
        c.put_u16(self.flags)?;
        TypeBitmap::compose(self.types, c)
    }
}

#[cfg(test)]
mod tests {
    use super::{Csync, CsyncParts};
    use crate::rdata::tests::{compose, parse, round_trip, text_error, text_round_trip};
    use crate::rdata::RData;
    use crate::{Class, Error, Rtype};

    #[test]
    fn rfc7477_example() {
        // RFC 7477 §2.2: www.example.com. CSYNC 66 3 A NS AAAA
        // (named-rrchecker).
        let wire = crate::testutil::hex("000000420003000460000008");
        round_trip(Rtype::CSYNC, &wire, "66 3 A NS AAAA");
        let RData::Csync(c) = parse(Rtype::CSYNC, Class::IN, &wire).unwrap() else {
            panic!()
        };
        assert!(c.immediate() && c.soa_minimum());
        assert!(c.types.contains(Rtype::AAAA));
        let parts = CsyncParts {
            serial: 66,
            flags: 3,
            types: &[Rtype::AAAA, Rtype::NS, Rtype::A],
        };
        assert_eq!(compose(&parts), wire);
        // Empty bitmap (named-rrchecker accepts it).
        round_trip(Rtype::CSYNC, b"\x00\x00\x00\x42\x00\x00", "66 0");
        let none = Csync {
            serial: 0,
            flags: 0,
            types: Default::default(),
        };
        assert!(!none.immediate() && !none.soa_minimum());
    }

    #[test]
    fn malformed() {
        assert_eq!(
            parse(Rtype::CSYNC, Class::IN, b"\x00\x00\x00\x42\x00"),
            Err(Error::UnexpectedEof)
        );
        assert_eq!(
            parse(Rtype::CSYNC, Class::IN, b"\x00\x00\x00\x42\x00\x00\x00\x00"),
            Err(Error::InvalidRdata)
        );
    }

    #[test]
    fn text() {
        // RFC 7477 §2.2 example (named-rrchecker).
        text_round_trip(
            Rtype::CSYNC,
            "66 3 A NS AAAA",
            &crate::testutil::hex("000000420003000460000008"),
            "66 3 A NS AAAA",
        );
        // Any order, duplicates, generic type names, empty bitmap.
        text_round_trip(
            Rtype::CSYNC,
            "66 3 aaaa TYPE2 a NS",
            &crate::testutil::hex("000000420003000460000008"),
            "66 3 A NS AAAA",
        );
        text_round_trip(
            Rtype::CSYNC,
            "4294967295 0",
            b"\xff\xff\xff\xff\x00\x00",
            "4294967295 0",
        );
        // The last window: block 255, 32 octets, bit 255 set.
        let mut wire = std::vec![0, 0, 0, 1, 0, 1, 0xff, 32];
        wire.extend_from_slice(&[0; 31]);
        wire.push(0x01);
        text_round_trip(Rtype::CSYNC, "1 1 TYPE65535", &wire, "1 1 TYPE65535");
        for (text, err) in [
            // BIND: "out of range", "unknown class/type".
            ("66 65536 A", Error::InvalidText),
            ("4294967296 1 A", Error::InvalidText),
            ("66 3 FOO", Error::UnknownMnemonic),
            ("66 3 \"A\"", Error::InvalidText),
            ("66", Error::UnexpectedEof),
            ("", Error::UnexpectedEof),
        ] {
            assert_eq!(text_error(Rtype::CSYNC, text), err, "{text:?}");
        }
    }
}
