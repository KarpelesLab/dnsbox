//! KX record data (RFC 2230 §3).

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Class, Result, Rtype};

/// `KX` record data: a key exchanger for the owner name (RFC 2230 §3).
/// Class IN only.
///
/// ```
/// use dnsbox::rdata::{Kx, ParseRdataText};
///
/// let mut buf = [0u8; 32];
/// let kx = Kx::from_text("10 kx1.foo.example.", &mut buf)?;
/// assert_eq!((kx.preference, kx.exchanger.to_string()), (10, "kx1.foo.example.".into()));
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Kx<'a> {
    /// Preference; lower values are preferred.
    pub preference: u16,
    /// The key exchanger host.
    pub exchanger: Name<'a>,
}

impl ParseRdataText for Kx<'_> {
    /// `<preference> <exchanger>` (RFC 2230 §3): a decimal number and a
    /// domain name, relative to the origin unless it ends in a dot.
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        out.put_u16(s.u16()?)?;
        s.name_into(out, NameEncoding::Lowercase)
    }
}

impl<'a> ParseRdata<'a> for Kx<'a> {
    const RTYPE: Rtype = Rtype::KX;
    const CLASS: Option<Class> = Some(Class::IN);

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        Ok(Kx {
            preference: rdata.read_u16()?,
            // KX is not among the RFC 3597 §4 decompressible types.
            exchanger: rdata.read_name_uncompressed()?,
        })
    }
}

impl ComposeRdata for Kx<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::KX
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_u16(self.preference)?;
        // Lowercased in canonical form (RFC 4034 §6.2).
        c.put_name(self.exchanger, NameEncoding::Lowercase)
    }
}

impl fmt::Display for Kx<'_> {
    /// `preference exchanger` (RFC 2230 §3).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.preference, self.exchanger)
    }
}

#[cfg(test)]
mod tests {
    use crate::rdata::tests::{parse, round_trip, text_error, text_round_trip};
    use crate::{Class, Error, Rtype};

    #[test]
    fn rfc2230_example() {
        // KX 10 kx1.foo.example. (named-rrchecker).
        round_trip(
            Rtype::KX,
            b"\x00\x0a\x03kx1\x03foo\x07example\x00",
            "10 kx1.foo.example.",
        );
        assert_eq!(
            parse(Rtype::KX, Class::IN, b"\x00\x0a\xc0\x00"),
            Err(Error::UnexpectedPointer)
        );
    }

    #[test]
    fn text() {
        // RFC 2230 §3: "<owner> KX <preference> <exchanger>".
        text_round_trip(
            Rtype::KX,
            "10 kx1.foo.example.",
            b"\x00\x0a\x03kx1\x03foo\x07example\x00",
            "10 kx1.foo.example.",
        );
        text_round_trip(
            Rtype::KX,
            "( 65535\n KX2 )",
            b"\xff\xff\x03KX2\x07example\x00",
            "65535 KX2.example.",
        );
        text_round_trip(Rtype::KX, "0 .", b"\x00\x00\x00", "0 .");
    }

    #[test]
    fn text_malformed() {
        for (text, err) in [
            ("", Error::UnexpectedEof),
            ("10", Error::UnexpectedEof),
            ("-10 a.", Error::InvalidText),
            ("10 a. b.", Error::InvalidText),
            ("10 a..b", Error::EmptyLabel),
        ] {
            assert_eq!(text_error(Rtype::KX, text), err, "{text:?}");
        }
    }
}
