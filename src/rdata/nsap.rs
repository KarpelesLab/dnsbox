//! NSAP record data (RFC 1706 §5).

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::wire::{Composer, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Class, Error, Result, Rtype};

/// `NSAP` record data: an OSI network service access point address
/// (RFC 1706 §5). Class IN only; deprecated in practice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Nsap<'a> {
    /// The binary NSAP address (at least one octet).
    pub address: &'a [u8],
}

/// Writes hexadecimal digits (either case) in which `.` separators may
/// appear anywhere, as in NSAP (RFC 1706 §5) and ATMA AESA addresses;
/// returns the number of octets. An odd digit count is
/// [`Error::InvalidText`].
pub(super) fn put_dotted_hex<C: Composer + ?Sized>(text: &[u8], out: &mut C) -> Result<usize> {
    let mut high: Option<u8> = None;
    let mut n = 0;
    for &c in text.iter().filter(|&&c| c != b'.') {
        let d = char::from(c).to_digit(16).ok_or(Error::InvalidText)? as u8;
        match high.take() {
            None => high = Some(d),
            Some(h) => {
                out.put_u8(h << 4 | d)?;
                n += 1;
            }
        }
    }
    match high {
        Some(_) => Err(Error::InvalidText),
        None => Ok(n),
    }
}

impl ParseRdataText for Nsap<'_> {
    /// `0x` (or `0X`) and the address in hexadecimal, with optional `.`
    /// separators, as one token (RFC 1706 §5).
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        let t = s.word()?;
        let digits = match t.as_bytes() {
            [b'0', b'x' | b'X', rest @ ..] => rest,
            _ => return Err(Error::InvalidText),
        };
        put_dotted_hex(digits, out).map(drop)
    }
}

impl<'a> ParseRdata<'a> for Nsap<'a> {
    const RTYPE: Rtype = Rtype::NSAP;
    const CLASS: Option<Class> = Some(Class::IN);

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        if rdata.is_empty() {
            return Err(Error::UnexpectedEof);
        }
        Ok(Nsap {
            address: rdata.read_rest(),
        })
    }
}

impl ComposeRdata for Nsap<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::NSAP
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        if self.address.is_empty() {
            return Err(Error::InvalidRdata);
        }
        c.put_bytes(self.address)
    }
}

impl fmt::Display for Nsap<'_> {
    /// `0x` followed by the address in lowercase hexadecimal, without the
    /// optional `.` separators (RFC 1706 §5).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("0x")?;
        self.address.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

#[cfg(test)]
mod tests {
    use crate::rdata::tests::{parse, round_trip, text_error, text_round_trip};
    use crate::rdata::{RData, UnknownRdata};
    use crate::{Class, Error, Rtype};

    #[test]
    fn rfc1706_example() {
        // NSAP 0x47.0005.80.005a00.0000.0001.e133.ffffff000161.00
        // (named-rrchecker).
        round_trip(
            Rtype::NSAP,
            &crate::testutil::hex("47000580005A0000000001E133FFFFFF00016100"),
            "0x47000580005a0000000001e133ffffff00016100",
        );
    }

    #[test]
    fn malformed_and_class() {
        assert_eq!(
            parse(Rtype::NSAP, Class::IN, b""),
            Err(Error::UnexpectedEof)
        );
        assert_eq!(
            parse(Rtype::NSAP, Class::CH, b"\x47").unwrap(),
            RData::Unknown(UnknownRdata::new(Rtype::NSAP, b"\x47"))
        );
    }

    #[test]
    fn text() {
        // RFC 1706 §5 / §7 examples (named-rrchecker).
        text_round_trip(
            Rtype::NSAP,
            "0x47.0005.80.005a00.0000.0001.e133.ffffff000161.00",
            &crate::testutil::hex("47000580005A0000000001E133FFFFFF00016100"),
            "0x47000580005a0000000001e133ffffff00016100",
        );
        text_round_trip(
            Rtype::NSAP,
            "0x39.840f.80.005a00.0000.0001.e133.ffffff000162.00",
            &crate::testutil::hex("39840F80005A0000000001E133FFFFFF00016200"),
            "0x39840f80005a0000000001e133ffffff00016200",
        );
        text_round_trip(Rtype::NSAP, "0X4700", b"\x47\x00", "0x4700");
        for (text, err) in [
            // BIND: "syntax error", "unexpected end of input", "extra
            // input text".
            ("47", Error::InvalidText),
            ("x47", Error::InvalidText),
            ("0x470", Error::InvalidText),
            ("0x47 00", Error::InvalidText),
            ("0x4g", Error::InvalidText),
            ("\"0x47\"", Error::InvalidText),
            ("0x", Error::UnexpectedEof),
            ("0x..", Error::UnexpectedEof),
            ("", Error::UnexpectedEof),
        ] {
            assert_eq!(text_error(Rtype::NSAP, text), err, "{text:?}");
        }
    }
}
