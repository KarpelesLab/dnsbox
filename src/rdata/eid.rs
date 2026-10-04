//! EID and NIMLOC record data (Nimrod routing architecture,
//! draft-ietf-nimrod-dns-02; IANA "Resource Record (RR) TYPEs").
//!
//! Both carry an opaque, non-empty binary value presented in hexadecimal.
//! They are class IN only, as in BIND.

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::text::Hex;
use crate::wire::{Composer, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Class, Error, Result, Rtype};

/// Defines a class-IN record type holding one non-empty opaque value
/// displayed as uppercase hexadecimal.
macro_rules! hex_rdata {
    ($(#[$doc:meta])* $ty:ident, $rt:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $ty<'a> {
            /// The opaque value (at least one octet).
            pub data: &'a [u8],
        }

        impl ParseRdataText for $ty<'_> {
            /// The value in hexadecimal (either case), possibly split by
            /// blanks, as BIND reads it.
            fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
                s.hex_rest_into(out).map(drop)
            }
        }

        impl<'a> ParseRdata<'a> for $ty<'a> {
            const RTYPE: Rtype = Rtype::$rt;
            const CLASS: Option<Class> = Some(Class::IN);

            fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
                if rdata.is_empty() {
                    return Err(Error::UnexpectedEof);
                }
                Ok($ty {
                    data: rdata.read_rest(),
                })
            }
        }

        impl ComposeRdata for $ty<'_> {
            fn rtype(&self) -> Rtype {
                Rtype::$rt
            }

            fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
                if self.data.is_empty() {
                    return Err(Error::InvalidRdata);
                }
                c.put_bytes(self.data)
            }
        }

        impl fmt::Display for $ty<'_> {
            /// The value in uppercase hexadecimal.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&Hex(self.data), f)
            }
        }
    };
}

hex_rdata! {
    /// `EID` record data: a Nimrod endpoint identifier
    /// (draft-ietf-nimrod-dns-02). Class IN only.
    Eid, EID
}

hex_rdata! {
    /// `NIMLOC` record data: a Nimrod locator
    /// (draft-ietf-nimrod-dns-02). Class IN only.
    Nimloc, NIMLOC
}

#[cfg(test)]
mod tests {
    use super::{Eid, Nimloc};
    use crate::rdata::tests::{parse, round_trip, text_error, text_round_trip};
    use crate::rdata::{RData, UnknownRdata};
    use crate::{Class, ComposeRdata, Error, Rtype};

    #[test]
    fn round_trips() {
        // EID 12 89 AB / NIMLOC 1289AB (named-rrchecker).
        round_trip(Rtype::EID, b"\x12\x89\xab", "1289AB");
        round_trip(Rtype::NIMLOC, b"\x12\x89\xab", "1289AB");
    }

    #[test]
    fn malformed_and_class() {
        for t in [Rtype::EID, Rtype::NIMLOC] {
            assert_eq!(parse(t, Class::IN, b""), Err(Error::UnexpectedEof));
            assert_eq!(
                parse(t, Class::CH, b"\x01").unwrap(),
                RData::Unknown(UnknownRdata::new(t, b"\x01"))
            );
        }
        let mut buf = [0u8; 4];
        let mut w = crate::WireWriter::new(&mut buf);
        assert_eq!(
            Eid { data: b"" }.compose_rdata(&mut w),
            Err(Error::InvalidRdata)
        );
        assert_eq!(
            Nimloc { data: b"" }.compose_rdata(&mut w),
            Err(Error::InvalidRdata)
        );
    }

    #[test]
    fn text() {
        // named-rrchecker.
        for t in [Rtype::EID, Rtype::NIMLOC] {
            text_round_trip(t, "12 89 AB", b"\x12\x89\xab", "1289AB");
            text_round_trip(t, "( 1289ab\n cd )", b"\x12\x89\xab\xcd", "1289ABCD");
            for (text, err) in [
                // BIND: "bad hex encoding", "unexpected end of input".
                ("1", Error::InvalidText),
                ("12.89", Error::InvalidText),
                ("\"12\"", Error::InvalidText),
                ("", Error::UnexpectedEof),
            ] {
                assert_eq!(text_error(t, text), err, "{t} {text:?}");
            }
        }
    }
}
