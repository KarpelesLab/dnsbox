//! EUI48 and EUI64 record data (RFC 7043 §3, §4).

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::wire::{Composer, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Error, Result, Rtype};

/// Parses `out.len()` groups of 1 to `max_digits` hexadecimal digits
/// (either case) separated by `sep`, as in `00-00-5e-00-53-2a` (EUI48,
/// RFC 7043 §3.2) or `0014:4fff:ff20:ee64` (NID, RFC 6742 §2.1).
pub(super) fn parse_hex_groups(
    raw: &[u8],
    sep: u8,
    max_digits: usize,
    out: &mut [u16],
) -> Result<()> {
    let mut groups = raw.split(|&c| c == sep);
    for v in out.iter_mut() {
        let group = groups.next().ok_or(Error::InvalidText)?;
        if group.is_empty() || group.len() > max_digits {
            return Err(Error::InvalidText);
        }
        *v = group.iter().try_fold(0u16, |v, &c| {
            let d = char::from(c).to_digit(16).ok_or(Error::InvalidText)?;
            Ok::<u16, Error>(v << 4 | d as u16)
        })?;
    }
    match groups.next() {
        Some(_) => Err(Error::InvalidText),
        None => Ok(()),
    }
}

/// Defines a fixed-size EUI address type.
macro_rules! eui_rdata {
    ($(#[$doc:meta])* $ty:ident, $rt:ident, $n:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $ty {
            /// The address octets, in transmission order.
            pub address: [u8; $n],
        }

        impl $ty {
            /// Wraps an address.
            #[inline]
            pub const fn new(address: [u8; $n]) -> Self {
                $ty { address }
            }
        }

        impl ParseRdataText for $ty {
            /// Hyphen-separated hexadecimal octets (RFC 7043 §3.2,
            /// §4.2). BIND also accepts single-digit octets, so this
            /// does too.
            fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
                let mut groups = [0u16; $n];
                parse_hex_groups(s.word()?.as_bytes(), b'-', 2, &mut groups)?;
                // Two hex digits always fit an octet.
                groups.iter().try_for_each(|&g| out.put_u8(g as u8))
            }
        }

        impl<'a> ParseRdata<'a> for $ty {
            const RTYPE: Rtype = Rtype::$rt;

            fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
                Ok($ty {
                    address: rdata.read_array()?,
                })
            }
        }

        impl ComposeRdata for $ty {
            fn rtype(&self) -> Rtype {
                Rtype::$rt
            }

            fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
                c.put_bytes(&self.address)
            }
        }

        impl fmt::Display for $ty {
            /// Lowercase hex octets separated by hyphens (RFC 7043 §3.2,
            /// §4.2).
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for (i, b) in self.address.iter().enumerate() {
                    if i > 0 {
                        f.write_str("-")?;
                    }
                    write!(f, "{b:02x}")?;
                }
                Ok(())
            }
        }
    };
}

eui_rdata! {
    /// `EUI48` record data: an IEEE EUI-48 address, e.g. a MAC address
    /// (RFC 7043 §3).
    Eui48, EUI48, 6
}

eui_rdata! {
    /// `EUI64` record data: an IEEE EUI-64 address (RFC 7043 §4).
    Eui64, EUI64, 8
}

#[cfg(test)]
mod tests {
    use super::{Eui48, Eui64};
    use crate::rdata::tests::{compose, parse, round_trip, text_error, text_round_trip};
    use crate::{Class, Error, Rtype};

    #[test]
    fn rfc7043_examples() {
        // RFC 7043 §3.2 and §4.2 (named-rrchecker).
        round_trip(Rtype::EUI48, b"\x00\x00\x5e\x00\x53\x2a", "00-00-5e-00-53-2a");
        round_trip(
            Rtype::EUI64,
            b"\x00\x00\x5e\xef\x10\x00\x00\x2a",
            "00-00-5e-ef-10-00-00-2a",
        );
        assert_eq!(compose(&Eui48::new([1, 2, 3, 4, 5, 6])), [1, 2, 3, 4, 5, 6]);
        assert_eq!(compose(&Eui64::new([0xff; 8])), [0xff; 8]);
    }

    #[test]
    fn malformed() {
        assert_eq!(
            parse(Rtype::EUI48, Class::IN, &[0; 5]),
            Err(Error::UnexpectedEof)
        );
        assert_eq!(
            parse(Rtype::EUI48, Class::IN, &[0; 7]),
            Err(Error::TrailingData)
        );
        assert_eq!(
            parse(Rtype::EUI64, Class::IN, &[0; 9]),
            Err(Error::TrailingData)
        );
    }

    #[test]
    fn text() {
        // RFC 7043 §3.2 and §4.2 examples (named-rrchecker).
        text_round_trip(
            Rtype::EUI48,
            "00-00-5e-00-53-2a",
            b"\x00\x00\x5e\x00\x53\x2a",
            "00-00-5e-00-53-2a",
        );
        text_round_trip(
            Rtype::EUI64,
            "00-00-5e-ef-10-00-00-2a",
            b"\x00\x00\x5e\xef\x10\x00\x00\x2a",
            "00-00-5e-ef-10-00-00-2a",
        );
        // Uppercase and single digits (BIND accepts both).
        text_round_trip(
            Rtype::EUI48,
            "0-0-5E-00-53-2A",
            b"\x00\x00\x5e\x00\x53\x2a",
            "00-00-5e-00-53-2a",
        );
        for (t, text, err) in [
            // BIND: "bad EUI".
            (Rtype::EUI48, "00:00:5e:00:53:2a", Error::InvalidText),
            (Rtype::EUI48, "00005e00532a", Error::InvalidText),
            (Rtype::EUI48, "00-00-5e-00-53", Error::InvalidText),
            (Rtype::EUI48, "00-00-5e-00-53-2a-01", Error::InvalidText),
            (Rtype::EUI48, "00-00-5e-00-53-2a-", Error::InvalidText),
            (Rtype::EUI48, "000-00-5e-00-53-2a", Error::InvalidText),
            (Rtype::EUI48, "00--5e-00-53-2a", Error::InvalidText),
            (Rtype::EUI48, "0g-00-5e-00-53-2a", Error::InvalidText),
            (Rtype::EUI48, "\"00-00-5e-00-53-2a\"", Error::InvalidText),
            (Rtype::EUI48, "00-00-5e-00-53-2a 1", Error::InvalidText),
            (Rtype::EUI64, "00-00-5e-00-53-2a", Error::InvalidText),
            (Rtype::EUI64, "", Error::UnexpectedEof),
        ] {
            assert_eq!(text_error(t, text), err, "{t} {text:?}");
        }
    }
}
