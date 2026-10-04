//! EUI48 and EUI64 record data (RFC 7043 §3, §4).

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::wire::{Composer, WireReader};
use crate::{Result, Rtype};

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

        impl super::ParseRdataText for $ty {}

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
    use crate::rdata::tests::{compose, parse, round_trip};
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
}
