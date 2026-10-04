//! DAU, DHU and N3U options: algorithms understood by a validator
//! (RFC 6975).

use core::fmt;

use super::{ComposeOption, OptionCode, ParseOption};
use crate::Result;
use crate::wire::{Composer, WireReader};

/// Defines one RFC 6975 option: a list of one-octet algorithm numbers.
macro_rules! algorithm_list_option {
    ($(#[$doc:meta])* $ty:ident, $code:ident, $registry:literal) => {
        $(#[$doc])*
        ///
        /// The value is a list of one-octet algorithm numbers
        /// (RFC 6975 §3), from the
        #[doc = concat!("IANA \"", $registry, "\" registry.")]
        /// It is only meaningful in queries.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $ty<'a> {
            /// The algorithm numbers, in the order sent.
            pub algorithms: &'a [u8],
        }

        impl<'a> $ty<'a> {
            /// Wraps a list of algorithm numbers.
            #[inline]
            #[must_use]
            pub const fn new(algorithms: &'a [u8]) -> Self {
                $ty { algorithms }
            }

            /// Iterates over the algorithm numbers.
            #[inline]
            pub fn iter(&self) -> core::iter::Copied<core::slice::Iter<'a, u8>> {
                self.algorithms.iter().copied()
            }

            /// Whether `algorithm` is listed.
            #[inline]
            #[must_use]
            pub fn contains(&self, algorithm: u8) -> bool {
                self.algorithms.contains(&algorithm)
            }
        }

        impl<'a> IntoIterator for $ty<'a> {
            type Item = u8;
            type IntoIter = core::iter::Copied<core::slice::Iter<'a, u8>>;
            #[inline]
            fn into_iter(self) -> Self::IntoIter {
                self.iter()
            }
        }

        impl<'a> IntoIterator for &$ty<'a> {
            type Item = u8;
            type IntoIter = core::iter::Copied<core::slice::Iter<'a, u8>>;
            #[inline]
            fn into_iter(self) -> Self::IntoIter {
                self.iter()
            }
        }

        impl<'a> ParseOption<'a> for $ty<'a> {
            const CODE: OptionCode = OptionCode::$code;

            #[inline]
            fn parse_option(data: &mut WireReader<'a>) -> Result<Self> {
                Ok($ty {
                    algorithms: data.read_rest(),
                })
            }
        }

        impl ComposeOption for $ty<'_> {
            #[inline]
            fn code(&self) -> OptionCode {
                OptionCode::$code
            }

            #[inline]
            fn compose_option<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
                c.put_bytes(self.algorithms)
            }
        }

        impl fmt::Display for $ty<'_> {
            #[doc = concat!("`", stringify!($code), "=8,13,15` (or `", stringify!($code), "` when empty).")]
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", OptionCode::$code)?;
                for (i, a) in self.algorithms.iter().enumerate() {
                    write!(f, "{}{a}", if i == 0 { '=' } else { ',' })?;
                }
                Ok(())
            }
        }
    };
}

algorithm_list_option! {
    /// `DAU` option: DNSSEC signing algorithms the validator understands
    /// (RFC 6975 §3).
    Dau, DAU, "DNS Security Algorithm Numbers"
}

algorithm_list_option! {
    /// `DHU` option: DS hash algorithms the validator understands
    /// (RFC 6975 §3).
    Dhu, DHU, "Delegation Signer (DS) Resource Record (RR) Type Digest Algorithms"
}

algorithm_list_option! {
    /// `N3U` option: NSEC3 hash algorithms the validator understands
    /// (RFC 6975 §3).
    N3u, N3U, "DNSSEC NSEC3 Hash Algorithms"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edns::tests::round_trip;
    use std::vec::Vec;

    #[test]
    fn lists() {
        // RFC 6975 §3 layout: one octet per algorithm.
        round_trip(OptionCode::DAU, &[8, 10, 13, 14, 15, 16], "DAU=8,10,13,14,15,16");
        round_trip(OptionCode::DHU, &[1, 2, 4], "DHU=1,2,4");
        round_trip(OptionCode::N3U, &[1], "N3U=1");
        round_trip(OptionCode::DAU, &[], "DAU");
        let d = Dau::new(&[8, 13]);
        assert!(d.contains(13) && !d.contains(5));
        assert_eq!(d.iter().collect::<Vec<_>>(), [8, 13]);
        assert_eq!(Dhu::new(&[2]).iter().count(), 1);
        assert!(N3u::new(&[1]).contains(1));
    }
}
