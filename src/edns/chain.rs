//! CHAIN query requests (RFC 7901).

use core::fmt;

use super::{ComposeOption, OptionCode, ParseOption};
use crate::Result;
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, WireReader};

/// `CHAIN` option: the closest trust point from which a resolver asks for
/// the complete DNSSEC chain (RFC 7901 §4).
///
/// The name is uncompressed (§4) and must fill the option exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Chain<'a> {
    /// The closest trust point: the lowest name for which the resolver
    /// already holds validated DS and DNSKEY records.
    pub closest_trust_point: Name<'a>,
}

impl<'a> Chain<'a> {
    /// Wraps a trust point name.
    #[inline]
    #[must_use]
    pub const fn new(closest_trust_point: Name<'a>) -> Self {
        Chain {
            closest_trust_point,
        }
    }
}

impl<'a> ParseOption<'a> for Chain<'a> {
    const CODE: OptionCode = OptionCode::CHAIN;

    #[inline]
    fn parse_option(data: &mut WireReader<'a>) -> Result<Self> {
        // "No DNS name compression is allowed for this value" (§4).
        data.read_name_uncompressed().map(Chain::new)
    }
}

impl ComposeOption for Chain<'_> {
    #[inline]
    fn code(&self) -> OptionCode {
        OptionCode::CHAIN
    }

    #[inline]
    fn compose_option<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_name(self.closest_trust_point, NameEncoding::Plain)
    }
}

impl fmt::Display for Chain<'_> {
    /// `CHAIN=<name>`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CHAIN={}", self.closest_trust_point)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use crate::edns::tests::{parse, round_trip};

    #[test]
    fn chain() {
        // RFC 7901 §8.1: closest trust point "com." (option length 5).
        round_trip(OptionCode::CHAIN, b"\x03com\x00", "CHAIN=com.");
        round_trip(OptionCode::CHAIN, b"\x07example\x03com\x00", "CHAIN=example.com.");
        round_trip(OptionCode::CHAIN, b"\x00", "CHAIN=.");
        assert_eq!(parse(OptionCode::CHAIN, b""), Err(Error::UnexpectedEof));
        assert_eq!(parse(OptionCode::CHAIN, b"\xc0\x00"), Err(Error::UnexpectedPointer));
        assert_eq!(parse(OptionCode::CHAIN, b"\x00\x00"), Err(Error::TrailingData));
    }
}
