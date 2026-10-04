//! NSID option (RFC 5001).

use core::fmt;

use super::{ComposeOption, OptionCode, ParseOption, fmt_hex_option};
use crate::Result;
use crate::wire::{Composer, WireReader};

/// `NSID` option: the name server identifier (RFC 5001 §2.3).
///
/// A query carries it empty ([`Nsid::REQUEST`]); the response carries an
/// opaque, server-chosen identifier (often a host name in ASCII).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Nsid<'a> {
    /// The identifier; empty in requests.
    pub id: &'a [u8],
}

impl<'a> Nsid<'a> {
    /// The empty option a client sends to ask for the server's NSID
    /// (RFC 5001 §2.1).
    pub const REQUEST: Nsid<'static> = Nsid { id: &[] };

    /// Wraps an identifier.
    #[inline]
    pub const fn new(id: &'a [u8]) -> Self {
        Nsid { id }
    }

    /// Whether this is a request (empty payload).
    #[inline]
    pub const fn is_request(&self) -> bool {
        self.id.is_empty()
    }

    /// The identifier as text, if it is valid UTF-8.
    #[inline]
    pub fn as_str(&self) -> Option<&'a str> {
        core::str::from_utf8(self.id).ok()
    }
}

impl<'a> ParseOption<'a> for Nsid<'a> {
    const CODE: OptionCode = OptionCode::NSID;

    #[inline]
    fn parse_option(data: &mut WireReader<'a>) -> Result<Self> {
        Ok(Nsid {
            id: data.read_rest(),
        })
    }
}

impl ComposeOption for Nsid<'_> {
    #[inline]
    fn code(&self) -> OptionCode {
        OptionCode::NSID
    }

    #[inline]
    fn compose_option<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_bytes(self.id)
    }
}

impl fmt::Display for Nsid<'_> {
    /// `NSID` for a request, `NSID=<hex>` otherwise.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_hex_option(f, OptionCode::NSID, self.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edns::tests::round_trip;

    #[test]
    fn request_and_response() {
        round_trip(OptionCode::NSID, b"", "NSID");
        // k.root-servers.net, captured October 2026.
        let s = round_trip(
            OptionCode::NSID,
            b"ns1.jp-tyo.k.ripe.net",
            "NSID=6E73312E6A702D74796F2E6B2E726970652E6E6574",
        );
        assert!(s.starts_with("NSID="));
        let n = Nsid::new(b"ns1");
        assert_eq!(n.as_str(), Some("ns1"));
        assert!(!n.is_request() && Nsid::REQUEST.is_request());
        assert_eq!(Nsid::new(b"\xff").as_str(), None);
    }
}
