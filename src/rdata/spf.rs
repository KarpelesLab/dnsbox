//! Record types whose RDATA has the TXT format (one or more
//! `<character-string>`s, RFC 1035 §3.3.14): SPF (RFC 7208 §3.1, RFC 4408
//! §3.1.1), NINFO, AVC, RESINFO (RFC 9606 §3) and WALLET.

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::charstr::{CharStrIter, CharStrs};
use crate::wire::{Composer, WireReader};
use crate::{Error, Result, Rtype};

/// Defines a TXT-format record-data view.
macro_rules! txt_like_rdata {
    ($(#[$doc:meta])* $ty:ident, $rt:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $ty<'a> {
            strings: CharStrs<'a>,
        }

        impl<'a> $ty<'a> {
            /// Wraps encoded character-strings (length octets included),
            /// which must hold at least one string.
            pub fn from_wire(wire: &'a [u8]) -> Result<Self> {
                let strings = CharStrs::new(wire)?;
                if strings.is_empty() {
                    return Err(Error::InvalidRdata);
                }
                Ok($ty { strings })
            }

            /// The strings.
            #[inline]
            pub fn strings(&self) -> CharStrIter<'a> {
                self.strings.iter()
            }

            /// The encoded RDATA.
            #[inline]
            pub const fn as_wire(&self) -> &'a [u8] {
                self.strings.as_wire()
            }
        }

        impl<'a> ParseRdata<'a> for $ty<'a> {
            const RTYPE: Rtype = Rtype::$rt;

            fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
                let data = $ty::from_wire(rdata.peek_rest())?;
                rdata.read_rest();
                Ok(data)
            }
        }

        impl ComposeRdata for $ty<'_> {
            fn rtype(&self) -> Rtype {
                Rtype::$rt
            }

            fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
                c.put_bytes(self.as_wire())
            }
        }

        impl fmt::Display for $ty<'_> {
            /// Space-separated quoted strings.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.strings, f)
            }
        }
    };
}

txt_like_rdata! {
    /// `SPF` record data: a Sender Policy Framework policy in TXT format
    /// (RFC 4408 §3.1.1). Deprecated: RFC 7208 §3.1 says to publish SPF
    /// policies as TXT only.
    Spf, SPF
}

txt_like_rdata! {
    /// `NINFO` record data: zone status information, TXT format
    /// (IANA template, draft-reid-dnsext-zs).
    Ninfo, NINFO
}

txt_like_rdata! {
    /// `AVC` record data: application visibility and control, TXT format
    /// (IANA template "AVC/avc-completed-template").
    Avc, AVC
}

txt_like_rdata! {
    /// `RESINFO` record data: resolver information as key=value strings,
    /// TXT format (RFC 9606 §3).
    Resinfo, RESINFO
}

txt_like_rdata! {
    /// `WALLET` record data: a public wallet address, TXT format (IANA
    /// template "WALLET/wallet-completed-template").
    Wallet, WALLET
}

#[cfg(test)]
mod tests {
    use super::Spf;
    use crate::rdata::tests::{parse, round_trip};
    use crate::{Class, Error, Rtype};
    use std::vec::Vec;

    #[test]
    fn round_trips() {
        // named-rrchecker: SPF "v=spf1 -all", NINFO "a b" c, AVC "app",
        // RESINFO qnamemin exterr=15,16,17, WALLET "x" "y".
        round_trip(Rtype::SPF, b"\x0bv=spf1 -all", "\"v=spf1 -all\"");
        round_trip(Rtype::NINFO, b"\x03a b\x01c", "\"a b\" \"c\"");
        round_trip(Rtype::AVC, b"\x03app", "\"app\"");
        round_trip(
            Rtype::RESINFO,
            b"\x08qnamemin\x0fexterr=15,16,17",
            "\"qnamemin\" \"exterr=15,16,17\"",
        );
        round_trip(Rtype::WALLET, b"\x01x\x01y", "\"x\" \"y\"");
        round_trip(Rtype::SPF, b"\x00", "\"\"");
    }

    #[test]
    fn malformed() {
        for t in [
            Rtype::SPF,
            Rtype::NINFO,
            Rtype::AVC,
            Rtype::RESINFO,
            Rtype::WALLET,
        ] {
            assert_eq!(parse(t, Class::IN, b""), Err(Error::InvalidRdata));
            assert_eq!(parse(t, Class::IN, b"\x02a"), Err(Error::UnexpectedEof));
        }
        let spf = Spf::from_wire(b"\x01a\x01b").unwrap();
        let s: Vec<_> = spf.strings().map(|s| s.as_bytes()).collect();
        assert_eq!(s, [b"a", b"b"]);
    }
}
