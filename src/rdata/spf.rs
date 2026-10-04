//! Record types whose RDATA has the TXT format (one or more
//! `<character-string>`s, RFC 1035 §3.3.14): SPF (RFC 7208 §3.1, RFC 4408
//! §3.1.1), NINFO, AVC, RESINFO (RFC 9606 §3) and WALLET.

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::charstr::{CharStrIter, CharStrs};
use crate::wire::{Composer, OutBuf, WireReader};
use crate::zone::Scanner;
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
            ///
            /// # Errors
            ///
            /// [`Error::InvalidRdata`] for an empty buffer,
            /// [`Error::UnexpectedEof`] if the last string is cut short.
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
            #[must_use]
            pub const fn as_wire(&self) -> &'a [u8] {
                self.strings.as_wire()
            }
        }

        impl ParseRdataText for $ty<'_> {
            /// One or more `<character-string>`s, quoted or not, as TXT
            /// (RFC 1035 §3.3.14, §5.1).
            fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
                s.char_strings_into(out)
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
    ///
    /// ```
    /// use dnsbox::rdata::{ParseRdataText, Spf};
    ///
    /// let mut buf = [0u8; 32];
    /// let spf = Spf::from_text(r#""v=spf1 -all""#, &mut buf)?;
    /// assert_eq!(spf.strings().next().map(|s| s.as_bytes()), Some(&b"v=spf1 -all"[..]));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    Spf, SPF
}

txt_like_rdata! {
    /// `NINFO` record data: zone status information, TXT format
    /// (IANA template, draft-reid-dnsext-zs).
    ///
    /// ```
    /// use dnsbox::rdata::Ninfo;
    ///
    /// let ninfo = Ninfo::from_wire(b"\x02ok")?;
    /// assert_eq!(ninfo.to_string(), r#""ok""#);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    Ninfo, NINFO
}

txt_like_rdata! {
    /// `AVC` record data: application visibility and control, TXT format
    /// (IANA template "AVC/avc-completed-template").
    ///
    /// ```
    /// use dnsbox::rdata::{Avc, ParseRdataText};
    ///
    /// let mut buf = [0u8; 32];
    /// let avc = Avc::from_text(r#""app-name:WOLFGANG|app-class:OAM""#, &mut buf)?;
    /// assert_eq!(avc.strings().count(), 1);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    Avc, AVC
}

txt_like_rdata! {
    /// `RESINFO` record data: resolver information as key=value strings,
    /// TXT format (RFC 9606 §3).
    ///
    /// ```
    /// use dnsbox::rdata::{ParseRdataText, Resinfo};
    ///
    /// // RFC 9606 §3.
    /// let mut buf = [0u8; 128];
    /// let info = Resinfo::from_text("qnamemin exterr=15,16,17 infourl=https://resolver.example.com/guide", &mut buf)?;
    /// let keys: Vec<&[u8]> = info.strings().map(|s| s.as_bytes()).collect();
    /// assert_eq!(keys[0], b"qnamemin");
    /// assert_eq!(keys.len(), 3);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    Resinfo, RESINFO
}

txt_like_rdata! {
    /// `WALLET` record data: a public wallet address, TXT format (IANA
    /// template "WALLET/wallet-completed-template").
    ///
    /// ```
    /// use dnsbox::rdata::{ParseRdataText, Wallet};
    ///
    /// let mut buf = [0u8; 64];
    /// let wallet = Wallet::from_text("BTC bc1qexampleaddress", &mut buf)?;
    /// assert_eq!(wallet.to_string(), r#""BTC" "bc1qexampleaddress""#);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    Wallet, WALLET
}

#[cfg(test)]
mod tests {
    use super::Spf;
    use crate::rdata::tests::{parse, round_trip, text_error, text_round_trip};
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
    fn text() {
        // RFC 7208 §3.1 / RFC 4408 §3.1.1: SPF records in TXT format.
        text_round_trip(Rtype::SPF, "\"v=spf1 -all\"", b"\x0bv=spf1 -all", "\"v=spf1 -all\"");
        text_round_trip(
            Rtype::SPF,
            "\"v=spf1 +mx a:colo.example.com/28\" \"-all\"",
            b"\x20v=spf1 +mx a:colo.example.com/28\x04-all",
            "\"v=spf1 +mx a:colo.example.com/28\" \"-all\"",
        );
        // RFC 9606 §3: RESINFO key=value pairs, unquoted.
        let wire = b"\x08qnamemin\x0fexterr=15,16,17\x2ainfourl=https://resolver.example.com/guide";
        text_round_trip(
            Rtype::RESINFO,
            "qnamemin exterr=15,16,17 infourl=https://resolver.example.com/guide",
            wire,
            "\"qnamemin\" \"exterr=15,16,17\" \"infourl=https://resolver.example.com/guide\"",
        );
        for t in [Rtype::NINFO, Rtype::AVC, Rtype::WALLET] {
            text_round_trip(t, "\"a b\" c \\065", b"\x03a b\x01c\x01A", "\"a b\" \"c\" \"A\"");
            text_round_trip(t, "\"\"", b"\x00", "\"\"");
        }
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

    #[test]
    fn text_examples() {
        // RFC 4408 §3.1.1 / RFC 7208 §3 policy; named-rrchecker.
        text_round_trip(
            Rtype::SPF,
            "\"v=spf1 +mx a:colo.example.com/28 -all\"",
            b"\x25v=spf1 +mx a:colo.example.com/28 -all",
            "\"v=spf1 +mx a:colo.example.com/28 -all\"",
        );
        text_round_trip(Rtype::NINFO, "a b c", b"\x01a\x01b\x01c", "\"a\" \"b\" \"c\"");
        text_round_trip(Rtype::AVC, "app ( \"x y\" )", b"\x03app\x03x y", "\"app\" \"x y\"");
        // RFC 9606 §3 example.
        text_round_trip(
            Rtype::RESINFO,
            "qnamemin exterr=15,16,17 infourl=https://resolver.example.com/guide",
            b"\x08qnamemin\x0fexterr=15,16,17\x2ainfourl=https://resolver.example.com/guide",
            "\"qnamemin\" \"exterr=15,16,17\" \"infourl=https://resolver.example.com/guide\"",
        );
        text_round_trip(Rtype::WALLET, "\"\" \\065", b"\x00\x01A", "\"\" \"A\"");
        for t in [
            Rtype::SPF,
            Rtype::NINFO,
            Rtype::AVC,
            Rtype::RESINFO,
            Rtype::WALLET,
        ] {
            assert_eq!(text_error(t, ""), Error::UnexpectedEof, "{t}");
            assert_eq!(text_error(t, "\\256"), Error::InvalidText, "{t}");
            assert_eq!(text_error(t, "\"a"), Error::InvalidText, "{t}");
            let long = "x".repeat(256);
            assert_eq!(text_error(t, &long), Error::CharStringTooLong, "{t}");
        }
    }
}
