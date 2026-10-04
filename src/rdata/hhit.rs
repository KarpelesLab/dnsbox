//! HHIT and BRID record data (RFC 9886 §5): DRIP (Drone Remote ID
//! Protocol) entity metadata.
//!
//! Both carry one CBOR (RFC 8949) object, presented as a single logical
//! base64 string (§5.1.1, §5.2.1). The CBOR object is not interpreted.

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::text::Base64;
use crate::wire::{Composer, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Error, Result, Rtype};

/// Defines a record type holding one non-empty CBOR object presented in
/// base64.
macro_rules! cbor_rdata {
    ($(#[$doc:meta])* $ty:ident, $rt:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $ty<'a> {
            /// The CBOR-encoded object: the whole RDATA (at least one
            /// octet).
            pub data: &'a [u8],
        }

        impl<'a> $ty<'a> {
            /// Wraps a CBOR-encoded object.
            #[inline]
            #[must_use]
            pub const fn new(data: &'a [u8]) -> Self {
                $ty { data }
            }
        }

        impl ParseRdataText for $ty<'_> {
            /// The object in base64, which may be split across blanks and
            /// lines (RFC 9886 §5.1.1, §5.2.1). At least one octet is
            /// required, as in BIND.
            fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
                if s.base64_rest_into(out)? == 0 {
                    return Err(Error::UnexpectedEof);
                }
                Ok(())
            }
        }

        impl<'a> ParseRdata<'a> for $ty<'a> {
            const RTYPE: Rtype = Rtype::$rt;

            fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
                // The object is mandatory (BIND rejects empty RDATA).
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

            /// # Errors
            ///
            /// [`Error::InvalidRdata`] for an empty object, and
            /// [`Error::BufferTooSmall`] if `c` is full.
            fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
                if self.data.is_empty() {
                    return Err(Error::InvalidRdata);
                }
                c.put_bytes(self.data)
            }
        }

        impl fmt::Display for $ty<'_> {
            /// The object in base64 (RFC 9886 §5.1.1, §5.2.1).
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&Base64(self.data), f)
            }
        }
    };
}

cbor_rdata! {
    /// `HHIT` record data: metadata of a Hierarchical Host Identity Tag
    /// (RFC 9886 §5.1), a CBOR array of the HHIT entity type, the HID
    /// abbreviation and the canonical registration certificate (X.509
    /// DER).
    ///
    /// ```
    /// use dnsbox::rdata::{Hhit, ParseRdataText};
    ///
    /// let mut buf = [0u8; 16];
    /// let hhit = Hhit::from_text("( gwpp\n Mw== )", &mut buf)?;
    /// // CBOR: array(3), 10, text(9) "3"...
    /// assert_eq!(hhit.data, [0x83, 0x0a, 0x69, 0x33]);
    /// assert_eq!(hhit.to_string(), "gwppMw==");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    Hhit, HHIT
}

cbor_rdata! {
    /// `BRID` record data: static UAS Broadcast Remote ID information
    /// (RFC 9886 §5.2), a CBOR map whose `auth` field holds Broadcast
    /// Endorsements (RFC 9575).
    ///
    /// ```
    /// use dnsbox::rdata::{Brid, ParseRdataText};
    ///
    /// let mut buf = [0u8; 16];
    /// let brid = Brid::from_text("owAA", &mut buf)?;
    /// // CBOR: map(3), 0: 0, ...
    /// assert_eq!(brid.data, [0xa3, 0x00, 0x00]);
    /// assert_eq!(brid, Brid::new(&[0xa3, 0, 0]));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    Brid, BRID
}

#[cfg(test)]
mod tests {
    use super::{Brid, Hhit};
    use crate::rdata::tests::{compose, parse, text_error, text_round_trip};
    use crate::rdata::{ComposeRdata, RData};
    use crate::{Class, Error, Rtype, WireWriter};
    use std::string::{String, ToString};
    use std::vec::Vec;

    /// RFC 9886 Appendix A.1.1, Figure 9: the RAA authentication HHIT.
    const RAA_HHIT: &str = "gwppM2ZmOCAwMDAwWQFGMIIBQjCB9aAD
        AgECAgE1MAUGAytlcDArMSkwJwYDVQQD
        DCAyMDAxMDAzZmZlMDAwMDA1NWU2MGEx
        NTcxZTkxYTBiNzAeFw0yNTA0MDkyMDU2
        MjZaFw0yNTA0MDkyMTU2MjZaMB0xGzAZ
        BgNVBAMMEkRSSVAtUkFBLUEtMTYzNzYt
        MDAqMAUGAytlcAMhAJmQ1bBLcqGAZtQJ
        K1LH1JlPt8Fr1+jB9ED/qNBP8eE/o0ww
        SjAPBgNVHRMBAf8EBTADAQH/MDcGA1Ud
        EQEB/wQtMCuHECABAD/+AAAFXmChVx6R
        oLeGF2h0dHBzOi8vcmFhLmV4YW1wbGUu
        Y29tMAUGAytlcANBALUPjhIB3rwqXQep
        r9/VDB+hhtwuWZIw1OUkEuDrF6DCkgc7
        5widXnXa5/uDfdKL7dZ83mPHm2Tf32Dv
        b8AzEw8=";

    /// RFC 9886 Appendix A.2.2, Figure 18: the registrant BRID.
    const REGISTRANT_BRID: &str = "owAAAYIEUQEgAQA//gAKBRMIJGmaS8ay
        AogFWIkB+t72Zwrt9mcgAQA//gAABV5g
        oVcekaC3mZDVsEtyoYBm1AkrUsfUmU+3
        wWvX6MH0QP+o0E/x4T8gAQA//gAABV5g
        oVcekaC3vC9m1JguvXt7W2o4wxPumaT1
        IP3TQN3fQP28hpInSIlsSwq8UCNjm2ad
        7pdTvm2EqfOJQNPKClvRZm4qTO5FDAVY
        iQGX4PZnp+72ZyABAD/+AAoFZhXuRdQn
        CaDOaB424RQa61YNbna8eWt7fLRU5GPM
        sfEt4wo4AQGAPyABAD/+AAAFXmChVx6R
        oLfv3q+mLRB3ya5TmjY8+3CzdoDZT9RZ
        +XpN5hDiA6JyyxBJvUewxLzPNhTXQp8v
        ED71XAE82tMmt3fB4zbzWNQLBViJAQrh
        9mca7/ZnIAEAP/4ACgUmDtQ3ayVuKIIz
        /a61BovBSFnRE6Dt/PjcB4FOPdJ2Xmtb
        guBNBwWXIAEAP/4ACgVmFe5F1CcJoIjy
        CriJCxAyAWTOHPmlHL02MKSpsHviiTze
        qwBH9K/Rrz41CYix9HazAIOAZO8FcfU5
        M+WLLJZoaQWBHnMbTQwFWIkB3OL2Z+zw
        9mcgAQA//gAKBRMIJGmaS8ayyS4vnZfo
        lg+bXxZU+LCQOfna3FvPBh6sTwzqeejo
        d/ogAQA//gAKBSYO1DdrJW4ogOfc8jTi
        mYLmTOOyFZoUx2jOOwtB1jnqUJr6bYaw
        MoPrR3MlKGBGWsVz1yXNqUURoCqYdwsY
        e61vd5i6YJqnAQ==";

    fn decode(b64: &str) -> (String, Vec<u8>) {
        let joined: String = b64.split_whitespace().collect();
        let mut out = std::vec![0u8; joined.len()];
        let n = crate::util::base64::decode(joined.as_bytes(), &mut out).unwrap();
        out.truncate(n);
        (joined, out)
    }

    #[test]
    fn rfc9886_examples() {
        // Written as in the RFC: split over lines inside parentheses.
        let (joined, wire) = decode(RAA_HHIT);
        // CBOR array(3): entity type 10, "3ff8 0000", a 326-octet DER
        // certificate (Figure 10).
        assert_eq!(&wire[..4], [0x83, 0x0a, 0x69, b'3']);
        assert_eq!(&wire[3..12], b"3ff8 0000");
        text_round_trip(Rtype::HHIT, &std::format!("( {RAA_HHIT} )"), &wire, &joined);
        let RData::Hhit(h) = parse(Rtype::HHIT, Class::IN, &wire).unwrap() else {
            panic!("not HHIT")
        };
        assert_eq!(h, Hhit::new(&wire));
        assert_eq!(compose(&h), wire);

        let (joined, wire) = decode(REGISTRANT_BRID);
        // CBOR map(3) (Figure 21).
        assert_eq!(wire[0], 0xa3);
        text_round_trip(Rtype::BRID, &std::format!("( {REGISTRANT_BRID} )"), &wire, &joined);
        assert_eq!(
            parse(Rtype::BRID, Class::IN, &wire),
            Ok(RData::Brid(Brid::new(&wire)))
        );
    }

    #[test]
    fn bind_vectors() {
        // BIND's text tests (lib/dns/tests/rdata_test.c).
        for rtype in [Rtype::HHIT, Rtype::BRID] {
            text_round_trip(rtype, "AA==", b"\x00", "AA==");
            text_round_trip(rtype, "aaaa", b"\x69\xa6\x9a", "aaaa");
            for (text, err) in [
                ("", Error::UnexpectedEof),
                ("\\# 0", Error::UnexpectedEof),
                ("aaaaa", Error::InvalidText),
                ("\"aaaa\"", Error::InvalidText),
            ] {
                assert_eq!(text_error(rtype, text), err, "{rtype} {text:?}");
            }
            assert_eq!(parse(rtype, Class::IN, b""), Err(Error::UnexpectedEof));
        }
        // Empty objects cannot be composed either.
        let mut buf = [0u8; 4];
        let mut w = WireWriter::new(&mut buf);
        assert_eq!(Hhit::new(b"").compose_rdata(&mut w), Err(Error::InvalidRdata));
        assert_eq!(Brid::new(b"").compose_rdata(&mut w), Err(Error::InvalidRdata));
        assert_eq!(Brid::new(b"\x01").to_string(), "AQ==");
    }
}
