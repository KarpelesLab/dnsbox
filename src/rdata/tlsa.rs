//! TLSA (RFC 6698 §2) and SMIMEA (RFC 8162 §2) record data, which share
//! one wire format, and the DANE certificate-association registries
//! (RFC 6698 §7.2–7.4, RFC 7218).

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::wire::{Composer, WireReader};
use crate::{Result, Rtype};

open_enum! {
    /// A DANE certificate usage (RFC 6698 §2.1.1, IANA "TLSA Certificate
    /// Usages"; acronyms from RFC 7218 §2.1).
    ///
    /// The presentation format of TLSA and SMIMEA uses the bare number.
    pub struct TlsaCertUsage(u8), generic "";
    /// CA constraint (RFC 6698 §2.1.1, RFC 7218).
    PKIX_TA = 0 => "PKIX-TA",
    /// Service certificate constraint (RFC 6698 §2.1.1, RFC 7218).
    PKIX_EE = 1 => "PKIX-EE",
    /// Trust anchor assertion (RFC 6698 §2.1.1, RFC 7218).
    DANE_TA = 2 => "DANE-TA",
    /// Domain-issued certificate (RFC 6698 §2.1.1, RFC 7218).
    DANE_EE = 3 => "DANE-EE",
    /// Reserved for private use (RFC 6698 §7.2, RFC 7218).
    PRIV_CERT = 255 => "PrivCert",
}

open_enum! {
    /// A DANE selector: which part of the certificate is matched
    /// (RFC 6698 §2.1.2, IANA "TLSA Selectors"; acronyms from RFC 7218 §2.2).
    ///
    /// The presentation format of TLSA and SMIMEA uses the bare number.
    pub struct TlsaSelector(u8), generic "";
    /// Full certificate (RFC 6698 §2.1.2, RFC 7218).
    CERT = 0 => "Cert",
    /// SubjectPublicKeyInfo (RFC 6698 §2.1.2, RFC 7218).
    SPKI = 1 => "SPKI",
    /// Reserved for private use (RFC 6698 §7.3, RFC 7218).
    PRIV_SEL = 255 => "PrivSel",
}

open_enum! {
    /// A DANE matching type: how the association data is compared
    /// (RFC 6698 §2.1.3, IANA "TLSA Matching Types"; acronyms from
    /// RFC 7218 §2.3).
    ///
    /// The presentation format of TLSA and SMIMEA uses the bare number.
    pub struct TlsaMatchingType(u8), generic "";
    /// Exact match on the selected content (RFC 6698 §2.1.3, RFC 7218).
    FULL = 0 => "Full",
    /// SHA-256 hash of the selected content (RFC 6698 §2.1.3, RFC 7218).
    SHA2_256 = 1 => "SHA2-256",
    /// SHA-512 hash of the selected content (RFC 6698 §2.1.3, RFC 7218).
    SHA2_512 = 2 => "SHA2-512",
    /// Reserved for private use (RFC 6698 §7.4, RFC 7218).
    PRIV_MATCH = 255 => "PrivMatch",
}

/// Defines a DANE certificate-association record-data view (TLSA layout,
/// RFC 6698 §2.1).
macro_rules! dane_rdata {
    ($(#[$doc:meta])* $ty:ident, $rt:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $ty<'a> {
            /// How the association is used (RFC 6698 §2.1.1).
            pub usage: TlsaCertUsage,
            /// Which part of the certificate is matched (RFC 6698 §2.1.2).
            pub selector: TlsaSelector,
            /// How the association data is presented (RFC 6698 §2.1.3).
            pub matching_type: TlsaMatchingType,
            /// The certificate association data: the rest of the RDATA
            /// (RFC 6698 §2.1.4).
            pub data: &'a [u8],
        }

        impl<'a> $ty<'a> {
            /// Builds the record data from its fields (RFC 6698 §2.1).
            #[inline]
            pub const fn new(
                usage: TlsaCertUsage,
                selector: TlsaSelector,
                matching_type: TlsaMatchingType,
                data: &'a [u8],
            ) -> Self {
                $ty {
                    usage,
                    selector,
                    matching_type,
                    data,
                }
            }
        }

        impl super::ParseRdataText for $ty<'_> {}

        impl<'a> ParseRdata<'a> for $ty<'a> {
            const RTYPE: Rtype = Rtype::$rt;

            fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
                Ok($ty {
                    usage: TlsaCertUsage::new(rdata.read_u8()?),
                    selector: TlsaSelector::new(rdata.read_u8()?),
                    matching_type: TlsaMatchingType::new(rdata.read_u8()?),
                    data: rdata.read_rest(),
                })
            }
        }

        impl ComposeRdata for $ty<'_> {
            fn rtype(&self) -> Rtype {
                Rtype::$rt
            }

            fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
                c.put_bytes(&[
                    self.usage.get(),
                    self.selector.get(),
                    self.matching_type.get(),
                ])?;
                c.put_bytes(self.data)
            }
        }

        impl fmt::Display for $ty<'_> {
            /// `usage selector matching-type data-hex` (RFC 6698 §2.2). An
            /// empty association has no such form and is written in the
            /// generic RFC 3597 §5 form instead.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let head = [
                    self.usage.get(),
                    self.selector.get(),
                    self.matching_type.get(),
                ];
                if self.data.is_empty() {
                    return crate::text::fmt_generic_rdata(f, &head);
                }
                write!(
                    f,
                    "{} {} {} {}",
                    head[0],
                    head[1],
                    head[2],
                    crate::text::Hex(self.data)
                )
            }
        }
    };
}

dane_rdata! {
    /// `TLSA` record data: a TLS certificate association for DANE
    /// (RFC 6698 §2.1).
    Tlsa, TLSA
}

dane_rdata! {
    /// `SMIMEA` record data: an S/MIME certificate association, in the
    /// TLSA format (RFC 8162 §2).
    Smimea, SMIMEA
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdata::tests::{compose, parse, round_trip};
    use crate::testutil::hex;
    use crate::{Class, Error, RData};
    use std::string::ToString;
    use std::vec::Vec;

    fn wire(head: [u8; 3], data: &str) -> Vec<u8> {
        let mut v = head.to_vec();
        v.extend(hex(data));
        v
    }

    #[test]
    fn rfc6698_examples() {
        // RFC 6698 §2.3: a hashed CA certificate.
        //   _443._tcp.www.example.com. IN TLSA (
        //      0 0 1 d2abde240d7cd3ee6b4b28c54df034b9
        //            7983a1d16e8a410e4561cb106618e971 )
        let w = wire(
            [0, 0, 1],
            "d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971",
        );
        round_trip(
            Rtype::TLSA,
            &w,
            "0 0 1 D2ABDE240D7CD3EE6B4B28C54DF034B97983A1D16E8A410E4561CB106618E971",
        );
        let Ok(RData::Tlsa(t)) = parse(Rtype::TLSA, Class::IN, &w) else {
            panic!("not TLSA")
        };
        assert_eq!(
            (t.usage, t.selector, t.matching_type),
            (
                TlsaCertUsage::PKIX_TA,
                TlsaSelector::CERT,
                TlsaMatchingType::SHA2_256
            )
        );
        assert_eq!(t.data.len(), 32);

        // RFC 6698 §2.3: a hashed subject public key.
        //   _443._tcp.www.example.com. IN TLSA (
        //      1 1 2 92003ba34942dc74152e2f2c408d29ec
        //            a5a520e7f2e06bb944f4dca346baf63c
        //            1b177615d466f6c4b71c216a50292bd5
        //            8c9ebdd2f74e38fe51ffd48c43326cbc )
        let data = "92003ba34942dc74152e2f2c408d29eca5a520e7f2e06bb944f4dca346baf63c\
                    1b177615d466f6c4b71c216a50292bd58c9ebdd2f74e38fe51ffd48c43326cbc";
        let w = wire([1, 1, 2], data);
        round_trip(
            Rtype::TLSA,
            &w,
            &std::format!("1 1 2 {}", data.to_ascii_uppercase()),
        );
    }

    #[test]
    fn smimea() {
        // RFC 8162 §2 uses the TLSA layout: DANE-EE, SPKI, SHA2-256.
        let data = "d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971";
        let w = wire([3, 1, 1], data);
        round_trip(
            Rtype::SMIMEA,
            &w,
            &std::format!("3 1 1 {}", data.to_ascii_uppercase()),
        );
        let Ok(RData::Smimea(s)) = parse(Rtype::SMIMEA, Class::IN, &w) else {
            panic!("not SMIMEA")
        };
        assert_eq!(s.usage, TlsaCertUsage::DANE_EE);
        assert_eq!(s.rtype(), Rtype::SMIMEA);
        let rebuilt = Smimea::new(
            TlsaCertUsage::DANE_EE,
            TlsaSelector::SPKI,
            TlsaMatchingType::SHA2_256,
            s.data,
        );
        assert_eq!(compose(&rebuilt), w);
    }

    #[test]
    fn registries_and_edge_cases() {
        assert_eq!(TlsaCertUsage::DANE_TA.to_string(), "DANE-TA");
        assert_eq!("pkix-ee".parse(), Ok(TlsaCertUsage::PKIX_EE));
        assert_eq!("SPKI".parse(), Ok(TlsaSelector::SPKI));
        assert_eq!("SHA2-512".parse(), Ok(TlsaMatchingType::SHA2_512));
        assert_eq!("255".parse(), Ok(TlsaMatchingType::PRIV_MATCH));
        assert_eq!(TlsaSelector::new(7).to_string(), "7");
        // Unassigned values round-trip as numbers.
        round_trip(Rtype::TLSA, b"\x04\x02\x03\x01", "4 2 3 01");
        // Empty association data: generic form.
        round_trip(Rtype::TLSA, b"\x03\x01\x01", "\\# 3 030101");
        round_trip(Rtype::SMIMEA, b"\x03\x01\x01", "\\# 3 030101");
        assert_eq!(
            parse(Rtype::TLSA, Class::IN, b"\x03\x01"),
            Err(Error::UnexpectedEof)
        );
    }
}
