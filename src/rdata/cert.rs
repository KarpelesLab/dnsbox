//! CERT record data (RFC 4398 §2) and the certificate-type registry.

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::dnssec::Algorithm;
use crate::wire::{Composer, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Error, Result, Rtype};

open_enum! {
    /// A CERT certificate type (RFC 4398 §2.1, IANA "Certificate Types").
    ///
    /// Presentation format uses the mnemonic when there is one and the
    /// bare number otherwise (RFC 4398 §2.2).
    pub struct CertType(u16), generic "";
    /// X.509 as per PKIX (RFC 4398 §2.1).
    PKIX = 1 => "PKIX",
    /// SPKI certificate (RFC 4398 §2.1).
    SPKI = 2 => "SPKI",
    /// OpenPGP packet (RFC 4398 §2.1).
    PGP = 3 => "PGP",
    /// The URL of an X.509 data object (RFC 4398 §2.1).
    IPKIX = 4 => "IPKIX",
    /// The URL of an SPKI certificate (RFC 4398 §2.1).
    ISPKI = 5 => "ISPKI",
    /// The fingerprint and URL of an OpenPGP packet (RFC 4398 §2.1).
    IPGP = 6 => "IPGP",
    /// Attribute Certificate (RFC 4398 §2.1).
    ACPKIX = 7 => "ACPKIX",
    /// The URL of an Attribute Certificate (RFC 4398 §2.1).
    IACPKIX = 8 => "IACPKIX",
    /// URI private (RFC 4398 §2.1).
    URI = 253 => "URI",
    /// OID private (RFC 4398 §2.1).
    OID = 254 => "OID",
}

/// `CERT` record data: a certificate or certificate revocation list
/// (RFC 4398 §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Cert<'a> {
    /// The certificate type (RFC 4398 §2.1).
    pub cert_type: CertType,
    /// Key tag of the key the certificate is for, computed as for DNSKEY
    /// (RFC 4398 §2, RFC 4034 Appendix B); zero if not applicable.
    pub key_tag: u16,
    /// DNSSEC algorithm of the key (RFC 4398 §2, IANA "Domain Name
    /// System Security (DNSSEC) Algorithm Numbers"); zero if unknown.
    pub algorithm: Algorithm,
    /// The certificate or CRL: the rest of the RDATA (RFC 4398 §2).
    pub certificate: &'a [u8],
}

impl<'a> Cert<'a> {
    /// Builds CERT data from its fields (RFC 4398 §2).
    #[inline]
    #[must_use]
    pub const fn new(
        cert_type: CertType,
        key_tag: u16,
        algorithm: Algorithm,
        certificate: &'a [u8],
    ) -> Self {
        Cert {
            cert_type,
            key_tag,
            algorithm,
            certificate,
        }
    }
}

impl ParseRdataText for Cert<'_> {
    /// `<type> <key-tag> <algorithm> <certificate>` (RFC 4398 §2.2): the
    /// type as a mnemonic (`PKIX`, `PGP`, ...) or a decimal number, the key
    /// tag as a decimal number, the algorithm as a DNSSEC algorithm
    /// mnemonic (`RSASHA256`, ...) or a decimal number, and the
    /// certificate in base64, which may be split across blanks and lines.
    /// At least one octet is required (an empty certificate has only the
    /// generic form, as in BIND).
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        out.put_u16(s.parse::<CertType>()?.get())?;
        out.put_u16(s.u16()?)?;
        out.put_u8(s.parse::<Algorithm>()?.get())?;
        if s.base64_rest_into(out)? == 0 {
            return Err(Error::UnexpectedEof);
        }
        Ok(())
    }
}

impl<'a> ParseRdata<'a> for Cert<'a> {
    const RTYPE: Rtype = Rtype::CERT;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        Ok(Cert {
            cert_type: CertType::new(rdata.read_u16()?),
            key_tag: rdata.read_u16()?,
            algorithm: Algorithm::new(rdata.read_u8()?),
            certificate: rdata.read_rest(),
        })
    }
}

impl ComposeRdata for Cert<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::CERT
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_u16(self.cert_type.get())?;
        c.put_u16(self.key_tag)?;
        c.put_u8(self.algorithm.get())?;
        c.put_bytes(self.certificate)
    }
}

impl fmt::Display for Cert<'_> {
    /// `type key-tag algorithm certificate-base64` (RFC 4398 §2.2), with
    /// the type as a mnemonic when registered and the algorithm as a
    /// number. An empty certificate has no such form and is written in the
    /// generic RFC 3597 §5 form instead.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.certificate.is_empty() {
            let [t0, t1] = self.cert_type.get().to_be_bytes();
            let [k0, k1] = self.key_tag.to_be_bytes();
            return crate::text::fmt_generic_rdata(f, &[t0, t1, k0, k1, self.algorithm.get()]);
        }
        write!(
            f,
            "{} {} {} {}",
            self.cert_type,
            self.key_tag,
            self.algorithm.get(),
            crate::text::Base64(self.certificate)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdata::tests::{compose, parse, round_trip, text_error, text_round_trip};
    use crate::{Class, RData};
    use std::string::ToString;

    #[test]
    fn rfc4398_types() {
        // A PGP certificate (RFC 4398 §2.1 type 3) with no key tag or
        // algorithm: "PGP 0 0 <base64>" (RFC 4398 §2.2).
        let wire = b"\x00\x03\x00\x00\x00\x98\x33\x04\x57\xf7\xe7\xbc\x16";
        round_trip(Rtype::CERT, wire, "PGP 0 0 mDMEV/fnvBY=");
        let Ok(RData::Cert(c)) = parse(Rtype::CERT, Class::IN, wire) else {
            panic!("not CERT")
        };
        assert_eq!(c.cert_type, CertType::PGP);
        assert_eq!(c, Cert::new(CertType::PGP, 0, Algorithm::new(0), &wire[5..]));
        // An IPKIX URL with key tag 12345 and algorithm 8 (RSASHA256).
        let c = Cert::new(CertType::IPKIX, 12345, Algorithm::RSASHA256, b"https://example.com/c.der");
        let wire = compose(&c);
        assert_eq!(&wire[..5], b"\x00\x04\x30\x39\x08");
        round_trip(
            Rtype::CERT,
            &wire,
            "IPKIX 12345 8 aHR0cHM6Ly9leGFtcGxlLmNvbS9jLmRlcg==",
        );
        // Private and unassigned types: mnemonic or bare number.
        round_trip(Rtype::CERT, b"\x00\xfd\x00\x00\x00\x01", "URI 0 0 AQ==");
        round_trip(Rtype::CERT, b"\xff\x00\x00\x01\x02\x01", "65280 1 2 AQ==");
    }

    #[test]
    fn registry_and_edge_cases() {
        assert_eq!("iacpkix".parse(), Ok(CertType::IACPKIX));
        assert_eq!("6".parse(), Ok(CertType::IPGP));
        assert_eq!(CertType::OID.to_string(), "OID");
        assert_eq!(CertType::all().count(), 10);
        // Empty certificate: generic form.
        round_trip(Rtype::CERT, b"\x00\x01\x00\x02\x03", "\\# 5 0001000203");
        assert_eq!(
            parse(Rtype::CERT, Class::IN, b"\x00\x01\x00\x02"),
            Err(Error::UnexpectedEof)
        );
    }

    /// Decodes base64 test data.
    fn b64(text: &str) -> std::vec::Vec<u8> {
        let mut buf = std::vec![0u8; text.len()];
        let n = crate::util::base64::decode(text.as_bytes(), &mut buf).unwrap();
        buf.truncate(n);
        buf
    }

    #[test]
    fn text() {
        // RFC 4398 §2.2: mnemonics or numbers for the type and the
        // algorithm. A record from BIND's system-test zones: numeric type,
        // private algorithm, base64 split across lines.
        let cert = "MxFcby9k/yvedMfQgKzhH5er0Mu/vILz45IkskceFGgiWCn/GxHhai6V\
                    AuHAoNUz4YoU1tVfSCSqQYn6//11U6Nld80jEeC8aTrO+KKmCaY=";
        let mut wire = b"\xff\xfe\xff\xff\xfe".to_vec();
        wire.extend(b64(cert));
        text_round_trip(
            Rtype::CERT,
            "65534 65535 PRIVATEOID ( MxFcby9k/yvedMfQgKzhH5er0Mu/vILz45IkskceFGgiWCn/GxHhai6V\n \
             AuHAoNUz4YoU1tVfSCSqQYn6//11U6Nld80jEeC8aTrO+KKmCaY= )",
            &wire,
            &std::format!("65534 65535 254 {cert}"),
        );
        // Mnemonic type (RFC 4398 §2.1), any case, mnemonic algorithm
        // (RFC 4034 Appendix A.1).
        text_round_trip(
            Rtype::CERT,
            "pgp 0 0 mDMEV/fnvBY=",
            b"\x00\x03\x00\x00\x00\x98\x33\x04\x57\xf7\xe7\xbc\x16",
            "PGP 0 0 mDMEV/fnvBY=",
        );
        text_round_trip(
            Rtype::CERT,
            "IPKIX 12345 RSASHA256 aHR0cHM6Ly9leGFtcGxl LmNvbS9jLmRlcg==",
            b"\x00\x04\x30\x39\x08https://example.com/c.der",
            "IPKIX 12345 8 aHR0cHM6Ly9leGFtcGxlLmNvbS9jLmRlcg==",
        );
        text_round_trip(Rtype::CERT, "1 2 3 AQ==", b"\x00\x01\x00\x02\x03\x01", "PKIX 2 3 AQ==");
        text_round_trip(
            Rtype::CERT,
            "URI 0 DELETE AQ==",
            b"\x00\xfd\x00\x00\x00\x01",
            "URI 0 0 AQ==",
        );
    }

    #[test]
    fn text_malformed() {
        for (text, err) in [
            ("", Error::UnexpectedEof),
            ("PGP 0", Error::UnexpectedEof),
            // An empty certificate: only the generic form expresses it.
            ("PGP 0 0", Error::UnexpectedEof),
            // Both registries have bare-number generic forms, so an unknown
            // mnemonic is malformed text.
            ("X509 0 0 AQ==", Error::InvalidText),
            ("65536 0 0 AQ==", Error::InvalidText),
            ("PGP 65536 0 AQ==", Error::InvalidText),
            ("PGP 0 NOSUCHALG AQ==", Error::InvalidText),
            ("PGP 0 256 AQ==", Error::InvalidText),
            ("PGP 0 0 AQ=", Error::InvalidText),
            ("PGP 0 0 A?==", Error::InvalidText),
            ("\"PGP\" 0 0 AQ==", Error::InvalidText),
        ] {
            assert_eq!(text_error(Rtype::CERT, text), err, "{text:?}");
        }
    }
}
