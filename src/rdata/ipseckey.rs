//! IPSECKEY record data (RFC 4025 §2) and the IPSECKEY public-key
//! algorithm registry it shares with HIP (RFC 8005 §5).

use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr};

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::name::Name;
use crate::text::Base64;
use crate::wire::{Composer, NameEncoding, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Error, Result, Rtype};

// IANA "IPSECKEY Resource Record Parameters", Algorithm Type Field
// (https://www.iana.org/assignments/ipseckey-rr-parameters), as of
// 2026-10. The registry has no official mnemonics; the ones below are
// descriptive only, and presentation formats use the number.
open_enum! {
    /// An IPSECKEY public-key algorithm type (RFC 4025 §2.4, IANA
    /// "IPSECKEY Resource Record Parameters"), also used for the HIP
    /// PK algorithm field (RFC 8005 §5).
    ///
    /// ```
    /// use dnsbox::rdata::IpseckeyAlgorithm;
    ///
    /// assert_eq!(IpseckeyAlgorithm::RSA.get(), 2);
    /// assert_eq!(IpseckeyAlgorithm::EDDSA.to_string(), "EDDSA");
    /// ```
    pub struct IpseckeyAlgorithm(u8) in dnsbox::rdata, generic "";
    /// No public key is present (RFC 4025).
    NONE = 0 => "NONE",
    /// A DSA public key (RFC 2536 §2, RFC 4025).
    DSA = 1 => "DSA",
    /// An RSA public key (RFC 3110 §2, RFC 4025).
    RSA = 2 => "RSA",
    /// An ECDSA public key (RFC 6605 §4, RFC 8005).
    ECDSA = 3 => "ECDSA",
    /// An EdDSA public key (RFC 8080 §3, RFC 9373).
    EDDSA = 4 => "EDDSA",
}

/// The gateway of an IPSECKEY record (RFC 4025 §2.3, §2.5): its variant
/// determines the gateway type field (0–3). Other gateway types have no
/// defined layout and are rejected with [`Error::InvalidRdata`]; the enum
/// is `#[non_exhaustive]` so that gateway types IANA registers later can be
/// added.
///
/// ```
/// use dnsbox::NameBuf;
/// use dnsbox::rdata::IpseckeyGateway;
///
/// let name: NameBuf = "gw.example.com".parse()?;
/// let gateway = IpseckeyGateway::Name(name.as_name());
/// assert_eq!(gateway.gateway_type(), 3);
/// assert_eq!(gateway.to_string(), "gw.example.com.");
/// assert_eq!(IpseckeyGateway::None.to_string(), ".");
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IpseckeyGateway<'a> {
    /// Gateway type 0: no gateway (`.` in presentation format).
    None,
    /// Gateway type 1: an IPv4 address.
    Ipv4(Ipv4Addr),
    /// Gateway type 2: an IPv6 address.
    Ipv6(Ipv6Addr),
    /// Gateway type 3: an uncompressed domain name.
    Name(Name<'a>),
}

impl IpseckeyGateway<'_> {
    /// The gateway type field value (RFC 4025 §2.3).
    #[must_use]
    pub const fn gateway_type(&self) -> u8 {
        match self {
            IpseckeyGateway::None => 0,
            IpseckeyGateway::Ipv4(_) => 1,
            IpseckeyGateway::Ipv6(_) => 2,
            IpseckeyGateway::Name(_) => 3,
        }
    }
}

impl fmt::Display for IpseckeyGateway<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpseckeyGateway::None => f.write_str("."),
            IpseckeyGateway::Ipv4(a) => fmt::Display::fmt(a, f),
            IpseckeyGateway::Ipv6(a) => fmt::Display::fmt(a, f),
            IpseckeyGateway::Name(n) => fmt::Display::fmt(n, f),
        }
    }
}

/// `IPSECKEY` record data: IPsec keying material (RFC 4025 §2).
///
/// ```
/// use dnsbox::rdata::{IpseckeyAlgorithm, IpseckeyGateway, Ipseckey, ParseRdataText};
///
/// let mut buf = [0u8; 64];
/// let key = Ipseckey::from_text("10 1 2 192.0.2.38 AQNRU3mG", &mut buf)?;
/// assert_eq!(key.algorithm, IpseckeyAlgorithm::RSA);
/// assert_eq!(key.gateway, IpseckeyGateway::Ipv4([192, 0, 2, 38].into()));
/// assert_eq!(key.gateway.gateway_type(), 1);
/// assert_eq!(key.to_string(), "10 1 2 192.0.2.38 AQNRU3mG");
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ipseckey<'a> {
    /// Precedence among the owner's IPSECKEY records; lower is preferred.
    pub precedence: u8,
    /// The public-key algorithm.
    pub algorithm: IpseckeyAlgorithm,
    /// The gateway.
    pub gateway: IpseckeyGateway<'a>,
    /// The public key in the algorithm's DNS format (empty when there is
    /// none).
    pub public_key: &'a [u8],
}

impl ParseRdataText for Ipseckey<'_> {
    /// `precedence gateway-type algorithm gateway [base64-key]`
    /// (RFC 4025 §3.1): decimal fields; the gateway is `.` for type 0, an
    /// IPv4 address for type 1, an IPv6 address for type 2 and a domain
    /// name for type 3 (other types are [`Error::InvalidRdata`]); the key
    /// may be split by blanks and may be absent.
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        let precedence = s.u8()?;
        let gateway_type = s.u8()?;
        let algorithm = s.u8()?;
        out.put_bytes(&[precedence, gateway_type, algorithm])?;
        match gateway_type {
            // "a single period" (RFC 4025 §3.1).
            0 => {
                if !s.word()?.is(".") {
                    return Err(Error::InvalidText);
                }
            }
            1 => out.put_bytes(&s.ipv4()?.octets())?,
            2 => out.put_bytes(&s.ipv6()?.octets())?,
            3 => s.name_into(out, NameEncoding::Plain)?,
            _ => return Err(Error::InvalidRdata),
        }
        s.base64_rest_into(out).map(drop)
    }
}

impl<'a> ParseRdata<'a> for Ipseckey<'a> {
    const RTYPE: Rtype = Rtype::IPSECKEY;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        let mut r = *rdata;
        let [precedence, gateway_type, algorithm] = r.read_array()?;
        let gateway = match gateway_type {
            0 => IpseckeyGateway::None,
            1 => IpseckeyGateway::Ipv4(Ipv4Addr::from(r.read_array::<4>()?)),
            2 => IpseckeyGateway::Ipv6(Ipv6Addr::from(r.read_array::<16>()?)),
            // "MUST NOT be compressed" (RFC 4025 §2.5).
            3 => IpseckeyGateway::Name(r.read_name_uncompressed()?),
            _ => return Err(Error::InvalidRdata),
        };
        let key = Ipseckey {
            precedence,
            algorithm: IpseckeyAlgorithm::new(algorithm),
            gateway,
            public_key: r.read_rest(),
        };
        *rdata = r;
        Ok(key)
    }
}

impl ComposeRdata for Ipseckey<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::IPSECKEY
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_bytes(&[
            self.precedence,
            self.gateway.gateway_type(),
            self.algorithm.get(),
        ])?;
        match self.gateway {
            IpseckeyGateway::None => {}
            IpseckeyGateway::Ipv4(a) => c.put_bytes(&a.octets())?,
            IpseckeyGateway::Ipv6(a) => c.put_bytes(&a.octets())?,
            // Not in the RFC 4034 §6.2 lowercasing list.
            IpseckeyGateway::Name(n) => c.put_name(n, NameEncoding::Plain)?,
        }
        c.put_bytes(self.public_key)
    }
}

impl fmt::Display for Ipseckey<'_> {
    /// `precedence gateway-type algorithm gateway [base64-key]`
    /// (RFC 4025 §3.1).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.precedence,
            self.gateway.gateway_type(),
            self.algorithm.get(),
            self.gateway
        )?;
        if !self.public_key.is_empty() {
            write!(f, " {}", Base64(self.public_key))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Ipseckey, IpseckeyAlgorithm, IpseckeyGateway};
    use crate::rdata::tests::{parse, round_trip, text_error, text_round_trip};
    use crate::rdata::RData;
    use crate::{Class, Error, Rtype};
    use std::string::ToString;

    const KEY: &str = "0103 51537986ED35533B6064478EEEB27B5BD74DAE149B6E81BA3A0521AF82AB7801";

    #[test]
    fn rfc4025_examples() {
        // RFC 4025 §3.3 examples (wire cross-checked with named-rrchecker).
        let key = crate::testutil::hex(KEY);
        let b64 = "AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==";
        let mut wire = crate::testutil::hex("0A0102C0000226");
        wire.extend_from_slice(&key);
        round_trip(Rtype::IPSECKEY, &wire, &std::format!("10 1 2 192.0.2.38 {b64}"));
        let mut wire = crate::testutil::hex("0A0002");
        wire.extend_from_slice(&key);
        round_trip(Rtype::IPSECKEY, &wire, &std::format!("10 0 2 . {b64}"));
        let mut wire = crate::testutil::hex("0A0302");
        wire.extend_from_slice(b"\x09mygateway\x07example\x03com\x00");
        wire.extend_from_slice(&key);
        round_trip(
            Rtype::IPSECKEY,
            &wire,
            &std::format!("10 3 2 mygateway.example.com. {b64}"),
        );
        // 10 2 2 2001:0DB8:0:8002::2000:1 AQID (named-rrchecker).
        round_trip(
            Rtype::IPSECKEY,
            &crate::testutil::hex("0A020220010DB8000080020000000020000001010203"),
            "10 2 2 2001:db8:0:8002::2000:1 AQID",
        );
        // No key at all.
        round_trip(Rtype::IPSECKEY, b"\x0a\x00\x00", "10 0 0 .");
    }

    #[test]
    fn fields_and_malformed() {
        let RData::Ipseckey(k) = parse(Rtype::IPSECKEY, Class::IN, b"\x01\x01\x04\x7f\x00\x00\x01\x01")
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(
            k,
            Ipseckey {
                precedence: 1,
                algorithm: IpseckeyAlgorithm::EDDSA,
                gateway: IpseckeyGateway::Ipv4([127, 0, 0, 1].into()),
                public_key: b"\x01",
            }
        );
        assert_eq!(k.algorithm.to_string(), "EDDSA");
        assert_eq!(IpseckeyAlgorithm::new(9).to_string(), "9");
        // Unknown gateway type (BIND: not implemented).
        assert_eq!(
            parse(Rtype::IPSECKEY, Class::IN, b"\x0a\x04\x02"),
            Err(Error::InvalidRdata)
        );
        assert_eq!(
            parse(Rtype::IPSECKEY, Class::IN, b"\x0a\x03\x02\xc0\x00"),
            Err(Error::UnexpectedPointer)
        );
        assert_eq!(
            parse(Rtype::IPSECKEY, Class::IN, b"\x0a\x02\x02\x20\x01"),
            Err(Error::UnexpectedEof)
        );
    }

    #[test]
    fn text() {
        // RFC 4025 §3.3 examples (wire from named-rrchecker).
        let key = crate::testutil::hex(KEY);
        let b64 = "AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==";
        let mut wire = crate::testutil::hex("0A0102C0000226");
        wire.extend_from_slice(&key);
        let text = std::format!("10 1 2 192.0.2.38 {b64}");
        text_round_trip(Rtype::IPSECKEY, &text, &wire, &text);
        let mut wire = crate::testutil::hex("0A0002");
        wire.extend_from_slice(&key);
        let text = std::format!("10 0 2 . {b64}");
        text_round_trip(Rtype::IPSECKEY, &text, &wire, &text);
        let mut wire = crate::testutil::hex("0A0102C0000203");
        wire.extend_from_slice(&key);
        let text = std::format!("10 1 2 192.0.2.3 {b64}");
        text_round_trip(Rtype::IPSECKEY, &text, &wire, &text);
        let mut wire = crate::testutil::hex("0A0302");
        wire.extend_from_slice(b"\x09mygateway\x07example\x03com\x00");
        wire.extend_from_slice(&key);
        let text = std::format!("10 3 2 mygateway.example.com. {b64}");
        text_round_trip(Rtype::IPSECKEY, &text, &wire, &text);
        let mut wire = crate::testutil::hex("0A020220010DB8000080020000000020000001");
        wire.extend_from_slice(&key);
        text_round_trip(
            Rtype::IPSECKEY,
            &std::format!("10 2 2 2001:0DB8:0:8002::2000:1 {b64}"),
            &wire,
            &std::format!("10 2 2 2001:db8:0:8002::2000:1 {b64}"),
        );
        // Relative gateway, key split by blanks (named-rrchecker).
        text_round_trip(
            Rtype::IPSECKEY,
            "10 3 2 mygateway ( AQNR\n U3mG )",
            &crate::testutil::hex("0A0302096D7967617465776179076578616D706C6500010351537986"),
            "10 3 2 mygateway.example. AQNRU3mG",
        );
        // No key (BIND requires one, but the wire format allows none).
        text_round_trip(Rtype::IPSECKEY, "10 0 0 .", b"\x0a\x00\x00", "10 0 0 .");
        for (text, err) in [
            // BIND: "syntax error", "bad dotted quad", "bad IPv6 address",
            // "out of range", "bad base64 encoding".
            ("10 0 0 foo.", Error::InvalidText),
            ("10 0 0 @", Error::InvalidText),
            ("10 1 0 .", Error::InvalidText),
            ("10 2 2 192.0.2.38 AQID", Error::InvalidText),
            ("10 1 2 192.0.2.38 AQN", Error::InvalidText),
            ("10 4 0 .", Error::InvalidRdata),
            ("256 0 0 .", Error::InvalidText),
            ("10 0 256 .", Error::InvalidText),
            ("10 0 0 \".\"", Error::InvalidText),
            ("10 0 0", Error::UnexpectedEof),
            ("10 3 0", Error::UnexpectedEof),
            ("10", Error::UnexpectedEof),
        ] {
            assert_eq!(text_error(Rtype::IPSECKEY, text), err, "{text:?}");
        }
    }
}
