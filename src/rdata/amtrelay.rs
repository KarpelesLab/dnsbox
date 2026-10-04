//! AMTRELAY record data (RFC 8777 §4): the location of an Automatic
//! Multicast Tunneling relay for a multicast source.

use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr};

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::name::Name;
use crate::text::Hex;
use crate::wire::{Composer, NameEncoding, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Error, Result, Rtype};

/// The D ("Discovery Optional") bit of the second RDATA octet (RFC 8777
/// §4.2.2); the low 7 bits are the relay type.
const D_BIT: u8 = 0x80;

/// The relay of an AMTRELAY record (RFC 8777 §4.2.3, §4.2.4): its variant
/// determines the relay type field.
///
/// Relay types 0–3 are defined by RFC 8777 (IANA "Relay Type Field"
/// registry); records with another type "SHOULD NOT be considered" for
/// relay discovery (§4.2.3) but are valid data, kept as
/// [`AmtrelayRelay::Unknown`] with their relay octets uninterpreted. The
/// enum is `#[non_exhaustive]` so that relay types IANA registers later
/// can get their own variant.
///
/// ```
/// use dnsbox::NameBuf;
/// use dnsbox::rdata::AmtrelayRelay;
///
/// let name: NameBuf = "amtrelays.example.com".parse()?;
/// let relay = AmtrelayRelay::Name(name.as_name());
/// assert_eq!(relay.relay_type(), 3);
/// assert_eq!(relay.to_string(), "amtrelays.example.com.");
/// assert_eq!(AmtrelayRelay::None.to_string(), ".");
/// assert_eq!(AmtrelayRelay::Unknown { relay_type: 9, data: &[1] }.relay_type(), 9);
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AmtrelayRelay<'a> {
    /// Relay type 0: no relay should be used for this source (`.` in
    /// presentation format).
    None,
    /// Relay type 1: an IPv4 address.
    Ipv4(Ipv4Addr),
    /// Relay type 2: an IPv6 address.
    Ipv6(Ipv6Addr),
    /// Relay type 3: an uncompressed domain name, whose A and AAAA records
    /// give the relay addresses (§4.2.4).
    Name(Name<'a>),
    /// A relay type RFC 8777 does not define (4–127), with the rest of the
    /// RDATA as its relay field.
    Unknown {
        /// The relay type (4–127).
        relay_type: u8,
        /// The relay field, uninterpreted.
        data: &'a [u8],
    },
}

impl AmtrelayRelay<'_> {
    /// The relay type field value (RFC 8777 §4.2.3).
    #[must_use]
    pub const fn relay_type(&self) -> u8 {
        match self {
            AmtrelayRelay::None => 0,
            AmtrelayRelay::Ipv4(_) => 1,
            AmtrelayRelay::Ipv6(_) => 2,
            AmtrelayRelay::Name(_) => 3,
            AmtrelayRelay::Unknown { relay_type, .. } => *relay_type,
        }
    }
}

impl fmt::Display for AmtrelayRelay<'_> {
    /// The relay field in presentation format (RFC 8777 §4.3.1): `.` for
    /// type 0, the address or name otherwise. An unknown relay type has no
    /// presentation format; its relay octets are written in hexadecimal.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AmtrelayRelay::None => f.write_str("."),
            AmtrelayRelay::Ipv4(a) => fmt::Display::fmt(a, f),
            AmtrelayRelay::Ipv6(a) => fmt::Display::fmt(a, f),
            AmtrelayRelay::Name(n) => fmt::Display::fmt(n, f),
            AmtrelayRelay::Unknown { data, .. } => fmt::Display::fmt(&Hex(data), f),
        }
    }
}

/// `AMTRELAY` record data: an AMT relay for the multicast source named by
/// the owner (RFC 8777 §4).
///
/// ```
/// use dnsbox::rdata::{Amtrelay, AmtrelayRelay, ParseRdataText};
///
/// // RFC 8777 §4.3.2.
/// let mut buf = [0u8; 64];
/// let relay = Amtrelay::from_text("10 0 1 203.0.113.15", &mut buf)?;
/// assert_eq!(relay.precedence, 10);
/// assert!(!relay.discovery_optional);
/// assert_eq!(relay.relay, AmtrelayRelay::Ipv4([203, 0, 113, 15].into()));
/// assert_eq!(relay.to_string(), "10 0 1 203.0.113.15");
///
/// let mut buf = [0u8; 64];
/// let relay = Amtrelay::from_text("128 1 3 amtrelays.example.com.", &mut buf)?;
/// assert!(relay.discovery_optional);
/// assert_eq!(relay.relay.relay_type(), 3);
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Amtrelay<'a> {
    /// Precedence among the owner's AMTRELAY records; lower values are
    /// tried first (§4.2.1).
    pub precedence: u8,
    /// The D bit: when set, a gateway may send an AMT Request directly,
    /// without relay discovery first (§4.2.2).
    pub discovery_optional: bool,
    /// The relay (and with it the relay type).
    pub relay: AmtrelayRelay<'a>,
}

impl ParseRdataText for Amtrelay<'_> {
    /// `precedence D-bit type relay` (RFC 8777 §4.3.1): decimal precedence,
    /// a D bit of 0 or 1 and a relay type of at most 127; the relay is `.`
    /// for type 0, an IPv4 address for type 1, an IPv6 address for type 2
    /// and a domain name for type 3. Other relay types have no
    /// presentation format and are [`Error::InvalidRdata`] (as in BIND):
    /// write them in the generic form.
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        let precedence = s.u8()?;
        let d = match s.u8()? {
            0 => 0,
            1 => D_BIT,
            _ => return Err(Error::InvalidText),
        };
        let relay_type = s.u8()?;
        if relay_type >= D_BIT {
            return Err(Error::InvalidText);
        }
        out.put_bytes(&[precedence, d | relay_type])?;
        match relay_type {
            // "the relay field MUST be '.'" (§4.3.1).
            0 => {
                if !s.word()?.is(".") {
                    return Err(Error::InvalidText);
                }
                Ok(())
            }
            1 => out.put_bytes(&s.ipv4()?.octets()),
            2 => out.put_bytes(&s.ipv6()?.octets()),
            3 => s.name_into(out, NameEncoding::Plain),
            _ => Err(Error::InvalidRdata),
        }
    }
}

impl<'a> ParseRdata<'a> for Amtrelay<'a> {
    const RTYPE: Rtype = Rtype::AMTRELAY;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        let mut r = *rdata;
        let [precedence, type_byte] = r.read_array()?;
        let relay = match type_byte & !D_BIT {
            0 => AmtrelayRelay::None,
            1 => AmtrelayRelay::Ipv4(Ipv4Addr::from(r.read_array::<4>()?)),
            2 => AmtrelayRelay::Ipv6(Ipv6Addr::from(r.read_array::<16>()?)),
            // "The domain name MUST NOT be compressed" (§4.2.3).
            3 => AmtrelayRelay::Name(r.read_name_uncompressed()?),
            relay_type => AmtrelayRelay::Unknown {
                relay_type,
                data: r.read_rest(),
            },
        };
        *rdata = r;
        Ok(Amtrelay {
            precedence,
            discovery_optional: type_byte & D_BIT != 0,
            relay,
        })
    }
}

impl ComposeRdata for Amtrelay<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::AMTRELAY
    }

    /// # Errors
    ///
    /// [`Error::InvalidRdata`] for an [`AmtrelayRelay::Unknown`] relay
    /// whose type is not in 4–127 (types 0–3 have their own variants, and
    /// the field has 7 bits), and [`Error::BufferTooSmall`] if `c` is full.
    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        let relay_type = self.relay.relay_type();
        if matches!(self.relay, AmtrelayRelay::Unknown { .. }) && !(4..D_BIT).contains(&relay_type) {
            return Err(Error::InvalidRdata);
        }
        let d = if self.discovery_optional { D_BIT } else { 0 };
        c.put_bytes(&[self.precedence, d | relay_type])?;
        match self.relay {
            AmtrelayRelay::None => Ok(()),
            AmtrelayRelay::Ipv4(a) => c.put_bytes(&a.octets()),
            AmtrelayRelay::Ipv6(a) => c.put_bytes(&a.octets()),
            // Never compressed (§4.2.4), and not in the RFC 4034 §6.2
            // lowercasing list.
            AmtrelayRelay::Name(n) => c.put_name(n, NameEncoding::Plain),
            AmtrelayRelay::Unknown { data, .. } => c.put_bytes(data),
        }
    }
}

impl fmt::Display for Amtrelay<'_> {
    /// `precedence D-bit type relay` (RFC 8777 §4.3.1). A relay type
    /// RFC 8777 does not define has no presentation format: such RDATA is
    /// written in the generic RFC 3597 §5 form, as BIND does.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let relay_type = self.relay.relay_type();
        let d = u8::from(self.discovery_optional);
        if let AmtrelayRelay::Unknown { data, .. } = self.relay {
            let header = [self.precedence, (d << 7) | relay_type];
            return write!(
                f,
                "\\# {} {}{}",
                data.len().saturating_add(header.len()),
                Hex(&header),
                Hex(data)
            );
        }
        write!(
            f,
            "{} {} {} {}",
            self.precedence, d, relay_type, self.relay
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{Amtrelay, AmtrelayRelay};
    use crate::name::NameBuf;
    use crate::rdata::tests::{compose, parse, round_trip, text_error, text_parse, text_round_trip};
    use crate::rdata::{ComposeRdata, RData};
    use crate::testutil::hex;
    use crate::{Class, Error, Rtype, WireWriter};
    use std::string::ToString;

    #[test]
    fn rfc8777_examples() {
        // RFC 8777 §4.3.2, in presentation format and in the generic form
        // the section gives for the same records.
        text_round_trip(
            Rtype::AMTRELAY,
            "10 0 1 203.0.113.15",
            &hex("0a01cb00710f"),
            "10 0 1 203.0.113.15",
        );
        text_round_trip(
            Rtype::AMTRELAY,
            "10 0 2 2001:db8::15",
            &hex("0a0220010db8000000000000000000000015"),
            "10 0 2 2001:db8::15",
        );
        // The RFC's generic form of the third record leaves out the root
        // label (and says 24 octets): with it, the RDATA is 25 octets.
        text_round_trip(
            Rtype::AMTRELAY,
            "128 1 3 amtrelays.example.com.",
            &hex("808309616d7472656c617973076578616d706c6503636f6d00"),
            "128 1 3 amtrelays.example.com.",
        );
        assert_eq!(
            text_parse(
                Rtype::AMTRELAY,
                "\\# ( 6  ; length\n 0a ; precedence=10\n 01 ; D=0, relay type=1\n cb00710f )"
            )
            .as_deref(),
            Ok(&hex("0a01cb00710f")[..])
        );
    }

    #[test]
    fn fields() {
        let wire = hex("808309616d7472656c617973076578616d706c6503636f6d00");
        let RData::Amtrelay(a) = parse(Rtype::AMTRELAY, Class::IN, &wire).unwrap() else {
            panic!("not AMTRELAY")
        };
        let name: NameBuf = "amtrelays.example.com".parse().unwrap();
        assert_eq!(
            a,
            Amtrelay {
                precedence: 128,
                discovery_optional: true,
                relay: AmtrelayRelay::Name(name.as_name()),
            }
        );
        assert_eq!(compose(&a), wire);
        // No relay, with and without the D bit (BIND's wire tests).
        round_trip(Rtype::AMTRELAY, b"\x00\x00", "0 0 0 .");
        round_trip(Rtype::AMTRELAY, b"\x00\x80", "0 1 0 .");
        round_trip(Rtype::AMTRELAY, b"\xff\x80", "255 1 0 .");
        let RData::Amtrelay(a) = parse(Rtype::AMTRELAY, Class::IN, b"\x05\x00").unwrap() else {
            panic!()
        };
        assert_eq!(a.relay, AmtrelayRelay::None);
        assert_eq!(a.to_string(), "5 0 0 .");
    }

    #[test]
    fn unknown_relay_types() {
        // "RRs with an undefined value in the Type field SHOULD NOT be
        // considered" (§4.2.3): they parse, keep their relay octets and
        // display in the generic form (as BIND does).
        for (wire, relay_type, data, shown) in [
            (&b"\x00\x04"[..], 4, &b""[..], "\\# 2 0004"),
            (b"\x00\x84", 4, b"", "\\# 2 0084"),
            (b"\x00\x7f", 127, b"", "\\# 2 007F"),
            (b"\x00\x04\x00", 4, b"\x00", "\\# 3 000400"),
            (b"\x0a\xff\x01\x02", 127, b"\x01\x02", "\\# 4 0AFF0102"),
        ] {
            round_trip(Rtype::AMTRELAY, wire, shown);
            let RData::Amtrelay(a) = parse(Rtype::AMTRELAY, Class::IN, wire).unwrap() else {
                panic!()
            };
            assert_eq!(a.relay, AmtrelayRelay::Unknown { relay_type, data });
            assert_eq!(a.discovery_optional, wire[1] & 0x80 != 0);
            assert_eq!(text_parse(Rtype::AMTRELAY, shown).as_deref(), Ok(wire));
        }
        assert_eq!(
            AmtrelayRelay::Unknown {
                relay_type: 9,
                data: b"\xab"
            }
            .to_string(),
            "AB"
        );
        // Unknown variants must carry an unknown 7-bit type.
        let mut buf = [0u8; 32];
        for relay_type in [0, 1, 2, 3, 128, 255] {
            let a = Amtrelay {
                precedence: 0,
                discovery_optional: false,
                relay: AmtrelayRelay::Unknown { relay_type, data: b"" },
            };
            let mut w = WireWriter::new(&mut buf);
            assert_eq!(a.compose_rdata(&mut w), Err(Error::InvalidRdata), "{relay_type}");
            assert!(w.as_bytes().is_empty());
        }
    }

    #[test]
    fn malformed() {
        for (wire, err) in [
            // BIND's wire tests: every relay must have exactly its length.
            (&b"\x00"[..], Error::UnexpectedEof),
            (b"", Error::UnexpectedEof),
            (b"\x00\x00\x00", Error::TrailingData),
            (b"\x00\x80\x00", Error::TrailingData),
            (b"\x00\x01", Error::UnexpectedEof),
            (b"\x00\x01\x00\x00\x00", Error::UnexpectedEof),
            (b"\x00\x01\x00\x00\x00\x00\x00", Error::TrailingData),
            (b"\x00\x02\x00", Error::UnexpectedEof),
            (&[0x00, 0x02, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], Error::TrailingData),
            (b"\x00\x03", Error::UnexpectedEof),
            (b"\x00\x03\x00\x00", Error::TrailingData),
            (b"\x00\x03\x01a", Error::UnexpectedEof),
            // "MUST NOT be compressed" (§4.2.3).
            (b"\x00\x03\xc0\x00", Error::UnexpectedPointer),
        ] {
            assert_eq!(parse(Rtype::AMTRELAY, Class::IN, wire), Err(err), "{wire:02x?}");
        }
        round_trip(Rtype::AMTRELAY, b"\x00\x03\x00", "0 0 3 .");
        round_trip(
            Rtype::AMTRELAY,
            &[0x00, 0x02, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15],
            "0 0 2 1:203:405:607:809:1011:1213:1415",
        );
    }

    #[test]
    fn text() {
        // BIND's text tests (lib/dns/tests/rdata_test.c).
        text_round_trip(Rtype::AMTRELAY, "0 0 0 .", b"\x00\x00", "0 0 0 .");
        text_round_trip(Rtype::AMTRELAY, "0 1 0 .", b"\x00\x80", "0 1 0 .");
        text_round_trip(Rtype::AMTRELAY, "255 1 0 .", b"\xff\x80", "255 1 0 .");
        text_round_trip(Rtype::AMTRELAY, "0 0 1 0.0.0.0", &hex("000100000000"), "0 0 1 0.0.0.0");
        text_round_trip(
            Rtype::AMTRELAY,
            "0 0 2 ::",
            &hex("000200000000000000000000000000000000"),
            "0 0 2 ::",
        );
        // Names are relative to the origin (`example.`); an address is a
        // valid name.
        text_round_trip(
            Rtype::AMTRELAY,
            "0 0 3 0.0.0.0.",
            b"\x00\x03\x010\x010\x010\x010\x00",
            "0 0 3 0.0.0.0.",
        );
        text_round_trip(
            Rtype::AMTRELAY,
            "0 0 3 relay",
            b"\x00\x03\x05relay\x07example\x00",
            "0 0 3 relay.example.",
        );
        text_round_trip(
            Rtype::AMTRELAY,
            "( 10 1\n 3 @ )",
            b"\x0a\x83\x07example\x00",
            "10 1 3 example.",
        );
        for (text, err) in [
            ("", Error::UnexpectedEof),
            ("0", Error::UnexpectedEof),
            ("0 0", Error::UnexpectedEof),
            ("0 0 0", Error::UnexpectedEof),
            ("0 0 1", Error::UnexpectedEof),
            ("0 0 2", Error::UnexpectedEof),
            ("0 0 3", Error::UnexpectedEof),
            ("0 0 0 x", Error::InvalidText),
            ("0 0 0 \".\"", Error::InvalidText),
            ("0 2 0 .", Error::InvalidText),
            ("256 1 0 .", Error::InvalidText),
            ("0 0 128 .", Error::InvalidText),
            ("0 0 1 0.0.0.0 x", Error::InvalidText),
            ("0 0 1 0.0.0.0.0", Error::InvalidText),
            ("0 0 1 ::", Error::InvalidText),
            ("0 0 1 .", Error::InvalidText),
            ("0 0 2 :: xx", Error::InvalidText),
            ("0 0 2 0.0.0.0", Error::InvalidText),
            ("0 0 2 .", Error::InvalidText),
            ("0 0 3 example. x", Error::InvalidText),
            ("0 0 3 a..b", Error::EmptyLabel),
            // Undefined relay types only have the generic form.
            ("0 0 4 .", Error::InvalidRdata),
            ("0 0 127 00", Error::InvalidRdata),
            // The generic form must still be valid AMTRELAY RDATA.
            ("\\# 1 00", Error::UnexpectedEof),
            ("\\# 3 000100", Error::UnexpectedEof),
        ] {
            assert_eq!(text_error(Rtype::AMTRELAY, text), err, "{text:?}");
        }
    }
}
