//! DHCID record data (RFC 4701).

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::wire::{Composer, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Error, Result, Rtype};

/// `DHCID` record data: the DHCP client identity associated with a name
/// (RFC 4701 §3).
///
/// The RDATA is an identifier-type code, a digest-type code and a digest
/// (RFC 4701 §3.3); it must hold at least the two codes, i.e. 3 bytes.
///
/// ```
/// use dnsbox::rdata::{Dhcid, ParseRdataText};
///
/// let mut buf = [0u8; 8];
/// let dhcid = Dhcid::from_text("AAIB", &mut buf)?;
/// assert_eq!((dhcid.identifier_type(), dhcid.digest_type()), (2, 1));
/// assert!(dhcid.digest().is_empty());
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Dhcid<'a> {
    data: &'a [u8],
}

impl<'a> Dhcid<'a> {
    /// Identifier type: the client's `htype` and `chaddr` from a DHCPv4
    /// message (RFC 4701 §3.3).
    pub const ID_CHADDR: u16 = 0x0000;
    /// Identifier type: the DHCPv4 client identifier option (RFC 4701
    /// §3.3).
    pub const ID_CLIENT_ID: u16 = 0x0001;
    /// Identifier type: the DHCPv6 client DUID (RFC 4701 §3.3).
    pub const ID_DUID: u16 = 0x0002;
    /// Digest type: SHA-256 (RFC 4701 §3.4).
    pub const DIGEST_SHA256: u8 = 1;

    /// Wraps the RDATA bytes, which must hold at least the identifier-type
    /// and digest-type codes (RFC 4701 §3.3).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRdata`] if `data` is shorter than 3 bytes.
    #[inline]
    pub const fn from_wire(data: &'a [u8]) -> Result<Self> {
        if data.len() < 3 {
            return Err(Error::InvalidRdata);
        }
        Ok(Dhcid { data })
    }

    /// The whole RDATA.
    #[inline]
    #[must_use]
    pub const fn as_wire(&self) -> &'a [u8] {
        self.data
    }

    /// The identifier-type code (RFC 4701 §3.3).
    #[inline]
    #[must_use]
    pub const fn identifier_type(&self) -> u16 {
        match self.data {
            [a, b, ..] => u16::from_be_bytes([*a, *b]),
            _ => 0,
        }
    }

    /// The digest-type code (RFC 4701 §3.4).
    #[inline]
    #[must_use]
    pub const fn digest_type(&self) -> u8 {
        match self.data {
            [_, _, d, ..] => *d,
            _ => 0,
        }
    }

    /// The digest: `digest(identifier || FQDN)` (RFC 4701 §3.3, §3.5).
    #[inline]
    #[must_use]
    pub const fn digest(&self) -> &'a [u8] {
        match self.data {
            [_, _, _, rest @ ..] => rest,
            _ => &[],
        }
    }
}

impl ParseRdataText for Dhcid<'_> {
    /// The whole RDATA in base64 (RFC 4701 §3.1), which may be split
    /// across blanks and lines; it must decode to at least the two type
    /// codes (3 octets).
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        if s.base64_rest_into(out)? == 0 {
            return Err(Error::UnexpectedEof);
        }
        Ok(())
    }
}

impl<'a> ParseRdata<'a> for Dhcid<'a> {
    const RTYPE: Rtype = Rtype::DHCID;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        let d = Dhcid::from_wire(rdata.peek_rest())?;
        rdata.read_rest();
        Ok(d)
    }
}

impl ComposeRdata for Dhcid<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::DHCID
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_bytes(self.data)
    }
}

impl fmt::Display for Dhcid<'_> {
    /// The RDATA in base64 (RFC 4701 §3.1).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&crate::text::Base64(self.data), f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdata::tests::{parse, round_trip, text_error, text_round_trip};
    use crate::testutil::hex;
    use crate::{Class, RData};

    #[test]
    fn rfc4701_examples() {
        // RFC 4701 §3.6, examples 1–3 (identifier types DUID, client-id
        // option, chaddr). The digests were checked against
        // SHA-256(identifier || FQDN) when writing this test.
        for (id_type, wire, text) in [
            (
                Dhcid::ID_DUID,
                "000201636fc0b8271c82825bb1ac5c41cf5351aa69b4febd94e8f17cdb95000da48c40",
                "AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=",
            ),
            (
                Dhcid::ID_CLIENT_ID,
                "0001013920fe5d1dceb3fd0ba3379756a70d73b17009f41d58bddbfcd6a2503956d8da",
                "AAEBOSD+XR3Os/0LozeXVqcNc7FwCfQdWL3b/NaiUDlW2No=",
            ),
            (
                Dhcid::ID_CHADDR,
                "000001c4b9a5b249651343158dde7bcc77169841f7a4243a572b5c283fffedeb3f75e6",
                "AAABxLmlskllE0MVjd57zHcWmEH3pCQ6VytcKD//7es/deY=",
            ),
        ] {
            let wire = hex(wire);
            round_trip(Rtype::DHCID, &wire, text);
            let Ok(RData::Dhcid(d)) = parse(Rtype::DHCID, Class::IN, &wire) else {
                panic!("not DHCID")
            };
            assert_eq!(d.identifier_type(), id_type);
            assert_eq!(d.digest_type(), Dhcid::DIGEST_SHA256);
            assert_eq!(d.digest().len(), 32);
            assert_eq!(d.as_wire(), &wire[..]);
        }
    }

    #[test]
    fn too_short() {
        for bad in [&b""[..], b"\x00", b"\x00\x02"] {
            assert_eq!(Dhcid::from_wire(bad), Err(Error::InvalidRdata));
            assert_eq!(
                parse(Rtype::DHCID, Class::IN, bad),
                Err(Error::InvalidRdata)
            );
        }
        let d = Dhcid::from_wire(b"\x00\x02\x01").unwrap();
        assert!(d.digest().is_empty());
        round_trip(Rtype::DHCID, b"\x00\x02\x01", "AAIB");
    }

    #[test]
    fn text() {
        // RFC 4701 §3.6, exactly as presented there: the base64 is split
        // mid-quantum across lines.
        for (text, wire, shown) in [
            (
                "( AAIBY2/AuCccgoJbsaxcQc9TUapptP69l\n  OjxfNuVAA2kjEA= )",
                "000201636fc0b8271c82825bb1ac5c41cf5351aa69b4febd94e8f17cdb95000da48c40",
                "AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=",
            ),
            (
                "( AAEBOSD+XR3Os/0LozeXVqcNc7FwCfQdW\n  L3b/NaiUDlW2No= )",
                "0001013920fe5d1dceb3fd0ba3379756a70d73b17009f41d58bddbfcd6a2503956d8da",
                "AAEBOSD+XR3Os/0LozeXVqcNc7FwCfQdWL3b/NaiUDlW2No=",
            ),
            (
                "( AAABxLmlskllE0MVjd57zHcWmEH3pCQ6V\n  ytcKD//7es/deY= )",
                "000001c4b9a5b249651343158dde7bcc77169841f7a4243a572b5c283fffedeb3f75e6",
                "AAABxLmlskllE0MVjd57zHcWmEH3pCQ6VytcKD//7es/deY=",
            ),
        ] {
            text_round_trip(Rtype::DHCID, text, &hex(wire), shown);
        }
        text_round_trip(Rtype::DHCID, "AAIB", b"\x00\x02\x01", "AAIB");
    }

    #[test]
    fn text_malformed() {
        for (text, err) in [
            ("", Error::UnexpectedEof),
            // Shorter than the two type codes (RFC 4701 §3.3).
            ("AAI=", Error::InvalidRdata),
            ("AA==", Error::InvalidRdata),
            ("AAIB=", Error::InvalidText),
            ("AAI", Error::InvalidText),
            ("AA!B", Error::InvalidText),
            ("\"AAIB\"", Error::InvalidText),
        ] {
            assert_eq!(text_error(Rtype::DHCID, text), err, "{text:?}");
        }
    }
}
