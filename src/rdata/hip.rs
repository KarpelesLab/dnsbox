//! HIP record data (RFC 8005 §5).

use core::fmt;

use super::{ComposeRdata, IpseckeyAlgorithm, ParseRdata, ParseRdataText};
use crate::name::Name;
use crate::text::{Base64, Hex};
use crate::wire::{Composer, NameEncoding, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Error, Result, Rtype};

/// `HIP` record data: a Host Identity Tag, Host Identity public key and
/// optional rendezvous servers (RFC 8005 §5).
///
/// The HIT and the public key are both non-empty (their length fields
/// would otherwise be meaningless; BIND rejects them too). To build a HIP
/// record from a list of names, use [`HipParts`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Hip<'a> {
    /// The public-key algorithm (shares the IPSECKEY registry,
    /// RFC 8005 §5).
    pub pk_algorithm: IpseckeyAlgorithm,
    /// The Host Identity Tag (1–255 octets).
    pub hit: &'a [u8],
    /// The Host Identity public key (1–65535 octets).
    pub public_key: &'a [u8],
    /// The rendezvous servers, in order of preference.
    pub servers: HipServers<'a>,
}

/// The rendezvous-server list of a [`Hip`] record: a validated run of
/// uncompressed domain names filling the rest of the RDATA (RFC 8005 §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct HipServers<'a>(&'a [u8]);

impl<'a> HipServers<'a> {
    /// Validates `wire` as a sequence of uncompressed names (possibly
    /// empty).
    pub fn new(wire: &'a [u8]) -> Result<Self> {
        let mut r = WireReader::new(wire);
        while !r.is_empty() {
            r.read_name_uncompressed()?;
        }
        Ok(HipServers(wire))
    }

    /// The encoded names.
    #[inline]
    pub const fn as_wire(&self) -> &'a [u8] {
        self.0
    }

    /// Whether there are no servers.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterates over the servers.
    #[inline]
    pub fn iter(&self) -> HipServerIter<'a> {
        HipServerIter(WireReader::new(self.0))
    }
}

impl<'a> IntoIterator for HipServers<'a> {
    type Item = Name<'a>;
    type IntoIter = HipServerIter<'a>;
    fn into_iter(self) -> HipServerIter<'a> {
        self.iter()
    }
}

/// Iterator over [`HipServers`].
#[derive(Clone, Debug)]
pub struct HipServerIter<'a>(WireReader<'a>);

impl<'a> Iterator for HipServerIter<'a> {
    type Item = Name<'a>;

    fn next(&mut self) -> Option<Name<'a>> {
        if self.0.is_empty() {
            return None;
        }
        match self.0.read_name_uncompressed() {
            Ok(name) => Some(name),
            // Unreachable for a validated list; stay panic-free anyway.
            Err(_) => {
                self.0.read_rest();
                None
            }
        }
    }
}

impl core::iter::FusedIterator for HipServerIter<'_> {}

/// Checks the HIT and key lengths and writes everything but the servers.
fn compose_head<C: Composer + ?Sized>(
    c: &mut C,
    pk_algorithm: IpseckeyAlgorithm,
    hit: &[u8],
    public_key: &[u8],
) -> Result<()> {
    let hit_len = u8::try_from(hit.len()).map_err(|_| Error::InvalidRdata)?;
    let pk_len = u16::try_from(public_key.len()).map_err(|_| Error::InvalidRdata)?;
    if hit_len == 0 || pk_len == 0 {
        return Err(Error::InvalidRdata);
    }
    c.put_u8(hit_len)?;
    c.put_u8(pk_algorithm.get())?;
    c.put_u16(pk_len)?;
    c.put_bytes(hit)?;
    c.put_bytes(public_key)
}

impl ParseRdataText for Hip<'_> {
    /// `pk-algorithm base16-HIT base64-public-key rendezvous-server...`
    /// (RFC 8005 §6): the HIT and the key are one token each (whitespace
    /// would make them ambiguous with the server names that follow, so
    /// BIND does not allow it either), then zero or more domain names.
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        let pk_algorithm = s.u8()?;
        let head = out.pos();
        // HIT length, algorithm and key length; the lengths are patched.
        out.put_bytes(&[0, pk_algorithm, 0, 0])?;
        let hit_len = u8::try_from(s.hex_into(out)?).map_err(|_| Error::InvalidRdata)?;
        let pk_len = u16::try_from(s.base64_into(out)?).map_err(|_| Error::InvalidRdata)?;
        out.patch(head, &[hit_len])?;
        out.patch(head + 2, &pk_len.to_be_bytes())?;
        while !s.is_at_end()? {
            // "MUST NOT be compressed" (RFC 8005 §5).
            s.name_into(out, NameEncoding::Plain)?;
        }
        Ok(())
    }
}

impl<'a> ParseRdata<'a> for Hip<'a> {
    const RTYPE: Rtype = Rtype::HIP;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        let mut r = *rdata;
        let hit_len = r.read_u8()?;
        let pk_algorithm = IpseckeyAlgorithm::new(r.read_u8()?);
        let pk_len = r.read_u16()?;
        if hit_len == 0 || pk_len == 0 {
            return Err(Error::InvalidRdata);
        }
        let hit = r.read_bytes(hit_len.into())?;
        let public_key = r.read_bytes(pk_len.into())?;
        // Rendezvous server names "MUST NOT be compressed" (RFC 8005 §5).
        let servers = HipServers::new(r.read_rest())?;
        *rdata = r;
        Ok(Hip {
            pk_algorithm,
            hit,
            public_key,
            servers,
        })
    }
}

impl ComposeRdata for Hip<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::HIP
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        compose_head(c, self.pk_algorithm, self.hit, self.public_key)?;
        c.put_bytes(self.servers.as_wire())
    }
}

/// Writes `pk-algorithm HIT public-key [servers]`.
fn fmt_hip<'n>(
    f: &mut fmt::Formatter<'_>,
    pk_algorithm: IpseckeyAlgorithm,
    hit: &[u8],
    public_key: &[u8],
    servers: impl Iterator<Item = Name<'n>>,
) -> fmt::Result {
    write!(
        f,
        "{} {} {}",
        pk_algorithm.get(),
        Hex(hit),
        Base64(public_key)
    )?;
    servers.into_iter().try_for_each(|s| write!(f, " {s}"))
}

impl fmt::Display for Hip<'_> {
    /// `pk-algorithm base16-HIT base64-public-key rendezvous-server...`
    /// (RFC 8005 §6).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_hip(
            f,
            self.pk_algorithm,
            self.hit,
            self.public_key,
            self.servers.iter(),
        )
    }
}

/// Compose-only `HIP` data with the rendezvous servers given as a slice
/// of names.
///
/// ```
/// use dnsbox::rdata::{HipParts, IpseckeyAlgorithm};
/// use dnsbox::{ComposeRdata, NameBuf, WireWriter};
///
/// let rvs: NameBuf = "rvs.example".parse()?;
/// let hip = HipParts {
///     pk_algorithm: IpseckeyAlgorithm::RSA,
///     hit: &[0x20, 0x01],
///     public_key: &[1, 2, 3],
///     servers: &[rvs.as_name()],
/// };
/// let mut buf = [0u8; 64];
/// let mut w = WireWriter::new(&mut buf);
/// hip.compose_rdata(&mut w)?;
/// assert_eq!(w.written(), b"\x02\x02\x00\x03\x20\x01\x01\x02\x03\x03rvs\x07example\x00");
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct HipParts<'s> {
    /// The public-key algorithm.
    pub pk_algorithm: IpseckeyAlgorithm,
    /// The Host Identity Tag (1–255 octets).
    pub hit: &'s [u8],
    /// The public key (1–65535 octets).
    pub public_key: &'s [u8],
    /// The rendezvous servers.
    pub servers: &'s [Name<'s>],
}

impl ComposeRdata for HipParts<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::HIP
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        compose_head(c, self.pk_algorithm, self.hit, self.public_key)?;
        // Not in the RFC 4034 §6.2 lowercasing list; never compressed.
        self.servers
            .iter()
            .try_for_each(|s| c.put_name(*s, NameEncoding::Plain))
    }
}

impl fmt::Display for HipParts<'_> {
    /// Same format as [`Hip`].
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_hip(
            f,
            self.pk_algorithm,
            self.hit,
            self.public_key,
            self.servers.iter().copied(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{HipParts, HipServers};
    use crate::rdata::tests::{compose, parse, round_trip, text_error, text_round_trip};
    use crate::rdata::{IpseckeyAlgorithm, RData};
    use crate::{Class, ComposeRdata, Error, Name, Rtype};
    use std::string::ToString;
    use std::vec::Vec;

    const WIRE: &str = "10020004200100107B1A74DF365639CC39F1D578010203040372767307\
                        6578616D706C6503636F6D000472767332076578616D706C6503636F6D00";
    const TEXT: &str =
        "2 200100107B1A74DF365639CC39F1D578 AQIDBA== rvs.example.com. rvs2.example.com.";

    #[test]
    fn rfc8005_style_example() {
        // HIP 2 200100107B1A74DF365639CC39F1D578 AQIDBA== rvs.example.com.
        // rvs2.example.com. (named-rrchecker).
        let wire = crate::testutil::hex(WIRE);
        round_trip(Rtype::HIP, &wire, TEXT);
        let RData::Hip(hip) = parse(Rtype::HIP, Class::IN, &wire).unwrap() else {
            panic!()
        };
        assert_eq!(hip.pk_algorithm, IpseckeyAlgorithm::RSA);
        let servers: Vec<_> = hip.servers.iter().map(|n| n.to_string()).collect();
        assert_eq!(servers, ["rvs.example.com.", "rvs2.example.com."]);
        let names: Vec<Name<'_>> = hip.servers.into_iter().collect();
        let parts = HipParts {
            pk_algorithm: hip.pk_algorithm,
            hit: hip.hit,
            public_key: hip.public_key,
            servers: &names,
        };
        assert_eq!(compose(&parts), wire);
        assert_eq!(parts.to_string(), TEXT);
        // No servers.
        round_trip(Rtype::HIP, b"\x01\x02\x00\x01\xaa\xbb", "2 AA uw==");
    }

    #[test]
    fn malformed() {
        for (bad, err) in [
            (&b"\x00\x02\x00\x01\x01\x02\x03\x04"[..], Error::InvalidRdata), // empty HIT
            (b"\x01\x02\x00\x00\x01\x02", Error::InvalidRdata),              // empty key
            (b"\x01\x02\x00\x01\xff\x01\xc0\x00", Error::UnexpectedPointer),
            (b"\x01\x02\x00\x01\xff\x01\x02\x03", Error::UnexpectedEof),
            (b"\x01\x02\x00\x05\xff\x01", Error::UnexpectedEof),
        ] {
            assert_eq!(parse(Rtype::HIP, Class::IN, bad), Err(err), "{bad:?}");
        }
        assert_eq!(HipServers::new(b"\x01a"), Err(Error::UnexpectedEof));
        assert!(HipServers::default().is_empty());
        let mut buf = [0u8; 64];
        let mut w = crate::WireWriter::new(&mut buf);
        let empty = HipParts {
            pk_algorithm: IpseckeyAlgorithm::RSA,
            hit: &[],
            public_key: &[1],
            servers: &[],
        };
        assert_eq!(empty.compose_rdata(&mut w), Err(Error::InvalidRdata));
        let big = [0u8; 256];
        let long_hit = HipParts { hit: &big, ..empty };
        assert_eq!(long_hit.compose_rdata(&mut w), Err(Error::InvalidRdata));
    }

    /// The public key of the RFC 8005 §6 examples.
    const RFC_KEY: &str = "AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsu\
                           xKbWIy87UOoJTwkUs7lBu+Upr1gsNrut79ryra+bSRGQb1slImA8YVJyuIDsj7kwzG7j\
                           nERNqnWxZ48AWkskmdHaVDP4BcelrTI3rMXdXF5D";

    /// Its wire form, after the HIT (named-rrchecker).
    const RFC_KEY_HEX: &str = "03010001B771CA136E4AEB5CE44333C53B3D2C13C22243851FC708BCCE29F7E2\
                               EB5787B5F56CCAD34F8223ACC10904DDB56B2EC4A6D6232F3B50EA094F0914B3\
                               B941BBE529AF582C36BBADEFDAF2ADAF9B4911906F5B2522603C615272B880EC\
                               8FB930CC6EE39C444DAA75B1678F005A4B2499D1DA5433F805C7A5AD3237ACC5\
                               DD5C5E43";

    #[test]
    fn text() {
        // RFC 8005 §6 examples, without and with rendezvous servers
        // (named-rrchecker).
        let mut wire = crate::testutil::hex("10020084200100107B1A74DF365639CC39F1D578");
        wire.extend_from_slice(&crate::testutil::hex(RFC_KEY_HEX));
        let text = std::format!("2 200100107B1A74DF365639CC39F1D578 {RFC_KEY}");
        text_round_trip(Rtype::HIP, &text, &wire, &text);
        let mut with_rvs = wire.clone();
        with_rvs.extend_from_slice(b"\x03rvs\x07example\x03com\x00");
        let text = std::format!(
            "( 2 200100107b1a74df365639cc39f1d578\n {RFC_KEY}\n rvs.example.com. )"
        );
        text_round_trip(
            Rtype::HIP,
            &text,
            &with_rvs,
            &std::format!("2 200100107B1A74DF365639CC39F1D578 {RFC_KEY} rvs.example.com."),
        );
        let mut two = wire.clone();
        two.extend_from_slice(b"\x03rvs\x07example\x03com\x00\x04rvs2\x07example\x03com\x00");
        let text = std::format!(
            "2 200100107B1A74DF365639CC39F1D578 {RFC_KEY} rvs.example.com. rvs2.example.com."
        );
        text_round_trip(Rtype::HIP, &text, &two, &text);
        // Relative server names (named-rrchecker).
        text_round_trip(
            Rtype::HIP,
            "2 2001 AQID rvs1 rvs2.",
            &crate::testutil::hex("0202000320010102030472767331076578616D706C6500047276733200"),
            "2 2001 AQID rvs1.example. rvs2.",
        );
        text_round_trip(Rtype::HIP, "2 2001 AQ==", b"\x02\x02\x00\x01\x20\x01\x01", "2 2001 AQ==");
        for (text, err) in [
            // BIND: "bad hex encoding", "out of range", "unexpected end of
            // input", "label too long" (a split key).
            ("2 200 AQID", Error::InvalidText),
            ("2 - AQID", Error::InvalidText),
            ("256 2001 AQID", Error::InvalidText),
            ("2 2001 AQI", Error::InvalidText),
            ("2 2001 \"AQID\"", Error::InvalidText),
            ("2 2001 AQID rvs..example.", Error::EmptyLabel),
            ("2 2001", Error::UnexpectedEof),
            ("2", Error::UnexpectedEof),
            ("", Error::UnexpectedEof),
        ] {
            assert_eq!(text_error(Rtype::HIP, text), err, "{text:?}");
        }
        // A HIT of 256 octets does not fit its length field.
        let long = std::format!("2 {} AQID", "00".repeat(256));
        assert_eq!(text_error(Rtype::HIP, &long), Error::InvalidRdata);
        assert_eq!(
            crate::rdata::tests::text_parse(Rtype::HIP, &std::format!("2 {} AQID", "ab".repeat(255)))
                .map(|w| w.len()),
            Ok(4 + 255 + 3)
        );
    }
}
