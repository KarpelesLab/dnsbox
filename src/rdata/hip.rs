//! HIP record data (RFC 8005 §5).

use core::fmt;

use super::{ComposeRdata, IpseckeyAlgorithm, ParseRdata};
use crate::name::Name;
use crate::text::{Base64, Hex};
use crate::wire::{Composer, NameEncoding, WireReader};
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
    use crate::rdata::tests::{compose, parse, round_trip};
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
}
