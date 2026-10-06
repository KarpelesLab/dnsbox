//! IPN record data: the node number of a Bundle Protocol node
//! (draft-johnson-dns-ipn-cla-07 §3.1; IANA "Resource Record (RR) TYPEs").
//!
//! The format is the one of an Internet-Draft that expired without being
//! published, and may change.

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::wire::{Composer, OutBuf, WireReader};
use crate::zone::{Scanner, decimal};
use crate::{Error, Result, Rtype};

/// `IPN` record data: the CBHE node number (`node-nbr`) of the Bundle
/// Protocol node a name stands for, the first component of its `ipn`
/// scheme endpoint IDs (RFC 9171 §4.2.5.1.2, RFC 7116).
///
/// Specified by draft-johnson-dns-ipn-cla-07 §3.1, the version IANA's
/// registration points to: an Internet-Draft that expired without being
/// published, so **the format may change**. The RDATA is the node number
/// as an unsigned 64-bit integer in network order; the presentation
/// format is either that number in decimal, or two 32-bit decimal numbers
/// joined by a period, the most significant half first (`1.2` is
/// 4294967298), without zero padding. `Display` writes the single
/// number. (The IANA registration template describes the number as
/// "encoded in US-ASCII"; the draft, which the registry cites, defines
/// the binary form used here.)
///
/// ```
/// use dnsbox::rdata::{Ipn, ParseRdataText};
///
/// let mut buf = [0u8; 8];
/// let ipn = Ipn::from_text("977000", &mut buf)?;
/// assert_eq!(ipn, Ipn::new(977_000));
/// assert_eq!(buf, [0, 0, 0, 0, 0, 0x0e, 0xe8, 0x68]);
///
/// // The two-halves form reads to the same number.
/// let mut buf = [0u8; 8];
/// let ipn = Ipn::from_text("1.2", &mut buf)?;
/// assert_eq!(ipn.parts(), (1, 2));
/// assert_eq!(ipn.to_string(), "4294967298");
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Ipn {
    /// The node number (`node-nbr`).
    pub node_number: u64,
}

impl Ipn {
    /// Wraps a node number.
    ///
    /// ```
    /// use dnsbox::rdata::Ipn;
    ///
    /// assert_eq!(Ipn::new(42).node_number, 42);
    /// ```
    #[inline]
    #[must_use]
    pub const fn new(node_number: u64) -> Self {
        Ipn { node_number }
    }

    /// Builds the node number from its two 32-bit halves, most significant
    /// first, as the dotted presentation form writes them
    /// (draft-johnson-dns-ipn-cla-07 §3.1).
    ///
    /// ```
    /// use dnsbox::rdata::Ipn;
    ///
    /// assert_eq!(Ipn::from_parts(1, 2), Ipn::new(0x1_0000_0002));
    /// ```
    #[inline]
    #[must_use]
    pub const fn from_parts(high: u32, low: u32) -> Self {
        Ipn {
            node_number: (high as u64) << 32 | low as u64,
        }
    }

    /// The two 32-bit halves of the node number, most significant first.
    ///
    /// ```
    /// use dnsbox::rdata::Ipn;
    ///
    /// assert_eq!(Ipn::new(0x1_0000_0002).parts(), (1, 2));
    /// assert_eq!(Ipn::new(7).parts(), (0, 7));
    /// ```
    #[inline]
    #[must_use]
    pub const fn parts(&self) -> (u32, u32) {
        ((self.node_number >> 32) as u32, self.node_number as u32)
    }
}

/// Parses an unsigned decimal number without zero padding
/// (draft-johnson-dns-ipn-cla-07 §3.1: "Values are not to be zero
/// padded").
fn unpadded<T: TryFrom<u64>>(digits: &[u8]) -> Result<T> {
    if digits.len() > 1 && digits.first() == Some(&b'0') {
        return Err(Error::InvalidText);
    }
    decimal(digits)
}

impl ParseRdataText for Ipn {
    /// A 64-bit unsigned decimal number, or two 32-bit ones joined by a
    /// period, most significant first; neither zero padded
    /// (draft-johnson-dns-ipn-cla-07 §3.1).
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        let raw = s.word()?.as_bytes();
        let ipn = match raw.iter().position(|&c| c == b'.') {
            Some(dot) => {
                let (high, low) = raw.split_at(dot);
                let low = low.get(1..).unwrap_or(&[]);
                Ipn::from_parts(unpadded(high)?, unpadded(low)?)
            }
            None => Ipn::new(unpadded(raw)?),
        };
        out.put_u64(ipn.node_number)
    }
}

impl<'a> ParseRdata<'a> for Ipn {
    const RTYPE: Rtype = Rtype::IPN;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        Ok(Ipn::new(rdata.read_u64()?))
    }
}

impl ComposeRdata for Ipn {
    fn rtype(&self) -> Rtype {
        Rtype::IPN
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_u64(self.node_number)
    }
}

impl fmt::Display for Ipn {
    /// The node number in decimal (draft-johnson-dns-ipn-cla-07 §3.1).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.node_number)
    }
}

#[cfg(test)]
mod tests {
    use super::Ipn;
    use crate::rdata::tests::{compose, parse, round_trip, text_error, text_round_trip};
    use crate::{Class, Error, Rtype};

    #[test]
    fn wire() {
        round_trip(Rtype::IPN, &[0; 8], "0");
        round_trip(Rtype::IPN, b"\x00\x00\x00\x00\x00\x0e\xe8\x68", "977000");
        round_trip(Rtype::IPN, &[0xff; 8], "18446744073709551615");
        round_trip(Rtype::IPN, b"\x00\x00\x00\x01\x00\x00\x00\x02", "4294967298");
        assert_eq!(compose(&Ipn::from_parts(1, 2)), b"\x00\x00\x00\x01\x00\x00\x00\x02");
        assert_eq!(Ipn::new(u64::MAX).parts(), (u32::MAX, u32::MAX));
        // Class-independent.
        assert!(matches!(
            parse(Rtype::IPN, Class::CH, &[0; 8]),
            Ok(crate::rdata::RData::Ipn(_))
        ));
    }

    #[test]
    fn malformed() {
        assert_eq!(parse(Rtype::IPN, Class::IN, &[0; 7]), Err(Error::UnexpectedEof));
        assert_eq!(parse(Rtype::IPN, Class::IN, &[0; 9]), Err(Error::TrailingData));
        assert_eq!(parse(Rtype::IPN, Class::IN, b""), Err(Error::UnexpectedEof));
    }

    #[test]
    fn text() {
        // draft-johnson-dns-ipn-cla-07 §3.1: one 64-bit number, or two
        // 32-bit numbers, most significant first.
        text_round_trip(Rtype::IPN, "977000", b"\x00\x00\x00\x00\x00\x0e\xe8\x68", "977000");
        text_round_trip(
            Rtype::IPN,
            "1.2",
            b"\x00\x00\x00\x01\x00\x00\x00\x02",
            "4294967298",
        );
        text_round_trip(Rtype::IPN, "0.977000", b"\x00\x00\x00\x00\x00\x0e\xe8\x68", "977000");
        text_round_trip(Rtype::IPN, "0", &[0; 8], "0");
        text_round_trip(
            Rtype::IPN,
            "18446744073709551615",
            &[0xff; 8],
            "18446744073709551615",
        );
        text_round_trip(
            Rtype::IPN,
            "4294967295.4294967295",
            &[0xff; 8],
            "18446744073709551615",
        );
        for (text, err) in [
            ("", Error::UnexpectedEof),
            ("18446744073709551616", Error::InvalidText),
            ("4294967296.0", Error::InvalidText),
            ("0.4294967296", Error::InvalidText),
            // Not zero padded.
            ("0977000", Error::InvalidText),
            ("01.2", Error::InvalidText),
            ("1.02", Error::InvalidText),
            ("00", Error::InvalidText),
            ("1.", Error::InvalidText),
            (".1", Error::InvalidText),
            ("1.2.3", Error::InvalidText),
            ("-1", Error::InvalidText),
            ("0x10", Error::InvalidText),
            ("\"1\"", Error::InvalidText),
            ("1 2", Error::InvalidText),
        ] {
            assert_eq!(text_error(Rtype::IPN, text), err, "{text:?}");
        }
    }
}
