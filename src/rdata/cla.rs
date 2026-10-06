//! CLA record data: the Bundle Protocol convergence layer adapters of a
//! node (draft-johnson-dns-ipn-cla-07 §3.2, §4; IANA "Resource Record
//! (RR) TYPEs").
//!
//! The format is the one of an Internet-Draft that expired without being
//! published, and may change.

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::charstr::{CharStrIter, CharStrs};
use crate::wire::{Composer, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Error, Result, Rtype};

/// `CLA` record data: the convergence layer adapters (CLAs) a Bundle
/// Protocol node offers over IP, such as `TCP-v6-v7` (TCPCLv4, RFC 9174,
/// over IPv6, for Bundle Protocol version 7).
///
/// Specified by draft-johnson-dns-ipn-cla-07 §3.2, the version IANA's
/// registration points to: an Internet-Draft that expired without being
/// published, so **the format may change**. The RDATA is one or more
/// `<character-string>`s (RFC 1035 §3.3), one per adapter, each made of
/// letters, digits and interior hyphens (`<protocol>-<IP version>-<BP
/// version>`, draft §4 lists the initial values). Strings with any other
/// character, empty ones, or ones starting or ending with a hyphen are
/// rejected with [`Error::InvalidRdata`]. The presentation format is the
/// strings separated by blanks, quoted or not; `Display` writes them
/// unquoted. (The IANA registration template has one string per record;
/// the draft, which the registry cites, allows several.)
///
/// ```
/// use dnsbox::rdata::{Cla, ParseRdataText};
///
/// // draft-johnson-dns-ipn-cla-07 §3.2.
/// let mut buf = [0u8; 32];
/// let cla = Cla::from_text(r#""TCP-V4-V6" "TCP-V6-V7""#, &mut buf)?;
/// let adapters: Vec<&[u8]> = cla.strings().map(|s| s.as_bytes()).collect();
/// assert_eq!(adapters, [&b"TCP-V4-V6"[..], b"TCP-V6-V7"]);
/// assert_eq!(cla.to_string(), "TCP-V4-V6 TCP-V6-V7");
/// assert_eq!(cla, Cla::from_wire(b"\x09TCP-V4-V6\x09TCP-V6-V7")?);
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Cla<'a> {
    strings: CharStrs<'a>,
}

/// Whether `s` is a valid CLA string: letters, digits and interior
/// hyphens (draft-johnson-dns-ipn-cla-07 §3.2).
fn valid_adapter(s: &[u8]) -> bool {
    !s.is_empty()
        && s.first() != Some(&b'-')
        && s.last() != Some(&b'-')
        && s.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'-')
}

impl<'a> Cla<'a> {
    /// Wraps encoded character-strings (length octets included), checking
    /// that there is at least one and that each is a valid adapter name
    /// (letters, digits and interior hyphens).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRdata`] for an empty buffer or an invalid adapter
    /// name, [`Error::UnexpectedEof`] if the last string is cut short.
    ///
    /// ```
    /// use dnsbox::Error;
    /// use dnsbox::rdata::Cla;
    ///
    /// let cla = Cla::from_wire(b"\x09LTP-v6-v7")?;
    /// assert_eq!(cla.to_string(), "LTP-v6-v7");
    /// assert_eq!(Cla::from_wire(b"\x08LTP v6v7"), Err(Error::InvalidRdata));
    /// assert_eq!(Cla::from_wire(b""), Err(Error::InvalidRdata));
    /// # Ok::<(), Error>(())
    /// ```
    pub fn from_wire(wire: &'a [u8]) -> Result<Self> {
        let strings = CharStrs::new(wire)?;
        if strings.is_empty() || !strings.iter().all(|s| valid_adapter(s.as_bytes())) {
            return Err(Error::InvalidRdata);
        }
        Ok(Cla { strings })
    }

    /// The adapter names, in RDATA order.
    ///
    /// ```
    /// use dnsbox::rdata::Cla;
    ///
    /// let cla = Cla::from_wire(b"\x09TCP-v4-v7\x09UDP-v4-v7")?;
    /// assert_eq!(cla.strings().count(), 2);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub fn strings(&self) -> CharStrIter<'a> {
        self.strings.iter()
    }

    /// The encoded RDATA.
    ///
    /// ```
    /// use dnsbox::rdata::Cla;
    ///
    /// let cla = Cla::from_wire(b"\x09TCP-v6-v7")?;
    /// assert_eq!(cla.as_wire(), b"\x09TCP-v6-v7");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub const fn as_wire(&self) -> &'a [u8] {
        self.strings.as_wire()
    }
}

impl ParseRdataText for Cla<'_> {
    /// One or more `<character-string>`s, quoted or not, one per adapter
    /// (draft-johnson-dns-ipn-cla-07 §3.2).
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        // The wire parser checks the adapter names.
        s.char_strings_into(out)
    }
}

impl<'a> ParseRdata<'a> for Cla<'a> {
    const RTYPE: Rtype = Rtype::CLA;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        let data = Cla::from_wire(rdata.peek_rest())?;
        rdata.read_rest();
        Ok(data)
    }
}

impl ComposeRdata for Cla<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::CLA
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_bytes(self.as_wire())
    }
}

impl fmt::Display for Cla<'_> {
    /// The adapter names, unquoted, separated by spaces
    /// (draft-johnson-dns-ipn-cla-07 §3.2).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, s) in self.strings().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            // Letters, digits and hyphens: nothing to escape.
            crate::text::fmt_label(f, s.as_bytes())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Cla;
    use crate::rdata::tests::{parse, round_trip, text_error, text_round_trip};
    use crate::{Class, Error, Rtype};

    /// The values of draft-johnson-dns-ipn-cla-07 §4, Table 1.
    const TABLE_1: &[&str] = &[
        "TCP-v4-v6",
        "UDP-v4-v6",
        "LTP-v4-v6",
        "STCP-v4-v6",
        "BSSP-v4-v6",
        "IPND-v4-v6",
        "TCP-v4-v7",
        "TCP-v6-v7",
        "UDP-v4-v7",
        "UDP-v6-v7",
        "LTP-v4-v7",
        "LTP-v6-v7",
        "STCP-v4-v7",
        "STCP-v6-v7",
        "BSSP-v4-v7",
        "BSSP-v6-v7",
        "IPND-v4-v7",
        "IPND-v6-v7",
    ];

    #[test]
    fn wire() {
        round_trip(Rtype::CLA, b"\x09TCP-v6-v7", "TCP-v6-v7");
        round_trip(
            Rtype::CLA,
            b"\x09TCP-v4-v7\x09TCP-v6-v7\x09LTP-v6-v7",
            "TCP-v4-v7 TCP-v6-v7 LTP-v6-v7",
        );
        for v in TABLE_1 {
            let mut wire = std::vec![v.len() as u8];
            wire.extend_from_slice(v.as_bytes());
            round_trip(Rtype::CLA, &wire, v);
        }
        // The IANA template's examples are valid names too.
        round_trip(Rtype::CLA, b"\x04UDP4\x05LTPU6\x04DCCP", "UDP4 LTPU6 DCCP");
        round_trip(Rtype::CLA, b"\x01x", "x");
    }

    #[test]
    fn malformed() {
        for (wire, err) in [
            (&b""[..], Error::InvalidRdata),
            (b"\x00", Error::InvalidRdata),
            (b"\x09TCP-v6-v7\x00", Error::InvalidRdata),
            (b"\x0aTCP-v6-v7-", Error::InvalidRdata),
            (b"\x0a-TCP-v6-v7", Error::InvalidRdata),
            (b"\x08TCP v6v7", Error::InvalidRdata),
            (b"\x09TCP_v6_v7", Error::InvalidRdata),
            (b"\x09TCP.v6.v7", Error::InvalidRdata),
            (b"\x03\xc3\xa9x", Error::InvalidRdata),
            (b"\x0aTCP-v6-v7", Error::UnexpectedEof),
            (b"\x09TCP-v6-v7\x05UDP", Error::UnexpectedEof),
        ] {
            assert_eq!(parse(Rtype::CLA, Class::IN, wire), Err(err), "{wire:?}");
        }
        assert_eq!(Cla::from_wire(b"\x01-"), Err(Error::InvalidRdata));
    }

    #[test]
    fn text() {
        // draft-johnson-dns-ipn-cla-07 §3.2: quoted or not, one string per
        // adapter.
        let wire = b"\x09TCP-V4-V6\x09TCP-V6-V7";
        text_round_trip(Rtype::CLA, r#""TCP-V4-V6" "TCP-V6-V7""#, wire, "TCP-V4-V6 TCP-V6-V7");
        text_round_trip(Rtype::CLA, "TCP-V4-V6 TCP-V6-V7", wire, "TCP-V4-V6 TCP-V6-V7");
        text_round_trip(
            Rtype::CLA,
            "TCP-v4-v7 TCP-v6-v7 LTP-v6-v7",
            b"\x09TCP-v4-v7\x09TCP-v6-v7\x09LTP-v6-v7",
            "TCP-v4-v7 TCP-v6-v7 LTP-v6-v7",
        );
        text_round_trip(Rtype::CLA, r"TCP\045v6-v7", b"\x09TCP-v6-v7", "TCP-v6-v7");
        for (text, err) in [
            ("", Error::UnexpectedEof),
            // §3.2: "two labels quoted together represent only a single
            // character string", which is not a valid adapter name.
            (r#""TCP-V4-V6 TCP-V6-V7""#, Error::InvalidRdata),
            (r#""""#, Error::InvalidRdata),
            ("TCP-v6-", Error::InvalidRdata),
            ("TCP_v6", Error::InvalidRdata),
            (r"TCP\000", Error::InvalidRdata),
            (r#""TCP"#, Error::InvalidText),
        ] {
            assert_eq!(text_error(Rtype::CLA, text), err, "{text:?}");
        }
        let long = "x".repeat(256);
        assert_eq!(text_error(Rtype::CLA, &long), Error::CharStringTooLong);
    }
}
