//! URI record data (RFC 7553 §4.5).

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::wire::{Composer, WireReader};
use crate::{Error, Result, Rtype};

/// `URI` record data: a URI for a service, with SRV-style priority and
/// weight (RFC 7553 §4.5).
///
/// The target is the rest of the RDATA (not a `<character-string>`, so it
/// may exceed 255 bytes) and must not be empty: an empty string is not a
/// URI (RFC 3986 §3); such RDATA is rejected with [`Error::InvalidRdata`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Uri<'a> {
    /// Priority; lower values are tried first (RFC 7553 §4.2).
    pub priority: u16,
    /// Relative weight among records of equal priority (RFC 7553 §4.3).
    pub weight: u16,
    /// The target URI (RFC 7553 §4.4).
    pub target: &'a [u8],
}

impl<'a> Uri<'a> {
    /// Builds URI data, rejecting an empty target with
    /// [`Error::InvalidRdata`] (RFC 7553 §4.4).
    #[inline]
    pub const fn new(priority: u16, weight: u16, target: &'a [u8]) -> Result<Self> {
        if target.is_empty() {
            return Err(Error::InvalidRdata);
        }
        Ok(Uri {
            priority,
            weight,
            target,
        })
    }
}

impl<'a> ParseRdata<'a> for Uri<'a> {
    const RTYPE: Rtype = Rtype::URI;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        let priority = rdata.read_u16()?;
        let weight = rdata.read_u16()?;
        let target = rdata.read_rest();
        Uri::new(priority, weight, target)
    }
}

impl ComposeRdata for Uri<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::URI
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        if self.target.is_empty() {
            return Err(Error::InvalidRdata);
        }
        c.put_u16(self.priority)?;
        c.put_u16(self.weight)?;
        c.put_bytes(self.target)
    }
}

impl fmt::Display for Uri<'_> {
    /// `priority weight "target"` (RFC 7553 §4.5).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} ", self.priority, self.weight)?;
        crate::text::fmt_quoted(f, self.target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Class;
    use crate::rdata::tests::{parse, round_trip};
    use crate::wire::WireWriter;

    #[test]
    fn rfc7553_examples() {
        // RFC 7553 §4: _ftp._tcp IN URI 10 1 "ftp://ftp1.example.com/public"
        round_trip(
            Rtype::URI,
            b"\x00\x0a\x00\x01ftp://ftp1.example.com/public",
            r#"10 1 "ftp://ftp1.example.com/public""#,
        );
        // An HTTP target.
        round_trip(
            Rtype::URI,
            b"\x00\x0a\x00\x01http://www.example.com/path",
            r#"10 1 "http://www.example.com/path""#,
        );
        // A target longer than 255 bytes is fine (not a character-string).
        let mut wire = b"\x00\x01\x00\x02".to_vec();
        wire.extend_from_slice(b"https://x/");
        wire.extend(core::iter::repeat_n(b'a', 300));
        let text = round_trip(Rtype::URI, &wire, &{
            let mut s = std::string::String::from("1 2 \"https://x/");
            s.extend(core::iter::repeat_n('a', 300));
            s.push('"');
            s
        });
        assert!(text.len() > 300);
        // Quotes and backslashes are escaped.
        round_trip(Rtype::URI, b"\x00\x00\x00\x00a\"\\", r#"0 0 "a\"\\""#);
    }

    #[test]
    fn malformed() {
        // Empty target.
        assert_eq!(
            parse(Rtype::URI, Class::IN, b"\x00\x0a\x00\x01"),
            Err(Error::InvalidRdata)
        );
        assert_eq!(
            parse(Rtype::URI, Class::IN, b"\x00\x0a\x00"),
            Err(Error::UnexpectedEof)
        );
        assert_eq!(Uri::new(1, 1, b""), Err(Error::InvalidRdata));
        let bad = Uri {
            priority: 1,
            weight: 1,
            target: b"",
        };
        let mut buf = [0u8; 8];
        let mut w = WireWriter::new(&mut buf);
        assert_eq!(bad.compose_rdata(&mut w), Err(Error::InvalidRdata));
        assert!(w.written().is_empty());
    }
}
