//! URI record data (RFC 7553 §4.5).

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::wire::{Composer, OutBuf, WireReader};
use crate::zone::Scanner;
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

impl ParseRdataText for Uri<'_> {
    /// `<priority> <weight> <target>` (RFC 7553 §4.5): two decimal
    /// numbers and the URI, normally a quoted string (an unquoted
    /// contiguous run of characters is accepted too; RFC 1035 §5.1
    /// escapes apply). The target is not a `<character-string>`: it may
    /// exceed 255 octets, but must not be empty.
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        out.put_u16(s.u16()?)?;
        out.put_u16(s.u16()?)?;
        for b in s.token()?.unescape() {
            out.put_u8(b?)?;
        }
        Ok(())
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
    use crate::rdata::tests::{parse, round_trip, text_error, text_parse, text_round_trip};
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

    #[test]
    fn text() {
        // RFC 7553 §4 examples of the §4.5 presentation format, and a
        // URI with a query.
        for (text, wire) in [
            (
                r#"10 1 "ftp://ftp1.example.com/public""#,
                &b"\x00\x0a\x00\x01ftp://ftp1.example.com/public"[..],
            ),
            (
                r#"10 1 "http://www.example.com/path""#,
                b"\x00\x0a\x00\x01http://www.example.com/path",
            ),
            (
                r#"1 0 "https://www.example.com/a%20b?c=d""#,
                b"\x00\x01\x00\x00https://www.example.com/a%20b?c=d",
            ),
        ] {
            text_round_trip(Rtype::URI, text, wire, text);
        }
        // Unquoted, split over lines, escapes.
        text_round_trip(
            Rtype::URI,
            "( 65535\n 65535 mailto:a@b )",
            b"\xff\xff\xff\xffmailto:a@b",
            r#"65535 65535 "mailto:a@b""#,
        );
        text_round_trip(
            Rtype::URI,
            r#"0 0 "a\"b\\ c\255""#,
            b"\x00\x00\x00\x00a\"b\\ c\xff",
            r#"0 0 "a\"b\\ c\255""#,
        );
        assert_eq!(
            text_parse(Rtype::URI, r"1 2 \104ttp://x"),
            Ok(b"\x00\x01\x00\x02http://x".to_vec())
        );
        // Longer than 255 octets (not a <character-string>).
        let target = std::format!("https://x/{}", "a".repeat(300));
        let mut wire = b"\x00\x01\x00\x02".to_vec();
        wire.extend_from_slice(target.as_bytes());
        let text = std::format!("1 2 \"{target}\"");
        text_round_trip(Rtype::URI, &text, &wire, &text);
    }

    #[test]
    fn text_malformed() {
        for (text, err) in [
            ("", Error::UnexpectedEof),
            ("10 1", Error::UnexpectedEof),
            // An empty target is not a URI (RFC 7553 §4.4).
            (r#"10 1 """#, Error::InvalidRdata),
            (r#"65536 1 "x""#, Error::InvalidText),
            (r#"10 -1 "x""#, Error::InvalidText),
            (r#""10" 1 "x""#, Error::InvalidText),
            (r#"10 1 "x" "y""#, Error::InvalidText),
            (r#"10 1 "x"#, Error::InvalidText),
            (r#"10 1 "\256""#, Error::InvalidText),
        ] {
            assert_eq!(text_error(Rtype::URI, text), err, "{text}");
        }
    }
}
