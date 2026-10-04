//! CAA record data (RFC 8659 §4.1).

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::wire::{Composer, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Error, Result, Rtype};

/// `CAA` record data: a Certification Authority Authorization property
/// (RFC 8659 §4.1).
///
/// The tag must be non-empty and consist of ASCII letters and digits
/// (RFC 8659 §4.1); RDATA with another tag is rejected with
/// [`Error::InvalidRdata`], as is composing such data.
///
/// ```
/// use dnsbox::rdata::{Caa, ParseRdataText};
///
/// let mut buf = [0u8; 64];
/// let caa = Caa::from_text(r#"0 issue "letsencrypt.org""#, &mut buf)?;
/// assert!(caa.tag_is("issue") && !caa.is_critical());
/// assert_eq!(caa.value, b"letsencrypt.org");
/// assert_eq!(caa, Caa::new(0, b"issue", b"letsencrypt.org")?);
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Caa<'a> {
    /// Flags octet; bit 0 (`0x80`) is the Issuer Critical Flag, the other
    /// bits are reserved (RFC 8659 §4.1).
    pub flags: u8,
    /// Property identifier, e.g. `issue`, `issuewild`, `iodef`
    /// (RFC 8659 §4.1 "Tag"; matched ASCII-case-insensitively).
    pub tag: &'a [u8],
    /// Property value: the rest of the RDATA, interpreted per tag
    /// (RFC 8659 §4.1 "Value").
    pub value: &'a [u8],
}

impl<'a> Caa<'a> {
    /// The Issuer Critical Flag bit of [`flags`](Self::flags)
    /// (RFC 8659 §4.1).
    pub const ISSUER_CRITICAL: u8 = 0x80;

    /// Builds CAA data, checking the tag (RFC 8659 §4.1).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRdata`] unless the tag is 1 to 255 ASCII letters
    /// and digits.
    pub const fn new(flags: u8, tag: &'a [u8], value: &'a [u8]) -> Result<Self> {
        if !valid_tag(tag) {
            return Err(Error::InvalidRdata);
        }
        Ok(Caa { flags, tag, value })
    }

    /// Whether the Issuer Critical Flag is set: a CA that does not
    /// understand the tag must not issue (RFC 8659 §4.1).
    #[inline]
    #[must_use]
    pub const fn is_critical(&self) -> bool {
        self.flags & Self::ISSUER_CRITICAL != 0
    }

    /// Whether the tag equals `tag`, ASCII-case-insensitively
    /// (RFC 8659 §4.1: "Matching of tags is case insensitive").
    #[inline]
    #[must_use]
    pub fn tag_is(&self, tag: &str) -> bool {
        self.tag.eq_ignore_ascii_case(tag.as_bytes())
    }
}

/// Whether `tag` is a valid CAA tag: 1 to 255 ASCII alphanumerics
/// (RFC 8659 §4.1).
const fn valid_tag(tag: &[u8]) -> bool {
    if tag.is_empty() || tag.len() > 255 {
        return false;
    }
    let mut i = 0;
    while i < tag.len() {
        if !tag[i].is_ascii_alphanumeric() {
            return false;
        }
        i += 1;
    }
    true
}

impl ParseRdataText for Caa<'_> {
    /// `<flags> <tag> <value>` (RFC 8659 §4.1.1): the flags as a decimal
    /// number, the tag as an unquoted token, and the value either as a
    /// contiguous run of characters or as a quoted string (RFC 1035 §5.1
    /// escapes apply). The value is not a `<character-string>`: it may
    /// exceed 255 octets.
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        out.put_u8(s.u8()?)?;
        // Tags are short ASCII alphanumerics; the wire parser checks them.
        let mut tag = [0u8; 255];
        let mut len = 0;
        for b in s.word()?.unescape() {
            *tag.get_mut(len).ok_or(Error::InvalidRdata)? = b?;
            len += 1;
        }
        out.put_char_string(tag.get(..len).unwrap_or(&[]))?;
        for b in s.token()?.unescape() {
            out.put_u8(b?)?;
        }
        Ok(())
    }
}

impl<'a> ParseRdata<'a> for Caa<'a> {
    const RTYPE: Rtype = Rtype::CAA;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        let flags = rdata.read_u8()?;
        let tag = rdata.read_char_string()?.as_bytes();
        if !valid_tag(tag) {
            return Err(Error::InvalidRdata);
        }
        Ok(Caa {
            flags,
            tag,
            value: rdata.read_rest(),
        })
    }
}

impl ComposeRdata for Caa<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::CAA
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        if !valid_tag(self.tag) {
            return Err(Error::InvalidRdata);
        }
        c.put_u8(self.flags)?;
        c.put_char_string(self.tag)?;
        c.put_bytes(self.value)
    }
}

impl fmt::Display for Caa<'_> {
    /// `flags tag "value"` (RFC 8659 §4.1.1).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ", self.flags)?;
        // The tag is validated ASCII alphanumerics.
        crate::text::fmt_label(f, self.tag)?;
        f.write_str(" ")?;
        crate::text::fmt_quoted(f, self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Class;
    use crate::rdata::tests::{compose, parse, round_trip, text_error, text_parse, text_round_trip};
    use crate::wire::WireWriter;

    #[test]
    fn rfc8659_examples() {
        // RFC 8659 §4.2: CAA 0 issue "ca1.example.net"
        round_trip(
            Rtype::CAA,
            b"\x00\x05issueca1.example.net",
            r#"0 issue "ca1.example.net""#,
        );
        // RFC 8659 §4.3: CAA 0 issuewild "ca2.example.org"
        round_trip(
            Rtype::CAA,
            b"\x00\x09issuewildca2.example.org",
            r#"0 issuewild "ca2.example.org""#,
        );
        // RFC 8659 §4.2: CAA 0 issue ";" (no CA may issue).
        round_trip(Rtype::CAA, b"\x00\x05issue;", r#"0 issue ";""#);
        // RFC 8659 §4.4: CAA 0 iodef "mailto:security@example.com"
        round_trip(
            Rtype::CAA,
            b"\x00\x05iodefmailto:security@example.com",
            r#"0 iodef "mailto:security@example.com""#,
        );
        // RFC 8659 §4.1 style: CAA 128 tbs "Unknown" (critical, unknown tag).
        let s = round_trip(Rtype::CAA, b"\x80\x03tbsUnknown", r#"128 tbs "Unknown""#);
        assert_eq!(s, r#"128 tbs "Unknown""#);
        // Empty value and escaped value bytes.
        round_trip(Rtype::CAA, b"\x00\x05issue", r#"0 issue """#);
        round_trip(
            Rtype::CAA,
            b"\x00\x05issuea\"b\\\x00",
            r#"0 issue "a\"b\\\000""#,
        );
    }

    #[test]
    fn accessors() {
        let caa = Caa::new(0x80, b"IssueWild", b"x").unwrap();
        assert!(caa.is_critical());
        assert!(caa.tag_is("issuewild"));
        assert!(!caa.tag_is("issue"));
        assert_eq!(compose(&caa), b"\x80\x09IssueWildx");
        assert!(!Caa::new(0, b"issue", b"").unwrap().is_critical());
    }

    #[test]
    fn malformed() {
        // Empty tag (RFC 8659 §4.1: the tag length MUST be at least 1).
        assert_eq!(
            parse(Rtype::CAA, Class::IN, b"\x00\x00value"),
            Err(Error::InvalidRdata)
        );
        // Non-alphanumeric tag.
        assert_eq!(
            parse(Rtype::CAA, Class::IN, b"\x00\x02a-x"),
            Err(Error::InvalidRdata)
        );
        // Tag length past the end.
        assert_eq!(
            parse(Rtype::CAA, Class::IN, b"\x00\x09issue"),
            Err(Error::UnexpectedEof)
        );
        assert_eq!(parse(Rtype::CAA, Class::IN, b""), Err(Error::UnexpectedEof));
        assert_eq!(Caa::new(0, b"", b"x"), Err(Error::InvalidRdata));
        assert_eq!(Caa::new(0, b"a b", b"x"), Err(Error::InvalidRdata));
        assert_eq!(Caa::new(0, &[b'a'; 256], b"x"), Err(Error::InvalidRdata));
        // Composing an invalid tag fails without writing.
        let bad = Caa {
            flags: 0,
            tag: b"",
            value: b"x",
        };
        let mut buf = [0u8; 16];
        let mut w = WireWriter::new(&mut buf);
        assert_eq!(bad.compose_rdata(&mut w), Err(Error::InvalidRdata));
        assert!(w.as_bytes().is_empty());
    }

    #[test]
    fn text() {
        // RFC 8659 §4.2–4.4 and §4.1 examples.
        for (text, wire) in [
            (r#"0 issue "ca1.example.net""#, &b"\x00\x05issueca1.example.net"[..]),
            (
                r#"0 issue "ca1.example.net; account=230123""#,
                b"\x00\x05issueca1.example.net; account=230123",
            ),
            (r#"0 issue ";""#, b"\x00\x05issue;"),
            (r#"0 issuewild "ca2.example.org""#, b"\x00\x09issuewildca2.example.org"),
            (
                r#"0 iodef "mailto:security@example.com""#,
                b"\x00\x05iodefmailto:security@example.com",
            ),
            (
                r#"0 iodef "https://iodef.example.com/""#,
                b"\x00\x05iodefhttps://iodef.example.com/",
            ),
            (r#"128 tbs "Unknown""#, b"\x80\x03tbsUnknown"),
            // RFC 8657 §3: account and validation-method parameters.
            (
                r#"0 issue "example.net; accounturi=https://example.net/account/1234""#,
                b"\x00\x05issueexample.net; accounturi=https://example.net/account/1234",
            ),
        ] {
            text_round_trip(Rtype::CAA, text, wire, text);
        }
        // RFC 8659 §4.1.1: the value may also be a contiguous run of
        // characters; tags keep their case; escapes in the value.
        text_round_trip(
            Rtype::CAA,
            "0 Issue ca1.example.net",
            b"\x00\x05Issueca1.example.net",
            r#"0 Issue "ca1.example.net""#,
        );
        text_round_trip(Rtype::CAA, r#"0 issue """#, b"\x00\x05issue", r#"0 issue """#);
        text_round_trip(
            Rtype::CAA,
            r#"( 0 issue "a\"b\\\000\255" )"#,
            b"\x00\x05issuea\"b\\\x00\xff",
            r#"0 issue "a\"b\\\000\255""#,
        );
        // An escaped tag octet that is alphanumeric is fine.
        assert_eq!(
            text_parse(Rtype::CAA, r#"0 \105ssue x"#),
            Ok(b"\x00\x05issuex".to_vec())
        );
        // The value is not a <character-string>: longer than 255 octets.
        let long = "x".repeat(1000);
        let mut wire = b"\x00\x05issue".to_vec();
        wire.extend_from_slice(long.as_bytes());
        let text = std::format!("0 issue \"{long}\"");
        text_round_trip(Rtype::CAA, &text, &wire, &text);
    }

    #[test]
    fn text_malformed() {
        for (text, err) in [
            ("", Error::UnexpectedEof),
            ("0", Error::UnexpectedEof),
            ("0 issue", Error::UnexpectedEof),
            ("256 issue x", Error::InvalidText),
            ("-1 issue x", Error::InvalidText),
            (r#"0 "issue" x"#, Error::InvalidText),
            (r#"0 issue "x" y"#, Error::InvalidText),
            (r#"0 issue "x"#, Error::InvalidText),
            (r#"0 issue "\999""#, Error::InvalidText),
            // RFC 8659 §4.1: tags are non-empty ASCII letters and digits.
            ("0 is-sue x", Error::InvalidRdata),
            (r#"0 is\032sue x"#, Error::InvalidRdata),
        ] {
            assert_eq!(text_error(Rtype::CAA, text), err, "{text}");
        }
        let long_tag = std::format!("0 {} x", "a".repeat(256));
        assert_eq!(text_error(Rtype::CAA, &long_tag), Error::InvalidRdata);
        // Past the 65535-octet RDATA limit.
        let huge = std::format!("0 issue {}", "x".repeat(65535));
        assert!(text_parse(Rtype::CAA, &huge).is_err());
    }
}
