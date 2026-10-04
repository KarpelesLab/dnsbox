//! TXT record data (RFC 1035 §3.3.14).

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::charstr::{CharStrIter, CharStrs};
use crate::wire::{Composer, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Error, Result, Rtype};

/// `TXT` record data: one or more `<character-string>`s
/// (RFC 1035 §3.3.14).
///
/// To build a TXT record from separate strings, use [`TxtParts`].
///
/// ```
/// use dnsbox::rdata::{ParseRdataText, Txt};
///
/// let mut buf = [0u8; 64];
/// let txt = Txt::from_text(r#""v=spf1 mx -all" second"#, &mut buf)?;
/// let strings: Vec<&[u8]> = txt.strings().map(|s| s.as_bytes()).collect();
/// assert_eq!(strings, [&b"v=spf1 mx -all"[..], b"second"]);
/// assert_eq!(txt.to_string(), r#""v=spf1 mx -all" "second""#);
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Txt<'a> {
    strings: CharStrs<'a>,
}

impl<'a> Txt<'a> {
    /// Wraps encoded character-strings (length octets included), which
    /// must hold at least one string.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRdata`] for an empty buffer,
    /// [`Error::UnexpectedEof`] if the last string is cut short.
    pub fn from_wire(wire: &'a [u8]) -> Result<Self> {
        let strings = CharStrs::new(wire)?;
        if strings.is_empty() {
            return Err(Error::InvalidRdata);
        }
        Ok(Txt { strings })
    }

    /// The strings.
    #[inline]
    pub fn strings(&self) -> CharStrIter<'a> {
        self.strings.iter()
    }

    /// The encoded RDATA.
    #[inline]
    #[must_use]
    pub const fn as_wire(&self) -> &'a [u8] {
        self.strings.as_wire()
    }
}

impl<'a> ParseRdata<'a> for Txt<'a> {
    const RTYPE: Rtype = Rtype::TXT;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        Txt::from_wire(rdata.peek_rest()).inspect(|_| {
            rdata.read_rest();
        })
    }
}

impl ComposeRdata for Txt<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::TXT
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_bytes(self.as_wire())
    }
}

impl fmt::Display for Txt<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.strings, f)
    }
}

impl ParseRdataText for Txt<'_> {
    /// One or more `<character-string>`s, quoted or not
    /// (RFC 1035 §3.3.14, §5.1).
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        s.char_strings_into(out)
    }
}

/// Compose-only `TXT` data built from separate strings, each at most 255
/// bytes (there must be at least one).
///
/// ```
/// use dnsbox::rdata::TxtParts;
/// use dnsbox::{ComposeRdata, WireWriter};
///
/// let mut buf = [0u8; 32];
/// let mut w = WireWriter::new(&mut buf);
/// TxtParts(&[b"v=spf1", b"-all"]).compose_rdata(&mut w)?;
/// assert_eq!(w.as_bytes(), b"\x06v=spf1\x04-all");
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct TxtParts<'s>(pub &'s [&'s [u8]]);

impl ComposeRdata for TxtParts<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::TXT
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        if self.0.is_empty() {
            return Err(Error::InvalidRdata);
        }
        self.0.iter().try_for_each(|s| c.put_char_string(s))
    }
}

#[cfg(test)]
mod tests {
    use crate::rdata::tests::{text_error, text_round_trip};
    use crate::{Error, Rtype};
    use std::string::String;
    use std::vec::Vec;

    #[test]
    fn text() {
        text_round_trip(
            Rtype::TXT,
            r#""v=spf1 -all""#,
            b"\x0bv=spf1 -all",
            r#""v=spf1 -all""#,
        );
        // Unquoted strings, escapes, empty strings, several strings over
        // several lines.
        text_round_trip(
            Rtype::TXT,
            "( hello \"\" \"a\\\"b\\\\c\" \\065\\066\\067 \"tab\\009\" ; comment\n  \"multi\nline\" )",
            b"\x05hello\x00\x05a\"b\\c\x03ABC\x04tab\x09\x0amulti\nline",
            r#""hello" "" "a\"b\\c" "ABC" "tab\009" "multi\010line""#,
        );
        // Bytes above 0x7e and the full 255-octet string.
        text_round_trip(Rtype::TXT, "\"\\255\\128 \"", b"\x03\xff\x80 ", r#""\255\128 ""#);
        let long = "x".repeat(255);
        let mut wire = Vec::from([255u8]);
        wire.extend_from_slice(long.as_bytes());
        text_round_trip(Rtype::TXT, &long, &wire, &std::format!("\"{long}\""));
        // UTF-8 text is kept as its octets.
        text_round_trip(Rtype::TXT, "\"é\"", b"\x02\xc3\xa9", r#""\195\169""#);

        assert_eq!(text_error(Rtype::TXT, ""), Error::UnexpectedEof);
        assert_eq!(
            text_error(Rtype::TXT, &"x".repeat(256)),
            Error::CharStringTooLong
        );
        assert_eq!(text_error(Rtype::TXT, "\"abc"), Error::InvalidText);
        assert_eq!(text_error(Rtype::TXT, "a\\25"), Error::InvalidText);
        assert_eq!(text_error(Rtype::TXT, "a\\256"), Error::InvalidText);
        assert_eq!(text_error(Rtype::TXT, "a )"), Error::InvalidText);
        // Many strings: the RDATA limit (65535 octets) still applies.
        let many: String = core::iter::repeat_n("\"\" ", 65536).collect();
        assert_eq!(text_error(Rtype::TXT, &many), Error::InvalidRdata);
    }
}
