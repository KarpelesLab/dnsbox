//! Presentation-format parsing of SVCB/HTTPS record data (RFC 9460 §2.1,
//! Appendix A).

use core::net::{Ipv4Addr, Ipv6Addr};
use core::str::FromStr;

use super::builder::Out;
use super::{SvcParamKey, Svcb, SvcbBuilder};
use crate::name::NameBuf;
use crate::util::base64;
use crate::{Error, Result};

/// Parses `SvcPriority TargetName SvcParams` into `buf` (see
/// [`Svcb::from_text`]).
pub(super) fn parse<'b>(text: &str, buf: &'b mut [u8]) -> Result<Svcb<'b>> {
    let mut tokens = Tokens(text.as_bytes());
    let priority = tokens.next().ok_or(Error::InvalidText)??;
    let priority = parse_u16(priority)?;
    let target = tokens.next().ok_or(Error::InvalidText)??;
    // Domain names are never quoted (RFC 1035 §5.1).
    if unquote(target)? != target {
        return Err(Error::InvalidText);
    }
    let target = NameBuf::from_text(target)?;
    let mut b = SvcbBuilder::new(buf, priority, &target)?;
    for token in tokens {
        param(&mut b, token?)?;
    }
    b.finish()
}

/// Parses one `key[=value]` token and adds it to `b`.
fn param(b: &mut SvcbBuilder<'_>, token: &[u8]) -> Result<()> {
    let (key, value) = match token.iter().position(|&c| c == b'=') {
        Some(eq) => {
            let (key, value) = token.split_at(eq);
            (key, value.get(1..))
        }
        None => (token, None),
    };
    // RFC 9460 §2.1: 1-63 characters from a-z, 0-9 and "-" (accepted
    // case-insensitively, like other mnemonics).
    if key.is_empty()
        || key.len() > 63
        || !key.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
    {
        return Err(Error::InvalidText);
    }
    let key = core::str::from_utf8(key).map_err(|_| Error::InvalidText)?;
    let key = SvcParamKey::from_str(key)?;
    let value = unquote(value.unwrap_or(b""))?;
    match key {
        SvcParamKey::MANDATORY => {
            let value = unescaped(value)?;
            b.insert(key, |o| {
                for item in value.split(|&c| c == b',') {
                    let item = core::str::from_utf8(item).map_err(|_| Error::InvalidText)?;
                    if item.is_empty() {
                        return Err(Error::InvalidText);
                    }
                    o.put_u16(SvcParamKey::from_str(item)?.get())?;
                }
                o.sort_u16();
                Ok(())
            })?;
        }
        SvcParamKey::PORT => {
            let port = parse_u16(unescaped(value)?)?;
            b.port(port)?;
        }
        SvcParamKey::IPV4HINT => {
            let value = unescaped(value)?;
            b.insert(key, |o| {
                for item in value.split(|&c| c == b',') {
                    o.extend(&parse_addr::<Ipv4Addr>(item)?.octets())?;
                }
                Ok(())
            })?;
        }
        SvcParamKey::IPV6HINT => {
            let value = unescaped(value)?;
            b.insert(key, |o| {
                for item in value.split(|&c| c == b',') {
                    o.extend(&parse_addr::<Ipv6Addr>(item)?.octets())?;
                }
                Ok(())
            })?;
        }
        SvcParamKey::ECH => {
            let value = unescaped(value)?;
            b.insert(key, |o| {
                let n = base64::decode(value, o.spare())?;
                o.advance(n);
                Ok(())
            })?;
        }
        SvcParamKey::TLS_SUPPORTED_GROUPS => {
            let value = unescaped(value)?;
            b.insert(key, |o| {
                for item in value.split(|&c| c == b',') {
                    o.put_u16(parse_u16(item)?)?;
                }
                Ok(())
            })?;
        }
        SvcParamKey::ALPN | SvcParamKey::DOCPATH => {
            b.insert(key, |o| decode_list(value, o, |_, _| Ok(())))?;
        }
        SvcParamKey::OOTS => {
            b.insert(key, |o| decode_list(value, o, oots_entry))?;
        }
        // dohpath, the keys with empty values, and unknown keys: the
        // character-string decoded value is the wire value (RFC 9460 §2.1);
        // the builder then checks it against the key's format.
        _ => {
            b.insert(key, |o| {
                for c in Unescape(value) {
                    o.push(c?)?;
                }
                Ok(())
            })?;
        }
    }
    Ok(())
}

/// Turns the `proto:weight` item just written at `start` (length octet
/// included) into the `oots` wire entry: the length covers `proto` and the
/// colon becomes the weight octet.
fn oots_entry(o: &mut Out<'_>, start: usize) -> Result<()> {
    let item = o.written().get(start + 1..).ok_or(Error::InvalidText)?;
    let colon = item
        .iter()
        .rposition(|&c| c == b':')
        .ok_or(Error::InvalidText)?;
    let digits = item.get(colon + 1..).ok_or(Error::InvalidText)?;
    if digits.is_empty() || digits.len() > 3 {
        return Err(Error::InvalidText);
    }
    let weight = u8::try_from(parse_u16(digits)?).map_err(|_| Error::InvalidText)?;
    if colon == 0 {
        return Err(Error::InvalidText);
    }
    let colon_at = start + 1 + colon;
    o.set(colon_at, weight)?;
    o.truncate(colon_at + 1);
    o.set(start, colon as u8)
}

/// Character-string decodes `value` and splits it as a comma-separated
/// value-list (RFC 9460 Appendix A.1: `\,` and `\\` escape a literal comma
/// or backslash), writing each item as a length-prefixed string of 1–255
/// octets and calling `finish_item(out, item_start)` after each. An empty
/// value is an empty list.
fn decode_list(
    value: &[u8],
    o: &mut Out<'_>,
    finish_item: fn(&mut Out<'_>, usize) -> Result<()>,
) -> Result<()> {
    if value.is_empty() {
        return Ok(());
    }
    let end_item = |o: &mut Out<'_>, start: usize| -> Result<()> {
        let len = o.len() - start - 1;
        match u8::try_from(len) {
            Ok(len) if len > 0 => o.set(start, len)?,
            _ => return Err(Error::InvalidText),
        }
        finish_item(o, start)
    };
    let mut start = o.len();
    o.push(0)?;
    let mut escaped = false;
    for c in Unescape(value) {
        let c = c?;
        if escaped {
            if c != b',' && c != b'\\' {
                return Err(Error::InvalidText);
            }
            o.push(c)?;
            escaped = false;
        } else if c == b'\\' {
            escaped = true;
        } else if c == b',' {
            end_item(o, start)?;
            start = o.len();
            o.push(0)?;
        } else {
            o.push(c)?;
        }
    }
    if escaped {
        return Err(Error::InvalidText);
    }
    end_item(o, start)
}

/// Strips the quotes of a quoted char-string (RFC 9460 Appendix A). A
/// contiguous one may not contain quotes.
fn unquote(value: &[u8]) -> Result<&[u8]> {
    if let [b'"', inner @ .., b'"'] = value {
        // The tokenizer guarantees an inner quote is escaped.
        return Ok(inner);
    }
    let mut escaped = false;
    for &c in value {
        if c == b'"' && !escaped {
            return Err(Error::InvalidText);
        }
        escaped = c == b'\\' && !escaped;
    }
    Ok(value)
}

/// Values of keys whose presentation format "MUST NOT contain escape
/// sequences" (RFC 9460 §7.2, §7.3, §8; RFC 9848 §3).
fn unescaped(value: &[u8]) -> Result<&[u8]> {
    if value.contains(&b'\\') {
        Err(Error::InvalidText)
    } else {
        Ok(value)
    }
}

/// A plain decimal number 0–65535 (no sign, no escapes).
fn parse_u16(digits: &[u8]) -> Result<u16> {
    if digits.is_empty() || digits.len() > 5 || !digits.iter().all(u8::is_ascii_digit) {
        return Err(Error::InvalidText);
    }
    let v = digits
        .iter()
        .fold(0u32, |v, d| v * 10 + u32::from(d - b'0'));
    u16::try_from(v).map_err(|_| Error::InvalidText)
}

/// An IP address in standard text form.
fn parse_addr<A: FromStr>(text: &[u8]) -> Result<A> {
    core::str::from_utf8(text)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or(Error::InvalidText)
}

/// Character-string decoding (RFC 1035 §5.1, RFC 9460 Appendix A): `\DDD`
/// is the octet DDD, `\X` is X; other octets stand for themselves.
struct Unescape<'t>(&'t [u8]);

impl Iterator for Unescape<'_> {
    type Item = Result<u8>;

    fn next(&mut self) -> Option<Result<u8>> {
        let (&c, rest) = self.0.split_first()?;
        if c != b'\\' {
            self.0 = rest;
            return Some(Ok(c));
        }
        let (byte, used) = match rest {
            [a, b, c, ..] if a.is_ascii_digit() && b.is_ascii_digit() && c.is_ascii_digit() => {
                let v = u16::from(a - b'0') * 100 + u16::from(b - b'0') * 10 + u16::from(c - b'0');
                match u8::try_from(v) {
                    Ok(v) => (v, 3),
                    Err(_) => return self.fail(),
                }
            }
            [a, ..] if a.is_ascii_digit() => return self.fail(),
            [x, ..] => (*x, 1),
            [] => return self.fail(),
        };
        self.0 = rest.get(used..).unwrap_or(&[]);
        Some(Ok(byte))
    }
}

impl Unescape<'_> {
    /// Reports a bad escape once, then ends.
    fn fail(&mut self) -> Option<Result<u8>> {
        self.0 = &[];
        Some(Err(Error::InvalidText))
    }
}

/// Splits presentation-format RDATA into tokens: runs of non-blank
/// characters, where a backslash escapes the next character and quotes
/// group blanks. Parentheses (line continuation) count as blanks and `;`
/// starts a comment up to the end of the line (RFC 1035 §5.1).
struct Tokens<'t>(&'t [u8]);

impl<'t> Iterator for Tokens<'t> {
    type Item = Result<&'t [u8]>;

    fn next(&mut self) -> Option<Result<&'t [u8]>> {
        // Skip blanks, parentheses and comments.
        loop {
            match self.0.split_first() {
                Some((c, rest)) if c.is_ascii_whitespace() || matches!(c, b'(' | b')') => {
                    self.0 = rest;
                }
                Some((b';', rest)) => {
                    let eol = rest.iter().position(|&c| c == b'\n').unwrap_or(rest.len());
                    self.0 = rest.get(eol..).unwrap_or(&[]);
                }
                Some(_) => break,
                None => return None,
            }
        }
        let mut quoted = false;
        let mut i = 0;
        while let Some(&c) = self.0.get(i) {
            match c {
                b'\\' => i += 1,
                b'"' => quoted = !quoted,
                c if !quoted && (c.is_ascii_whitespace() || matches!(c, b'(' | b')' | b';')) => {
                    break;
                }
                _ => {}
            }
            i += 1;
        }
        if quoted || i > self.0.len() {
            // Unterminated quote, or a trailing lone backslash.
            self.0 = &[];
            return Some(Err(Error::InvalidText));
        }
        let (token, rest) = self.0.split_at(i);
        self.0 = rest;
        Some(Ok(token))
    }
}
