//! Presentation-format parsing of SVCB/HTTPS record data (RFC 9460 §2.1,
//! Appendix A).

use core::net::{Ipv4Addr, Ipv6Addr};
use core::str::FromStr;

use super::builder::Out;
use super::{SvcParamKey, Svcb, SvcbBuilder};
use crate::util::base64;
use crate::wire::OutBuf;
use crate::zone::{Scanner, Unescape};
use crate::{Error, Result};

/// The largest RDATA a record can carry (RDLENGTH is 16 bits).
const MAX_RDATA: usize = u16::MAX as usize;

/// Parses `SvcPriority TargetName SvcParams` (RFC 9460 §2.1) from the
/// remaining tokens of `s` into `buf` (see [`Svcb::from_text`]). The
/// TargetName is completed with the scanner's origin if relative.
pub(super) fn parse<'b>(s: &mut Scanner<'_>, buf: &'b mut [u8]) -> Result<Svcb<'b>> {
    let priority = s.u16()?;
    let target = s.name()?;
    let mut b = SvcbBuilder::new(buf, priority, &target)?;
    while let Some(token) = s.next_token()? {
        // `key="value"` is one unquoted token; a quoted key is not.
        if token.is_quoted() {
            return Err(Error::InvalidText);
        }
        param(&mut b, token.as_bytes())?;
    }
    b.finish()
}

/// [`parse`] appending the wire form to `out`
/// ([`ParseRdataText`](crate::rdata::ParseRdataText) for SVCB and HTTPS).
///
/// SvcParams are sorted as they are inserted, which needs random access to
/// the output: the room the RDATA may take is reserved in `out` first,
/// then trimmed. Nothing is allocated beyond what `out` itself does.
pub(super) fn parse_into<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
    const ZEROS: [u8; 256] = [0; 256];
    let start = out.as_bytes().len();
    let mut room = out.capacity_limit().saturating_sub(start).min(MAX_RDATA);
    while room > 0 {
        let n = room.min(ZEROS.len());
        out.append(ZEROS.get(..n).unwrap_or(&[]))?;
        room -= n;
    }
    let res = match out.as_bytes_mut().get_mut(start..) {
        Some(buf) => parse(s, buf)
            .map(|svcb| 2 + svcb.target.wire_len() + svcb.params.as_wire().len()),
        None => Err(Error::BufferTooSmall),
    };
    match res {
        Ok(len) => {
            out.truncate(start + len);
            Ok(())
        }
        Err(e) => {
            out.truncate(start);
            Err(e)
        }
    }
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
                for c in Unescape::new(value) {
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
    let item = o.as_bytes().get(start + 1..).ok_or(Error::InvalidText)?;
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
    for c in Unescape::new(value) {
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
    crate::zone::decimal(digits)
}

/// An IP address in standard text form.
fn parse_addr<A: FromStr>(text: &[u8]) -> Result<A> {
    core::str::from_utf8(text)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or(Error::InvalidText)
}
