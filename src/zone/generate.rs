//! BIND's `$GENERATE` directive: the iteration range and the `$`
//! substitutions in the owner and RDATA templates.
//!
//! Syntax (BIND 9 ARM, "BIND Primary File Extension: the $GENERATE
//! Directive"): `$GENERATE <start>-<stop>[/<step>] <lhs> [TTL] [class]
//! <type> <rhs>`. In the templates, `$` is replaced by the iterator value
//! and `${offset[,width[,base]]}` by the value plus `offset`, zero-padded
//! to `width`, in `base` `d` (decimal), `o` (octal), `x`/`X` (hex) or
//! `n`/`N` (reversed nibbles separated by dots, for `ip6.arpa`); `\$` and
//! `$$` are a literal `$`.

use crate::{Error, Result};

/// Most records one `$GENERATE` directive may produce (a hostile zone file
/// must not turn one line into billions of records). 65536 covers a whole
/// `/16` of reverse entries.
pub const MAX_GENERATE: u32 = 65536;

/// Longest text a template may expand to.
pub(super) const TEXT_MAX: usize = 1024;

/// An iteration range: `start-stop[/step]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Range {
    pub(super) start: u32,
    pub(super) stop: u32,
    pub(super) step: u32,
}

impl Range {
    /// Parses `start-stop[/step]`: `start <= stop`, `step >= 1`, and at
    /// most [`MAX_GENERATE`] iterations.
    pub(super) fn parse(text: &[u8]) -> Result<Range> {
        let (range, step) = match text.iter().position(|&c| c == b'/') {
            Some(i) => (
                text.get(..i).unwrap_or(&[]),
                number(text.get(i + 1..).unwrap_or(&[]))?,
            ),
            None => (text, 1),
        };
        let dash = range
            .iter()
            .position(|&c| c == b'-')
            .ok_or(Error::InvalidText)?;
        let start = number(range.get(..dash).unwrap_or(&[]))?;
        let stop = number(range.get(dash + 1..).unwrap_or(&[]))?;
        if start > stop || step == 0 || (stop - start) / step >= MAX_GENERATE {
            return Err(Error::InvalidText);
        }
        Ok(Range { start, stop, step })
    }

    /// The value after `v`, if still in range.
    pub(super) fn after(&self, v: u32) -> Option<u32> {
        v.checked_add(self.step).filter(|&n| n <= self.stop)
    }
}

/// A plain decimal `u32`.
fn number(digits: &[u8]) -> Result<u32> {
    if digits.is_empty() || digits.len() > 10 || !digits.iter().all(u8::is_ascii_digit) {
        return Err(Error::InvalidText);
    }
    let v = digits
        .iter()
        .fold(0u64, |v, d| v * 10 + u64::from(d - b'0'));
    u32::try_from(v).map_err(|_| Error::InvalidText)
}

/// Bounded output cursor.
struct Out<'o> {
    buf: &'o mut [u8],
    len: usize,
}

impl Out<'_> {
    fn push(&mut self, c: u8) -> Result<()> {
        *self.buf.get_mut(self.len).ok_or(Error::InvalidText)? = c;
        self.len += 1;
        Ok(())
    }
}

/// Expands `template` for iterator value `value` into `out`, returning the
/// length. Escapes other than `\$` are copied as written (they are decoded
/// when the result is parsed). Fails with [`Error::InvalidText`] on a
/// malformed `${...}`, a negative value, or output longer than `out`.
pub(super) fn substitute(template: &[u8], value: u32, out: &mut [u8]) -> Result<usize> {
    let mut o = Out { buf: out, len: 0 };
    let mut i = 0;
    while let Some(&c) = template.get(i) {
        i += 1;
        match c {
            b'\\' => {
                let next = template.get(i).copied().ok_or(Error::InvalidText)?;
                i += 1;
                // `\$` keeps its backslash: a `$` in a name or string means
                // the same either way, and `\$` stays valid presentation
                // format.
                o.push(b'\\')?;
                o.push(next)?;
            }
            // `$$` is a literal `$` (kept by BIND for compatibility).
            b'$' if template.get(i) == Some(&b'$') => {
                i += 1;
                o.push(b'\\')?;
                o.push(b'$')?;
            }
            b'$' if template.get(i) == Some(&b'{') => {
                let rest = template.get(i + 1..).unwrap_or(&[]);
                let close = rest
                    .iter()
                    .position(|&c| c == b'}')
                    .ok_or(Error::InvalidText)?;
                modifier(rest.get(..close).unwrap_or(&[]), value, &mut o)?;
                i += 1 + close + 1;
            }
            b'$' => format(i64::from(value), 0, b'd', &mut o)?,
            c => o.push(c)?,
        }
    }
    Ok(o.len)
}

/// Expands `offset[,width[,base]]`.
fn modifier(spec: &[u8], value: u32, o: &mut Out<'_>) -> Result<()> {
    let mut parts = spec.split(|&c| c == b',');
    let offset = parts.next().ok_or(Error::InvalidText)?;
    let (negative, digits) = match offset {
        [b'-', rest @ ..] => (true, rest),
        [b'+', rest @ ..] => (false, rest),
        _ => (false, offset),
    };
    let offset = i64::from(number(digits)?);
    let offset = if negative { -offset } else { offset };
    let width = match parts.next() {
        Some(w) => number(w)?,
        None => 0,
    };
    let base = match parts.next() {
        Some([b]) if b"doxXnN".contains(b) => *b,
        Some(_) => return Err(Error::InvalidText),
        None => b'd',
    };
    if parts.next().is_some() {
        return Err(Error::InvalidText);
    }
    format(i64::from(value) + offset, width, base, o)
}

/// Writes `v` in `base`, zero-padded to `width` characters.
fn format(v: i64, width: u32, base: u8, o: &mut Out<'_>) -> Result<()> {
    let mut v = u64::try_from(v).map_err(|_| Error::InvalidText)?;
    let digits: &[u8; 16] = if base.is_ascii_uppercase() {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    if base == b'n' || base == b'N' {
        // BIND's nibble mode: least significant nibble first, dot
        // separated; `width` counts output characters, dots included.
        let mut width = i64::from(width);
        loop {
            o.push(digits[(v & 0xf) as usize])?;
            v >>= 4;
            width -= 1;
            if width > 0 || v != 0 {
                o.push(b'.')?;
                width -= 1;
            }
            if v == 0 && width <= 0 {
                return Ok(());
            }
        }
    }
    let radix: u64 = match base {
        b'o' => 8,
        b'x' | b'X' => 16,
        _ => 10,
    };
    // u64 in octal is at most 22 digits.
    let mut tmp = [0u8; 22];
    let mut n = 0;
    loop {
        tmp[n] = digits[(v % radix) as usize];
        n += 1;
        v /= radix;
        if v == 0 {
            break;
        }
    }
    for _ in n..usize::try_from(width).unwrap_or(usize::MAX) {
        o.push(b'0')?;
    }
    for &c in tmp[..n].iter().rev() {
        o.push(c)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sub(template: &str, v: u32) -> Result<std::string::String> {
        let mut buf = [0u8; 64];
        let n = substitute(template.as_bytes(), v, &mut buf)?;
        Ok(std::string::String::from_utf8(buf[..n].to_vec()).unwrap())
    }

    #[test]
    fn ranges() {
        assert_eq!(
            Range::parse(b"1-10"),
            Ok(Range {
                start: 1,
                stop: 10,
                step: 1
            })
        );
        let r = Range::parse(b"0-255/16").unwrap();
        assert_eq!((r.start, r.stop, r.step), (0, 255, 16));
        assert_eq!(r.after(240), None);
        assert_eq!(r.after(224), Some(240));
        assert_eq!(Range::parse(b"0-65535").map(|r| r.stop), Ok(65535));
        assert_eq!(
            Range::parse(b"0-4294967295/65536").map(|r| r.step),
            Ok(65536)
        );
        for bad in [
            &b"5-1"[..],
            b"1-",
            b"-1",
            b"1",
            b"1-2/0",
            b"1-2/",
            b"0-65536",
            b"0-4294967296",
            b"a-b",
            b"1--2",
        ] {
            assert_eq!(Range::parse(bad), Err(Error::InvalidText), "{bad:?}");
        }
        let r = Range::parse(b"4294967290-4294967295/3").unwrap();
        assert_eq!(r.after(4294967293), None);
    }

    #[test]
    fn substitutions() {
        assert_eq!(sub("host-$", 7).unwrap(), "host-7");
        assert_eq!(sub("$.$", 12).unwrap(), "12.12");
        assert_eq!(sub("a\\$b$", 3).unwrap(), "a\\$b3");
        assert_eq!(sub("a$$b$", 3).unwrap(), "a\\$b3");
        // An even nibble width ends in a dot, as in BIND.
        assert_eq!(sub("${0,2,n}", 1).unwrap(), "1.");
        assert_eq!(sub("${0,3,d}", 5).unwrap(), "005");
        assert_eq!(sub("${10}", 5).unwrap(), "15");
        assert_eq!(sub("${-5,0,d}", 5).unwrap(), "0");
        assert_eq!(sub("${+1,2,x}", 254).unwrap(), "ff");
        assert_eq!(sub("${0,4,X}", 255).unwrap(), "00FF");
        assert_eq!(sub("${0,2,o}", 8).unwrap(), "10");
        // BIND nibble mode: `${0,7,n}` of 0x1234 is "4.3.2.1".
        assert_eq!(sub("${0,7,n}", 0x1234).unwrap(), "4.3.2.1");
        assert_eq!(sub("${0,7,N}", 0xab).unwrap(), "B.A.0.0");
        assert_eq!(sub("${0,0,n}", 0).unwrap(), "0");
        assert_eq!(sub("${0,0,n}", 0x21).unwrap(), "1.2");
        for bad in [
            "${",
            "${}",
            "${-6}",
            "${0,1,q}",
            "${0,1,d,1}",
            "a\\",
            "${x}",
        ] {
            assert_eq!(sub(bad, 5), Err(Error::InvalidText), "{bad}");
        }
        // Output bounded by the buffer, even with a huge width.
        assert_eq!(sub("${0,4294967295}", 1), Err(Error::InvalidText));
        assert_eq!(sub("${0,4294967295,n}", 1), Err(Error::InvalidText));
        assert_eq!(sub(&"${0}".repeat(40), 99), Err(Error::InvalidText));
    }
}
