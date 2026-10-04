//! Presentation-format (zone-file text) helpers shared by `Display`
//! implementations: escaping (RFC 1035 §5.1), hex, base64 and base32hex
//! (RFC 4648), and the generic RDATA form of RFC 3597 §5.
//!
//! Record-data `Display` impls should use these rather than rolling their
//! own, so every type escapes and encodes identically.

use core::fmt;

/// Characters that must be backslash-escaped inside a label, besides
/// non-printable bytes: the label separator, the escape character, and the
/// characters with special meaning in zone files (RFC 1035 §5.1).
const fn label_special(b: u8) -> bool {
    matches!(b, b'.' | b'\\' | b'"' | b'(' | b')' | b';' | b'@' | b'$')
}

/// Writes runs of bytes, escaping those for which `escape` returns true with
/// a backslash and non-printable ones (outside `0x21..=0x7e`, plus space
/// when `space_ok` is false) as `\DDD`.
fn fmt_escaped<W: fmt::Write + ?Sized>(
    w: &mut W,
    bytes: &[u8],
    escape: fn(u8) -> bool,
    space_ok: bool,
) -> fmt::Result {
    let mut run = 0;
    for (i, &b) in bytes.iter().enumerate() {
        let printable = (0x21..=0x7e).contains(&b) || (space_ok && b == b' ');
        if printable && !escape(b) {
            continue;
        }
        // Everything in `bytes[run..i]` is printable ASCII.
        if let Ok(s) = core::str::from_utf8(bytes.get(run..i).unwrap_or(&[])) {
            w.write_str(s)?;
        }
        if printable {
            w.write_char('\\')?;
            w.write_char(b as char)?;
        } else {
            write!(w, "\\{b:03}")?;
        }
        run = i + 1;
    }
    if let Ok(s) = core::str::from_utf8(bytes.get(run..).unwrap_or(&[])) {
        w.write_str(s)?;
    }
    Ok(())
}

/// Writes a label in presentation format: `.`, `\`, `"`, `(`, `)`, `;`,
/// `@` and `$` are backslash-escaped; space and non-printable bytes become
/// `\DDD` (RFC 1035 §5.1, RFC 4343 §2.1).
pub fn fmt_label<W: fmt::Write + ?Sized>(w: &mut W, label: &[u8]) -> fmt::Result {
    fmt_escaped(w, label, label_special, false)
}

/// Writes a `<character-string>` in quoted presentation format: `"` and `\`
/// are backslash-escaped; non-printable bytes become `\DDD` (RFC 1035 §5.1).
pub fn fmt_quoted<W: fmt::Write + ?Sized>(w: &mut W, data: &[u8]) -> fmt::Result {
    w.write_char('"')?;
    fmt_escaped(w, data, |b| matches!(b, b'"' | b'\\'), true)?;
    w.write_char('"')
}

/// Writes RDATA in the generic RFC 3597 §5 form: `\# <length> <hex>`
/// (just `\# 0` when empty).
pub fn fmt_generic_rdata<W: fmt::Write + ?Sized>(w: &mut W, rdata: &[u8]) -> fmt::Result {
    write!(w, "\\# {}", rdata.len())?;
    if !rdata.is_empty() {
        write!(w, " {}", Hex(rdata))?;
    }
    Ok(())
}

/// `Display` adapter: uppercase hexadecimal, no separators.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hex<'a>(pub &'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02X}")?;
        }
        Ok(())
    }
}

/// `Display` adapter: standard base64 with padding (RFC 4648 §4), as used by
/// DNSKEY, RRSIG, CERT, OPENPGPKEY, DHCID, ...
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Base64<'a>(pub &'a [u8]);

impl fmt::Display for Base64<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let sym = |v: u32| ALPHABET[(v & 63) as usize] as char;
        for chunk in self.0.chunks(3) {
            let mut b = [0u8; 3];
            b[..chunk.len()].copy_from_slice(chunk);
            let v = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            let mut out = [sym(v >> 18), sym(v >> 12), sym(v >> 6), sym(v)];
            for c in out.iter_mut().skip(chunk.len() + 1) {
                *c = '=';
            }
            for c in out {
                fmt::Write::write_char(f, c)?;
            }
        }
        Ok(())
    }
}

/// `Display` adapter: base32 with the "extended hex" alphabet, uppercase,
/// unpadded (RFC 4648 §7), as used by NSEC3 (RFC 5155 §3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Base32Hex<'a>(pub &'a [u8]);

impl fmt::Display for Base32Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
        for chunk in self.0.chunks(5) {
            let mut b = [0u8; 8];
            b[3..3 + chunk.len()].copy_from_slice(chunk);
            let v = u64::from_be_bytes(b);
            let symbols = (chunk.len() * 8).div_ceil(5);
            for i in 0..symbols {
                let idx = (v >> (35 - 5 * i)) & 31;
                fmt::Write::write_char(f, ALPHABET[idx as usize] as char)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::format;
    use std::string::{String, ToString};

    #[test]
    fn labels() {
        let mut s = String::new();
        fmt_label(&mut s, b"a.b\\c d\x7f@").unwrap();
        assert_eq!(s, "a\\.b\\\\c\\032d\\127\\@");
    }

    #[test]
    fn encodings() {
        assert_eq!(Hex(&[0x0a, 0xff]).to_string(), "0AFF");
        // RFC 4648 §10 test vectors.
        for (i, o) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(Base64(i.as_bytes()).to_string(), o);
        }
        for (i, o) in [
            ("", ""),
            ("f", "CO"),
            ("fo", "CPNG"),
            ("foo", "CPNMU"),
            ("foob", "CPNMUOG"),
            ("fooba", "CPNMUOJ1"),
            ("foobar", "CPNMUOJ1E8"),
        ] {
            assert_eq!(Base32Hex(i.as_bytes()).to_string(), o);
        }
    }

    #[test]
    fn generic() {
        let mut s = String::new();
        fmt_generic_rdata(&mut s, &[10, 0, 0, 1]).unwrap();
        assert_eq!(s, "\\# 4 0A000001");
        assert_eq!(format!("{}", G(&[])), "\\# 0");
        struct G<'a>(&'a [u8]);
        impl fmt::Display for G<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt_generic_rdata(f, self.0)
            }
        }
    }
}
