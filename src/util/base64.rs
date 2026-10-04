//! Base64 decoding (RFC 4648 §4), `no_std` and allocation-free. Encoding
//! is [`crate::text::Base64`].

use crate::{Error, Result};

/// The value of a base64 alphabet character.
const fn sextet(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// An upper bound of the decoded length of `len` input characters.
#[cfg(test)]
pub(crate) const fn max_decoded_len(len: usize) -> usize {
    len / 4 * 3 + 2
}

/// Decodes padded base64 (RFC 4648 §4) from `input` into `out`, returning
/// the number of bytes written. ASCII whitespace is ignored (zone files
/// may split base64 across tokens and lines); empty input decodes to
/// nothing.
///
/// Fails with [`Error::InvalidText`] on characters outside the alphabet,
/// missing or misplaced padding, or data after the padding, and with
/// [`Error::BufferTooSmall`] if `out` is too short. Non-zero bits in the
/// last character before padding are accepted.
pub(crate) fn decode(input: &[u8], out: &mut [u8]) -> Result<usize> {
    let mut quad = [0u8; 4];
    let mut filled = 0usize;
    let mut pad = 0usize;
    let mut done = false;
    let mut len = 0usize;
    for &c in input {
        if c.is_ascii_whitespace() {
            continue;
        }
        if done {
            return Err(Error::InvalidText);
        }
        let v = if c == b'=' {
            pad += 1;
            0
        } else if pad > 0 {
            return Err(Error::InvalidText);
        } else {
            sextet(c).ok_or(Error::InvalidText)?
        };
        if let Some(slot) = quad.get_mut(filled) {
            *slot = v;
        }
        filled += 1;
        if filled < 4 {
            continue;
        }
        if pad > 2 {
            return Err(Error::InvalidText);
        }
        let bits = (u32::from(quad[0]) << 18)
            | (u32::from(quad[1]) << 12)
            | (u32::from(quad[2]) << 6)
            | u32::from(quad[3]);
        let bytes = bits.to_be_bytes();
        let n = 3 - pad;
        out.get_mut(len..len + n)
            .ok_or(Error::BufferTooSmall)?
            .copy_from_slice(bytes.get(1..1 + n).unwrap_or(&[]));
        len += n;
        filled = 0;
        done = pad > 0;
    }
    if filled != 0 {
        return Err(Error::InvalidText);
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text::Base64;
    use std::string::ToString;

    fn dec(s: &str) -> Result<std::vec::Vec<u8>> {
        let mut buf = [0u8; 64];
        let n = decode(s.as_bytes(), &mut buf)?;
        assert!(n <= max_decoded_len(s.len()));
        Ok(buf[..n].to_vec())
    }

    #[test]
    fn rfc4648_vectors() {
        for (plain, enc) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(dec(enc).unwrap(), plain.as_bytes(), "{enc}");
        }
        assert_eq!(dec(" Zm9v\n YmFy ").unwrap(), b"foobar");
        // Every byte value round-trips through the encoder.
        let all: std::vec::Vec<u8> = (0..=255).collect();
        for chunk in all.chunks(47) {
            let text = Base64(chunk).to_string();
            let mut buf = [0u8; 64];
            let n = decode(text.as_bytes(), &mut buf).unwrap();
            assert_eq!(&buf[..n], chunk);
        }
    }

    #[test]
    fn malformed() {
        for bad in [
            "Zg", "Zg=", "Z===", "====", "Zg==Zg==", "Zg=a", "Zm9*", "Zm9v=", "Zg== =", "Z",
        ] {
            assert_eq!(dec(bad), Err(Error::InvalidText), "{bad}");
        }
        let mut small = [0u8; 2];
        assert_eq!(decode(b"Zm9v", &mut small), Err(Error::BufferTooSmall));
    }
}
