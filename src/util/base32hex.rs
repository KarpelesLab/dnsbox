//! Base32hex decoding (RFC 4648 §7), `no_std` and allocation-free, as
//! used by NSEC3 hashed owner names (RFC 5155 §3). Encoding is
//! [`crate::text::Base32Hex`].

use crate::{Error, Result};

/// Decodes unpadded base32hex (RFC 4648 §7), case-insensitively, into
/// `out`, returning the decoded length. Rejects non-canonical input
/// (impossible lengths or non-zero trailing bits).
pub(crate) fn decode(input: &[u8], out: &mut [u8]) -> Result<usize> {
    if matches!(input.len() % 8, 1 | 3 | 6) {
        return Err(Error::InvalidText);
    }
    let mut acc: u64 = 0;
    let mut bits = 0u32;
    let mut len = 0usize;
    for &c in input {
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'v' => c - b'a' + 10,
            b'A'..=b'V' => c - b'A' + 10,
            _ => return Err(Error::InvalidText),
        };
        acc = (acc << 5) | u64::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            *out.get_mut(len).ok_or(Error::InvalidText)? = (acc >> bits) as u8;
            len += 1;
            acc &= (1 << bits) - 1;
        }
    }
    if acc != 0 {
        return Err(Error::InvalidText);
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        let mut out = [0u8; 40];
        assert_eq!(decode(b"", &mut out), Ok(0));
        for (enc, dec) in [
            ("CO", "f"),
            ("CPNG", "fo"),
            ("cpnmu", "foo"),
            ("CPNMUOG", "foob"),
            ("CPNMUOJ1", "fooba"),
            ("CPNMUOJ1E8", "foobar"),
        ] {
            let n = decode(enc.as_bytes(), &mut out).unwrap();
            assert_eq!(&out[..n], dec.as_bytes(), "{enc}");
        }
        for bad in ["C", "CPN", "CPNMUO", "CP", "W0", "C=", "CPNMUOJ1E9"] {
            assert_eq!(
                decode(bad.as_bytes(), &mut out),
                Err(Error::InvalidText),
                "{bad}"
            );
        }
        assert_eq!(decode(b"00", &mut [0u8; 0]), Err(Error::InvalidText));
    }
}
