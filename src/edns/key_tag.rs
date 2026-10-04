//! DNSSEC key tag signaling option (RFC 8145).

use core::fmt;

use super::{ComposeOption, OptionCode, ParseOption};
use crate::wire::{Composer, WireReader};
use crate::{Error, Result};

/// `KEY-TAG` option: the key tags of the trust anchors a validator uses
/// for a zone (RFC 8145 §4.1).
///
/// The value is one or more 16-bit key tags; an empty or odd-length value
/// fails with [`Error::InvalidOption`]. To build the option from a list of
/// tags, use [`KeyTags`].
///
/// ```
/// use dnsbox::edns::KeyTag;
///
/// // The root KSKs 20326 and 38696, as a validator signals them.
/// let tags = KeyTag::from_wire(&[0x4f, 0x66, 0x97, 0x28])?;
/// assert_eq!(tags.iter().collect::<Vec<_>>(), [20326, 38696]);
/// assert!(tags.contains(38696));
/// assert_eq!(tags.to_string(), "KEY-TAG=20326,38696");
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyTag<'a> {
    raw: &'a [u8],
}

impl<'a> KeyTag<'a> {
    /// Wraps encoded key tags (a non-empty, even number of bytes).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidOption`] for an empty or odd-length value.
    pub const fn from_wire(raw: &'a [u8]) -> Result<Self> {
        if raw.is_empty() || !raw.len().is_multiple_of(2) {
            return Err(Error::InvalidOption);
        }
        Ok(KeyTag { raw })
    }

    /// The encoded key tags.
    #[inline]
    #[must_use]
    pub const fn as_wire(&self) -> &'a [u8] {
        self.raw
    }

    /// Iterates over the key tags.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = u16> + 'a {
        self.raw.as_chunks::<2>().0.iter().map(|&p| u16::from_be_bytes(p))
    }

    /// Whether `tag` is listed.
    #[must_use]
    pub fn contains(&self, tag: u16) -> bool {
        self.iter().any(|t| t == tag)
    }
}

impl<'a> ParseOption<'a> for KeyTag<'a> {
    const CODE: OptionCode = OptionCode::KEY_TAG;

    fn parse_option(data: &mut WireReader<'a>) -> Result<Self> {
        KeyTag::from_wire(data.peek_rest()).inspect(|_| {
            data.read_rest();
        })
    }
}

impl ComposeOption for KeyTag<'_> {
    #[inline]
    fn code(&self) -> OptionCode {
        OptionCode::KEY_TAG
    }

    #[inline]
    fn compose_option<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_bytes(self.raw)
    }
}

impl fmt::Display for KeyTag<'_> {
    /// `KEY-TAG=20326,38696`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_tags(f, self.iter())
    }
}

/// Compose-only `KEY-TAG` option from a list of tags (RFC 8145 §4.1),
/// which must not be empty.
///
/// ```
/// use dnsbox::WireWriter;
/// use dnsbox::edns::{ComposeOption, KeyTags};
///
/// let mut buf = [0u8; 16];
/// let mut w = WireWriter::new(&mut buf);
/// KeyTags(&[20326, 38696]).compose_tlv(&mut w)?;
/// assert_eq!(w.as_bytes(), b"\x00\x0e\x00\x04\x4f\x66\x97\x28");
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyTags<'s>(pub &'s [u16]);

impl ComposeOption for KeyTags<'_> {
    #[inline]
    fn code(&self) -> OptionCode {
        OptionCode::KEY_TAG
    }

    fn compose_option<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        if self.0.is_empty() {
            return Err(Error::InvalidOption);
        }
        self.0.iter().try_for_each(|&t| c.put_u16(t))
    }
}

impl fmt::Display for KeyTags<'_> {
    /// `KEY-TAG=20326,38696`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_tags(f, self.0.iter().copied())
    }
}

fn fmt_tags(f: &mut fmt::Formatter<'_>, tags: impl Iterator<Item = u16>) -> fmt::Result {
    f.write_str("KEY-TAG")?;
    for (i, t) in tags.enumerate() {
        write!(f, "{}{t}", if i == 0 { '=' } else { ',' })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edns::tests::{compose_tlv, parse, round_trip};
    use std::string::ToString;
    use std::vec::Vec;

    #[test]
    fn key_tags() {
        // The root KSKs 2017 and 2024 (key tags 20326 and 38696).
        round_trip(OptionCode::KEY_TAG, b"\x4f\x66\x97\x28", "KEY-TAG=20326,38696");
        let k = KeyTag::from_wire(b"\x4f\x66\x97\x28").unwrap();
        assert_eq!(k.iter().collect::<Vec<_>>(), [20326, 38696]);
        assert_eq!(k.iter().len(), 2);
        assert!(k.contains(38696) && !k.contains(1));
        assert_eq!(k.as_wire().len(), 4);
        for bad in [&b""[..], b"\x01", b"\x01\x02\x03"] {
            assert_eq!(parse(OptionCode::KEY_TAG, bad), Err(Error::InvalidOption));
        }
        assert_eq!(compose_tlv(&KeyTags(&[1])), b"\x00\x0e\x00\x02\x00\x01");
        assert_eq!(KeyTags(&[1, 2]).to_string(), "KEY-TAG=1,2");
        let mut buf = [0u8; 8];
        let mut w = crate::WireWriter::new(&mut buf);
        assert_eq!(KeyTags(&[]).compose_option(&mut w), Err(Error::InvalidOption));
    }
}
