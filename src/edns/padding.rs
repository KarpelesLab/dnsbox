//! Padding option (RFC 7830).

use core::fmt;

use super::{ComposeOption, OptionCode, ParseOption};
use crate::Result;
use crate::wire::{Composer, WireReader};

/// `PADDING` option: filler that hides the message size on encrypted
/// transports (RFC 7830 §3).
///
/// Senders fill it with zero octets; receivers must accept any content
/// (§3), so the parsed bytes are kept as they are and round-trip exactly.
/// To add padding while building, use [`PaddingLen`] or let
/// [`MessageBuilder::push_edns_padded`](crate::MessageBuilder::push_edns_padded)
/// size it from a [`PaddingPolicy`](super::PaddingPolicy) (RFC 8467).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Padding<'a> {
    /// The padding octets.
    pub data: &'a [u8],
}

impl<'a> Padding<'a> {
    /// Wraps padding octets.
    #[inline]
    pub const fn new(data: &'a [u8]) -> Self {
        Padding { data }
    }

    /// The number of padding octets.
    #[inline]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the option is empty.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl<'a> ParseOption<'a> for Padding<'a> {
    const CODE: OptionCode = OptionCode::PADDING;

    #[inline]
    fn parse_option(data: &mut WireReader<'a>) -> Result<Self> {
        Ok(Padding {
            data: data.read_rest(),
        })
    }
}

impl ComposeOption for Padding<'_> {
    #[inline]
    fn code(&self) -> OptionCode {
        OptionCode::PADDING
    }

    #[inline]
    fn compose_option<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_bytes(self.data)
    }
}

impl fmt::Display for Padding<'_> {
    /// `PADDING=<number of octets>` (the content is not shown).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PADDING={}", self.data.len())
    }
}

/// Compose-only `PADDING` option of the given number of zero octets
/// (RFC 7830 §3).
///
/// ```
/// use dnsbox::WireWriter;
/// use dnsbox::edns::{ComposeOption, PaddingLen};
///
/// let mut buf = [0xffu8; 8];
/// let mut w = WireWriter::new(&mut buf);
/// PaddingLen(3).compose_tlv(&mut w)?;
/// assert_eq!(w.as_bytes(), [0, 12, 0, 3, 0, 0, 0]);
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PaddingLen(pub u16);

impl ComposeOption for PaddingLen {
    #[inline]
    fn code(&self) -> OptionCode {
        OptionCode::PADDING
    }

    fn compose_option<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        const ZEROS: [u8; 64] = [0; 64];
        let mut left = self.0 as usize;
        while left > 0 {
            let n = left.min(ZEROS.len());
            c.put_bytes(ZEROS.get(..n).unwrap_or(&[]))?;
            left -= n;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edns::tests::{compose_tlv, round_trip};

    #[test]
    fn padding() {
        round_trip(OptionCode::PADDING, &[0; 5], "PADDING=5");
        round_trip(OptionCode::PADDING, &[], "PADDING=0");
        // Non-zero content is accepted and preserved (RFC 7830 §3).
        round_trip(OptionCode::PADDING, b"xyz", "PADDING=3");
        let p = Padding::new(&[0; 4]);
        assert_eq!((p.len(), p.is_empty()), (4, false));
        assert!(Padding::new(&[]).is_empty());
        let long = compose_tlv(&PaddingLen(200));
        assert_eq!(long.len(), 204);
        assert_eq!(long[..4], [0, 12, 0, 200]);
        assert!(long[4..].iter().all(|&b| b == 0));
        assert_eq!(compose_tlv(&PaddingLen(0)), [0, 12, 0, 0]);
    }
}
