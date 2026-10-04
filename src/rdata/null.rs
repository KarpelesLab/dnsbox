//! NULL record data (RFC 1035 §3.3.10).

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::wire::{Composer, WireReader};
use crate::{Result, Rtype};

/// `NULL` record data: up to 65535 arbitrary octets — experimental
/// (RFC 1035 §3.3.10).
///
/// NULL has no presentation format; it displays in the generic RFC 3597
/// form.
///
/// ```
/// use dnsbox::rdata::{Null, ParseRdataText};
///
/// // NULL has only the generic text form (RFC 3597 §5).
/// let mut buf = [0u8; 8];
/// let null = Null::from_text(r"\# 3 ABCDEF", &mut buf)?;
/// assert_eq!(null.data, [0xab, 0xcd, 0xef]);
/// assert_eq!(null.to_string(), r"\# 3 ABCDEF");
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Null<'a> {
    /// The payload.
    pub data: &'a [u8],
}

impl<'a> ParseRdata<'a> for Null<'a> {
    const RTYPE: Rtype = Rtype::NULL;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        Ok(Null {
            data: rdata.read_rest(),
        })
    }
}

impl ComposeRdata for Null<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::NULL
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_bytes(self.data)
    }
}

impl fmt::Display for Null<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::text::fmt_generic_rdata(f, self.data)
    }
}

/// NULL has no presentation format (RFC 1035 §3.3.10 defines none); only
/// the RFC 3597 §5 generic form `\# <length> <hex>` is accepted, as in
/// BIND.
impl super::ParseRdataText for Null<'_> {}

#[cfg(test)]
mod tests {
    use crate::rdata::tests::{text_error, text_round_trip};
    use crate::{Error, Rtype};

    #[test]
    fn text() {
        text_round_trip(Rtype::NULL, "\\# 3 ABCDEF", b"\xab\xcd\xef", "\\# 3 ABCDEF");
        text_round_trip(Rtype::NULL, "\\# 0", b"", "\\# 0");
        assert_eq!(text_error(Rtype::NULL, "abcdef"), Error::NoTextFormat);
        assert_eq!(text_error(Rtype::NULL, ""), Error::NoTextFormat);
        assert_eq!(text_error(Rtype::NULL, "\\# 2 ABCDEF"), Error::InvalidText);
    }
}
