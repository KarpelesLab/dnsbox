//! TXT record data (RFC 1035 §3.3.14).

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::charstr::{CharStrIter, CharStrs};
use crate::wire::{Composer, WireReader};
use crate::{Error, Result, Rtype};

/// `TXT` record data: one or more `<character-string>`s
/// (RFC 1035 §3.3.14).
///
/// To build a TXT record from separate strings, use [`TxtParts`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Txt<'a> {
    strings: CharStrs<'a>,
}

impl<'a> Txt<'a> {
    /// Wraps encoded character-strings (length octets included), which
    /// must hold at least one string.
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
/// assert_eq!(w.written(), b"\x06v=spf1\x04-all");
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
