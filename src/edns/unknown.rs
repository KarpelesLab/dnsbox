//! Options without a typed implementation (passthrough).

use core::fmt;

use super::{ComposeOption, OptionCode, fmt_hex_option};
use crate::Result;
use crate::wire::Composer;

/// An EDNS option kept as raw bytes: codes without a typed implementation
/// (RFC 6891 §6.1.2 asks receivers to ignore options they do not
/// understand, and they round-trip unchanged).
///
/// ```
/// use dnsbox::edns::{OptionCode, UnknownOption};
///
/// let opt = UnknownOption::new(OptionCode::new(65001), &[0xc0, 0xff, 0xee]);
/// assert_eq!(opt.code(), OptionCode::new(65001));
/// assert_eq!(opt.data(), [0xc0, 0xff, 0xee]);
/// assert_eq!(opt.to_string(), "OPT65001=C0FFEE");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UnknownOption<'a> {
    code: OptionCode,
    data: &'a [u8],
}

impl<'a> UnknownOption<'a> {
    /// Wraps a raw option value.
    #[inline]
    #[must_use]
    pub const fn new(code: OptionCode, data: &'a [u8]) -> Self {
        UnknownOption { code, data }
    }

    /// The option code.
    #[inline]
    #[must_use]
    pub const fn code(&self) -> OptionCode {
        self.code
    }

    /// The raw OPTION-DATA.
    #[inline]
    #[must_use]
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }
}

impl ComposeOption for UnknownOption<'_> {
    #[inline]
    fn code(&self) -> OptionCode {
        self.code
    }

    #[inline]
    fn compose_option<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_bytes(self.data)
    }
}

impl fmt::Display for UnknownOption<'_> {
    /// `CODE` when empty, `CODE=<hex>` otherwise (e.g. `OPT65001=C0FFEE`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_hex_option(f, self.code, self.data)
    }
}
