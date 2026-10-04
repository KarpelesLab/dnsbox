//! Opaque record data (RFC 3597).

use core::fmt;

use super::ComposeRdata;
use crate::wire::Composer;
use crate::{Result, Rtype};

/// Record data kept as raw bytes: types without a typed implementation,
/// class-mismatched data, and empty update RDATA (RFC 3597 §2).
///
/// Unknown types never contain compressed names (RFC 3597 §4), so the bytes
/// can be copied verbatim into another message. Displays in the generic
/// `\# <len> <hex>` form (RFC 3597 §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UnknownRdata<'a> {
    rtype: Rtype,
    data: &'a [u8],
}

impl<'a> UnknownRdata<'a> {
    /// Wraps raw RDATA of the given type.
    #[inline]
    #[must_use]
    pub const fn new(rtype: Rtype, data: &'a [u8]) -> Self {
        UnknownRdata { rtype, data }
    }

    /// The record type.
    #[inline]
    #[must_use]
    pub const fn rtype(&self) -> Rtype {
        self.rtype
    }

    /// The raw RDATA.
    #[inline]
    #[must_use]
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }
}

impl ComposeRdata for UnknownRdata<'_> {
    #[inline]
    fn rtype(&self) -> Rtype {
        self.rtype
    }

    #[inline]
    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_bytes(self.data)
    }
}

impl fmt::Display for UnknownRdata<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::text::fmt_generic_rdata(f, self.data)
    }
}
