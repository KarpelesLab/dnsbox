//! The window-block type bitmap shared by NSEC (RFC 4034 §4.1.2), NSEC3
//! (RFC 5155 §3.2.1) and CSYNC (RFC 7477 §2.1.2).

use core::fmt;

use crate::wire::{Composer, WireReader};
use crate::{Error, Result, Rtype};

/// A validated type bitmap: a sequence of `(window, length, bitmap)` blocks
/// with strictly increasing window numbers and lengths 1–32
/// (RFC 4034 §4.1.2). An empty bitmap is valid (RFC 5155 §3.2.1 allows it).
///
/// ```
/// use dnsbox::rdata::TypeBitmap;
/// use dnsbox::{Rtype, WireWriter};
///
/// let mut buf = [0u8; 64];
/// let mut w = WireWriter::new(&mut buf);
/// TypeBitmap::compose(&[Rtype::MX, Rtype::A, Rtype::RRSIG, Rtype::NSEC, Rtype::new(1234)], &mut w)?;
/// let bitmap = TypeBitmap::new(w.written())?;
/// assert!(bitmap.contains(Rtype::MX) && !bitmap.contains(Rtype::NS));
/// assert_eq!(bitmap.to_string(), "A MX RRSIG NSEC TYPE1234");
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct TypeBitmap<'a>(&'a [u8]);

impl<'a> TypeBitmap<'a> {
    /// Validates `wire` as a complete type bitmap.
    pub fn new(wire: &'a [u8]) -> Result<Self> {
        let mut rest = wire;
        let mut last: Option<u8> = None;
        while let [window, len, tail @ ..] = rest {
            if last.is_some_and(|l| *window <= l) || !(1..=32).contains(len) {
                return Err(Error::InvalidRdata);
            }
            last = Some(*window);
            rest = tail.get(*len as usize..).ok_or(Error::InvalidRdata)?;
        }
        if !rest.is_empty() {
            return Err(Error::InvalidRdata);
        }
        Ok(TypeBitmap(wire))
    }

    /// Reads the rest of `rdata` as a type bitmap (it is always the last
    /// field of the RDATA).
    pub fn parse(rdata: &mut WireReader<'a>) -> Result<Self> {
        let bitmap = Self::new(rdata.peek_rest())?;
        rdata.read_rest();
        Ok(bitmap)
    }

    /// The encoded bitmap.
    #[inline]
    pub const fn as_wire(&self) -> &'a [u8] {
        self.0
    }

    /// Whether no type is present.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.iter().next().is_none()
    }

    /// Whether `rtype` is present.
    pub fn contains(&self, rtype: Rtype) -> bool {
        let [hi, lo] = rtype.get().to_be_bytes();
        let mut rest = self.0;
        while let [window, len, tail @ ..] = rest {
            let (bits, next) = tail.split_at((*len as usize).min(tail.len()));
            if *window == hi {
                return bits
                    .get(lo as usize / 8)
                    .is_some_and(|b| b & (0x80 >> (lo % 8)) != 0);
            }
            rest = next;
        }
        false
    }

    /// Iterates over the types present, in ascending order.
    #[inline]
    pub fn iter(&self) -> TypeBitmapIter<'a> {
        TypeBitmapIter {
            rest: self.0,
            window: 0,
            bits: &[],
            index: 0,
        }
    }

    /// Writes the bitmap for `types` (in any order; duplicates ignored).
    pub fn compose<C: Composer + ?Sized>(types: &[Rtype], c: &mut C) -> Result<()> {
        let mut windows = [false; 256];
        for t in types {
            windows[(t.get() >> 8) as usize] = true;
        }
        for (window, _) in windows.iter().enumerate().filter(|(_, used)| **used) {
            let mut bits = [0u8; 32];
            for t in types.iter().filter(|t| (t.get() >> 8) as usize == window) {
                let lo = (t.get() & 0xff) as usize;
                bits[lo / 8] |= 0x80 >> (lo % 8);
            }
            let len = bits.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
            c.put_u8(window as u8)?;
            c.put_u8(len as u8)?;
            c.put_bytes(&bits[..len])?;
        }
        Ok(())
    }
}

impl<'a> IntoIterator for TypeBitmap<'a> {
    type Item = Rtype;
    type IntoIter = TypeBitmapIter<'a>;
    fn into_iter(self) -> TypeBitmapIter<'a> {
        self.iter()
    }
}

impl fmt::Display for TypeBitmap<'_> {
    /// Space-separated type mnemonics.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, t) in self.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            fmt::Display::fmt(&t, f)?;
        }
        Ok(())
    }
}

impl fmt::Debug for TypeBitmap<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// Iterator over the types in a [`TypeBitmap`].
#[derive(Clone, Debug)]
pub struct TypeBitmapIter<'a> {
    rest: &'a [u8],
    window: u8,
    bits: &'a [u8],
    index: usize,
}

impl Iterator for TypeBitmapIter<'_> {
    type Item = Rtype;

    fn next(&mut self) -> Option<Rtype> {
        loop {
            while self.index < self.bits.len() * 8 {
                let i = self.index;
                self.index += 1;
                if self.bits[i / 8] & (0x80 >> (i % 8)) != 0 {
                    return Some(Rtype::new(u16::from(self.window) << 8 | i as u16));
                }
            }
            let [window, len, tail @ ..] = self.rest else {
                return None;
            };
            let (bits, rest) = tail.split_at((*len as usize).min(tail.len()));
            self.window = *window;
            self.bits = bits;
            self.rest = rest;
            self.index = 0;
        }
    }
}

impl core::iter::FusedIterator for TypeBitmapIter<'_> {}
