//! Composing option lists into OPT RDATA.

use super::{ComposeOption, Opt};
use crate::rdata::ComposeRdata;
use crate::wire::Composer;
use crate::{Result, Rtype};

/// A list of EDNS options that can be written as OPT RDATA.
///
/// Implemented by every [`ComposeOption`] (a single option), slices and
/// arrays of one option type (e.g. `[EdnsOption<'_>]`), tuples of up to
/// eight [`ComposeOptions`] (to mix option types without allocating), `()`
/// (no options), and a parsed [`Opt`] (echoed byte for byte).
///
/// ```
/// use dnsbox::WireWriter;
/// use dnsbox::edns::{ComposeOptions, Expire, Nsid};
///
/// let mut buf = [0u8; 16];
/// let mut w = WireWriter::new(&mut buf);
/// (Nsid::REQUEST, Expire::REQUEST).compose_options(&mut w)?;
/// assert_eq!(w.as_bytes(), b"\x00\x03\x00\x00\x00\x09\x00\x00");
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub trait ComposeOptions {
    /// Writes every option, as `{OPTION-CODE, OPTION-LENGTH, OPTION-DATA}`
    /// triples (RFC 6891 §6.1.2).
    ///
    /// # Errors
    ///
    /// The first error of an option's
    /// [`compose_option`](ComposeOption::compose_option) (typically
    /// [`Error::BufferTooSmall`](crate::Error::BufferTooSmall)).
    fn compose_options<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()>;
}

impl<T: ComposeOption> ComposeOptions for T {
    #[inline]
    fn compose_options<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        self.compose_tlv(c)
    }
}

impl<T: ComposeOption> ComposeOptions for [T] {
    fn compose_options<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        self.iter().try_for_each(|o| o.compose_tlv(c))
    }
}

impl<T: ComposeOption, const N: usize> ComposeOptions for [T; N] {
    #[inline]
    fn compose_options<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        self.as_slice().compose_options(c)
    }
}

impl ComposeOptions for Opt<'_> {
    #[inline]
    fn compose_options<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_bytes(self.as_wire())
    }
}

impl ComposeOptions for () {
    #[inline]
    fn compose_options<C: Composer + ?Sized>(&self, _c: &mut C) -> Result<()> {
        Ok(())
    }
}

macro_rules! tuple_options {
    ($( ($($name:ident),+) )*) => {
        $(
            impl<$($name: ComposeOptions),+> ComposeOptions for ($($name,)+) {
                #[allow(non_snake_case)]
                fn compose_options<W: Composer + ?Sized>(&self, w: &mut W) -> Result<()> {
                    let ($($name,)+) = self;
                    $( $name.compose_options(w)?; )+
                    Ok(())
                }
            }
        )*
    };
}

tuple_options! {
    (O1)
    (O1, O2)
    (O1, O2, O3)
    (O1, O2, O3, O4)
    (O1, O2, O3, O4, O5)
    (O1, O2, O3, O4, O5, O6)
    (O1, O2, O3, O4, O5, O6, O7)
    (O1, O2, O3, O4, O5, O6, O7, O8)
}

/// Compose-only `OPT` record data built from any [`ComposeOptions`]
/// (RFC 6891 §6.1.2).
///
/// [`MessageBuilder::push_edns`](crate::MessageBuilder::push_edns) uses it;
/// it is public for callers writing the OPT record themselves.
///
/// ```
/// use dnsbox::edns::{Nsid, OptData, OptHeader};
/// use dnsbox::{MessageBuilder, Name};
///
/// // What push_edns does, spelled out.
/// let header = OptHeader::new(1232);
/// let mut buf = [0u8; 64];
/// let mut b = MessageBuilder::new(&mut buf)?;
/// b.push_additional(Name::ROOT, header.class(), header.ttl(), &OptData(&Nsid::REQUEST))?;
/// assert_eq!(b.len(), 12 + 11 + 4);
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct OptData<'o, O: ?Sized>(pub &'o O);

impl<O: ComposeOptions + ?Sized> ComposeRdata for OptData<'_, O> {
    #[inline]
    fn rtype(&self) -> Rtype {
        Rtype::OPT
    }

    #[inline]
    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        self.0.compose_options(c)
    }
}
