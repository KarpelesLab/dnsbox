//! SVCB and HTTPS record data (RFC 9460): service bindings.
//!
//! Both types share one layout (RFC 9460 §2.2, §9): a SvcPriority (0 is
//! AliasMode, anything else ServiceMode), an uncompressed TargetName, and a
//! list of SvcParams ([`SvcParams`]) with strictly increasing keys
//! ([`SvcParamKey`]). Parsing validates the whole list once — ordering,
//! every registered key's value format ([`SvcParamValue`]), and
//! self-consistency — so later access cannot fail.
//!
//! To build record data, use [`SvcbBuilder`] (params in any order, sorted
//! on insertion) or parse presentation format with [`Svcb::from_text`] /
//! [`Https::from_text`]; both write into a caller-supplied buffer.
//!
//! The typed SvcParamValue views ([`Alpn`](svcparam::Alpn),
//! [`Ipv4Hint`](svcparam::Ipv4Hint), ...) live in [`svcparam`].

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Class, Result, Rtype};

mod builder;
mod key;
mod params;
mod text;
mod value;

pub use builder::SvcbBuilder;
pub use key::SvcParamKey;
pub use params::{SvcParam, SvcParamIter, SvcParams};
pub use value::SvcParamValue;

/// Typed views of individual SvcParamValues (RFC 9460 §7–8 and the specs
/// registering later keys), as carried by [`SvcParamValue`].
pub mod svcparam {
    pub use super::value::{
        Alpn, DocPath, DohPath, Ech, Ipv4Hint, Ipv6Hint, Mandatory, Oots, TlsSupportedGroups,
    };
}

/// Defines one SVCB-compatible record type (RFC 9460 §6).
macro_rules! svcb_type {
    ($(#[$doc:meta])* $name:ident, $rtype:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $name<'a> {
            /// SvcPriority: 0 selects AliasMode; otherwise ServiceMode, lower
            /// values preferred (RFC 9460 §2.4.1).
            pub priority: u16,
            /// TargetName (RFC 9460 §2.2). `.` means "no service" in
            /// AliasMode and "the owner name" in ServiceMode (§2.5); see
            #[doc = concat!("[`", stringify!($name), "::effective_target`].")]
            pub target: Name<'a>,
            /// The SvcParams, sorted by key (RFC 9460 §2.2). Recipients
            /// ignore them in AliasMode (§2.4.2).
            pub params: SvcParams<'a>,
        }

        impl<'a> $name<'a> {
            /// Assembles record data from its fields.
            #[inline]
            pub const fn new(priority: u16, target: Name<'a>, params: SvcParams<'a>) -> Self {
                $name { priority, target, params }
            }

            /// An AliasMode record (SvcPriority 0, no SvcParams) pointing
            /// at `target` (RFC 9460 §2.4.2).
            #[inline]
            pub const fn alias(target: Name<'a>) -> Self {
                $name { priority: 0, target, params: SvcParams::EMPTY }
            }

            /// Whether this is an AliasMode record (SvcPriority 0,
            /// RFC 9460 §2.4.1).
            #[inline]
            pub const fn is_alias_mode(&self) -> bool {
                self.priority == 0
            }

            /// Whether this is a ServiceMode record (SvcPriority > 0,
            /// RFC 9460 §2.4.1).
            #[inline]
            pub const fn is_service_mode(&self) -> bool {
                self.priority != 0
            }

            /// The effective TargetName for a record owned by `owner`
            /// (RFC 9460 §2.5): `None` for an AliasMode record with target
            /// `.` (the service does not exist), `owner` for a ServiceMode
            /// record with target `.`, and the target otherwise.
            pub fn effective_target<'n>(&self, owner: Name<'n>) -> Option<Name<'n>>
            where
                'a: 'n,
            {
                match (self.target.is_root(), self.is_alias_mode()) {
                    (false, _) => Some(self.target),
                    (true, true) => None,
                    (true, false) => Some(owner),
                }
            }

            /// Parses presentation-format RDATA (`SvcPriority TargetName
            /// SvcParams`, RFC 9460 §2.1) into `buf`, which receives the
            /// wire form, and returns a view over it.
            ///
            /// SvcParams may appear in any order and may be quoted;
            /// values are character-string decoded (Appendix A), lists are
            /// comma-separated with `\,` / `\\` escaping (Appendix A.1),
            /// `ech` is base64, and parentheses and `;` comments are
            /// accepted as in zone files. Fails with
            /// [`Error::InvalidText`](crate::Error::InvalidText) on syntax
            /// errors, [`Error::UnexpectedEof`](crate::Error::UnexpectedEof)
            /// if the priority or target is missing,
            /// [`Error::UnknownMnemonic`](crate::Error::UnknownMnemonic)
            /// for unknown key names,
            /// [`Error::InvalidRdata`](crate::Error::InvalidRdata) for
            /// values or combinations RFC 9460 forbids (repeated keys,
            /// a value of the wrong form, a missing mandatory key, ...),
            /// and [`Error::BufferTooSmall`](crate::Error::BufferTooSmall)
            /// if `buf` is too short.
            pub fn from_text(text: &str, buf: &'a mut [u8]) -> Result<Self> {
                text::parse(&mut Scanner::new(text), buf).map($name::from)
            }
        }

        impl ParseRdataText for $name<'_> {
            /// `SvcPriority TargetName SvcParams` (RFC 9460 §2.1); see
            #[doc = concat!("[`", stringify!($name), "::from_text`].")]
            fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
                text::parse_into(s, out)
            }
        }

        impl<'a> ParseRdata<'a> for $name<'a> {
            const RTYPE: Rtype = Rtype::$rtype;
            // "defined specifically within the Internet ("IN") Class"
            // (RFC 9460 §2.1).
            const CLASS: Option<Class> = Some(Class::IN);

            fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
                let priority = rdata.read_u16()?;
                // Never compressed (RFC 9460 §2.2).
                let target = rdata.read_name_uncompressed()?;
                let params = SvcParams::new(rdata.peek_rest())?;
                rdata.read_rest();
                Ok($name { priority, target, params })
            }
        }

        impl ComposeRdata for $name<'_> {
            fn rtype(&self) -> Rtype {
                Rtype::$rtype
            }

            fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
                c.put_u16(self.priority)?;
                // Uncompressed (RFC 9460 §2.2), and not lowercased in
                // canonical form (not listed in RFC 4034 §6.2).
                c.put_name(self.target, NameEncoding::Plain)?;
                c.put_bytes(self.params.as_wire())
            }
        }

        impl fmt::Display for $name<'_> {
            /// `SvcPriority TargetName SvcParams` (RFC 9460 §2.1).
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{} {}", self.priority, self.target)?;
                if !self.params.is_empty() {
                    write!(f, " {}", self.params)?;
                }
                Ok(())
            }
        }
    };
}

svcb_type! {
    /// `SVCB` record data: a service binding (RFC 9460 §2). Class IN only.
    ///
    /// ```
    /// use dnsbox::rdata::Svcb;
    ///
    /// let mut buf = [0u8; 64];
    /// let svcb = Svcb::from_text("16 foo.example.org. alpn=h2,h3-19 port=8443", &mut buf)?;
    /// assert!(svcb.is_service_mode());
    /// assert_eq!(svcb.params.port(), Some(8443));
    /// let alpn: Vec<&[u8]> = svcb.params.alpn().unwrap().iter().collect();
    /// assert_eq!(alpn, [&b"h2"[..], b"h3-19"]);
    /// assert_eq!(svcb.to_string(), "16 foo.example.org. alpn=\"h2,h3-19\" port=8443");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    Svcb, SVCB
}

svcb_type! {
    /// `HTTPS` record data: a service binding for the `https` and `http`
    /// schemes (RFC 9460 §9), with the same format as [`Svcb`]. Class IN
    /// only.
    Https, HTTPS
}

impl<'a> From<Svcb<'a>> for Https<'a> {
    #[inline]
    fn from(s: Svcb<'a>) -> Self {
        Https::new(s.priority, s.target, s.params)
    }
}

impl<'a> From<Https<'a>> for Svcb<'a> {
    #[inline]
    fn from(h: Https<'a>) -> Self {
        Svcb::new(h.priority, h.target, h.params)
    }
}

#[cfg(test)]
mod tests;
