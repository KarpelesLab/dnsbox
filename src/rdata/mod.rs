//! Record data (RDATA): the [`ParseRdata`] / [`ComposeRdata`] traits, the
//! typed [`RData`] enum, and one module per record type (or tightly related
//! family).
//!
//! # Adding a record type
//!
//! 1. Create `src/rdata/<type>.rs` with a view struct (borrowing from the
//!    message, e.g. `Foo<'a>`) and implement [`ParseRdata`],
//!    [`ComposeRdata`], [`fmt::Display`] (presentation format, using
//!    [`crate::text`] helpers), and derive `Clone, Debug, PartialEq, Eq`.
//! 2. Add the module to the `rdata_modules!` list below (one line).
//! 3. Add the type to the `rdata_registry!` list below (one line):
//!    `FOO => Foo(Foo<'a>),` — the [`Rtype`] constant, the [`RData`]
//!    variant name, and the type.
//!
//! See `ARCHITECTURE.md` for the full recipe and a worked example.
//!
//! # Name compression
//!
//! Names inside RDATA are written with [`Composer::put_name`] and a
//! [`NameEncoding`](crate::NameEncoding): only the RFC 1035 types may use
//! [`Compressible`](crate::NameEncoding::Compressible) (RFC 3597 §4).
//! When parsing, use [`WireReader::read_name`] only for the types that
//! RFC 3597 §4 allows to be decompressed, and
//! [`WireReader::read_name_uncompressed`] otherwise.

use core::fmt;

use crate::wire::{Composer, WireReader};
use crate::{Class, Result, Rtype};

/// Declares the record-data modules and re-exports their public items.
/// One line per file; keep the list sorted.
macro_rules! rdata_modules {
    ($($module:ident,)*) => {
        $(
            mod $module;
            pub use $module::*;
        )*
    };
}

rdata_modules! {
    a,
    aaaa,
    bitmap,
    caa,
    cert,
    dhcid,
    dname,
    dnskey,
    ds,
    hinfo,
    minfo,
    mx,
    naptr,
    nsec,
    nsec3,
    null,
    openpgpkey,
    rrsig,
    single_name,
    soa,
    srv,
    sshfp,
    tlsa,
    txt,
    unknown,
    uri,
    wks,
}

/// Parsing half of a typed record-data implementation.
///
/// Implementations are views: they borrow from the message (lifetime `'a`)
/// and allocate nothing.
pub trait ParseRdata<'a>: Sized {
    /// The record type this implementation handles.
    const RTYPE: Rtype;

    /// For class-specific types (RFC 3597 §4: "class-specific" RDATA such as
    /// A and AAAA, whose format is only defined in class IN), the class the
    /// format is defined for. Records of another class are left as
    /// [`RData::Unknown`]. `None` (the default) means class-independent.
    const CLASS: Option<Class> = None;

    /// Parses RDATA from `rdata`, a reader whose window is exactly the
    /// record's RDATA (RDLENGTH bytes) but which can still follow
    /// compression pointers into the whole message.
    ///
    /// Implementations read their fields and return; the dispatcher
    /// ([`RData::parse`], [`Record::data_as`](crate::Record::data_as))
    /// rejects RDATA that is not fully consumed with
    /// [`Error::TrailingData`](crate::Error::TrailingData). Malformed
    /// fields should be reported as
    /// [`Error::InvalidRdata`](crate::Error::InvalidRdata) (truncation is
    /// reported by the reader as `UnexpectedEof`).
    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self>;
}

/// Composing half of a typed record-data implementation; also what the
/// [`MessageBuilder`](crate::MessageBuilder) accepts as record data.
///
/// Implement it for parse views (so parsed records can be re-emitted) and,
/// where a view is awkward to construct, for compose-only helper types
/// (see [`TxtParts`]).
pub trait ComposeRdata {
    /// The record type of this data.
    fn rtype(&self) -> Rtype;

    /// Writes the RDATA (without the RDLENGTH prefix) to `c`.
    ///
    /// Names must be written through [`Composer::put_name`] with the
    /// [`NameEncoding`](crate::NameEncoding) the type's RFC mandates.
    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()>;
}

impl<T: ComposeRdata + ?Sized> ComposeRdata for &T {
    #[inline]
    fn rtype(&self) -> Rtype {
        (**self).rtype()
    }

    #[inline]
    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        (**self).compose_rdata(c)
    }
}

/// Whether a record of `class` should be parsed with a type restricted to
/// `restriction`. NONE and ANY are accepted: dynamic update (RFC 2136 §2.5)
/// uses them with zone-class RDATA.
const fn class_ok(restriction: Option<Class>, class: Class) -> bool {
    match restriction {
        None => true,
        Some(c) => c.get() == class.get() || class.get() == 254 || class.get() == 255,
    }
}

/// Generates [`RData`] and its dispatch from a list of
/// `RTYPE_CONST => Variant(Type),` lines.
macro_rules! rdata_registry {
    ($( $(#[$attr:meta])* $rt:ident => $var:ident($ty:ty), )*) => {
        /// Typed record data, as returned by
        /// [`Record::data`](crate::Record::data).
        ///
        /// Types without a typed implementation — and records whose class or
        /// form does not match a typed implementation — are kept as
        /// [`RData::Unknown`], which round-trips the raw bytes (RFC 3597).
        #[derive(Clone, Debug, PartialEq, Eq)]
        #[non_exhaustive]
        pub enum RData<'a> {
            $(
                $(#[$attr])*
                #[doc = concat!("`", stringify!($rt), "` record data.")]
                $var($ty),
            )*
            /// Opaque record data (RFC 3597).
            Unknown(UnknownRdata<'a>),
        }

        impl<'a> RData<'a> {
            /// Parses RDATA of the given type and class. `rdata`'s window
            /// must be exactly the RDATA; it is fully consumed.
            ///
            /// Empty RDATA of a data type in class NONE or ANY (dynamic
            /// update deletions and prerequisites, RFC 2136 §2.4–2.5; meta
            /// types such as OPT, whose CLASS field means something else,
            /// are excluded) is returned as
            /// [`RData::Unknown`], as is any type that has no typed
            /// implementation or whose class does not match
            /// [`ParseRdata::CLASS`].
            pub fn parse(rtype: Rtype, class: Class, mut rdata: WireReader<'a>) -> Result<Self> {
                if rdata.is_empty()
                    && !rtype.is_meta()
                    && (class == Class::NONE || class == Class::ANY)
                {
                    return Ok(RData::Unknown(UnknownRdata::new(rtype, &[])));
                }
                let data = match rtype {
                    $(
                        $(#[$attr])*
                        Rtype::$rt => {
                            const {
                                assert!(
                                    <$ty as ParseRdata<'a>>::RTYPE.get() == Rtype::$rt.get(),
                                    "registry entry does not match ParseRdata::RTYPE",
                                )
                            };
                            if !class_ok(<$ty as ParseRdata<'a>>::CLASS, class) {
                                return Ok(RData::Unknown(UnknownRdata::new(rtype, rdata.read_rest())));
                            }
                            RData::$var(<$ty as ParseRdata<'a>>::parse_rdata(&mut rdata)?)
                        }
                    )*
                    _ => RData::Unknown(UnknownRdata::new(rtype, rdata.read_rest())),
                };
                rdata.finish()?;
                Ok(data)
            }

            /// Whether `rtype` has a typed implementation.
            pub const fn is_known(rtype: Rtype) -> bool {
                match rtype {
                    $( $(#[$attr])* Rtype::$rt => true, )*
                    _ => false,
                }
            }
        }

        impl ComposeRdata for RData<'_> {
            fn rtype(&self) -> Rtype {
                match self {
                    $( $(#[$attr])* RData::$var(_) => Rtype::$rt, )*
                    RData::Unknown(u) => u.rtype(),
                }
            }

            fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
                match self {
                    $( $(#[$attr])* RData::$var(d) => d.compose_rdata(c), )*
                    RData::Unknown(u) => u.compose_rdata(c),
                }
            }
        }

        impl fmt::Display for RData<'_> {
            /// Presentation format of the RDATA (RFC 1035 §5.1; RFC 3597 §5
            /// generic form for unknown data).
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    $( $(#[$attr])* RData::$var(d) => fmt::Display::fmt(d, f), )*
                    RData::Unknown(u) => fmt::Display::fmt(u, f),
                }
            }
        }
    };
}

// One line per typed record type; keep the list sorted by mnemonic.
rdata_registry! {
    A => A(A),
    AAAA => Aaaa(Aaaa),
    CAA => Caa(Caa<'a>),
    CDNSKEY => Cdnskey(Cdnskey<'a>),
    CDS => Cds(Cds<'a>),
    CERT => Cert(Cert<'a>),
    CNAME => Cname(Cname<'a>),
    DHCID => Dhcid(Dhcid<'a>),
    DLV => Dlv(Dlv<'a>),
    DNAME => Dname(Dname<'a>),
    DNSKEY => Dnskey(Dnskey<'a>),
    DS => Ds(Ds<'a>),
    HINFO => Hinfo(Hinfo<'a>),
    KEY => Key(Key<'a>),
    MB => Mb(Mb<'a>),
    MD => Md(Md<'a>),
    MF => Mf(Mf<'a>),
    MG => Mg(Mg<'a>),
    MINFO => Minfo(Minfo<'a>),
    MR => Mr(Mr<'a>),
    MX => Mx(Mx<'a>),
    NAPTR => Naptr(Naptr<'a>),
    NS => Ns(Ns<'a>),
    NSEC => Nsec(Nsec<'a>),
    NSEC3 => Nsec3(Nsec3<'a>),
    NSEC3PARAM => Nsec3param(Nsec3param<'a>),
    NULL => Null(Null<'a>),
    OPENPGPKEY => Openpgpkey(Openpgpkey<'a>),
    PTR => Ptr(Ptr<'a>),
    RRSIG => Rrsig(Rrsig<'a>),
    SIG => Sig(Sig<'a>),
    SMIMEA => Smimea(Smimea<'a>),
    SOA => Soa(Soa<'a>),
    SRV => Srv(Srv<'a>),
    SSHFP => Sshfp(Sshfp<'a>),
    TA => Ta(Ta<'a>),
    TLSA => Tlsa(Tlsa<'a>),
    TXT => Txt(Txt<'a>),
    URI => Uri(Uri<'a>),
    WKS => Wks(Wks<'a>),
}

impl RData<'_> {
    /// The record type of this data.
    #[inline]
    pub fn rtype(&self) -> Rtype {
        ComposeRdata::rtype(self)
    }
}

#[cfg(test)]
mod tests;
