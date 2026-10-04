//! Record types whose RDATA is a single domain name: NS, CNAME, PTR
//! (RFC 1035 §3.3.11, §3.3.1, §3.3.12) and the obsolete/experimental MD,
//! MF, MB, MG, MR (RFC 1035 §3.3.3–3.3.8).
//!
//! Other single-name types (e.g. DNAME) can reuse
//! [`single_name_rdata!`](crate::rdata) from their own module:
//!
//! ```ignore
//! super::single_name::single_name_rdata! {
//!     /// `DNAME` record data (RFC 6672 §2.1).
//!     Dname, DNAME, target, Lowercase, read_name
//! }
//! ```

/// Defines a record-data view holding exactly one domain name.
///
/// Arguments: doc attributes, type name, [`Rtype`](crate::Rtype) constant,
/// field name, [`NameEncoding`](crate::NameEncoding) variant used when
/// composing, and the [`WireReader`](crate::WireReader) method used to read
/// the name (`read_name` or `read_name_uncompressed`).
macro_rules! single_name_rdata {
    ($(#[$doc:meta])* $ty:ident, $rt:ident, $field:ident, $enc:ident, $read:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $ty<'a> {
            #[doc = concat!("The `", stringify!($field), "` domain name.")]
            pub $field: $crate::name::Name<'a>,
        }

        impl<'a> $ty<'a> {
            /// Wraps a name.
            #[inline]
            pub const fn new($field: $crate::name::Name<'a>) -> Self {
                $ty { $field }
            }
        }

        impl<'a> $crate::rdata::ParseRdata<'a> for $ty<'a> {
            const RTYPE: $crate::Rtype = $crate::Rtype::$rt;

            #[inline]
            fn parse_rdata(rdata: &mut $crate::wire::WireReader<'a>) -> $crate::Result<Self> {
                Ok($ty { $field: rdata.$read()? })
            }
        }

        impl $crate::rdata::ComposeRdata for $ty<'_> {
            #[inline]
            fn rtype(&self) -> $crate::Rtype {
                $crate::Rtype::$rt
            }

            #[inline]
            fn compose_rdata<C: $crate::wire::Composer + ?Sized>(
                &self,
                c: &mut C,
            ) -> $crate::Result<()> {
                c.put_name(self.$field, $crate::wire::NameEncoding::$enc)
            }
        }

        impl ::core::fmt::Display for $ty<'_> {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::fmt::Display::fmt(&self.$field, f)
            }
        }
    };
}
#[allow(unused_imports)] // used by sibling modules added later
pub(crate) use single_name_rdata;

single_name_rdata! {
    /// `NS` record data: an authoritative name server (RFC 1035 §3.3.11).
    Ns, NS, nsdname, Compressible, read_name
}
single_name_rdata! {
    /// `CNAME` record data: the canonical name of an alias
    /// (RFC 1035 §3.3.1).
    Cname, CNAME, cname, Compressible, read_name
}
single_name_rdata! {
    /// `PTR` record data: a domain name pointer (RFC 1035 §3.3.12).
    Ptr, PTR, ptrdname, Compressible, read_name
}
single_name_rdata! {
    /// `MD` record data: a mail destination — obsolete (RFC 1035 §3.3.4).
    Md, MD, madname, Compressible, read_name
}
single_name_rdata! {
    /// `MF` record data: a mail forwarder — obsolete (RFC 1035 §3.3.5).
    Mf, MF, madname, Compressible, read_name
}
single_name_rdata! {
    /// `MB` record data: a mailbox host — experimental (RFC 1035 §3.3.3).
    Mb, MB, madname, Compressible, read_name
}
single_name_rdata! {
    /// `MG` record data: a mail group member — experimental
    /// (RFC 1035 §3.3.6).
    Mg, MG, mgmname, Compressible, read_name
}
single_name_rdata! {
    /// `MR` record data: a mailbox rename — experimental (RFC 1035 §3.3.8).
    Mr, MR, newname, Compressible, read_name
}
