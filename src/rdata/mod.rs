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
//! 4. Implement [`ParseRdataText`] (presentation-format parsing through a
//!    [`Scanner`]); an empty `impl ParseRdataText for Foo<'_> {}` means
//!    the type has no text format besides the RFC 3597 `\#` generic form.
//!
//! See `ARCHITECTURE.md` for the full recipes and worked examples.
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

use crate::wire::{Composer, OutBuf, WireReader, WireWriter};
use crate::zone::Scanner;
use crate::{Class, Error, Result, Rtype};

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
    a6,
    aaaa,
    afsdb,
    apl,
    atma,
    bitmap,
    caa,
    cert,
    csync,
    dhcid,
    dname,
    dnskey,
    ds,
    eid,
    eui,
    gpos,
    hinfo,
    hip,
    ilnp,
    ipseckey,
    isdn,
    kx,
    loc,
    minfo,
    mx,
    naptr,
    nsap,
    nsap_ptr,
    nsec,
    nsec3,
    null,
    nxt,
    openpgpkey,
    px,
    rkey,
    rp,
    rrsig,
    rt,
    single_name,
    sink,
    soa,
    spf,
    srv,
    sshfp,
    svcb,
    talink,
    tlsa,
    tsig,
    txt,
    unknown,
    uri,
    wks,
    x25,
    zonemd,
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
    /// [`Error::TrailingData`]. Malformed
    /// fields should be reported as
    /// [`Error::InvalidRdata`] (truncation is
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

/// Presentation-format (zone-file text) parsing of a record type's RDATA
/// (RFC 1035 §5.1): reads the fields from a [`Scanner`] and writes the
/// **wire-format** RDATA to an [`OutBuf`].
///
/// Parsing text into wire bytes, rather than into a view, keeps it
/// allocation-free: the bytes go into the caller's buffer (a
/// [`WireWriter`] over a `&mut [u8]`, or a `Vec<u8>` with `alloc`), and a
/// typed view is then obtained with the type's [`ParseRdata`]
/// implementation ([`from_text`](Self::from_text) does both). Names are
/// written uncompressed (an `OutBuf` never compresses); a
/// [`MessageBuilder`](crate::MessageBuilder) recompresses them when the
/// parsed view is pushed into a message.
///
/// Every type in the [`RData`] registry implements this trait;
/// [`RData::parse_text`] dispatches on the record type. An empty
/// `impl ParseRdataText for Foo<'_> {}` keeps the provided
/// [`parse_text`](Self::parse_text), which fails with
/// [`Error::NoTextFormat`]: such types can only be written in the
/// generic RFC 3597 §5 form (`\# <length> <hex>`), which the dispatcher
/// accepts for every type.
///
/// ```
/// use dnsbox::rdata::{Mx, ParseRdataText};
///
/// let mut buf = [0u8; 64];
/// let mx = Mx::from_text("10 mail.example.com.", &mut buf)?;
/// assert_eq!(mx.preference, 10);
/// assert_eq!(mx.to_string(), "10 mail.example.com.");
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub trait ParseRdataText {
    /// Reads this type's presentation-format fields from `s` and appends
    /// the wire-format RDATA to `out`.
    ///
    /// Implementations read exactly their fields with the [`Scanner`]
    /// methods (numbers, names completed with the scanner's origin,
    /// character-strings, base64, hex, type bitmaps, ...) and write them
    /// with the [`Composer`] methods `out` provides (`put_u16`,
    /// `put_name`, ...; [`Scanner::name_into`] and the other `*_into`
    /// helpers write directly). They need not check for leftover tokens
    /// or validate the result: [`RData::parse_text`] and
    /// [`from_text`](Self::from_text) reject leftover tokens, run the
    /// type's wire parser over the output, and remove partial output on
    /// failure. Report bad text as [`Error::InvalidText`] (the scanner
    /// methods already do) and semantically invalid values as
    /// [`Error::InvalidRdata`].
    ///
    /// The provided implementation fails with [`Error::NoTextFormat`].
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        let _ = (s, out);
        Err(Error::NoTextFormat)
    }

    /// Parses standalone presentation-format RDATA (relative names are
    /// completed with the root; newlines are blanks) into `buf` and
    /// returns a view over it. The RFC 3597 generic form
    /// `\# <length> <hex>` is accepted too.
    ///
    /// Fails like [`parse_text`](Self::parse_text), with
    /// [`Error::InvalidText`] for leftover tokens, with the wire parser's
    /// error if the result is not valid RDATA, and with
    /// [`Error::BufferTooSmall`] if `buf` is too short. To complete
    /// relative names with another origin, use [`RData::parse_text`] with
    /// [`Scanner::with_origin`].
    fn from_text<'b>(text: &str, buf: &'b mut [u8]) -> Result<Self>
    where
        Self: ParseRdata<'b>,
    {
        let mut s = Scanner::new(text);
        let mut w = WireWriter::new(buf);
        if !s.generic_into(&mut w)? {
            Self::parse_text(&mut s, &mut w)?;
        }
        s.finish()?;
        let wire: &'b [u8] = w.into_written();
        let mut r = WireReader::new(wire);
        let data = Self::parse_rdata(&mut r)?;
        r.finish()?;
        Ok(data)
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
                // Every arm builds its variant directly in the return value
                // (no intermediate `RData` to copy).
                match rtype {
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
                            let data = <$ty as ParseRdata<'a>>::parse_rdata(&mut rdata)?;
                            rdata.finish()?;
                            Ok(RData::$var(data))
                        }
                    )*
                    _ => Ok(RData::Unknown(UnknownRdata::new(rtype, rdata.read_rest()))),
                }
            }

            /// Whether `rtype` has a typed implementation.
            pub const fn is_known(rtype: Rtype) -> bool {
                match rtype {
                    $( $(#[$attr])* Rtype::$rt => true, )*
                    _ => false,
                }
            }
        }

        impl<'a> RData<'a> {
            /// Parses presentation-format RDATA of type `rtype` and class
            /// `class` from `s` (RFC 1035 §5.1) and appends its wire form
            /// to `out`; all of `s`'s remaining tokens must be consumed.
            ///
            /// The generic form of RFC 3597 §5 (`\# <length> <hex>`) is
            /// accepted for every type; otherwise the type's
            /// [`ParseRdataText`] implementation is used. Types without one
            /// (unregistered types, registered types without a text format,
            /// and class-specific types such as `A` in a class other than
            /// their [`ParseRdata::CLASS`]) fail with
            /// [`Error::NoTextFormat`] unless written in the generic form.
            /// The result is checked with the wire parser
            /// ([`RData::parse`]), so it is always valid RDATA: generic
            /// RDATA of a known type must have that type's wire format
            /// (RFC 3597 §5).
            ///
            /// On error, `out` is left as it was.
            ///
            /// ```
            /// use dnsbox::rdata::RData;
            /// use dnsbox::zone::Scanner;
            /// use dnsbox::{Class, NameBuf, Rtype, WireWriter};
            ///
            /// let origin: NameBuf = "example.com".parse()?;
            /// let mut s = Scanner::new("10 mail").with_origin(origin.as_name());
            /// let mut buf = [0u8; 512];
            /// let mut out = WireWriter::new(&mut buf);
            /// RData::parse_text(Rtype::MX, Class::IN, &mut s, &mut out)?;
            /// assert_eq!(out.as_bytes(), b"\x00\x0a\x04mail\x07example\x03com\x00");
            ///
            /// // Any type, in the generic form (RFC 3597 §5).
            /// let mut s = Scanner::new(r"\# 4 C0000201");
            /// let mut buf = [0u8; 512];
            /// let mut out = WireWriter::new(&mut buf);
            /// RData::parse_text(Rtype::A, Class::IN, &mut s, &mut out)?;
            /// assert_eq!(out.as_bytes(), [192, 0, 2, 1]);
            /// # Ok::<(), dnsbox::Error>(())
            /// ```
            pub fn parse_text<B: OutBuf + ?Sized>(
                rtype: Rtype,
                class: Class,
                s: &mut Scanner<'_>,
                out: &mut B,
            ) -> Result<()> {
                let start = out.as_bytes().len();
                let res = Self::parse_text_at(rtype, class, s, out, start);
                if res.is_err() {
                    out.truncate(start);
                }
                res
            }

            /// [`parse_text`](Self::parse_text) without the cleanup.
            fn parse_text_at<B: OutBuf + ?Sized>(
                rtype: Rtype,
                class: Class,
                s: &mut Scanner<'_>,
                out: &mut B,
                start: usize,
            ) -> Result<()> {
                if !s.generic_into(out)? {
                    match rtype {
                        $(
                            $(#[$attr])*
                            Rtype::$rt => {
                                if !class_ok(<$ty as ParseRdata<'a>>::CLASS, class) {
                                    return Err(Error::NoTextFormat);
                                }
                                <$ty as ParseRdataText>::parse_text(s, out)?;
                            }
                        )*
                        _ => return Err(Error::NoTextFormat),
                    }
                }
                s.finish()?;
                let rdata = out.as_bytes().get(start..).unwrap_or(&[]);
                if rdata.len() > usize::from(u16::MAX) {
                    return Err(Error::InvalidRdata);
                }
                RData::parse(rtype, class, WireReader::new(rdata)).map(drop)
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
    A6 => A6(A6<'a>),
    AAAA => Aaaa(Aaaa),
    AFSDB => Afsdb(Afsdb<'a>),
    APL => Apl(Apl<'a>),
    ATMA => Atma(Atma<'a>),
    AVC => Avc(Avc<'a>),
    CAA => Caa(Caa<'a>),
    CDNSKEY => Cdnskey(Cdnskey<'a>),
    CDS => Cds(Cds<'a>),
    CERT => Cert(Cert<'a>),
    CNAME => Cname(Cname<'a>),
    CSYNC => Csync(Csync<'a>),
    DHCID => Dhcid(Dhcid<'a>),
    DLV => Dlv(Dlv<'a>),
    DNAME => Dname(Dname<'a>),
    DNSKEY => Dnskey(Dnskey<'a>),
    DS => Ds(Ds<'a>),
    EID => Eid(Eid<'a>),
    EUI48 => Eui48(Eui48),
    EUI64 => Eui64(Eui64),
    GPOS => Gpos(Gpos<'a>),
    HINFO => Hinfo(Hinfo<'a>),
    HIP => Hip(Hip<'a>),
    HTTPS => Https(Https<'a>),
    IPSECKEY => Ipseckey(Ipseckey<'a>),
    ISDN => Isdn(Isdn<'a>),
    KEY => Key(Key<'a>),
    KX => Kx(Kx<'a>),
    L32 => L32(L32),
    L64 => L64(L64),
    LOC => Loc(Loc),
    LP => Lp(Lp<'a>),
    MB => Mb(Mb<'a>),
    MD => Md(Md<'a>),
    MF => Mf(Mf<'a>),
    MG => Mg(Mg<'a>),
    MINFO => Minfo(Minfo<'a>),
    MR => Mr(Mr<'a>),
    MX => Mx(Mx<'a>),
    NAPTR => Naptr(Naptr<'a>),
    NID => Nid(Nid),
    NIMLOC => Nimloc(Nimloc<'a>),
    NINFO => Ninfo(Ninfo<'a>),
    NS => Ns(Ns<'a>),
    NSAP => Nsap(Nsap<'a>),
    NSAP_PTR => NsapPtr(NsapPtr<'a>),
    NSEC => Nsec(Nsec<'a>),
    NSEC3 => Nsec3(Nsec3<'a>),
    NSEC3PARAM => Nsec3param(Nsec3param<'a>),
    NULL => Null(Null<'a>),
    NXT => Nxt(Nxt<'a>),
    OPENPGPKEY => Openpgpkey(Openpgpkey<'a>),
    OPT => Opt(crate::edns::Opt<'a>),
    PTR => Ptr(Ptr<'a>),
    PX => Px(Px<'a>),
    RESINFO => Resinfo(Resinfo<'a>),
    RKEY => Rkey(Rkey<'a>),
    RP => Rp(Rp<'a>),
    RRSIG => Rrsig(Rrsig<'a>),
    RT => Rt(Rt<'a>),
    SIG => Sig(Sig<'a>),
    SINK => Sink(Sink<'a>),
    SMIMEA => Smimea(Smimea<'a>),
    SOA => Soa(Soa<'a>),
    SPF => Spf(Spf<'a>),
    SRV => Srv(Srv<'a>),
    SSHFP => Sshfp(Sshfp<'a>),
    SVCB => Svcb(Svcb<'a>),
    TA => Ta(Ta<'a>),
    TALINK => Talink(Talink<'a>),
    TLSA => Tlsa(Tlsa<'a>),
    TSIG => Tsig(Tsig<'a>),
    TXT => Txt(Txt<'a>),
    URI => Uri(Uri<'a>),
    WALLET => Wallet(Wallet<'a>),
    WKS => Wks(Wks<'a>),
    X25 => X25(X25<'a>),
    ZONEMD => Zonemd(Zonemd<'a>),
}

impl<'a> RData<'a> {
    /// Parses standalone presentation-format RDATA (RFC 1035 §5.1; relative
    /// names are completed with the root, newlines are blanks) into `buf`
    /// and returns the typed view over it; see [`RData::parse_text`].
    ///
    /// ```
    /// use dnsbox::rdata::RData;
    /// use dnsbox::{Class, Rtype};
    ///
    /// let mut buf = [0u8; 512];
    /// let soa = RData::from_text(
    ///     Rtype::SOA,
    ///     Class::IN,
    ///     "ns1.example. hostmaster.example. ( 2024010101 1h 15m 1w 1d )",
    ///     &mut buf,
    /// )?;
    /// assert_eq!(
    ///     soa.to_string(),
    ///     "ns1.example. hostmaster.example. 2024010101 3600 900 604800 86400"
    /// );
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn from_text(rtype: Rtype, class: Class, text: &str, buf: &'a mut [u8]) -> Result<Self> {
        let mut w = WireWriter::new(buf);
        RData::parse_text(rtype, class, &mut Scanner::new(text), &mut w)?;
        let wire: &'a [u8] = w.into_written();
        RData::parse(rtype, class, WireReader::new(wire))
    }

    /// Parses standalone presentation-format RDATA (see
    /// [`from_text`](Self::from_text)) and returns its wire form in a new
    /// `Vec`.
    ///
    /// ```
    /// use dnsbox::rdata::RData;
    /// use dnsbox::{Class, Rtype};
    ///
    /// let wire = RData::text_to_wire(Rtype::TXT, Class::IN, r#""hello world" x"#)?;
    /// assert_eq!(wire, b"\x0bhello world\x01x");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[cfg(feature = "alloc")]
    pub fn text_to_wire(rtype: Rtype, class: Class, text: &str) -> Result<alloc::vec::Vec<u8>> {
        let mut out = alloc::vec::Vec::new();
        RData::parse_text(rtype, class, &mut Scanner::new(text), &mut out)?;
        Ok(out)
    }
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
