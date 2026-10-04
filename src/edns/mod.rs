//! EDNS(0) (RFC 6891): the OPT pseudo-record, option codes, and typed
//! options.
//!
//! # Reading
//!
//! [`Message::edns`](crate::Message::edns) finds the OPT record of a message
//! (rejecting duplicates and non-root owners) and returns an [`Edns`] view
//! with the header fields packed into the record's CLASS and TTL — UDP
//! payload size, extended RCODE, version, DO and the other flag bits — and
//! the option list ([`Opt`]). Options are iterated lazily, either raw
//! ([`Opt::raw_options`], infallible) or typed ([`Opt::options`], yielding
//! [`EdnsOption`]s); [`Opt::get`] finds one typed option.
//!
//! ```
//! use dnsbox::{Message, Rcode};
//! use dnsbox::edns::{EdnsOption, Nsid};
//!
//! # let wire: &[u8] = &[
//! #     0xbe, 0xef, 0x84, 0x00, 0, 0, 0, 0, 0, 0, 0, 1,
//! #     0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 7, 0, 3, 0, 3, b'n', b's', b'1',
//! # ];
//! let msg = Message::parse_validated(wire)?;
//! let edns = msg.edns()?.expect("EDNS present");
//! assert_eq!(edns.udp_payload_size(), 1232);
//! assert!(edns.dnssec_ok());
//! assert_eq!(msg.effective_rcode()?, Rcode::NOERROR);
//! for opt in edns.options() {
//!     if let EdnsOption::Nsid(nsid) = opt? {
//!         assert_eq!(nsid.id, b"ns1");
//!     }
//! }
//! let nsid: Nsid<'_> = edns.get().expect("NSID present")?;
//! assert_eq!(nsid.id, b"ns1");
//! # Ok::<(), dnsbox::Error>(())
//! ```
//!
//! # Building
//!
//! [`MessageBuilder::push_edns`](crate::MessageBuilder::push_edns) appends an
//! OPT record from an [`OptHeader`] and any [`ComposeOptions`] — a single
//! option, a slice or array of options, a tuple of up to eight, or a parsed
//! [`Opt`] to echo. [`push_edns_padded`] adds a Padding option sized by an
//! RFC 8467 [`PaddingPolicy`].
//!
//! ```
//! use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
//! use dnsbox::edns::{Cookie, Nsid, OptHeader, PaddingPolicy};
//!
//! let name: NameBuf = "example.com".parse()?;
//! let mut buf = [0u8; 512];
//! let mut b = MessageBuilder::new(&mut buf)?;
//! b.push_question(&name, Rtype::A, Class::IN)?;
//! let header = OptHeader::new(1232).with_dnssec_ok(true);
//! let options = (Nsid::REQUEST, Cookie::client_only([1, 2, 3, 4, 5, 6, 7, 8]));
//! b.push_edns_padded(header, &options, PaddingPolicy::QUERY)?;
//! let wire = b.finish();
//! assert_eq!(wire.len(), 128);
//! let edns = Message::parse_validated(wire)?.edns()?.unwrap();
//! assert_eq!(edns.opt().raw_options().count(), 3);
//! # Ok::<(), dnsbox::Error>(())
//! ```
//!
//! [`push_edns_padded`]: crate::MessageBuilder::push_edns_padded
//!
//! # Adding an option
//!
//! 1. Create `src/edns/<option>.rs` with a view struct (borrowing from the
//!    message where useful) and implement [`ParseOption`],
//!    [`ComposeOption`] and [`fmt::Display`] (`MNEMONIC` or
//!    `MNEMONIC=value`).
//! 2. Add the module to the `edns_modules!` list below (one line).
//! 3. Add `CODE => Variant(Type),` to the `edns_registry!` list below (one
//!    line), with the [`OptionCode`] constant.
//!
//! Option codes without a typed implementation are kept as
//! [`EdnsOption::Unknown`] and pass through byte for byte.

use core::fmt;

use crate::Result;
use crate::wire::{Composer, WireReader};

open_enum! {
    /// An EDNS(0) option code (RFC 6891 §6.1.2; IANA "DNS EDNS0 Option
    /// Codes (OPT)" registry).
    ///
    /// Unregistered codes round-trip unchanged and display as `OPTnnn`.
    ///
    /// ```
    /// use dnsbox::edns::OptionCode;
    ///
    /// assert_eq!(OptionCode::COOKIE.get(), 10);
    /// assert_eq!("client-subnet".parse(), Ok(OptionCode::ECS));
    /// assert_eq!("OPT65001".parse(), Ok(OptionCode::new(65001)));
    /// assert_eq!(OptionCode::new(65001).to_string(), "OPT65001");
    /// ```
    pub struct OptionCode(u16), generic "OPT", aliases {
        "UPDATE-LEASE" => UL,
        "CLIENT-SUBNET" => ECS,
        "EDNS-CLIENT-SUBNET" => ECS,
        "EDNS-EXPIRE" => EXPIRE,
        "KEEPALIVE" => TCP_KEEPALIVE,
        "EDNS-TCP-KEEPALIVE" => TCP_KEEPALIVE,
        "EDNS-KEY-TAG" => KEY_TAG,
        "EXTENDED-DNS-ERROR" => EDE,
        "EDNS-CLIENT-TAG" => CLIENT_TAG,
        "EDNS-SERVER-TAG" => SERVER_TAG,
        "ZONE-VERSION" => ZONEVERSION,
    };
    // The complete IANA registry as of 2026-10-04
    // (https://www.iana.org/assignments/dns-parameters/dns-parameters-11.csv).
    /// Long-Lived Queries (RFC 8764).
    LLQ = 1 => "LLQ",
    /// Update Lease (RFC 9664).
    UL = 2 => "UL",
    /// Name Server Identifier (RFC 5001).
    NSID = 3 => "NSID",
    /// DNSSEC Algorithm Understood (RFC 6975 §3).
    DAU = 5 => "DAU",
    /// DS Hash Understood (RFC 6975 §3).
    DHU = 6 => "DHU",
    /// NSEC3 Hash Understood (RFC 6975 §3).
    N3U = 7 => "N3U",
    /// Client Subnet (RFC 7871 §6).
    ECS = 8 => "ECS",
    /// Zone expiry timer (RFC 7314).
    EXPIRE = 9 => "EXPIRE",
    /// DNS Cookie (RFC 7873 §4).
    COOKIE = 10 => "COOKIE",
    /// TCP keepalive timeout (RFC 7828 §3).
    TCP_KEEPALIVE = 11 => "TCP-KEEPALIVE",
    /// Padding (RFC 7830 §4).
    PADDING = 12 => "PADDING",
    /// CHAIN query requests (RFC 7901 §4).
    CHAIN = 13 => "CHAIN",
    /// Trust-anchor key tags (RFC 8145 §4).
    KEY_TAG = 14 => "KEY-TAG",
    /// Extended DNS Error (RFC 8914 §2).
    EDE = 15 => "EDE",
    /// Client tag (draft-bellis-dnsop-edns-tags).
    CLIENT_TAG = 16 => "CLIENT-TAG",
    /// Server tag (draft-bellis-dnsop-edns-tags).
    SERVER_TAG = 17 => "SERVER-TAG",
    /// Error-reporting agent domain (RFC 9567 §6.1).
    REPORT_CHANNEL = 18 => "REPORT-CHANNEL",
    /// Zone version (RFC 9660 §2).
    ZONEVERSION = 19 => "ZONEVERSION",
    /// Multiple QTYPEs, query side (RFC 10029).
    MQTYPE_QUERY = 20 => "MQTYPE-QUERY",
    /// Multiple QTYPEs, response side (RFC 10029).
    MQTYPE_RESPONSE = 21 => "MQTYPE-RESPONSE",
    /// Language of EDE EXTRA-TEXT (draft-muks-dns-filtering).
    EDE_EXTRA_TEXT_LANGUAGE = 22 => "EDE-EXTRA-TEXT-LANGUAGE",
    /// Filtering contact (draft-muks-dns-filtering).
    FILTERING_CONTACT = 23 => "FILTERING-CONTACT",
    /// Filtering organization (draft-muks-dns-filtering).
    FILTERING_ORGANIZATION = 24 => "FILTERING-ORGANIZATION",
    /// Filtering database (draft-muks-dns-filtering).
    FILTERING_DB = 25 => "FILTERING-DB",
    /// Structured DNS Error (RFC-ietf-dnsop-structured-dns-error).
    STRUCTURED_DNS_ERROR = 26 => "STRUCTURED-DNS-ERROR",
    /// Cisco Umbrella identity.
    UMBRELLA_IDENT = 20292 => "UMBRELLA-IDENT",
    /// Cisco device ID.
    DEVICE_ID = 26946 => "DEVICEID",
}

impl OptionCode {
    /// Whether the code lies in the range reserved for local or
    /// experimental use, 65001–65534 (RFC 6891 §9).
    #[inline]
    pub const fn is_local_use(self) -> bool {
        self.0 >= 65001 && self.0 <= 65534
    }
}

/// Parsing half of a typed EDNS option.
///
/// Implementations are views: they borrow from the message (lifetime `'a`)
/// and allocate nothing.
pub trait ParseOption<'a>: Sized {
    /// The option code this implementation handles.
    const CODE: OptionCode;

    /// Parses OPTION-DATA from `data`, a reader whose window is exactly the
    /// option's value (OPTION-LENGTH bytes).
    ///
    /// Implementations read their fields and return; the dispatcher
    /// ([`EdnsOption::parse`], [`RawOption::parse_as`]) rejects data that is
    /// not fully consumed with [`Error::TrailingData`](crate::Error). Report
    /// invalid lengths or field values as
    /// [`Error::InvalidOption`](crate::Error::InvalidOption).
    fn parse_option(data: &mut WireReader<'a>) -> Result<Self>;
}

/// Composing half of a typed EDNS option; what the OPT builders accept.
pub trait ComposeOption {
    /// The option code.
    fn code(&self) -> OptionCode;

    /// Writes OPTION-DATA (without the code and length) to `c`.
    fn compose_option<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()>;

    /// Writes the whole option: OPTION-CODE, OPTION-LENGTH and OPTION-DATA
    /// (RFC 6891 §6.1.2).
    fn compose_tlv<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_u16(self.code().get())?;
        c.put_u16_prefixed(|c| self.compose_option(c))
    }
}

/// Declares the option modules and re-exports their public items. One line
/// per file; keep the list sorted.
macro_rules! edns_modules {
    ($($module:ident,)*) => {
        $(
            mod $module;
            pub use $module::*;
        )*
    };
}

edns_modules! {
    chain,
    cookie,
    dau,
    ecs,
    ede,
    expire,
    keepalive,
    key_tag,
    nsid,
    padding,
    report_channel,
    unknown,
    zone_version,
}

mod build;
mod compose;
mod message;
mod opt;
mod record;

pub use build::{OPT_RR_OVERHEAD, PaddingPolicy};
pub use compose::{ComposeOptions, OptData};
pub use opt::{Opt, Options, RawOption, RawOptions};
pub use record::{Edns, EdnsFlags, OptHeader};

/// Generates [`EdnsOption`] and its dispatch from a list of
/// `CODE_CONST => Variant(Type),` lines.
macro_rules! edns_registry {
    ($( $(#[$attr:meta])* $code:ident => $var:ident($ty:ty), )*) => {
        /// A typed EDNS option, as yielded by [`Opt::options`].
        ///
        /// Option codes without a typed implementation are kept as
        /// [`EdnsOption::Unknown`], which round-trips the raw bytes.
        #[derive(Clone, Debug, PartialEq, Eq)]
        #[non_exhaustive]
        pub enum EdnsOption<'a> {
            $(
                $(#[$attr])*
                #[doc = concat!("`", stringify!($code), "` option.")]
                $var($ty),
            )*
            /// An option without a typed implementation.
            Unknown(UnknownOption<'a>),
        }

        impl<'a> EdnsOption<'a> {
            /// Parses OPTION-DATA of the given code. `data`'s window must be
            /// exactly the option value; it is fully consumed. Typed parse
            /// errors are returned, not downgraded to
            /// [`EdnsOption::Unknown`].
            pub fn parse(code: OptionCode, mut data: WireReader<'a>) -> Result<Self> {
                let opt = match code {
                    $(
                        $(#[$attr])*
                        OptionCode::$code => {
                            const {
                                assert!(
                                    <$ty as ParseOption<'a>>::CODE.get() == OptionCode::$code.get(),
                                    "registry entry does not match ParseOption::CODE",
                                )
                            };
                            EdnsOption::$var(<$ty as ParseOption<'a>>::parse_option(&mut data)?)
                        }
                    )*
                    _ => EdnsOption::Unknown(UnknownOption::new(code, data.read_rest())),
                };
                data.finish()?;
                Ok(opt)
            }

            /// Whether `code` has a typed implementation.
            pub const fn is_known(code: OptionCode) -> bool {
                match code {
                    $( $(#[$attr])* OptionCode::$code => true, )*
                    _ => false,
                }
            }
        }

        impl ComposeOption for EdnsOption<'_> {
            fn code(&self) -> OptionCode {
                match self {
                    $( $(#[$attr])* EdnsOption::$var(_) => OptionCode::$code, )*
                    EdnsOption::Unknown(u) => u.code(),
                }
            }

            fn compose_option<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
                match self {
                    $( $(#[$attr])* EdnsOption::$var(o) => o.compose_option(c), )*
                    EdnsOption::Unknown(u) => u.compose_option(c),
                }
            }
        }

        impl fmt::Display for EdnsOption<'_> {
            /// `MNEMONIC` or `MNEMONIC=value`; unknown options show their
            /// value in hex (`OPT65001=C0FFEE`).
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    $( $(#[$attr])* EdnsOption::$var(o) => fmt::Display::fmt(o, f), )*
                    EdnsOption::Unknown(u) => fmt::Display::fmt(u, f),
                }
            }
        }
    };
}

// One line per typed option; keep the list sorted by code constant.
edns_registry! {
    CHAIN => Chain(Chain<'a>),
    COOKIE => Cookie(Cookie<'a>),
    DAU => Dau(Dau<'a>),
    DHU => Dhu(Dhu<'a>),
    ECS => ClientSubnet(ClientSubnet),
    EDE => ExtendedError(ExtendedError<'a>),
    EXPIRE => Expire(Expire),
    KEY_TAG => KeyTag(KeyTag<'a>),
    N3U => N3u(N3u<'a>),
    NSID => Nsid(Nsid<'a>),
    PADDING => Padding(Padding<'a>),
    REPORT_CHANNEL => ReportChannel(ReportChannel<'a>),
    TCP_KEEPALIVE => TcpKeepalive(TcpKeepalive),
    ZONEVERSION => ZoneVersion(ZoneVersion<'a>),
}

impl EdnsOption<'_> {
    /// The option code.
    #[inline]
    pub fn code(&self) -> OptionCode {
        ComposeOption::code(self)
    }
}

/// Writes `CODE` when `data` is empty, `CODE=HEX` otherwise.
pub(crate) fn fmt_hex_option(
    f: &mut fmt::Formatter<'_>,
    code: OptionCode,
    data: &[u8],
) -> fmt::Result {
    if data.is_empty() {
        write!(f, "{code}")
    } else {
        write!(f, "{code}={}", crate::text::Hex(data))
    }
}

#[cfg(test)]
pub(crate) mod tests;
