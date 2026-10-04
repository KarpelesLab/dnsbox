//! # dnsbox
//!
//! High-performance DNS message parsing and building, for both queries and
//! responses.
//!
//! The design goals, in order:
//!
//! 1. **Safe on hostile input.** Parsing never panics and never reads out of
//!    bounds; malformed messages are rejected with an [`Error`]. The crate is
//!    `#![forbid(unsafe_code)]`.
//! 2. **Zero-copy, allocation-free parsing.** Messages are parsed as views
//!    over the caller's buffer; names and record data are decoded lazily.
//! 3. **Fast building.** Messages are written straight into a caller-supplied
//!    buffer, with name compression handled by the builder.
//! 4. **Broad RFC coverage.** EDNS(0), DNSSEC, SVCB/HTTPS, and the long tail
//!    of record types — see `ROADMAP.md` for the plan.
//!
//! The crate is `no_std`; the `alloc` and `std` features add owned types and
//! standard-library integration (see [Cargo features](#cargo-features)).
//!
//! ## Parsing
//!
//! ```
//! use dnsbox::{Message, Rtype, rdata::RData};
//!
//! # let wire: &[u8] = &[
//! #     0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
//! #     7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
//! #     0, 1, 0, 1,
//! #     0xc0, 12, 0, 1, 0, 1, 0, 0, 0x0e, 0x10, 0, 4, 93, 184, 216, 34,
//! # ];
//! let msg = Message::parse(wire)?;
//! for rr in msg.answers() {
//!     let rr = rr?;
//!     if let RData::A(a) = rr.data()? {
//!         println!("{} has address {}", rr.name(), a.addr);
//!     }
//! }
//! # Ok::<(), dnsbox::Error>(())
//! ```
//!
//! ## Building
//!
//! ```
//! use dnsbox::{Class, MessageBuilder, NameBuf, Rtype, Flags};
//!
//! let name: NameBuf = "example.com".parse()?;
//! let mut buf = [0u8; 512];
//! let mut b = MessageBuilder::new(&mut buf)?;
//! b.set_id(0x1234);
//! b.set_flags(Flags::default().with_rd(true));
//! b.push_question(&name, Rtype::A, Class::IN)?;
//! let wire = b.finish();
//! assert_eq!(wire.len(), 29);
//! # Ok::<(), dnsbox::Error>(())
//! ```
//!
//! ## Text, owned data and serde
//!
//! A [`Message`] displays in `dig` style (BIND 9's layout, no allocation).
//! With `alloc`, [`OwnedMessage`] and friends ([`owned`]) copy a message
//! out of its buffer and write it back through the builder. Text parses
//! back too: [`ParseRdataText`] and [`RData::parse_text`] read a record's
//! presentation format, and [`zone::ZoneReader`] reads RFC 1035 master
//! files, both without allocating. The `serde`
//! feature (`no_std`) serializes protocol numbers ([`Rtype`], [`Class`],
//! [`Opcode`], [`Rcode`], every registry newtype) as mnemonics such as
//! `"MX"` or `"TYPE65534"` in human-readable formats and as integers
//! otherwise, names as presentation strings, [`Flags`] as a struct of
//! bits, and, with `alloc`, the owned types.
//!
//! ## Cargo features
//!
//! Every feature is additive, and the crate builds with none of them
//! (`no_std`, no allocation, no dependencies). Items that need a feature
//! are labelled with it in the documentation.
//!
//! | Feature | Default | Adds |
//! |---------|---------|------|
//! | `std` | yes | `std::io` TCP helpers ([`tcp::read_message`], [`tcp::write_message`]), `$INCLUDE` from the file system ([`zone::FsIncludes`]); implies `alloc` |
//! | `alloc` | | `Vec`-backed builders ([`MessageBuilder::new_vec`]), the owned types ([`owned`]), [`zone::ZoneReader::records`] and [`zone::parse`], DNSSEC RRset sorting and ZONEMD collation, the SIG(0) adapters over the DNSSEC traits |
//! | `dnssec-digest` | | DS digests and NSEC3 hashing ([`dnssec::verify_ds`], [`dnssec::nsec3_hash`]) without `alloc`; with `alloc`, ZONEMD digests |
//! | `dnssec` | | DNSSEC and SIG(0) signature verification and signing: RSA, ECDSA P-256/P-384, Ed25519, Ed448; implies `alloc` and `dnssec-digest` |
//! | `tsig` | | the TSIG HMAC backend ([`tsig::HmacKey`]: HMAC-MD5, SHA-1, SHA-2) |
//! | `cookie-siphash` | | RFC 9018 server cookies ([`edns::ServerCookie::generate`] / [`verify`](edns::ServerCookie::verify)) |
//! | `serde` | | `Serialize` / `Deserialize` (`no_std`) for the registries, names, header flags and, with `alloc`, the owned types |
//!
//! dnsbox never implements cryptography: the crypto features enable the
//! optional, `no_std` [`purecrypto`](https://crates.io/crates/purecrypto)
//! dependency. Every crypto-using API sits behind a trait
//! ([`dnssec::Verifier`], [`dnssec::Signer`], [`tsig::TsigKey`],
//! [`sig0::Sig0Signer`], ...) so other backends can be plugged in, and the
//! wire-format side (signed data, MAC input, canonical forms) works without
//! any feature.
//!
//! ## Errors
//!
//! Fallible functions return [`Result<T>`](Result) with the crate-wide
//! [`Error`]: one byte, `Copy`, `#[non_exhaustive]`. Zone-file errors carry
//! their position ([`zone::ZoneError`]) and convert into [`Error`] with `?`.
//! Parsing never panics on hostile input; see `SECURITY.md`.
//!
//! ## Conventions
//!
//! - Protocol numbers ([`Rtype`], [`Class`], [`Opcode`], [`Rcode`],
//!   [`edns::OptionCode`], [`dnssec::Algorithm`], ...) are open newtypes:
//!   unknown values round-trip, `Display` prints the mnemonic or the
//!   generic form (`TYPE65534`) and `FromStr` parses both back.
//! - Views borrow the caller's buffer (`Message<'a>`, `Name<'a>`, every
//!   type in [`rdata`]); `parse` / `from_wire` read wire data, `from_text`
//!   presentation format; `as_wire` returns a view's wire form, `as_bytes`
//!   the contents of a buffer or an opaque field.
//! - Builders write into an [`OutBuf`]: a [`WireWriter`] over a caller's
//!   `&mut [u8]` (`new`), or, with `alloc`, a `Vec<u8>` (`new_vec`); any
//!   `OutBuf` (`from_buf`). `set_*` methods configure a builder in place;
//!   `with_*` methods take a value and return it modified (builder style).
//! - Every public type is `Send` and `Sync` (when its type parameters
//!   are).
//!
//! See `ARCHITECTURE.md` in the repository for the module layout and the
//! extension recipes (adding record types, EDNS options, ...).

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(any(test, feature = "alloc"))]
extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate std;

#[macro_use]
mod macros;

pub mod builder;
pub mod charstr;
pub mod class;
pub mod dnssec;
pub mod dso;
pub mod edns;
mod error;
pub mod header;
pub mod message;
pub mod name;
pub mod notify;
#[cfg(feature = "alloc")]
pub mod owned;
pub mod rdata;
pub mod rtype;
#[cfg(feature = "serde")]
mod serde_impls;
pub mod sig0;
pub mod tcp;
pub mod text;
pub mod tsig;
pub mod update;
mod util;
pub mod wire;
pub mod xfr;
pub mod zone;

pub use builder::{Checkpoint, MessageBuilder};
pub use charstr::CharStr;
pub use class::Class;
pub use error::{Error, Result};
pub use header::{Flags, Header, Opcode, Rcode};
pub use message::{Message, Question, Record, Section};
pub use name::{Label, Name, NameBuf, ToName};
#[cfg(feature = "alloc")]
pub use owned::{OwnedMessage, OwnedQuestion, OwnedRData, OwnedRecord};
pub use rdata::{ComposeRdata, ParseRdata, ParseRdataText, RData};
pub use rtype::Rtype;
pub use wire::{Composer, NameEncoding, OutBuf, WireReader, WireWriter};

#[cfg(test)]
pub(crate) mod testutil {
    use std::vec::Vec;

    /// Decodes a hex string (whitespace ignored).
    pub(crate) fn hex(s: &str) -> Vec<u8> {
        let digits: Vec<u8> = s
            .bytes()
            .filter(|b| !b.is_ascii_whitespace())
            .map(|b| (b as char).to_digit(16).expect("hex digit") as u8)
            .collect();
        digits.chunks(2).map(|p| p[0] << 4 | p[1]).collect()
    }
}

// Compile and run the README example as a doctest.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
