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
//! standard-library integration.
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
pub mod edns;
mod error;
pub mod header;
pub mod message;
pub mod name;
pub mod notify;
pub mod rdata;
pub mod rtype;
pub mod sig0;
pub mod tcp;
pub mod text;
pub mod tsig;
mod util;
pub mod update;
pub mod wire;

pub use builder::{Checkpoint, MessageBuilder};
pub use charstr::CharStr;
pub use class::Class;
pub use error::{Error, Result};
pub use header::{Flags, Header, Opcode, Rcode};
pub use message::{Message, Question, Record, Section};
pub use name::{Label, Name, NameBuf, ToName};
pub use rdata::{ComposeRdata, ParseRdata, RData};
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
