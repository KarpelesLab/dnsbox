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
//!    buffer, with name compression and truncation handled by the builder.
//! 4. **Broad RFC coverage.** EDNS(0), DNSSEC, SVCB/HTTPS, and the long tail
//!    of record types — see `ROADMAP.md` for the plan.
//!
//! The crate is `no_std`; the `alloc` and `std` features add owned types and
//! standard-library integration.
//!
//! **Status:** early development. Only the wire header is implemented so far.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod error;
pub mod header;

pub use error::{Error, Result};
pub use header::{Flags, Header, Opcode, Rcode};

// Compile and run the README example as a doctest.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
