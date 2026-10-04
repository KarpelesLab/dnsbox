//! Presentation format and master (zone) files (RFC 1035 §5).
//!
//! - [`Scanner`] reads the fields of presentation-format RDATA: the
//!   token source of every type's
//!   [`ParseRdataText`](crate::rdata::ParseRdataText) implementation, with
//!   the shared field parsers (numbers, TTLs, names relative to an origin,
//!   character-strings, hex, base64, base32hex, type bitmaps, DNSSEC
//!   timestamps).
//! - [`ZoneReader`] streams the records of a master file out of a `&str`
//!   without allocating: owner names are inline [`NameBuf`]s and RDATA is
//!   written to a caller-supplied buffer.
//! - With `alloc`, [`ZoneReader::records`] is an [`Iterator`] of owned
//!   [`ZoneRecordBuf`]s that can also follow `$INCLUDE` directives through
//!   an [`IncludeResolver`] (such as [`FsIncludes`] with `std`), and
//!   [`parse`] collects a whole zone.
//!
//! # Syntax
//!
//! The master-file format of RFC 1035 §5.1, as written by BIND and other
//! servers:
//!
//! - one entry per line; `(` ... `)` continue an entry over several
//!   lines; `;` starts a comment; `"..."` quotes a character-string;
//!   `\X` and `\DDD` escape a character;
//! - `owner [TTL] [class] type RDATA` with the TTL and class in either
//!   order; a line starting with a blank reuses the previous owner, `@` is
//!   the origin, and names without a trailing dot are relative to it;
//! - an omitted TTL is the `$TTL` default (RFC 2308 §4), else the last
//!   explicit TTL (RFC 1035 §5.1), else, for an SOA record, its MINIMUM
//!   field (as BIND does); an omitted class is the previous record's
//!   (initially IN, see [`ZoneReader::with_class`]);
//! - TTLs may use units: `1h30m`, `2d`, `1w` ([`parse_ttl`]);
//! - `TYPEnnn` and `CLASSnnn` (RFC 3597 §5) for any type and class, and
//!   `\# <length> <hex>` generic RDATA for any type (RFC 3597 §5);
//! - directives: `$ORIGIN <name>`, `$TTL <ttl>` (RFC 2308 §4),
//!   `$INCLUDE <file> [<origin>]` (reported as an [`Entry::Include`], or
//!   followed by [`Records`] with a resolver), and BIND's
//!   `$GENERATE <start>-<stop>[/<step>] <owner> [TTL] [class] <type>
//!   <rdata>` with `$` and `${offset,width,base}` substitutions.
//!
//! # Hostile input
//!
//! Every step does work linear in the text it consumes, and parenthesis
//! nesting is bounded. What a file can make the reader do beyond its own
//! length is bounded by [`ZoneLimits`], which are on by default: the
//! number of records (`$GENERATE` turns one short line into up to
//! [`MAX_GENERATE`] records), the `$INCLUDE` nesting, count and total
//! size, and the length of the text, its lines and its tokens. A limit
//! reached is an [`Error::LimitExceeded`](crate::Error::LimitExceeded)
//! with its position; raise the limits for large trusted zones.
//!
//! Errors carry the line and column ([`ZoneError`]); after an error the
//! reader resynchronises on the next entry, so all errors of a file can be
//! reported in one pass.
//!
//! `$INCLUDE` paths come from the file: [`FsIncludes::new`] serves only
//! regular files inside one directory (no absolute paths, no `..`, no
//! symbolic link leading out), [`FsIncludes::unconfined`] any file, for
//! trusted zone files.
//!
//! # Example
//!
//! ```
//! use dnsbox::zone::ZoneReader;
//! use dnsbox::{Rtype, rdata::RData};
//!
//! let zone = "\
//! $ORIGIN example.com.
//! $TTL 1h
//! @       IN  SOA ns1 hostmaster ( 2024010101 ; serial
//!                 2h 15m 2w 1h )
//!         IN  NS  ns1
//!         IN  MX  10 mail
//! ns1         A   192.0.2.1
//! mail    300 A   192.0.2.2
//! www         CNAME @
//! ";
//! let mut reader = ZoneReader::new(zone);
//! let mut buf = [0u8; 1024];
//! let mut lines = Vec::new();
//! while let Some(rr) = reader.next_record(&mut buf)? {
//!     if rr.rtype == Rtype::MX {
//!         let RData::Mx(mx) = rr.data()? else { unreachable!() };
//!         assert_eq!(mx.exchange.to_string(), "mail.example.com.");
//!     }
//!     lines.push(rr.to_string());
//! }
//! assert_eq!(lines[2], "example.com. 3600 IN MX 10 mail.example.com.");
//! assert_eq!(lines[4], "mail.example.com. 300 IN A 192.0.2.2");
//! # Ok::<(), dnsbox::Error>(())
//! ```
//!
//! [`NameBuf`]: crate::NameBuf

mod generate;
mod lexer;
mod limits;
mod reader;
#[cfg(feature = "alloc")]
mod records;
mod scanner;

pub use generate::MAX_GENERATE;
pub use limits::ZoneLimits;
pub use reader::{Entry, Include, ZoneError, ZoneReader, ZoneRecord};
#[cfg(feature = "std")]
pub use records::FsIncludes;
#[cfg(feature = "alloc")]
pub use records::{
    DEFAULT_MAX_INCLUDE_DEPTH, DEFAULT_MAX_INCLUDES, IncludeResolver, NoIncludes, Records,
    ZoneRecordBuf, parse, parse_with_limits,
};
pub(crate) use scanner::decimal;
pub use scanner::{Scanner, Token, Unescape, parse_ttl};

#[cfg(test)]
mod tests;
