# dnsbox architecture

This is the guide for anyone extending `dnsbox`. It describes how the crate
is laid out, the core APIs every layer builds on, and the recipes for the
"many small things" (record types, protocol registries, EDNS options) so
that parallel work merges with trivial conflicts.

The design principles in [ROADMAP.md](ROADMAP.md) are binding. In short:
never panic or index out of bounds on hostile input, bounded work per
message, `#![forbid(unsafe_code)]`, zero-copy views, no allocation in the
core, builders write into caller buffers, open newtypes for protocol
numbers, `no_std` first, no mandatory dependencies, MSRV 1.89.

## Module layout

```text
src/
  lib.rs          crate root: re-exports, crate docs
  macros.rs       open_enum! (protocol-number newtypes)        [crate-internal]
  error.rs        Error (#[non_exhaustive]) and Result
  header.rs       Header, Flags, Opcode, Rcode (RFC 1035 §4.1.1)
  rtype.rs        Rtype: complete IANA RR TYPE registry
  class.rs        Class: IANA CLASS registry
  wire/
    reader.rs     WireReader: bounds-checked read cursor
    writer.rs     OutBuf, WireWriter, Composer, NameEncoding, Canonical
  name/
    mod.rs        Name<'a>, Label, Labels, ToName, limits
    decode.rs     the wire decoder (hardening) and its suffix cache
    buf.rs        NameBuf (inline 255-byte owned name), text parsing
    tests.rs
  charstr.rs      CharStr, CharStrs (<character-string>, RFC 1035 §3.3)
  tcp.rs          TCP framing (RFC 1035 §4.2.2 / RFC 7766): length prefix,
                  frame splitting, FrameReassembler, std::io helpers
  text.rs         presentation-format helpers: escaping, Hex, Base64,
                  Base32Hex, RFC 3597 generic RDATA
  util/           crate-internal helpers: base64.rs, base32hex.rs
                  (no_std, allocation-free decoders)
  message/
    mod.rs        Message<'a>, Section, Question, Record, iterators, validate
    dig.rs        dig-style Display of whole messages (BIND 9 layout; shared
                  with OwnedMessage through the DigMessage/DigRecord traits)
    tests.rs
  owned/          (alloc) OwnedMessage, OwnedQuestion, OwnedRecord, OwnedRData:
    mod.rs        conversions from the views and into the builder
    serde_impl.rs serde for the owned types (serde + alloc)
    tests.rs
  serde_impls.rs  (serde) helpers for open_enum!, Name/NameBuf, Flags,
                  Opcode, Rcode
  rdata/
    mod.rs        ParseRdata / ComposeRdata traits, rdata_modules!,
                  rdata_registry! -> RData<'a>
    <type>.rs     one file per record type or tight family
    svcb/         SVCB/HTTPS (RFC 9460): SvcParamKey, SvcParams view,
                  typed values (`rdata::svcparam`), SvcbBuilder, text
    bitmap.rs     TypeBitmap (NSEC/NSEC3/CSYNC window bitmaps)
    unknown.rs    UnknownRdata (RFC 3597 passthrough)
    tests.rs      shared test helpers (round_trip, parse, compose)
  builder/
    mod.rs        MessageBuilder, Checkpoint
    compress.rs   fixed-size label trie for name compression
    truncate.rs   Truncation policy, Outcome, push_rrset(_with),
                  copy_section, copy_message, reserve (RFC 2181 §9)
    query.rs      start_query / start_response, response_flags
    raw.rs        push_raw_records (pre-encoded records)
    framing.rs    new_tcp / from_buf_tcp (length-prefixed messages)
    tests.rs
  edns/           EDNS(0) (RFC 6891): OPT view, OptHeader, option registry,
                  typed options, builder support (see below)
  dnssec/         DNSSEC (RFC 4033-4035, 5155): registries, canonical
                  form, key tags, DS/NSEC3, RRSIG checks, backends
  tsig/           TSIG (RFC 8945): MAC input, signer/verifier, key traits,
                  hmac.rs = purecrypto HMAC backend (feature `tsig`)
  sig0.rs         SIG(0) (RFC 2931): signed data, Sig0Signer/Sig0Verifier,
                  adapters over the DNSSEC Signer/Verifier (`alloc`)
  update.rs       dynamic UPDATE (RFC 2136): UpdateBuilder, UpdateMessage
  notify.rs       NOTIFY (RFC 1996)
  xfr.rs, xfr/    AXFR/IXFR (RFC 5936, RFC 1995): queries, XfrProcessor
  dso.rs          DNS Stateful Operations (RFC 8490): TLVs, DsoBuilder
  zone/           presentation format and master files (RFC 1035 §5):
    lexer.rs      tokenizer: blanks, comments, parentheses, quotes,
                  escapes, positions                    [crate-internal]
    scanner.rs    Scanner (RDATA field reader + shared field parsers),
                  Token, Unescape, parse_ttl
    reader.rs     ZoneReader (streaming, allocation-free), ZoneRecord,
                  Entry/Include, ZoneError (line/column)
    generate.rs   BIND $GENERATE ranges and substitutions
    records.rs    alloc: Records iterator, ZoneRecordBuf, $INCLUDE via
                  IncludeResolver (FsIncludes with std), parse()
    tests.rs      RFC 1035 §5.3 zone, signed zone, directives, errors
tests/
  captures.rs     real wire captures, truncation and mutation tests
  builder_truncation.rs  truncation / TCP stream tests on captures
  edns.rs, svcb_captures.rs, dnssec_captures.rs, rdata_batch_a.rs,
  rdata_b.rs      real captures per feature area (decode, rebuild byte
                  for byte, truncate, mutate)
  *_named.rs      BIND 9.18 interop (TSIG, SIG(0), UPDATE, XFR); the
                  binary captures live in tests/data/named/
  corpus.rs, corpus/   interop corpus (BIND, NSD, Knot, PowerDNS, ...)
  fuzz_regressions.rs  fuzz seeds/regressions replayed on stable
  proptest_roundtrip.rs, no_alloc.rs   property tests, allocation check
  dig_display.rs  Message Display vs BIND dig 9.18 output (tests/data/dig/)
  serde.rs        serde forms and corpus round trips (serde_json, serde_test)
fuzz/             cargo-fuzz targets (own workspace, nightly)
benches/          criterion benchmarks (own package; see BENCH.md)
```

Everything public is re-exported at the crate root when it is used often
(`Message`, `Record`, `Name`, `NameBuf`, `Rtype`, `Class`, `RData`,
`MessageBuilder`, `WireReader`, `WireWriter`, `Composer`, ...). Record data
types live in `dnsbox::rdata` (`dnsbox::rdata::Mx`, ...).

## Wire primitives (`wire`)

### Reading: `WireReader<'a>`

A cursor over a received message. It holds the **whole message**, a
position and an **end** (the read window):

```rust
let mut r = WireReader::new(msg);                     // window = whole msg
let mut r = WireReader::with_range(msg, start, end)?; // window = msg[start..end]
r.read_u8()? / read_u16()? / read_u32()? / read_u48()? / read_u64()?
r.read_bytes(n)?        // -> &'a [u8], zero-copy
r.read_array::<N>()?    // -> [u8; N]
r.read_rest()           // rest of the window
r.peek_u8()? / peek_rest()
r.skip(n)?
r.read_char_string()?   // -> CharStr<'a>
r.read_name()?          // -> Name<'a>, follows compression pointers
r.read_name_uncompressed()? // pointer => Error::UnexpectedPointer
r.sub_reader(n)?        // split off the next n bytes as their own window
r.finish()?             // Error::TrailingData unless the window is consumed
r.position() / end() / remaining() / is_empty() / message()
```

All reads are bounds-checked and return `Error::UnexpectedEof` instead of
panicking; **a failed read never moves the cursor**. Names may follow
pointers anywhere *before* them in the whole message, even when the window
is just one record's RDATA — that is why the reader carries the message.

### Writing: `OutBuf`, `WireWriter`, `Composer`

- `OutBuf` is byte storage: `WireWriter<'b>` (a cursor over a caller's
  `&mut [u8]`) and, with `alloc`, `Vec<u8>`. Appends are all-or-nothing
  (`Error::BufferTooSmall`).
- `Composer` is what record data writes to. Methods: `pos`, `put_bytes`,
  `patch`, `put_name(name, NameEncoding)`, plus provided `put_u8/u16/u32/
  u48/u64`, `put_char_string` and `put_u16_prefixed(|c| ...)` (writes a
  16-bit length placeholder, runs the closure, patches the length — use it
  for EDNS options, SvcParams, ...).
- Every `OutBuf` is a `Composer` that writes names **uncompressed and
  verbatim**. The message builder hands record data its own composer that
  may compress. `wire::Canonical::new(&mut composer)` is an adapter that
  produces DNSSEC canonical form (RFC 4034 §6.2): no compression, and
  `Compressible`/`Lowercase` names lowercased.

`NameEncoding` is how a record type declares the RFC rules for each name it
writes:

| Variant        | Compressed by builder | Lowercased in canonical form | Use for |
|----------------|-----------------------|------------------------------|---------|
| `Compressible` | yes (if enabled)      | yes | owner/question names; RDATA of NS, MD, MF, CNAME, SOA, MB, MG, MR, PTR, MINFO, MX only (RFC 3597 §4) |
| `Lowercase`    | never                 | yes | RP, AFSDB, RT, SIG, PX, NXT, NAPTR, KX, SRV, DNAME, A6, RRSIG (RFC 4034 §6.2 / RFC 6840 §5.1) |
| `Plain`        | never                 | no  | everything else (NSEC next name, SVCB target, HIP, ...) |

## Names (`name`)

- **`Name<'a>`** — `Copy` view of a validated name. It points into a
  message (possibly compressed: labels are followed lazily) or into any
  uncompressed buffer. Construct with `WireReader::read_name`,
  `Name::from_wire(bytes)` (uncompressed, must fill `bytes`), or
  `NameBuf::as_name()`. `Name::ROOT` is `.`.
  Accessors (all infallible): `labels()` (left to right, root excluded,
  `ExactSizeIterator`), `label_count()`, `wire_len()` (uncompressed length
  incl. root), `is_root()`, `is_wildcard()`, `first_label()`, `parent()`,
  `strip_labels(n)`, `is_subdomain_of(&other)`, `as_contiguous()` (the
  uncompressed wire bytes if stored contiguously — the fast path),
  `flatten(&mut [u8; 255])`, `to_buf()`, `eq_exact()` (case-sensitive),
  `cmp_canonical()`.
- **`NameBuf`** — owned, uncompressed, inline `[u8; 255]` + 2 bytes; no
  allocation, `Clone` but not `Copy`. `"www.example.com".parse()`,
  `from_wire`, `from_labels`, `from_name`, `as_name`, `as_wire`,
  `prepend_label`, `make_ascii_lowercase` (canonical form).
- **`Label<'a>`** — one label's bytes, `Display` with escapes.
- **`ToName`** — implemented by `Name`, `NameBuf` and references; builder
  methods take `impl ToName`.

Semantics: names are always **absolute** (`example.com` ≡ `example.com.`).
`PartialEq`/`Hash` are ASCII-case-insensitive (RFC 4343); `Ord` is DNSSEC
canonical order (RFC 4034 §6.1). `Display` is presentation format with a
trailing dot, `\.`, `\\`, `\"`, `\(`, `\)`, `\;`, `\@`, `\$` and `\DDD`
escapes; `FromStr` accepts `\X` and `\DDD`.

Hardening on the wire (all in `name/decode.rs`, behind
`Name::parse_bounded`, used by the reader): labels ≤ 63, names ≤ 255 octets
uncompressed, label types `0b01`/`0b10` rejected (`BadLabelType`), a
pointer must point **strictly before the start of the current run of
labels** (rejects forward pointers, self pointers and all loops —
`BadPointer`), at most `MAX_POINTERS` (128) hops per name
(`TooManyPointers`).

The record iterators decode owner names through a small suffix cache
(`NameCache`, 16 entries, no allocation): what decoding from an offset
produced is remembered, so a pointer to an offset already decoded in this
message costs one lookup instead of a walk (every owner name of a large
response points at the question; chains of names each one label longer
than the previous one would otherwise be re-walked). A cached suffix is
only used when the combined name provably passes the checks the walk would
make; otherwise the decoder walks, so results and errors are identical with
and without the cache (unit-tested differentially, and checked by the
`message` fuzz target).

## Messages (`message`)

- `Message::parse(buf)` checks only the 12-byte header (O(1)).
- `msg.questions()` → `Result<Question>` items; `msg.answers()`,
  `authority()`, `additional()`, `section(Section)` → `Result<Record>`;
  `msg.records()` → `Result<(Section, Record)>` over all three RR sections
  in one pass. Iterators yield exactly the header count, then stop; on
  error they yield the error once and then end (fused). Iterating never
  looks at RDATA (only RDLENGTH); `data()` decodes it. Locating a later
  section skips the earlier ones cheaply (no pointer following).
- `msg.validate()` / `Message::parse_validated(buf)` walk everything once:
  names with full hardening, counts, typed RDATA of every registered type,
  and no trailing bytes. Use this to fail fast.
- `Question`: `name()`, `qtype()`, `qclass()`, `range()`.
- `Record`: `name()`, `rtype()`, `class()`, `ttl()` (raw), `rdata()` (raw
  bytes — **may contain compression pointers** for RFC 1035 types),
  `rdata_reader()`, `data()` → `RData` (typed), `data_as::<T>()`
  (`WrongType` on mismatch), `start()`, `end()`, `rdata_range()`,
  `message()`. Ranges let TSIG/SIG(0) code slice the message.
  `Display` is zone-file style `name ttl class type rdata`.
- `Section` is ordered `Question < Answer < Authority < Additional`.

## Record data (`rdata`)

### The traits

```rust
pub trait ParseRdata<'a>: Sized {
    const RTYPE: Rtype;
    const CLASS: Option<Class> = None;   // Some(Class::IN) for A, AAAA, WKS...
    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self>;
}

pub trait ComposeRdata {
    fn rtype(&self) -> Rtype;
    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()>;
}

pub trait ParseRdataText {           // presentation format -> wire
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        Err(Error::NoTextFormat)     // default: only `\# len hex` accepted
    }
    fn from_text<'b>(text: &str, buf: &'b mut [u8]) -> Result<Self>
    where Self: ParseRdata<'b>;      // provided: text -> wire -> view
}
```

- `parse_rdata` gets a reader whose window is exactly the RDATA. Just read
  the fields; the dispatcher calls `finish()` afterwards and reports
  leftovers as `TrailingData`. Report invalid field values as
  `Error::InvalidRdata`.
- Types are **views**: borrow from the message (`&'a [u8]`, `Name<'a>`,
  `CharStr<'a>`, ...) and allocate nothing. Derive
  `Clone, Copy (if possible), Debug, PartialEq, Eq` (+ `Hash` when cheap).
- Implement `fmt::Display` with the type's presentation format (RFC zone
  file syntax) using the `text` helpers (`fmt_quoted`, `Hex`, `Base64`,
  `Base32Hex`, `fmt_generic_rdata` for types without one).
- Where a view is awkward to construct for building (e.g. TXT needs
  pre-encoded strings), add a compose-only companion implementing just
  `ComposeRdata` (see `TxtParts`). It does not go in the registry.
- Names in RDATA: read with `read_name()` only for types RFC 3597 §4 lets
  receivers decompress (the RFC 1035 types plus RP, AFSDB, RT, SIG, PX,
  NXT, NAPTR, SRV); everything else uses `read_name_uncompressed()`. Write
  with the `NameEncoding` from the table above.

### The registry and `RData<'a>`

`src/rdata/mod.rs` contains two one-line-per-entry lists:

```rust
rdata_modules! {
    a,
    aaaa,
    ...
}

rdata_registry! {
    A => A(A),
    AAAA => Aaaa(Aaaa),
    CNAME => Cname(Cname<'a>),
    ...
}
```

`rdata_modules!` declares `mod x; pub use x::*;` per file.
`rdata_registry!` lines are `RTYPE_CONST => Variant(Type),` and generate the
`#[non_exhaustive] enum RData<'a>` (plus `RData::Unknown(UnknownRdata)`),
`RData::parse(rtype, class, reader)`, `RData::is_known(rtype)`,
`RData::parse_text(rtype, class, scanner, out)` (text → wire, through each
type's `ParseRdataText`; see below), `ComposeRdata for RData` and
`Display for RData`. A compile-time assertion
checks that each line's constant equals the type's `ParseRdata::RTYPE`.
Lines may carry attributes (e.g. `#[cfg(feature = "alloc")]`).

Dispatch rules (`RData::parse`):

1. Empty RDATA of a non-meta type in class NONE or ANY (dynamic-update
   deletions and prerequisites, RFC 2136) → `Unknown` with empty data.
   Meta types (OPT, TSIG, TKEY, ...) are exempt because their CLASS field
   means something else.
2. A registered class-specific type (`CLASS = Some(c)`) in a class other
   than `c`, NONE or ANY → `Unknown` (RFC 3597 §4: class-specific formats).
3. Otherwise the registered type's parser; **errors are returned, not
   downgraded to `Unknown`**. Callers wanting leniency can fall back to
   `UnknownRdata::new(rr.rtype(), rr.rdata())`.
4. Unregistered types → `Unknown` (raw bytes, RFC 3597; such RDATA never
   contains compression pointers so it can be copied verbatim).

### Recipe: adding a record type

1. **Create `src/rdata/<type>.rs`** named after the lowercase mnemonic:
   one file per type (`ds.rs`, `dnskey.rs`, `rrsig.rs`, ...) or per tight
   family sharing one wire layout (e.g. DS and CDS in `ds.rs`). Avoid
   catch-all files such as `dnssec.rs`: small files keep parallel branches
   from conflicting.
2. **Define the view struct** with public fields named after the RFC.
3. **Implement `ParseRdata<'a>`, `ComposeRdata`, `Display` and
   `ParseRdataText`** (the registry requires the last one; see
   [the text recipe](#recipe-adding-text-parsing-for-a-type), or write
   `impl super::ParseRdataText for Foo<'_> {}` if the type has no
   presentation format of its own).
4. **Register it**: add `<file>,` to `rdata_modules!` and
   `RTYPE => Variant(Type),` to `rdata_registry!`, both in sorted position
   (the `Rtype` constant already exists — `rtype.rs` holds the complete
   IANA registry; never edit it for a new type).
5. **Test it** in the same file (`#[cfg(test)] mod tests`), using
   `crate::rdata::tests::round_trip(rtype, wire, presentation)`, which
   parses, checks `Display`, re-composes to identical bytes and tries every
   truncation. Use RFC examples and real captures; add malformed cases
   (bad lengths, invalid fields) asserting the exact `Error`.

Worked example (a simplified version of `src/rdata/srv.rs`):

```rust
//! SRV record data (RFC 2782).

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, WireReader};
use crate::{Result, Rtype};

/// `SRV` record data: the location of a service (RFC 2782).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Srv<'a> {
    /// Priority; lower values are tried first.
    pub priority: u16,
    /// Relative weight among records of equal priority.
    pub weight: u16,
    /// Port of the service.
    pub port: u16,
    /// Host providing the service (`.` means "not available").
    pub target: Name<'a>,
}

impl<'a> ParseRdata<'a> for Srv<'a> {
    const RTYPE: Rtype = Rtype::SRV;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        Ok(Srv {
            priority: rdata.read_u16()?,
            weight: rdata.read_u16()?,
            port: rdata.read_u16()?,
            // RFC 3597 §4 lists SRV among the types receivers decompress.
            target: rdata.read_name()?,
        })
    }
}

impl ComposeRdata for Srv<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::SRV
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_u16(self.priority)?;
        c.put_u16(self.weight)?;
        c.put_u16(self.port)?;
        // Never compressed (RFC 2782), lowercased in canonical form
        // (RFC 4034 §6.2).
        c.put_name(self.target, NameEncoding::Lowercase)
    }
}

impl fmt::Display for Srv<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {} {}", self.priority, self.weight, self.port, self.target)
    }
}

#[cfg(test)]
mod tests {
    use crate::Rtype;
    use crate::rdata::tests::round_trip;

    #[test]
    fn rfc2782_example() {
        round_trip(
            Rtype::SRV,
            b"\x00\x00\x00\x01\x00\x15\x04ftp1\x07example\x03com\x00",
            "0 1 21 ftp1.example.com.",
        );
    }
}
```

and in `src/rdata/mod.rs`:

```diff
 rdata_modules! {
     ...
     soa,
+    srv,
     txt,
 }
 rdata_registry! {
     ...
     SOA => Soa(Soa<'a>),
+    SRV => Srv(Srv<'a>),
     TXT => Txt(Txt<'a>),
 }
```

Single-name types (like DNAME) can reuse the internal macro:

```rust
// src/rdata/dname.rs
super::single_name::single_name_rdata! {
    /// `DNAME` record data: a delegation name (RFC 6672 §2.1).
    Dname, DNAME, target, Lowercase, read_name
}
```

(arguments: docs, type, `Rtype` constant, field, `NameEncoding` variant for
composing, reader method for parsing). The macro also implements
`ParseRdataText` (one `<domain-name>`).

### Recipe: adding text parsing for a type

Presentation-format parsing (zone files, `nsupdate`-style tools, test
fixtures) is one trait per type, `ParseRdataText`, dispatched by
`RData::parse_text(rtype, class, &mut scanner, &mut out)`. It turns the
type's text form (RFC 1035 §5.1 for the classic types, the "Presentation
Format" section of each later RFC) into the **wire form**, appended to an
`OutBuf` (a `WireWriter` over a caller's `&mut [u8]`, or a `Vec<u8>`), so
it allocates nothing; `ParseRdataText::from_text(text, &mut buf)` then
returns the typed view and `zone::ZoneReader` uses it for every record.

Every registered type already implements the trait; types without a
real implementation have a one-line stub,
`impl super::ParseRdataText for Foo<'_> {}`, whose provided `parse_text`
fails with `Error::NoTextFormat` (such types can only be written in the
RFC 3597 generic form `\# <length> <hex>`, which the dispatcher accepts
for every type). Adding text parsing to a type:

1. **Replace the stub** in `src/rdata/<type>.rs` (inside the family
   macro if the whole family shares one format) with an implementation
   that reads the fields in RFC order with the `Scanner` methods and
   writes them with the `Composer` methods `out` provides — the same
   order and encodings as `compose_rdata`, names with the same
   `NameEncoding`.
2. **Only read your fields.** Do not call `s.finish()`, validate the
   output, or clean up after an error: the dispatcher handles `\#` first,
   then calls you, then rejects leftover tokens (`InvalidText`), checks
   the 65535-octet limit, runs the type's **wire parser** over what you
   wrote (whatever `parse_rdata` rejects is rejected in text too), and
   truncates `out` back on any error. Report malformed text as
   `InvalidText` (the scanner methods do), unknown mnemonics as
   `UnknownMnemonic`, bad values as `InvalidRdata`.
3. **`Display` and `parse_text` must be inverses**: what `Display` prints
   must parse back to RDATA that displays identically. Accept every form
   the RFC (and, where it is more liberal, BIND) accepts: numbers *and*
   mnemonics where both are allowed, base64/hex split over several
   tokens, TTL units for time fields BIND accepts them in.
4. **Test** in the type's file with the helpers of
   `crate::rdata::tests`: `text_round_trip(rtype, text, wire, display)`
   checks text → wire, the wire round trip (`round_trip`: Display,
   re-compose, truncation), Display → the same wire, the generic form →
   the same wire, and that no prefix of `text` panics; `text_error(rtype,
   text)` returns the error of a rejected text, `text_parse` the wire of
   an accepted one. Relative names are completed with
   `TEXT_ORIGIN` (`example.`). Use the RFC's presentation examples and
   add malformed cases asserting the exact error.
5. Nothing else: no registry line, no shared file. The fuzz property
   `check_text_round_trip` (`fuzz/src/lib.rs`, replayed on stable by
   `tests/fuzz_regressions.rs`, the corpus and the property tests) checks
   Display → `parse_text` for every type as soon as the stub is replaced.

Worked example (`src/rdata/mx.rs`):

```rust
use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::wire::{Composer, NameEncoding, OutBuf, WireReader};
use crate::zone::Scanner;

impl ParseRdataText for Mx<'_> {
    /// `<preference> <exchange>` (RFC 1035 §3.3.9).
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        out.put_u16(s.u16()?)?;
        s.name_into(out, NameEncoding::Compressible)
    }
}

#[cfg(test)]
mod tests {
    use crate::rdata::tests::{text_error, text_round_trip};
    use crate::{Error, Rtype};

    #[test]
    fn text() {
        // RFC 1035 §5.3 ("MX 10 VENERA"), origin `example.`.
        text_round_trip(Rtype::MX, "10 VENERA", b"\x00\x0a\x06VENERA\x07example\x00",
                        "10 VENERA.example.");
        assert_eq!(text_error(Rtype::MX, "65536 a."), Error::InvalidText);
        assert_eq!(text_error(Rtype::MX, "10"), Error::UnexpectedEof);
    }
}
```

A type with binary fields (sketch, SSHFP-shaped: RFC 4255 §3.2 allows
the hex fingerprint to be split by blanks):

```rust
fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
    out.put_u8(s.u8()?)?;   // algorithm
    out.put_u8(s.u8()?)?;   // fingerprint type
    s.hex_rest_into(out)?;  // all remaining tokens
    Ok(())
}
```

Scanner methods (each takes the next token; a missing one is
`UnexpectedEof`, a malformed one `InvalidText`):

| Field | Method |
|-------|--------|
| decimal integers | `s.u8()`, `s.u16()`, `s.u32()` |
| time values with units (`1h30m`) | `s.ttl()` (also `zone::parse_ttl`) |
| DNSSEC timestamps | `s.timestamp()` (`YYYYMMDDHHmmSS` or seconds) |
| mnemonics, any `FromStr<Err = Error>` | `s.parse::<Rtype>()`, `s.parse::<Algorithm>()`, ... |
| addresses | `s.ipv4()`, `s.ipv6()` |
| domain names (relative to the origin, `@`) | `s.name_into(out, encoding)`, `s.name()` → `NameBuf` |
| `<character-string>` | `s.char_string_into(out)`; all remaining: `s.char_strings_into(out)` |
| unprefixed string to the end of the RDATA (CAA value, URI target) | `for b in s.token()?.unescape() { out.put_u8(b?)?; }` |
| hex | one token: `s.hex_into(out)`; the rest of the entry: `s.hex_rest_into(out)` |
| base64 | `s.base64_into(out)`; the rest: `s.base64_rest_into(out)` |
| base32hex (NSEC3) | `s.base32hex_into(out)` |
| NSEC/NSEC3/CSYNC type bitmap | `s.type_bitmap_into(out)` (the rest of the entry) |
| anything else | `s.word()` (unquoted), `s.token()`, `s.next_token()` (`None` at the end), `s.peek()`, `s.is_at_end()` → `Token`: `as_bytes`, `as_str`, `is("TCP")` (case-insensitive), `is_quoted`, `unescape()`, `u8/u16/u32` |

The `*_into` methods return the number of octets written where useful.
A trailing hex/base64 field that needs at least one octet in text (as in
BIND: SSHFP, TLSA, CERT, OPENPGPKEY, DHCID, ...) checks that count and
fails with `UnexpectedEof` when it is 0; `Display` writes RDATA with an
empty field in the generic form instead.
Length-prefixed fields: write a placeholder and patch it, e.g.
`let at = out.pos(); out.put_u8(0)?; let n = s.hex_into(out)?;
out.patch(at, &[u8::try_from(n).map_err(|_| Error::InvalidRdata)?])?;`
(or `out.put_u16_prefixed(|o| ...)`). Special tokens (NSEC3's `-` for an
empty salt, ...) are handled with `s.word()?` / `Token::is`. Types whose
fields need random access to the output (SVCB sorts its SvcParams) may
use `OutBuf::as_bytes_mut` (see `rdata/svcb/text.rs`).

### Shared field types

- `CharStr<'a>` / `CharStrs<'a>` — `<character-string>` and runs of them
  (TXT, SPF, NAPTR, CAA tag/value, HINFO, ...). `reader.read_char_string()`,
  `composer.put_char_string(bytes)`.
- `TypeBitmap<'a>` — NSEC/NSEC3/CSYNC type bitmaps: `TypeBitmap::parse
  (&mut reader)` (consumes the rest of the RDATA), `iter()`, `contains()`,
  `TypeBitmap::compose(&[Rtype], composer)`; `Display` is the mnemonic
  list.
- `text::{Hex, Base64, Base32Hex}` — `Display` adapters. The matching
  decoders are crate-internal: `util::base64::decode` (and the
  incremental `util::base64::Decoder`) and `util::base32hex::decode`
  (no_std, no allocation); reuse them rather than writing new ones. For
  presentation-format parsing use the `zone::Scanner` methods, which wrap
  them.

## Protocol-number registries: `open_enum!`

Every 8/16-bit protocol registry (EDNS option codes, SvcParamKeys, DNSSEC
algorithm numbers, digest types, TLSA fields, ...) must be an **open
newtype**. Use the crate-internal macro from `src/macros.rs` (it is
`#[macro_use]`, so just invoke it):

```rust
open_enum! {
    /// An EDNS(0) option code (RFC 6891 §6.1.2, IANA "DNS EDNS0 Option Codes").
    pub struct OptionCode(u16), generic "OPT", aliases { "CLIENT-SUBNET" => ECS };
    /// Client subnet (RFC 7871).
    ECS = 8 => "ECS",
    /// Cookie (RFC 7873).
    COOKIE = 10 => "COOKIE",
}
```

This generates the struct (derives `Clone, Copy, PartialEq, Eq, Hash,
PartialOrd, Ord, Default`), one constant per line, `new`, `get`,
`mnemonic`, `from_mnemonic` (case-insensitive, aliases included), `all`,
`From` conversions, `Display`/`Debug` (mnemonic or `<generic><number>`),
`FromStr` (mnemonic, alias or generic form) and, with the `serde` feature,
`Serialize`/`Deserialize` (the `Display` string in human-readable formats,
the integer otherwise). Use an empty generic prefix
(`generic ""`) for registries whose presentation format is the bare number
(e.g. DNSSEC algorithms); use `generic "key"` for SvcParamKeys (`key65535`,
RFC 9460 §2.1). Add extra inherent methods in a separate `impl` block.
`Rtype` and `Class` are built this way.

Put the **complete current IANA registry** in when you create one, one
line per value, so nobody needs to edit it again.

## EDNS(0) (`edns`) and other TLV families

```text
src/edns/
  mod.rs        OptionCode (open_enum!, full IANA registry), ParseOption<'a> /
                ComposeOption traits, edns_modules! + edns_registry! ->
                EdnsOption<'a> (+ Unknown passthrough)
  opt.rs        Opt<'a>: OPT RDATA view (framing checked on construction),
                raw_options() / options() / find() / get::<T>() / validate()
  record.rs     OptHeader (UDP size, extended RCODE, version, EdnsFlags with
                DO/CO and the Z bits preserved) <-> CLASS/TTL; Edns<'a> view
  message.rs    Message::edns() (DuplicateOpt / OptNotRoot), effective_rcode()
  compose.rs    ComposeOptions (one option, [T], [T; N], tuples, (), Opt
                echo), OptData (compose-only OPT RDATA)
  build.rs      MessageBuilder::push_edns / push_edns_padded, PaddingPolicy
                (RFC 8467), start_response_edns / push_reserved_edns
                (RFC 6891 §7 echo), OPT_RR_OVERHEAD
  <option>.rs   one file per option or tight family (nsid.rs, ecs.rs,
                cookie.rs, padding.rs, keepalive.rs, ede.rs, chain.rs,
                key_tag.rs, expire.rs, zone_version.rs, report_channel.rs,
                dau.rs for DAU/DHU/N3U, unknown.rs)
```

- `trait ParseOption<'a> { const CODE: OptionCode; fn parse_option(data:
  &mut WireReader<'a>) -> Result<Self>; }` and `trait ComposeOption { fn
  code(&self) -> OptionCode; fn compose_option<C: Composer + ?Sized>(&self,
  c: &mut C) -> Result<()>; }` (plus the provided `compose_tlv`), with a
  registry of `CODE => Variant(Type),` lines, exactly like
  `rdata_registry!`. Adding an option: a new file, one line in
  `edns_modules!`, one line in `edns_registry!`, and tests with
  `crate::edns::tests::round_trip(code, value, presentation)`.
- Malformed option values are `Error::InvalidOption` and only affect that
  option (`Opt::options` keeps going); broken framing makes the whole OPT
  RDATA invalid (`UnexpectedEof`).
- `Opt<'a>` is registered in `rdata_registry!` as
  `OPT => Opt(crate::edns::Opt<'a>),`. Build an OPT record with
  `b.push_edns(OptHeader::new(1232).with_dnssec_ok(true),
  &(Nsid::REQUEST, Cookie::client_only(c)))`; `push_edns_padded(header,
  &options, PaddingPolicy::QUERY)` appends a Padding option sized over the
  whole message. The extended RCODE goes in `OptHeader::with_rcode`, the
  low 4 bits in `Flags::with_rcode`.
- RFC 9018 server cookies: `ServerCookie` (layout, hash input, freshness)
  is always available; `generate` / `verify` call SipHash-2-4 from
  `purecrypto` behind the `cookie-siphash` feature.
- SVCB SvcParams follow the same pattern (`SvcParamKey` via `open_enum!`
  with `generic "key"`, one file per param or a small family).

## Building (`builder`)

```rust
let mut b = MessageBuilder::new(&mut buf)?;     // &mut [u8]
let mut b = MessageBuilder::new_vec();          // alloc: Vec<u8>, ≤ 65535
let mut b = MessageBuilder::from_buf(out_buf)?; // any OutBuf; the message
                                                // starts at its current end
b.set_id(id); b.set_flags(flags);
b.set_compression(false);       // default on
b.set_limit(512);               // max message size (clamped to capacity)
b.push_question(name, qtype, qclass)?;
b.push_answer(name, class, ttl, &rdata)?;      // any ComposeRdata
b.push_authority(..)?; b.push_additional(..)?;
b.push_record(section, name, class, ttl, &rdata)?;
b.copy_question(&q)?; b.copy_record(section, &rr)?; // re-encodes RDATA
let cp = b.checkpoint(); ...; b.rollback(cp);
b.header(); b.as_bytes(); b.len(); b.section();
let wire = b.finish();          // &mut [u8] (written part) or Vec<u8>

// Convenience constructors (also query_vec / response_vec with alloc,
// and start_query / start_response / start_response_edns on any empty
// builder):
let mut b = MessageBuilder::query(&mut buf, id, name, Rtype::A, Class::IN)?; // QUERY + RD
let mut b = MessageBuilder::response(&mut buf, &parsed_query)?; // ID, opcode,
                                // RD, CD, question copied; QR set
b.set_rcode(Rcode::NXDOMAIN);

// RRset-level pushes with truncation (RFC 2181 §9):
b.set_truncation(Truncation::SetTc);           // default: Truncation::Error
b.set_reserve(11);                             // keep room for OPT/TSIG
let out = b.push_rrset(Section::Answer, name, class, ttl, &rdatas)?;
let out = b.push_rrset_with(Section::Answer, |b| { b.push_answer(..)?; Ok(()) })?;
let out = b.copy_section(&msg, Section::Answer)?; // RRset by RRset (+RRSIGs)
let out = b.copy_message(&msg)?; // whole message, keeps the OPT record
b.push_raw_records(Section::Answer, wire_records)?; // re-encoded, atomic

// DNS over TCP: the 2-byte length prefix is kept in front of the message.
let mut b = MessageBuilder::new_tcp(&mut buf)?; // or new_tcp_vec / from_buf_tcp
let frame = b.finish();                         // prefix + message
```

- Sections are runtime-ordered; going back is `Error::SectionOrder`.
  Records cannot be pushed to `Section::Question`.
- Header counts are kept up to date in the buffer after every push, so
  `as_bytes()` is always a well-formed message.
- **Every push is atomic**: on any error (`BufferTooSmall`, a composer
  error, ...) the buffer, counts, section and compression table are rolled
  back to their state before the push. `checkpoint`/`rollback` give the
  same guarantee for larger units.
- **Truncation** happens only in the RRset-level pushes (`push_rrset`,
  `push_rrset_with`, `copy_section`, `copy_message`): a unit that does not
  fit is removed whole; with `Truncation::Error` the call fails with
  `BufferTooSmall`, with `Truncation::SetTc` TC is set, `Outcome::Truncated`
  returned and later RRset-level pushes become no-ops. Additional-section
  units are optional: they are dropped (`Outcome::Dropped`) without TC;
  call `b.truncate()` yourself if they were required (e.g. in-domain glue).
  Record-level pushes are never affected, so OPT/TSIG can be appended after
  truncation; `set_reserve(n)` keeps `n` bytes free for them.
- **EDNS echo** (RFC 6891 §7): `start_response_edns(&query, our_udp_size)`
  is `start_response` plus the OPT bookkeeping — it returns the response
  `OptHeader` (DO copied, version 0, BADVERS for a query version above 0)
  when the query had EDNS, and reserves `edns::OPT_RR_OVERHEAD` bytes so
  a truncated response still has room for the OPT record; append it last
  with `push_reserved_edns(header, &options)`. `copy_message` reserves
  room for and preserves the source OPT.
- `from_buf` with a non-empty buffer leaves the prefix alone (e.g. a TCP
  length placeholder); compression offsets are relative to the message.

### Name compression

`builder/compress.rs` keeps a fixed trie of up to `CAPACITY` (128) labels
already written, with a hash index — under 1 KiB, all zero when empty
(so starting a message is a `memset`), no allocation. Each entry is one
label written at some offset `< 0x4000` and links to its *parent* (the
entry for the rest of the name, or the root). Writing a `Compressible`
name:

1. if the name, or the name minus its first label, is the last name
   written, confirm that label by label against the message (no hashing:
   RRsets share owners, and names often grow one label at a time);
2. otherwise walk the trie from the root: look up the last label under the
   root, the one before it under that entry, and so on (one hash probe per
   label, keyed by (parent, label));
3. write the unmatched labels plus a pointer to the deepest match, and
   enter the new labels right to left (so a parent always precedes its
   children and a full table drops the leftmost labels, never orphaning
   one).

Every entry a lookup returns is checked against the output bytes: the
label must be there byte for byte, followed by the root octet, the
parent's label (contiguous) or a pointer to the parent's offset. Properties:

- matching is **exact (case-sensitive)**, so the case of every name is
  preserved (0x20 randomisation, case-sensitive applications);
- only `Compressible` names are compressed **or registered as targets** —
  `Lowercase`/`Plain` names are never compressed and never pointed into;
- a pointer always decodes to exactly the matched suffix, even if record
  data rewrote earlier bytes with `Composer::patch`;
- a full table only means less compression; lookups cost one verified
  entry per label plus at most `MAX_PROBES` (32) false candidates per name,
  so hash collisions cannot blow up the cost;
- entries are appended in order, so rollback is a truncation.

## Error handling conventions

- One `Error` enum (`#[non_exhaustive]`, `Copy`), one `Result<T>` alias.
  Add variants as needed (keep them small and data-free, with a doc comment
  citing the RFC section and a `Display` string). Prefer reusing (e.g.
  `BadSignature` covers DNSSEC, TSIG and SIG(0) failures alike):
  `UnexpectedEof` (truncation / counts), `TrailingData`, `InvalidRdata`
  (bad field value or length), `InvalidText` / `UnknownMnemonic`
  (presentation parsing), `BufferTooSmall` (output full or limit hit).
- Never `unwrap`, `expect`, index with `[]` on untrusted offsets, or do
  unchecked arithmetic that could overflow on hostile values in library
  code. Use `get()`, `checked_*`, and the reader. Indexing fixed-size local
  arrays with provably in-range indices is fine.
- A failed read leaves the reader untouched; a failed builder push leaves
  the message untouched. Keep that property in new code.
- Parsing is strict per the RFCs; leniency belongs to callers (they have
  the raw bytes).

## Testing conventions

- Unit tests next to the code: `#[cfg(test)] mod tests` in the file, or
  `tests.rs` beside `mod.rs` for big modules. The crate is `no_std`; tests
  get `std` (`use std::vec::Vec; use std::string::ToString;
  std::format!`). `crate::testutil::hex("..")` decodes hex fixtures.
- Use RFC examples and real wire captures (hex, with a comment saying where
  they came from) — `tests/captures.rs` shows the style. New corpora go in
  new files under `tests/` to avoid merge conflicts.
- Every parser gets: a round trip (`rdata::tests::round_trip` for RDATA),
  truncation at every byte offset (must return `Err`, never panic), bad
  lengths / invalid values asserting the exact `Error` variant.
- Builder output must always pass `Message::parse_validated`.
- Assurance infrastructure (Milestone 8) covers new record types
  automatically through the registry (`Rtype::all()` filtered by
  `RData::is_known`), so registering a type is enough to get it fuzzed and
  property-tested:
  - `fuzz/` — cargo-fuzz targets (`edns`, `message`, `name`, `rdata`,
    `roundtrip`, `text`), its own workspace; `message` also runs the
    protocol views (EDNS, TSIG/SIG(0), UPDATE, NOTIFY, XFR, DSO); the properties live in `fuzz/src/lib.rs`
    and are also replayed on stable by `tests/fuzz_regressions.rs` over
    `fuzz/seeds/` and `fuzz/regressions/` (put every fixed crash there).
  - `tests/proptest_roundtrip.rs` — build → parse and parse → build →
    parse identity of generated messages.
  - `tests/corpus/` + `tests/corpus.rs` — real responses from BIND, NSD,
    Knot, PowerDNS, Unbound, Knot Resolver and public resolvers (hex files
    written by `tests/corpus/capture.py`); all must validate and round-trip.
  - `tests/no_alloc.rs` — the hot path under a counting allocator, run with
    `--no-default-features` in CI.
  - `benches/` — separate package: criterion comparisons against
    hickory-proto and domain; results in `BENCH.md`.
- Before pushing, all of these must pass:

  ```sh
  cargo fmt --all --check
  cargo clippy --all-targets --all-features -- -D warnings
  cargo test --all-features
  cargo test --no-default-features
  cargo +1.89 test --all-features
  cargo build --target thumbv7em-none-eabi --no-default-features
  RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
  ```

## Cryptography

dnsbox never implements cryptographic primitives. Digests, HMAC, and
signature verification come from the optional `purecrypto` dependency
(already declared in `Cargo.toml`, `default-features = false`). Wire-format
work — signed data / MAC input construction, canonical forms, key tags, DS
digest input, NSEC3 hashing *input* — lives in dnsbox and works without it;
only the actual primitive calls are gated. Features enable what they need
with explicit `dep:` syntax:

| Feature          | purecrypto features         | Provides |
|------------------|-----------------------------|----------|
| `dnssec-digest`  | `hash`                      | DS digests, NSEC3 hashing (no `alloc`) |
| `dnssec`         | `hash`, `alloc`, `rsa`, `ec` | RRSIG/SIG(0) verification and signing (`PurecryptoVerifier`, `SigningKey`) |
| `tsig`           | `hash`                      | TSIG HMAC backend (`HmacKey`) |
| `cookie-siphash` | `mac`                       | RFC 9018 server cookies (`ServerCookie::generate` / `verify`) |

Every crypto-using API sits behind a trait (`dnssec::{Signer, Verifier}`,
`tsig::{TsigKey, TsigMac}`, `sig0::{Sig0Signer, Sig0Verifier}`) so other
backends can be plugged in without these features. MAC and signature
comparisons are constant time and come from purecrypto.

### DNSSEC (`src/dnssec/`)

Record types are ordinary `rdata` files (`dnskey.rs`: DNSKEY/CDNSKEY/KEY,
`ds.rs`: DS/CDS/DLV/TA, `rrsig.rs`: RRSIG/SIG, `nsec.rs`, `nsec3.rs`:
NSEC3/NSEC3PARAM); the protocol logic lives in `src/dnssec/`:

```text
src/dnssec/
  alg.rs        Algorithm, DigestType, Nsec3HashAlgorithm (open_enum!)
  time.rs       serial_cmp / check_validity (RFC 1982), Timestamp
  keys.rs       key_tag (RFC 4034 App. B), RsaPublicKey (RFC 3110)
  canonical.rs  canonical_name, CanonicalRrset (sorted, deduplicated,
                in the caller's OutBuf; no allocation)
  ds.rs         ds_digest_input; DsDigest, verify_ds   [dnssec-digest]
  nsec3.rs      Nsec3Hash (base32hex); nsec3_hash      [dnssec-digest]
  rrsig.rs      Rrset, RecordRdata, ZoneKey, rrsig_owner (wildcards),
                check_rrsig, signed_data, verify_rrsig, sign_rrset
  crypto.rs     Verifier / Signer traits (pluggable backends)
  backend.rs    PurecryptoVerifier, SigningKey        [dnssec]
  chain.rs      TrustedKeys (DS/anchors -> DNSKEY -> RRsets, wildcard
                answers), Verified, Answer, MAX_CRYPTO_OPERATIONS
  denial.rs     DenialProof, DenialStatus (Secure/Insecure/Bogus), Denial,
                ClosestEncloser; denial/nsec.rs NsecProof, denial/nsec3.rs
                Nsec3Proof, Nsec3Hasher, Nsec3Limits (RFC 9276)
  zonemd.rs     ZoneCollation (SIMPLE scheme)          [alloc]
                zonemd_digest, verify_zonemd    [alloc + dnssec-digest]
```

- Features: `dnssec-digest` (= `purecrypto/hash`, no `alloc`) for DS
  digests and NSEC3 hashing; `dnssec` (adds `alloc`, `purecrypto/rsa`,
  `purecrypto/ec`) for signature verification and signing.
- Signed data is built into a caller-supplied scratch `OutBuf` (removed
  again after use); backends see `(algorithm, DNSKEY public key, data,
  RRSIG signature)` in wire format, so any crypto library can implement
  `Verifier`/`Signer`.
- `verify_rrsig` performs the RFC 4035 §5.3.1 checks itself (labels,
  signer zone, key tag/algorithm/zone flag/protocol, validity window with
  serial arithmetic) and reconstructs wildcard owners (§5.3.2). Callers
  select the RRset (owner, class, type) and authenticate the key.
- `TrustedKeys` does the key selection on top of it: RRSIGs of other
  types/signers/unknown keys are skipped, one valid signature suffices,
  revoked keys are never used, and every call is capped at
  `MAX_CRYPTO_OPERATIONS` verifications and DS digests (KeyTrap).
- Denial proofs take records the caller has already authenticated (one
  zone per proof, any re-iterable source: slices, cloneable iterators over
  a message section) and never allocate. Results are `DenialStatus`:
  `Secure(Denial)`, `Insecure(InsecureReason)` (NSEC3 Opt-Out, iteration
  count over `Nsec3Limits`) or `Bogus(BogusReason)`. NSEC3 checks hash at
  most one name per query-name label plus one wildcard, and only after the
  iteration limits are checked.
- ZONEMD collation copies each RR once in canonical form into one buffer
  and sorts an index of it; the digest is streamed over the sorted RRs.
- Canonical RDATA comes from each type's `NameEncoding` through
  `wire::Canonical`; NSEC next names are `Plain` (RFC 6840 §5.1).
- The type bitmap shared with CSYNC is `rdata::TypeBitmap` (`bitmap.rs`).
- The `Algorithm` newtype is shared by DNSKEY/RRSIG/DS and also by SIG,
  KEY, CERT and RKEY.

## Transactions, updates and zone transfers (Milestone 6)

- **TSIG** (`tsig`): the MAC is behind two traits, `TsigKey` (name,
  algorithm, digest length, generated/required MAC length, `new_mac()`)
  and `TsigMac` (`update`, `finalize`, constant-time `verify` of a possibly
  truncated MAC). `HmacKey` implements them with purecrypto (feature
  `tsig`); everything else (MAC input, placement, size/truncation/time
  rules, error responses, streams) is crypto-free. `TsigSigner` signs a
  request, a response or a TCP stream (first MAC: prior MAC + message +
  all variables; later ones: prior MAC + messages since + timers, up to 99
  unsigned messages in between); `verify_request` (server) returns
  `RequestStatus::{Unsigned, Verified, Rejected}`, and `Rejected` knows
  the RCODE/TSIG error and writes the RFC-mandated error TSIG;
  `TsigVerifier` (client) checks responses and streams. Time is always
  passed in (`now`, seconds since the epoch). The TSIG owner name is
  written uncompressed, like BIND. Replay caching is the caller's job.
- **SIG(0)** (`sig0`): `SignedData` builds the exact signed byte stream
  as a few slices; signing/verification go through the minimal
  `Sig0Signer`/`Sig0Verifier` traits. SIG RDATA is the DNSSEC branch's
  `rdata::Sig` (same layout as RRSIG, typed `Algorithm`).
  `DnssecSig0Signer` / `DnssecSig0Verifier` (`alloc`) adapt any DNSSEC
  `Signer` / `Verifier`, so with the `dnssec` feature SIG(0) gets RSA,
  ECDSA and EdDSA from purecrypto.
- **UPDATE** (`update`): section aliases `ZONE`, `PREREQUISITE`,
  `UPDATE`, `ADDITIONAL`; `UpdateBuilder` has one method per RFC 2136
  §2.4/§2.5 form; `UpdateMessage` classifies prerequisites and updates and
  reports FORMERR conditions as `Error::InvalidUpdate` (NOTZONE is left
  to the caller via `in_zone`).
- **XFR** (`xfr`): `XfrProcessor` is fed one message at a time and keeps
  only integers between messages; events borrow from the current message.
- **DSO** (`dso`): its own builder (`DsoBuilder`, not `MessageBuilder`),
  because DSO messages carry TLVs instead of RRs. New DSO TLVs follow the
  EDNS-option shape: `ParseDsoTlv<'a>` / `ComposeDsoTlv`.

## Owned data, `dig` display and serde (Milestone 7)

- **`dig` display** (`message/dig.rs`): `Display for Message` prints the
  whole message as BIND 9's `dig` does — header and flags lines (with
  `dig`'s warnings), the OPT pseudosection (EDNS header, one line per
  option in `dig`'s own format; options `dig` 9.18 does not decode but
  dnsbox does show their presentation value), the sections in BIND's tab
  columns, and TSIG / SIG(0) pseudosections. No allocation; a malformed
  message is shown up to the first error (`;; ERROR: ...`). The only
  intended difference from `dig` is that long base64/hex RDATA fields are
  not split into 56-character chunks. `tests/dig_display.rs` compares
  against real `dig` output for the whole corpus.
- **Owned types** (`owned/`, `alloc`): `OwnedMessage` (ID, flags, four
  `Vec` sections; counts are the lengths), `OwnedQuestion`, `OwnedRecord`
  (`NameBuf` owner, raw class/TTL, `OwnedRData`). `OwnedRData` is the
  record type plus the RDATA in **uncompressed wire form** in one boxed
  slice: the typed `RData<'_>` view is decoded on demand (`parse(class)` /
  `as_rdata()`), so every registered type (and unknown ones) is covered
  without a parallel owned type per format. As `ComposeRdata` it re-encodes
  through the typed view, so the builder recompresses exactly the names
  RFC 3597 §4 allows and `Canonical` lowercases the right ones.
  Conversions: `from_*` / `TryFrom` / `to_owned_*` from the views (typed
  RDATA must be valid), `push_to` / `write_to` / `to_vec` into a builder.
  From text: `OwnedRData::from_text(rtype, class, text)` (presentation or
  generic form, through `RData::parse_text`), `OwnedRecord: FromStr` (one
  master-file entry, read with `ZoneReader`), and `From<ZoneRecord>` /
  `From<ZoneRecordBuf>` for records read from a zone file (their RDATA is
  already checked, so it is moved in as is).
- **serde** (feature `serde`, `serde` with `default-features = false`, so
  `no_std`; `alloc` enables `serde/alloc`): protocol numbers as mnemonics or
  RFC 3597 generic forms in human-readable formats (numbers accepted on
  input) and integers otherwise; names as presentation strings; `Flags` as
  a struct of bits (raw word when compact); owned types as structs with
  RDATA in the RFC 3597 §5 generic form (`\# 4 C0000201`) or as bytes, so
  every type round-trips exactly. Human-readable input may instead use the
  type's presentation format (`"10 mail.example.com."`), parsed like
  `OwnedRData::from_text`; byte input is validated like
  `OwnedRData::from_wire`.

## Decisions and limitations to know

- `Name` equality/hash are case-insensitive; use `eq_exact` for byte
  equality. `Ord` is canonical DNSSEC order.
- Labels iterate without the root; `label_count()` excludes the root.
- `Record::ttl()` is the raw field (RFC 2181 §8 says treat a set top bit
  as 0; OPT stores flags there). `Record::class()` is raw too (OPT: UDP
  size; mDNS: cache-flush bit).
- `Record::rdata()` raw bytes may contain compression pointers for RFC 1035
  types: re-emit records through `copy_record` / typed data, never by
  copying raw RDATA of known types.
- `RData` is `#[non_exhaustive]`; typed parse errors are errors, not
  `Unknown`.
- `Message` iterators are lazy; `answers()`/`additional()` re-skip earlier
  sections per call (cheap); use `records()` to walk everything in one
  pass.
- The builder never compresses against differently-cased names, and does
  not compress names beyond offset 0x3fff (not addressable by pointers).
- Zone files (`zone`): `ZoneReader` is a lending reader (RDATA goes to
  the caller's buffer), so it is not an `Iterator`; `records()` (`alloc`)
  is. Errors carry line and column and the reader resynchronises on the
  next entry. `$INCLUDE` is reported as `Entry::Include` by the core
  reader and followed only by `Records` with an `IncludeResolver`
  (depth- and count-limited). Without `$TTL` and without an earlier
  explicit TTL, an SOA's MINIMUM is the default TTL (BIND's behaviour);
  `$GENERATE` follows BIND's syntax and yields at most `MAX_GENERATE`
  records. The owner field is "present" only when the line starts with a
  non-blank character (RFC 1035 §5.1).
- Do not edit `ROADMAP.md` or `CHANGELOG.md` on feature branches; the
  integrator does.
