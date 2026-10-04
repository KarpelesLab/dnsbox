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
    mod.rs        Name<'a>, Label, Labels, ToName, limits, hardening
    buf.rs        NameBuf (inline 255-byte owned name), text parsing
    tests.rs
  charstr.rs      CharStr, CharStrs (<character-string>, RFC 1035 §3.3)
  tcp.rs          TCP framing (RFC 1035 §4.2.2 / RFC 7766): length prefix,
                  frame splitting, FrameReassembler, std::io helpers
  text.rs         presentation-format helpers: escaping, Hex, Base64,
                  Base32Hex, RFC 3597 generic RDATA
  message/
    mod.rs        Message<'a>, Section, Question, Record, iterators, validate
    tests.rs
  rdata/
    mod.rs        ParseRdata / ComposeRdata traits, rdata_modules!,
                  rdata_registry! -> RData<'a>
    <type>.rs     one file per record type or tight family
    bitmap.rs     TypeBitmap (NSEC/NSEC3/CSYNC window bitmaps)
    unknown.rs    UnknownRdata (RFC 3597 passthrough)
    tests.rs      shared test helpers (round_trip, parse, compose)
  builder/
    mod.rs        MessageBuilder, Checkpoint
    compress.rs   fixed-size suffix table for name compression
    truncate.rs   Truncation policy, Outcome, push_rrset(_with),
                  copy_section, copy_message, reserve (RFC 2181 §9)
    query.rs      start_query / start_response, response_flags
    raw.rs        push_raw_records (pre-encoded records)
    framing.rs    new_tcp / from_buf_tcp (length-prefixed messages)
    tests.rs
tests/
  captures.rs     real wire captures, truncation and mutation tests
  builder_truncation.rs  truncation / TCP stream tests on captures
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

Hardening on the wire (all in `Name::parse_bounded`, used by the reader):
labels ≤ 63, names ≤ 255 octets uncompressed, label types `0b01`/`0b10`
rejected (`BadLabelType`), a pointer must point **strictly before the start
of the current run of labels** (rejects forward pointers, self pointers and
all loops — `BadPointer`), at most `MAX_POINTERS` (128) hops per name
(`TooManyPointers`).

## Messages (`message`)

- `Message::parse(buf)` checks only the 12-byte header (O(1)).
- `msg.questions()` → `Result<Question>` items; `msg.answers()`,
  `authority()`, `additional()`, `section(Section)` → `Result<Record>`;
  `msg.records()` → `Result<(Section, Record)>` over all three RR sections
  in one pass. Iterators yield exactly the header count, then stop; on
  error they yield the error once and then end (fused). Locating a later
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
`ComposeRdata for RData` and `Display for RData`. A compile-time assertion
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
3. **Implement `ParseRdata<'a>`, `ComposeRdata` and `Display`.**
4. **Register it**: add `<file>,` to `rdata_modules!` and
   `RTYPE => Variant(Type),` to `rdata_registry!`, both in sorted position
   (the `Rtype` constant already exists — `rtype.rs` holds the complete
   IANA registry; never edit it for a new type).
5. **Test it** in the same file (`#[cfg(test)] mod tests`), using
   `crate::rdata::tests::round_trip(rtype, wire, presentation)`, which
   parses, checks `Display`, re-composes to identical bytes and tries every
   truncation. Use RFC examples and real captures; add malformed cases
   (bad lengths, invalid fields) asserting the exact `Error`.

Worked example (this is exactly how SRV should look; the Milestone 4 owner
adds it):

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
composing, reader method for parsing).

### Shared field types

- `CharStr<'a>` / `CharStrs<'a>` — `<character-string>` and runs of them
  (TXT, SPF, NAPTR, CAA tag/value, HINFO, ...). `reader.read_char_string()`,
  `composer.put_char_string(bytes)`.
- `TypeBitmap<'a>` — NSEC/NSEC3/CSYNC type bitmaps: `TypeBitmap::parse
  (&mut reader)` (consumes the rest of the RDATA), `iter()`, `contains()`,
  `TypeBitmap::compose(&[Rtype], composer)`; `Display` is the mnemonic
  list.
- `text::{Hex, Base64, Base32Hex}` — `Display` adapters; decoders will be
  added by the zone-file parser work.

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
`From` conversions, `Display`/`Debug` (mnemonic or `<generic><number>`) and
`FromStr` (mnemonic, alias or generic form). Use an empty generic prefix
(`generic ""`) for registries whose presentation format is the bare number
(e.g. DNSSEC algorithms); use `generic "key"` for SvcParamKeys (`key65535`,
RFC 9460 §2.1). Add extra inherent methods in a separate `impl` block.
`Rtype` and `Class` are built this way.

Put the **complete current IANA registry** in when you create one, one
line per value, so nobody needs to edit it again.

## EDNS options and other TLV families (pattern)

EDNS(0) is owned by the Milestone 3 work; the expected shape mirrors
`rdata`:

```text
src/edns/
  mod.rs        OptionCode (open_enum!), ParseOption<'a> / ComposeOption
                traits, edns_modules! + edns_registry! -> EdnsOption<'a>
                (+ Unknown passthrough), Opt<'a> view over OPT RDATA with an
                option iterator, OPT header accessors (UDP size, extended
                RCODE, version, DO) from Record::class()/ttl()
  <option>.rs   one file per option (ecs.rs, cookie.rs, padding.rs, ...)
```

- `trait ParseOption<'a> { const CODE: OptionCode; fn parse_option(data:
  &mut WireReader<'a>) -> Result<Self>; }` and `trait ComposeOption { fn
  code(&self) -> OptionCode; fn compose_option<C: Composer + ?Sized>(&self,
  c: &mut C) -> Result<()>; }`, with a registry macro of
  `CODE => Variant(Type),` lines, exactly like `rdata_registry!`.
- `Opt<'a>` is an ordinary record-data type registered in
  `rdata_registry!` as `OPT => Opt(Opt<'a>),`; building an OPT record is
  `builder.push_additional(Name::ROOT, Class::new(udp_size), ttl_bits,
  &opt_data)`, where option bodies are written with
  `Composer::put_u16_prefixed`.
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
// and start_query / start_response on any empty builder):
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
- **EDNS hook:** `start_response` does not echo EDNS (no OPT types in the
  builder). The EDNS module should add the echo on top of it: reserve the
  OPT size, then append the OPT record last with `push_additional`.
  `copy_message` already reserves room for and preserves the source OPT.
- `from_buf` with a non-empty buffer leaves the prefix alone (e.g. a TCP
  length placeholder); compression offsets are relative to the message.

### Name compression

`builder/compress.rs` keeps a fixed table of `CAPACITY` (128) entries
`(suffix hash, offset)` — 768 bytes, no allocation. Writing a
`Compressible` name: flatten it, hash every suffix right-to-left (FNV-1a,
chained), look the suffixes up longest-first, verify a candidate by
decoding the name at that offset in the output, write the unmatched labels
plus a pointer, and register the newly written labels whose offset is
`< 0x4000`. Properties:

- matching is **exact (case-sensitive)**, so the case of every name is
  preserved (0x20 randomisation, case-sensitive applications);
- only `Compressible` names are compressed **or registered as targets** —
  `Lowercase`/`Plain` names are never compressed and never pointed into;
- a full table only means less compression; verification work is capped at
  `MAX_PROBES` (32) candidates per name, so hash collisions cannot blow up
  the cost;
- entries are appended in offset order, so rollback is a truncation.

## Error handling conventions

- One `Error` enum (`#[non_exhaustive]`, `Copy`), one `Result<T>` alias.
  Add variants as needed (keep them small and data-free, with a doc comment
  citing the RFC section and a `Display` string). Prefer reusing:
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
with explicit `dep:` syntax, for example:

```toml
dnssec-verify = ["dep:purecrypto", "purecrypto/hash", "purecrypto/rsa", "purecrypto/ec"]
```

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
- Not yet implemented (owned by later milestones): EDNS, owned message
  types, zone-file parsing (presentation-format *parsing*
  hooks for RDATA will be added as a separate trait plus one more arm in
  `rdata_registry!`).
- Do not edit `ROADMAP.md` or `CHANGELOG.md` on feature branches; the
  integrator does.
