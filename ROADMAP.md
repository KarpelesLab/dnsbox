# dnsbox roadmap

`dnsbox` aims to be a fast, safe, `no_std` DNS wire-format library covering
both sides of the protocol: parsing and producing queries and responses,
with broad RFC extension coverage. This document lays out the design and the
order of work. Items are checked off as they land.

## Design principles

- **Safe on hostile input.** Every parser is written for untrusted network
  data: no panics, no out-of-bounds reads, bounded work per message
  (compression-pointer loops, label counts, record counts). The crate is
  `#![forbid(unsafe_code)]`; performance comes from layout and algorithms,
  not from `unsafe`.
- **Zero-copy parsing.** A parsed message is a view over the caller's
  `&[u8]`. Sections, records, names and RDATA are decoded lazily through
  iterators; nothing is allocated or copied unless asked for.
- **Single-pass, buffer-backed building.** Builders write directly into a
  caller-supplied `&mut [u8]` (or a `Vec` with `alloc`), with name
  compression, section-count bookkeeping and size limits handled internally.
- **Open enums.** Record types, classes, opcodes, rcodes, EDNS option codes
  and SvcParam keys are newtypes with associated constants, so unknown values
  round-trip losslessly (RFC 3597).
- **`no_std` first.** The core works with neither `alloc` nor `std`. `alloc`
  adds owned types and growable builders; `std` adds `std::io` glue.
- **Minimal dependencies.** None in the core. Optional integrations (serde,
  async I/O, crypto backends for DNSSEC/TSIG) live behind features.
- **MSRV 1.89**, edition 2024. MSRV bumps are minor-version changes.

## Milestone 0 — Foundation

- [x] Crate scaffold, CI, release automation
- [x] Error type
- [x] Header (RFC 1035 §4.1.1): ID, flags, opcode, rcode, section counts
- [ ] Bounds-checked wire reader (cursor over `&[u8]`) and writer (cursor
      over `&mut [u8]`), the primitives every later layer builds on
- [ ] Open newtypes: `Rtype`, `Class`, with IANA mnemonics and parsing from
      text mnemonics (`A`, `TYPE65534`, `IN`, `CLASS3`)

## Milestone 1 — Core RFC 1035 parsing

- [ ] Domain names
  - [ ] Wire-format label parsing with compression pointers (RFC 1035 §4.1.4)
  - [ ] Hardening: forward/self-pointer rejection, hop limit, 255-octet name
        limit, 63-octet label limit
  - [ ] Borrowed `Name<'a>` (lazy, pointer-following) and an inline/owned
        uncompressed form
  - [ ] Case-insensitive comparison and hashing (RFC 4343), canonical
        ordering (RFC 4034 §6.1)
  - [ ] Presentation format with escapes (`\.`, `\DDD`)
  - [ ] Reserved label types: reject extended label types (RFC 6891 §5)
- [ ] `Message<'a>` view: header + section iterators (question, answer,
      authority, additional), validated against section counts
- [ ] `Question` and `Record` views (name, type, class, TTL, raw RDATA)
- [ ] Unknown-type RDATA passthrough (RFC 3597)
- [ ] Typed RDATA for the RFC 1035 set: A, NS, CNAME, SOA, PTR, MX, TXT,
      HINFO, plus AAAA (RFC 3596)
- [ ] Whole-message validation mode (walk once, report the first error) for
      callers that want to fail fast before iterating

## Milestone 2 — Building messages

- [ ] `MessageBuilder` over `&mut [u8]` with typestate or runtime-checked
      section ordering (question → answer → authority → additional)
- [ ] Name compression with a fixed-size, allocation-free suffix table;
      option to disable compression (and never compress inside RDATA of
      types where RFC 3597 forbids it)
- [ ] Automatic section counts
- [ ] Size limits and truncation: stop at a max size, set TC, roll back the
      partial RRset (RFC 2181 §9)
- [ ] Convenience constructors: query for (name, type), response skeleton
      from a parsed query (copies ID, opcode, RD, question, EDNS echo)
- [ ] Growable `Vec`-backed builder (`alloc`)
- [ ] TCP framing helpers (2-byte length prefix, RFC 1035 §4.2.2 / RFC 7766)

## Milestone 3 — EDNS(0)

- [ ] OPT pseudo-record (RFC 6891): UDP payload size, extended RCODE,
      version, DO bit, option iteration and building
- [ ] Options:
  - [ ] Client Subnet (RFC 7871)
  - [ ] Cookies (RFC 7873, RFC 9018 interoperable server cookies)
  - [ ] Padding (RFC 7830) with RFC 8467 padding policies in the builder
  - [ ] TCP keepalive (RFC 7828)
  - [ ] Extended DNS Errors (RFC 8914)
  - [ ] NSID (RFC 5001)
  - [ ] Chain query (RFC 7901), Key tag (RFC 8145), Expire (RFC 7314)
  - [ ] Zone version (RFC 9660), Report-Channel (RFC 9567)
  - [ ] DAU/DHU/N3U (RFC 6975)
- [ ] Unknown options pass through untouched

## Milestone 4 — Record type coverage

- [ ] SRV (RFC 2782), NAPTR (RFC 3403), CAA (RFC 8659), SSHFP (RFC 4255,
      RFC 6594), TLSA (RFC 6698), SMIMEA (RFC 8162), OPENPGPKEY (RFC 7929)
- [ ] DNAME (RFC 6672), LOC (RFC 1876), RP / AFSDB (RFC 1183), URI
      (RFC 7553), CERT (RFC 4398), DHCID (RFC 4701), NID/L32/L64/LP
      (RFC 6742), EUI48/EUI64 (RFC 7043), CSYNC (RFC 7477), ZONEMD
      (RFC 8976), APL (RFC 3123), IPSECKEY (RFC 4025), HIP (RFC 8005)
- [ ] SVCB and HTTPS (RFC 9460) with typed SvcParams: mandatory, alpn,
      no-default-alpn, port, ipv4hint, ipv6hint, ech, dohpath (RFC 9461),
      ohttp (RFC 9540); unknown keys pass through
- [ ] Obsolete/legacy types parsed as opaque RDATA with mnemonics
- [ ] Presentation-format (zone-file style) `Display` for every typed RDATA

## Milestone 5 — DNSSEC wire support

- [ ] DNSKEY, RRSIG, NSEC, DS (RFC 4034), NSEC3, NSEC3PARAM (RFC 5155),
      CDS/CDNSKEY (RFC 7344, RFC 8078)
- [ ] Type bitmap parsing and building
- [ ] Canonical RR form and canonical RRset ordering (RFC 4034 §6)
- [ ] Key tag computation, DS digest input construction
- [ ] NSEC3 hashing
- [ ] Optional `dnssec-verify` feature: signature verification against a
      pluggable crypto backend (RSA/SHA-2, ECDSA P-256/P-384, Ed25519/Ed448)
      — the core never hard-depends on a crypto crate

## Milestone 6 — Transactions, updates and zone transfer

- [ ] TSIG (RFC 8945): record parsing, MAC input construction, signing and
      verification via a pluggable HMAC backend
- [ ] SIG(0) (RFC 2931) wire support
- [ ] Dynamic UPDATE (RFC 2136) message helpers (zone/prerequisite/update
      sections, deletion encodings)
- [ ] NOTIFY (RFC 1996)
- [ ] AXFR/IXFR (RFC 5936, RFC 1995) multi-message stream helpers
- [ ] DNS Stateful Operations (RFC 8490) TLV framing

## Milestone 7 — Text formats and owned data (`alloc`)

- [ ] Owned `OwnedMessage` / `OwnedRecord` types with conversion from views
- [ ] Zone-file / presentation-format parser (RFC 1035 §5) for records
- [ ] `dig`-style message `Display`
- [ ] Optional `serde` support

## Milestone 8 — Performance and assurance

- [ ] Criterion benchmarks: parse/iterate/build for typical queries,
      large responses, heavily compressed messages; comparisons against
      `hickory-proto` and `domain`
- [ ] cargo-fuzz targets: message parsing, name decompression, RDATA,
      build→parse round-trip, presentation-format parser
- [ ] Property tests: build→parse and parse→build→parse identity
- [ ] Interop corpus: real-world captures, plus responses from BIND,
      Unbound, Knot and PowerDNS
- [ ] Allocation-free hot path verified in CI (no-alloc build + tests)
- [ ] Hot-path tuning: branch layout of the name decoder, SIMD-free
      bulk label scanning, compression table hashing

## Milestone 9 — 1.0

- [ ] API review: naming, error granularity, feature layout
- [ ] Complete rustdoc with examples on every public item
- [ ] SECURITY.md threat model finalized after a fuzzing campaign
- [ ] Stability commitment and MSRV policy documented

## Out of scope

`dnsbox` is a wire-format library. Resolvers, caches, server frameworks and
socket handling belong in crates built on top of it. Transport framing
helpers (TCP length prefix, DoT/DoH/DoQ message shaping per RFC 7858,
RFC 8484, RFC 9250) are in scope only insofar as they are pure byte
transformations.
