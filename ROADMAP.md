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
- **Minimal dependencies.** None in the core. Cryptography (digests, HMAC,
  SipHash, RSA/ECDSA/EdDSA) is never implemented in dnsbox: it comes from
  the optional `purecrypto` dependency (`default-features = false`, no_std
  capable), enabled per feature (`dnssec-digest`, `dnssec`, `tsig`,
  `cookie-siphash`). Every crypto-using API sits behind a trait
  (`dnssec::{Signer, Verifier}`, `tsig::{TsigKey, TsigMac}`,
  `sig0::{Sig0Signer, Sig0Verifier}`) so alternative backends can be
  plugged in, and all wire-format work (signed data, MAC input, canonical
  forms, key tags) works without it. Other optional integrations (serde,
  async I/O) live behind features too.
- **MSRV 1.89**, edition 2024. MSRV bumps are minor-version changes
  (see "Stability and MSRV policy" in README.md).

## Milestone 0 — Foundation

- [x] Crate scaffold, CI, release automation
- [x] Error type
- [x] Header (RFC 1035 §4.1.1): ID, flags, opcode, rcode, section counts
- [x] Bounds-checked wire reader (cursor over `&[u8]`) and writer (cursor
      over `&mut [u8]`), the primitives every later layer builds on
- [x] Open newtypes: `Rtype`, `Class`, with IANA mnemonics and parsing from
      text mnemonics (`A`, `TYPE65534`, `IN`, `CLASS3`)

## Milestone 1 — Core RFC 1035 parsing

- [x] Domain names
  - [x] Wire-format label parsing with compression pointers (RFC 1035 §4.1.4)
  - [x] Hardening: forward/self-pointer rejection, hop limit, 255-octet name
        limit, 63-octet label limit
  - [x] Borrowed `Name<'a>` (lazy, pointer-following) and an inline/owned
        uncompressed form
  - [x] Case-insensitive comparison and hashing (RFC 4343), canonical
        ordering (RFC 4034 §6.1)
  - [x] Presentation format with escapes (`\.`, `\DDD`)
  - [x] Reserved label types: reject extended label types (RFC 6891 §5)
- [x] `Message<'a>` view: header + section iterators (question, answer,
      authority, additional), validated against section counts
- [x] `Question` and `Record` views (name, type, class, TTL, raw RDATA)
- [x] Unknown-type RDATA passthrough (RFC 3597)
- [x] Typed RDATA for the RFC 1035 set: A, NS, CNAME, SOA, PTR, MX, TXT,
      HINFO, plus AAAA (RFC 3596)
- [x] Whole-message validation mode (walk once, report the first error) for
      callers that want to fail fast before iterating

## Milestone 2 — Building messages

- [x] `MessageBuilder` over `&mut [u8]` with runtime-checked section
      ordering (question → answer → authority → additional)
- [x] Name compression with a fixed-size, allocation-free suffix table;
      option to disable compression (and never compress inside RDATA of
      types where RFC 3597 forbids it)
- [x] Automatic section counts
- [x] Size limits and truncation: stop at a max size, set TC, roll back the
      partial RRset (RFC 2181 §9); `Truncation::Error` / `SetTc` policies,
      reserve for OPT/TSIG, `copy_section` / `copy_message`
- [x] Convenience constructors: query for (name, type), response skeleton
      from a parsed query (copies ID, opcode, RD, CD, question; EDNS echo
      with `start_response_edns`)
- [x] Growable `Vec`-backed builder (`alloc`)
- [x] TCP framing helpers (2-byte length prefix, RFC 1035 §4.2.2 / RFC 7766):
      frame splitting, allocation-free `FrameReassembler`, `std::io`
      helpers, length-prefixed builder
- [x] Appending pre-encoded records (`push_raw_records`) and copying parsed
      records with name recompression

## Milestone 3 — EDNS(0)

- [x] OPT pseudo-record (RFC 6891): UDP payload size, extended RCODE
      (combined with the header RCODE), version, DO bit (other flag bits
      preserved), option iteration and building; open `OptionCode` with
      the full IANA registry
- [x] Options:
  - [x] Client Subnet (RFC 7871)
  - [x] Cookies (RFC 7873, RFC 9018 interoperable server cookies; SipHash
        from purecrypto behind `cookie-siphash`)
  - [x] Padding (RFC 7830) with RFC 8467 padding policies in the builder
  - [x] TCP keepalive (RFC 7828)
  - [x] Extended DNS Errors (RFC 8914)
  - [x] NSID (RFC 5001)
  - [x] Chain query (RFC 7901), Key tag (RFC 8145), Expire (RFC 7314)
  - [x] Zone version (RFC 9660), Report-Channel (RFC 9567)
  - [x] DAU/DHU/N3U (RFC 6975)
- [x] Unknown options pass through untouched

## Milestone 4 — Record type coverage

- [x] SRV (RFC 2782), NAPTR (RFC 3403), CAA (RFC 8659), SSHFP (RFC 4255,
      RFC 6594), TLSA (RFC 6698), SMIMEA (RFC 8162), OPENPGPKEY (RFC 7929)
- [x] DNAME (RFC 6672), LOC (RFC 1876), RP / AFSDB (RFC 1183), URI
      (RFC 7553), CERT (RFC 4398), DHCID (RFC 4701), NID/L32/L64/LP
      (RFC 6742), EUI48/EUI64 (RFC 7043), CSYNC (RFC 7477), ZONEMD
      (RFC 8976; zone digests in Milestone 5), APL
      (RFC 3123), IPSECKEY (RFC 4025), HIP (RFC 8005), KX (RFC 2230)
- [x] SVCB and HTTPS (RFC 9460) with typed SvcParams: mandatory, alpn,
      no-default-alpn, port, ipv4hint, ipv6hint, ech, dohpath (RFC 9461),
      ohttp (RFC 9540), plus tls-supported-groups, docpath, pvd, oots;
      unknown keys pass through; `SvcbBuilder`; presentation parsing
      (`Svcb::from_text`)
- [x] Obsolete/legacy types: X25, ISDN, RT, GPOS, NSAP, NSAP-PTR, PX, A6,
      NXT, EID, NIMLOC, ATMA, SINK, NINFO, RKEY, TALINK, SPF, AVC, RESINFO,
      WALLET typed; UINFO/UID/GID/UNSPEC opaque with mnemonics
- [x] Presentation-format (zone-file style) `Display` for every typed RDATA

## Milestone 5 — DNSSEC

Wire format and validation logic live in dnsbox and need no crypto; the
digest and signature calls come from `purecrypto` behind features
(`dnssec-digest`: DS digests and NSEC3 hashing, no `alloc`; `dnssec`:
signatures), through the pluggable `Verifier` / `Signer` traits.

- [x] DNSKEY, RRSIG, NSEC, DS (RFC 4034), NSEC3, NSEC3PARAM (RFC 5155),
      CDS/CDNSKEY (RFC 7344, RFC 8078 delete forms), KEY/SIG (RFC 2535,
      RFC 2931), DLV/TA
- [x] Open newtypes for algorithm numbers, DS digest types and NSEC3 hash
      algorithms (IANA registries)
- [x] Type bitmap parsing and building
- [x] Canonical RR form and canonical RRset ordering (RFC 4034 §6,
      RFC 6840 §5.1), allocation-free
- [x] Key tag computation, DS digest input construction
- [x] NSEC3 hashing (base32hex owner names)
- [x] RRSIG validation logic: signed data, labels/wildcard reconstruction,
      RFC 1982 validity window, key matching (RFC 4035 §5.3)
- [x] Signature verification and signing via purecrypto (`dnssec`
      feature): RSA/SHA-1, RSA/SHA-1-NSEC3, RSA/SHA-256, RSA/SHA-512, ECDSA
      P-256/P-384, Ed25519, Ed448; DNSKEY/DS generation from keys. GOST,
      SM2/SM3, DSA and RSA/MD5 are not supported (`UnsupportedAlgorithm`)
- [x] Authenticated denial of existence: NSEC/NSEC3 proof checking
      (RFC 4035 §5.4, RFC 5155 §8, RFC 6840 §4, RFC 7129) with
      closest-encloser proofs, Opt-Out as insecure and RFC 9276 iteration
      limits (`dnssec::denial`)
- [x] Chain of trust: DNSKEY authentication from DS or trust anchors,
      RRset and wildcard-answer verification, KeyTrap work bound
      (`dnssec::chain`)
- [x] ZONEMD zone digest computation and verification (RFC 8976,
      `dnssec::zonemd`)

## Milestone 6 — Transactions, updates and zone transfer

- [x] TSIG (RFC 8945): record parsing, MAC input construction, signing and
      verification (requests, responses, TCP streams, error responses)
      through the `TsigKey` / `TsigMac` traits; HMAC-MD5/SHA-1/SHA-2 from
      purecrypto behind the `tsig` feature
- [x] SIG(0) (RFC 2931): signed-data construction, sign/find/verify through
      `Sig0Signer` / `Sig0Verifier`; RSA/ECDSA/EdDSA via the DNSSEC
      backend adapters
- [x] Dynamic UPDATE (RFC 2136) message helpers (zone/prerequisite/update
      sections, every prerequisite and deletion encoding)
- [x] NOTIFY (RFC 1996)
- [x] AXFR/IXFR (RFC 5936, RFC 1995) multi-message stream helpers
- [x] DNS Stateful Operations (RFC 8490) TLV framing

## Milestone 7 — Text formats and owned data (`alloc`)

- [x] Owned `OwnedMessage` / `OwnedRecord` / `OwnedRData` types with
      conversion from views, from zone-file records and from text
- [x] Zone-file / presentation-format parser (RFC 1035 §5) for records:
      `ParseRdataText` for every type, `ZoneReader` with `$ORIGIN`,
      `$TTL`, `$INCLUDE` and `$GENERATE`
- [x] `dig`-style message `Display`
- [x] Optional `serde` support

## Milestone 8 — Performance and assurance

- [x] Criterion benchmarks: parse/iterate/build for typical queries,
      large responses, heavily compressed messages; comparisons against
      `hickory-proto` and `domain` (`benches/`, `BENCH.md`)
- [x] cargo-fuzz targets: message parsing (plus EDNS, TSIG/SIG(0), UPDATE,
      NOTIFY, XFR and DSO views), name decompression, RDATA (every
      registered type), EDNS options, build→parse round-trip,
      presentation-format parser (whole zone files; every type's
      displayed RDATA parses back), and the trust decisions (NSEC/NSEC3
      denial, DNSSEC backend and chain of trust, TSIG/SIG(0) tampering,
      `$INCLUDE`/`$GENERATE`/ZONEMD order independence); all run with
      overflow checks (`-a`)
- [x] Property tests: build→parse and parse→build→parse identity
- [x] Interop corpus: real-world captures, plus responses from BIND,
      Unbound, Knot and PowerDNS (also NSD, Knot Resolver, PowerDNS
      Recursor, public resolvers); tool-level interop with BIND 9.18
      (zone files, signers for every algorithm, a local `named`), ldns
      and dnspython (RDATA text and wire, TSIG, UPDATE, EDNS, ZONEMD),
      and DNSSEC validation of the corpus from the IANA root anchors
      (`tests/corpus/README.md`)
- [x] Allocation-free hot path verified in CI (no-alloc build + tests)
- [x] Hot-path tuning: name decoder and suffix cache, fixed-field
      parsing, label-trie compression table (`BENCH.md`: faster than
      `domain` and `hickory-proto` on every benchmark)

## Milestone 9 — 1.0

- [x] API review: naming, error granularity, feature layout (the
      conventions are in `ARCHITECTURE.md`, the breaking changes in
      `CHANGELOG.md`)
- [x] Complete rustdoc with examples on every public item: every public
      item is documented (`missing_docs`, denied in CI), every fallible
      public function has an `# Errors` section
      (`clippy::missing_errors_doc`), and every public module, type, trait
      and free function, plus the main methods, has a runnable doctest
      (trivial accessors such as `Record::ttl` are shown in their type's
      example rather than their own); a guided tour opens the crate docs
      and `examples/` holds four complete programs. The nightly-only
      `rustdoc::missing_doc_code_examples` lint is not enforced
- [x] SECURITY.md threat model finalized after a fuzzing campaign (attacker
      model, guarantees, work bounds, caller duties; seven findings, all
      fixed with regression tests in `tests/security_audit.rs`)
- [x] Stability commitment and MSRV policy documented (README.md,
      "Stability and MSRV policy")

## Known gaps

Nothing above is open. The gaps found by the Milestone 9 review are
closed: AMTRELAY, DSYNC and TKEY have typed RDATA (with DOA, HHIT and
BRID); Knot DNS and Unbound interop runs in CI; work an attacker controls
is bounded by library limits on by default (`ZoneLimits`,
`ValidationBudget`); `cargo doc` is clean in every feature combination.
What remains to know before 1.0:

- Record types defined only by drafts that neither BIND nor dnspython
  implements round-trip as RFC 3597 opaque data: IPN and CLA
  (draft-johnson-dns-ipn-cla, expired), UNECE and ISO
  (draft-woodcock-faltstrom-external-registry-rrtypes, still changing).
  UINFO, UID, GID and UNSPEC are reserved without a format and stay
  opaque by design.
- TKEY (RFC 2930): dnsbox builds and reads the messages (`tkey`) but does
  no key exchange (Diffie-Hellman, GSS-API). Its presentation format is
  BIND's, with the key and other-data sizes, which dnspython does not
  write or read (`tests/corpus/dnspython/gen_rdata.py` skips TKEY).
- Zone transfer limits (`XfrProcessor::with_max_records`,
  `with_max_messages`) are opt-in with no default, since zones range from
  one record to millions.
- Knot DNS and Unbound interop needs their tools, so it runs only in
  GitHub CI (`.github/workflows/interop.yml`); `cargo test` checks a kept
  subset of a CI run offline.

## Out of scope

`dnsbox` is a wire-format library. Resolvers, caches, server frameworks and
socket handling belong in crates built on top of it. Transport framing
helpers (TCP length prefix, DoT/DoH/DoQ message shaping per RFC 7858,
RFC 8484, RFC 9250) are in scope only insofar as they are pure byte
transformations.
