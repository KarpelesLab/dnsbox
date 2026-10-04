# dnsbox fuzzing

[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets for dnsbox.
This directory is its own Cargo workspace (it needs nightly and libFuzzer),
so it never affects the crate's MSRV or dependency tree.

| Target      | What it checks |
|-------------|----------------|
| `edns`      | OPT RDATA framing and every EDNS(0) option through the generic `EdnsOption` dispatch: display, re-compose to the same TLV, re-parse |
| `message`   | `Message::parse`, every lazy iterator, typed RDATA of every record, `validate`, and parse → build → parse identity (with and without compression, rebuild is a fixed point); plus the protocol views: EDNS, TSIG/SIG(0) placement, UPDATE, NOTIFY, AXFR/IXFR processing, DSO |
| `name`      | name decompression at any offset (pointer hardening), `Name`/`NameBuf` invariants: labels, flattening, parents, canonical order, case-insensitive equality and hashing, presentation round trip |
| `rdata`     | every record type through the generic `RData` dispatch — registered types are found through the registry, so new types are fuzzed automatically — then display, re-compose (to the very octets parsed: one wire form per value), re-parse, canonical form and embedding in a built message |
| `roundtrip` | build → parse identity: a byte-driven sequence of builder operations (questions, records of any registered type, compression toggles, size limits, checkpoints and rollbacks) must parse back exactly; failed pushes and rollbacks must leave the bytes untouched |
| `text`      | presentation-format parsing: names (escapes), types, classes, SVCB/HTTPS RDATA (display re-parses to the same value) |
| `denial`    | NSEC and NSEC3 denial-of-existence proofs over records generated from a small name pool (matches, covers, wildcards, zone cuts, opt-out, short hashes): verdicts never contradict each other or prove anything outside the zone |
| `dnssec`    | the purecrypto signature backend on hostile keys and signatures (every algorithm), and `TrustedKeys` over the records of a message with a verifier that accepts every signature: each accepted RRset is justified by an RRSIG passing every RFC 4035 §5.3.1 check |
| `sign`      | a message signed with TSIG (request and response) or SIG(0) verifies, and a changed copy (flip, insert, append, truncate) verifies only if everything the signature covers is unchanged (header but the TSIG ID, octets before the signature record, the record's data) |
| `zone`      | master files whose `$INCLUDE`s name other parts of the input, with `$GENERATE`: every record is valid, and the ZONEMD collation and verdict do not depend on record order |

The properties live in [`src/lib.rs`](src/lib.rs) and
[`src/security.rs`](src/security.rs), which the crate's own
test suite also includes (`tests/fuzz_regressions.rs`,
`tests/proptest_roundtrip.rs`, `tests/corpus.rs`), so the same checks run on
stable in every feature configuration.

## Running

```sh
cargo install cargo-fuzz
cd fuzz
mkdir -p corpus/message
cargo +nightly fuzz run -a message corpus/message seeds/message -- -max_total_time=600
```

`-a` turns on debug assertions, so integer overflow panics instead of
silently wrapping as in a plain release build: always fuzz with it. The
first corpus directory receives new inputs (it is git-ignored); the
committed `seeds/<target>/` directories are small starting points. CI runs
every target for 60 seconds on each push and pull request
(`.github/workflows/fuzz.yml`).

## When a target finds a crash

1. Reproduce: `cargo +nightly fuzz run -a <target> artifacts/<target>/<file>`.
2. Fix the bug in the crate.
3. Copy the reproducer to `regressions/<target>/<descriptive-name>`; the
   `fuzz_regressions` test replays it on every `cargo test`.
