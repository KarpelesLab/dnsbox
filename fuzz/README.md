# dnsbox fuzzing

[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets for dnsbox.
This directory is its own Cargo workspace (it needs nightly and libFuzzer),
so it never affects the crate's MSRV or dependency tree.

| Target      | What it checks |
|-------------|----------------|
| `edns`      | OPT RDATA framing and every EDNS(0) option through the generic `EdnsOption` dispatch: display, re-compose to the same TLV, re-parse |
| `message`   | `Message::parse`, every lazy iterator, typed RDATA of every record, `validate`, and parse → build → parse identity (with and without compression, rebuild is a fixed point); plus the protocol views: EDNS, TSIG/SIG(0) placement, UPDATE, NOTIFY, AXFR/IXFR processing, DSO |
| `name`      | name decompression at any offset (pointer hardening), `Name`/`NameBuf` invariants: labels, flattening, parents, canonical order, case-insensitive equality and hashing, presentation round trip |
| `rdata`     | every record type through the generic `RData` dispatch — registered types are found through the registry, so new types are fuzzed automatically — then display, re-compose, re-parse, canonical form and embedding in a built message |
| `roundtrip` | build → parse identity: a byte-driven sequence of builder operations (questions, records of any registered type, compression toggles, size limits, checkpoints and rollbacks) must parse back exactly; failed pushes and rollbacks must leave the bytes untouched |
| `text`      | presentation-format parsing: names (escapes), types, classes, SVCB/HTTPS RDATA (display re-parses to the same value) |

The properties live in [`src/lib.rs`](src/lib.rs), which the crate's own
test suite also includes (`tests/fuzz_regressions.rs`,
`tests/proptest_roundtrip.rs`, `tests/corpus.rs`), so the same checks run on
stable in every feature configuration.

## Running

```sh
cargo install cargo-fuzz
cd fuzz
mkdir -p corpus/message
cargo +nightly fuzz run message corpus/message seeds/message -- -max_total_time=600
```

The first corpus directory receives new inputs (it is git-ignored); the
committed `seeds/<target>/` directories are small starting points. CI runs
every target for 60 seconds on each push and pull request
(`.github/workflows/fuzz.yml`).

## When a target finds a crash

1. Reproduce: `cargo +nightly fuzz run <target> artifacts/<target>/<file>`.
2. Fix the bug in the crate.
3. Copy the reproducer to `regressions/<target>/<descriptive-name>`; the
   `fuzz_regressions` test replays it on every `cargo test`.
