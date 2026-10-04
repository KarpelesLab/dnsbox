# Benchmarks

dnsbox compared with [hickory-proto](https://crates.io/crates/hickory-proto)
0.26.3 and [domain](https://crates.io/crates/domain) 0.12.3 (NLnet Labs),
using criterion 0.8.2. The benchmarks are a separate package under
[`benches/`](benches), with its own workspace and lockfile, so their
dependencies and MSRVs never affect the crate.

```sh
cd benches
cargo test --release            # the three libraries agree on every fixture
cargo bench                     # all benchmarks
cargo bench -- parse/large      # one group
```

## What is measured

Three fixtures (`benches/src/lib.rs`):

| Fixture        | Size (dnsbox / hickory / domain encoding) | Content |
|----------------|-------------------------------------------|---------|
| `query`        | 44 / 44 / 44 bytes | `www.example.com. IN A` with an EDNS(0) OPT record: a typical stub query |
| `large`        | 1302 / 1302 / 1302 bytes | 66 records in all three sections (A, AAAA, MX, TXT, CNAME, NS, SOA, glue) whose names share suffixes, so nearly every name is compressed |
| `pathological` | 4107 / 23146 / 33703 bytes | 240 A records whose owner names are `x.x.….x.a.example`, each one label longer than the previous one, up to 120 labels: on the wire every owner is one label plus a pointer to the previous owner, so decoding name *n* follows *n* pointers. This is the most pointer-hopping a decoder with a sane hop limit has to accept |

Two operations:

- **parse**: decode the message and visit everything: walk the labels of
  every owner name and decode the typed RDATA of every record (names in
  RDATA included). hickory-proto decodes eagerly into owned values; dnsbox
  and domain decode lazily, and the walk forces the same work out of them.
  All three parse the same bytes (the message as dnsbox encodes it).
  `dnsbox-validate` is `Message::parse_validated`, dnsbox's single-pass
  fail-fast check (every name, count and typed RDATA, without the walk).
- **build**: encode the message with name compression from records
  constructed beforehand. `dnsbox` writes into a reused `&mut [u8]` (no
  allocation); `dnsbox-vec` uses the `Vec`-backed builder
  (`MessageBuilder::new_vec`), which is what hickory-proto
  (`Message::to_vec`) and domain (`MessageBuilder` over a
  `StaticCompressor<Vec<u8>>`) do.

`cargo test --release` in `benches/` checks that each library parses what
each library built, with identical record counts and an identical checksum
over every name label and RDATA field, so the numbers compare like with
like.

## Results

Machine: AMD Ryzen Threadripper 9970X (32 cores / 64 threads), 125 GB RAM,
Linux 6.18.41 (Gentoo), `powersave` governor; Rust 1.98.0 stable,
`[profile.bench]` with thin LTO and one codegen unit; benchmark process
pinned to one core (`taskset -c 40`). The machine was shared with other
builds (load average 20–35), so absolute numbers are noisy; the ratios are
what matter. Median of criterion's estimate (lower is better).

*Before* is dnsbox at commit `e8eb495`, just before the Milestone 8
hot-path tuning; *after* is the tuned code. Both were measured back to back
in the same session, with the same harness; the hickory-proto and domain
columns are from the *after* run (in the *before* run they differed by up
to 14 %, which gives an idea of the noise).

### Parse and visit everything

| Fixture        | dnsbox before | dnsbox after | dnsbox-validate before | dnsbox-validate after | hickory-proto | domain   |
|----------------|---------------|--------------|------------------------|-----------------------|---------------|----------|
| `query`        | 39.5 ns       | **19.5 ns**  | 31.2 ns                | **16.6 ns**           | 141.4 ns      | 27.4 ns  |
| `large`        | 2.04 µs       | **0.99 µs**  | 1.50 µs                | **0.97 µs**           | 4.79 µs       | 1.33 µs  |
| `pathological` | 85.3 µs       | **43.8 µs**  | 43.9 µs                | **3.2 µs**            | 159.7 µs      | 91.7 µs  |

### Build with compression

| Fixture        | dnsbox before | dnsbox after | dnsbox-vec before | dnsbox-vec after | hickory-proto | domain   |
|----------------|---------------|--------------|-------------------|------------------|---------------|----------|
| `query`        | 67.0 ns       | **33.6 ns**  | 101.3 ns          | **40.3 ns**      | 146.6 ns      | 51.9 ns  |
| `large`        | 3.19 µs       | **2.11 µs**  | 3.23 µs           | **1.93 µs**      | 4.86 µs       | 3.06 µs  |
| `pathological` | 168.3 µs      | **67.1 µs**  | 168.5 µs          | **68.0 µs**      | 153.2 µs      | 292.3 µs |

The encoded messages are byte for byte the same before and after.

## Observations

- dnsbox is now ahead of both libraries on every benchmark. Against domain
  it needs 26–29 % less time to parse `query` and `large` and half the time
  on `pathological`; it needs 31–35 % less time to build `query` and
  `large`, and builds `pathological` 4.4× faster (into an 8× smaller
  message). Against
  hickory-proto it parses 3.6–7.3× and builds 2.3–4.4× faster, including
  the pointer-heavy message that hickory used to build faster (while
  emitting 5.6× more bytes).
- The Milestone 8 tuning halved most dnsbox timings. What it changed,
  without `unsafe` and without dropping any hardening check:
  - **Name decoder** (`name/decode.rs`): one tight loop for the in-place
    labels, which is the whole decoder for uncompressed names, and the
    pointer-following part split out of the hot path; errors are built in
    `#[cold]` paths. Same checks, same errors, same extents.
  - **Suffix cache in the record iterators**: what decoding from an offset
    produced is remembered (16 slots, 128 bytes, no allocation), so an
    owner name that points at the question, or at the previous owner, costs
    one lookup instead of a walk. A cached suffix is only used when the
    combined name provably passes the checks the walk would make, so the
    results are identical with and without it. This is what takes
    `dnsbox-validate` on `pathological` from 43.9 µs to 3.2 µs.
  - **Cheap section iteration**: the iterators read TYPE/CLASS/TTL/RDLENGTH
    with one bounds check and never look at RDATA; locating a later
    section is a plain slice walk; `RData::parse` builds its variant in
    place.
  - **Compression table** (`builder/compress.rs`): a trie of the labels
    already written, with a hash index keyed by (parent, label), replaces
    the suffix table that flattened every name, hashed every suffix with
    byte-at-a-time FNV, scanned the whole table per suffix and decoded each
    candidate. Labels are hashed eight bytes at a time and checked against
    the message with one word compare; the two commonest cases (same name
    as the last one, or one label more) are checked without hashing; the
    empty table is all zeros, so starting a message is one `memset`;
    root names skip the table entirely.
  - **Builder**: TYPE, CLASS, TTL and the RDLENGTH placeholder are written
    in one append, and `MessageBuilder::new_vec` starts with room for 512
    bytes instead of growing from 12.
- Every encoding of every fixture parses identically in all three
  libraries, including the 120-hop pointer chains.
