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
  allocation); `dnsbox-vec` uses the `Vec`-backed builder, which is what
  hickory-proto (`Message::to_vec`) and domain (`MessageBuilder` over a
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
builds (load average 40–50), so absolute numbers are noisy; the ratios are
what matter. dnsbox at commit `9cea488` (foundation). Median of criterion's
estimate (lower is better).

### Parse and visit everything

| Fixture        | dnsbox   | dnsbox-validate | hickory-proto | domain   |
|----------------|----------|-----------------|---------------|----------|
| `query`        | 39.3 ns  | 32.6 ns         | 144.3 ns      | 28.8 ns  |
| `large`        | 2.10 µs  | 1.59 µs         | 5.66 µs       | 1.44 µs  |
| `pathological` | 89.1 µs  | 45.5 µs         | 176.4 µs      | 95.5 µs  |

### Build with compression

| Fixture        | dnsbox (`&mut [u8]`) | dnsbox-vec | hickory-proto | domain   |
|----------------|----------------------|------------|---------------|----------|
| `query`        | 71.2 ns              | 103.7 ns   | 160.3 ns      | 53.6 ns  |
| `large`        | 3.38 µs              | 3.57 µs    | 5.39 µs       | 3.00 µs  |
| `pathological` | 175.2 µs             | 176.8 µs   | 171.2 µs      | 312.9 µs |

## Observations

- dnsbox is 2.0–3.7× faster than hickory-proto at parsing, and 1.5–2.3×
  faster at building typical messages; on the pathological message hickory
  builds about as fast but emits 5.6× more bytes (it does not chain
  compression through owner names the way dnsbox does).
- domain is currently ahead of dnsbox on typical messages: it needs 27–31 %
  less time to parse `query` and `large`, and 11–25 % less to build them.
  dnsbox is ahead on the pointer-heavy message (parse 7 % faster, build
  1.8× faster and 8× smaller, since domain's static compressor only
  remembers 24 names). This is the baseline for the Milestone 8 hot-path
  tuning item. Likely places to look:
  - every RDATA decode goes through `RData::parse`'s dispatch and a
    `WireReader` window per record; the visit then re-walks names that
    were just validated (`dnsbox-validate`, a single pass, is already
    within about 10 % of domain's full walk on `large`);
  - `MessageBuilder` flattens each compressible name and hashes every
    suffix before looking anything up; for short messages with few names
    a direct scan could be cheaper;
  - the `&mut [u8]` builder already avoids allocation; the 30 ns between
    `dnsbox` and `dnsbox-vec` on `query` is the cost of growing a `Vec`.
- Every encoding of every fixture parses identically in all three
  libraries, including the 120-hop pointer chains.
