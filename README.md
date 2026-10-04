# dnsbox

[![CI](https://github.com/KarpelesLab/dnsbox/actions/workflows/ci.yml/badge.svg)](https://github.com/KarpelesLab/dnsbox/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/dnsbox.svg)](https://crates.io/crates/dnsbox)
[![docs.rs](https://docs.rs/dnsbox/badge.svg)](https://docs.rs/dnsbox)

High-performance DNS message parsing and building for Rust — queries and
responses, zero-copy, `no_std`, with broad RFC extension coverage (EDNS(0),
DNSSEC, SVCB/HTTPS, TSIG, and more).

> **Status:** early development. The API is not stable and most of the
> functionality is still on the [roadmap](ROADMAP.md).

## Goals

- **Safe on hostile input** — no panics, no out-of-bounds reads,
  `#![forbid(unsafe_code)]`.
- **Zero-copy parsing** — messages are views over your buffer; names and
  record data decode lazily.
- **Fast building** — write straight into a caller-supplied buffer with name
  compression and truncation handled for you.
- **`no_std`** — `alloc` and `std` are optional features.

## Example

```rust
use dnsbox::{Header, Opcode};

let wire = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
let header = Header::parse(&wire).unwrap();
assert_eq!(header.id, 0x1234);
assert_eq!(header.flags.opcode(), Opcode::QUERY);
assert!(header.flags.rd());
```

## Minimum supported Rust version

Rust 1.89, edition 2024.

## License

MIT — see [LICENSE](LICENSE).
