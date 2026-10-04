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
use dnsbox::{Class, Flags, Message, MessageBuilder, NameBuf, Rtype};
use dnsbox::rdata::{A, RData};

fn main() -> Result<(), dnsbox::Error> {
    // Build a response into a stack buffer: no allocation, names compressed.
    let name: NameBuf = "example.com".parse()?;
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf)?;
    b.set_id(0x1234);
    b.set_flags(Flags::default().with_qr(true).with_rd(true));
    b.push_question(&name, Rtype::A, Class::IN)?;
    b.push_answer(&name, Class::IN, 3600, &A::new([192, 0, 2, 1].into()))?;
    let wire = b.finish();

    // Parse it back: a zero-copy view, decoded lazily.
    let msg = Message::parse_validated(wire)?;
    for rr in msg.answers() {
        let rr = rr?;
        assert_eq!(rr.to_string(), "example.com. 3600 IN A 192.0.2.1");
        if let RData::A(a) = rr.data()? {
            assert_eq!(a.addr.octets(), [192, 0, 2, 1]);
        }
    }
    Ok(())
}
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the design and extension guide.

## Assurance and performance

dnsbox is continuously fuzzed ([`fuzz/`](fuzz)), property-tested, and
checked against real responses from BIND, NSD, Knot, PowerDNS, Unbound and
public resolvers ([`tests/corpus/`](tests/corpus)). Benchmarks against
`hickory-proto` and `domain` are in [BENCH.md](BENCH.md).

## Minimum supported Rust version

Rust 1.89, edition 2024.

## License

MIT — see [LICENSE](LICENSE).
