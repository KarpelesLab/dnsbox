# dnsbox

[![CI](https://github.com/KarpelesLab/dnsbox/actions/workflows/ci.yml/badge.svg)](https://github.com/KarpelesLab/dnsbox/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/dnsbox.svg)](https://crates.io/crates/dnsbox)
[![docs.rs](https://docs.rs/dnsbox/badge.svg)](https://docs.rs/dnsbox)

High-performance DNS message parsing and building for Rust — queries and
responses, zero-copy, `no_std`, with broad RFC extension coverage (EDNS(0),
DNSSEC, SVCB/HTTPS, TSIG, and more).

> **Status:** pre-1.0. Wire formats, EDNS(0), DNSSEC, SVCB/HTTPS, TSIG and
> the long tail of record types are implemented; the API may still change.
> See the [roadmap](ROADMAP.md) for what is left before 1.0 (rustdoc
> examples everywhere, the final threat model, the stability policy).

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

### EDNS(0): a query and the response echo

```rust
use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
use dnsbox::edns::{Nsid, OptHeader};
use dnsbox::rdata::Aaaa;

fn main() -> Result<(), dnsbox::Error> {
    let name: NameBuf = "example.com".parse()?;

    // Query: RD set, EDNS with DO and an NSID request.
    let mut qbuf = [0u8; 512];
    let mut q = MessageBuilder::query(&mut qbuf, 0xbeef, &name, Rtype::AAAA, Class::IN)?;
    q.push_edns(OptHeader::new(1232).with_dnssec_ok(true), &Nsid::REQUEST)?;
    let query = Message::parse_validated(q.finish())?;

    // Response skeleton: ID, flags, question and the OPT echo (RFC 6891 §7);
    // room for the OPT record is reserved even if the answer is truncated.
    let mut rbuf = [0u8; 512];
    let mut r = MessageBuilder::new(&mut rbuf)?;
    let opt = r.start_response_edns(&query, 1232)?.expect("query had EDNS");
    r.push_answer(&name, Class::IN, 300, &Aaaa::new("2001:db8::1".parse().unwrap()))?;
    r.push_reserved_edns(opt, &Nsid::new(b"ns1"))?;

    let resp = Message::parse_validated(r.finish())?;
    let edns = resp.edns()?.expect("echoed");
    assert!(edns.dnssec_ok());
    assert_eq!(edns.get::<Nsid>().transpose()?.map(|n| n.id), Some(&b"ns1"[..]));
    Ok(())
}
```

### SVCB / HTTPS

```rust
use dnsbox::rdata::Https;

fn main() -> Result<(), dnsbox::Error> {
    let mut buf = [0u8; 256];
    let https = Https::from_text("1 . alpn=h3,h2 port=8443 ipv4hint=192.0.2.1", &mut buf)?;
    assert_eq!(https.params.port(), Some(8443));
    assert_eq!(https.to_string(), r#"1 . alpn="h3,h2" port=8443 ipv4hint=192.0.2.1"#);
    Ok(())
}
```

### Zone files

```rust
use dnsbox::zone::ZoneReader;

fn main() -> Result<(), dnsbox::Error> {
    let zone = "\
$ORIGIN example.com.
$TTL 1h
@    SOA  ns1 hostmaster ( 2024010101 2h 15m 2w 1h )
     NS   ns1
ns1  A    192.0.2.1
www  300  CNAME @
";
    // Streams records without allocating: RDATA goes into `buf`.
    let mut reader = ZoneReader::new(zone);
    let mut buf = [0u8; 1024];
    let mut lines = Vec::new();
    while let Some(rr) = reader.next_record(&mut buf)? {
        lines.push(rr.to_string());
    }
    assert_eq!(lines[3], "www.example.com. 300 IN CNAME example.com.");
    Ok(())
}
```

## What is covered

- **Core** (RFC 1035, 3596, 3597, 2181, 4343): zero-copy `Message` views,
  hardened name decompression, whole-message validation, a compressing
  builder with atomic pushes, RRset-level truncation (TC) and size limits,
  query/response constructors, TCP framing and stream reassembly.
- **EDNS(0)** (RFC 6891): OPT view and builder, extended RCODE, DO/CO flags,
  the full option-code registry and typed options — Client Subnet, Cookies
  (with RFC 9018 server cookies), Padding with RFC 8467 policies, TCP
  keepalive, Extended DNS Errors, NSID, Chain, Key tag, Expire, Zone
  version, Report-Channel, DAU/DHU/N3U.
- **Record types**: about 80 typed RDATA formats — the RFC 1035 set, SRV,
  NAPTR, CAA, SSHFP, TLSA, SMIMEA, OPENPGPKEY, DNAME, URI, CERT, DHCID, LOC,
  RP, AFSDB, ILNP, EUI48/64, CSYNC, ZONEMD, APL, IPSECKEY, HIP, KX, SVCB and
  HTTPS (all RFC 9460 SvcParams), the DNSSEC types and the legacy types —
  each with presentation-format `Display`; unknown types round-trip.
- **DNSSEC** (RFC 4033–4035, 5155, 6840): canonical form and RRset order,
  key tags, DS digests, NSEC3 hashing, RRSIG validation logic, the chain of
  trust (DS → DNSKEY → RRset, wildcard expansions), NSEC/NSEC3
  denial-of-existence proofs (NXDOMAIN, NODATA, wildcards, unsigned
  delegations, Opt-Out, RFC 9276 iteration limits), ZONEMD zone digests
  (RFC 8976), and with the `dnssec` feature RSA, ECDSA P-256/P-384,
  Ed25519 and Ed448 verification and signing.
- **Zone files** (RFC 1035 §5): a streaming, allocation-free master-file
  reader (`$ORIGIN`, `$TTL`, `$INCLUDE`, BIND's `$GENERATE`, TTL units,
  RFC 3597 generic RDATA, errors with line and column) and
  presentation-format parsing of RDATA (`ParseRdataText`).
- **Transactions and zone transfer**: TSIG (RFC 8945), SIG(0) (RFC 2931),
  dynamic UPDATE (RFC 2136), NOTIFY (RFC 1996), AXFR/IXFR (RFC 5936,
  RFC 1995) stream processing, DNS Stateful Operations (RFC 8490).
- **Text and owned data**: `dig`-style `Display` of whole messages (no
  allocation, matches BIND's `dig` line for line), owned `OwnedMessage` /
  `OwnedRecord` / `OwnedRData` types (`alloc`) and `serde` support.

## Features

| Feature          | Default | What it adds |
|------------------|---------|--------------|
| `std`            | yes     | `std::io` TCP helpers, `$INCLUDE` from the file system (implies `alloc`) |
| `alloc`          |         | `Vec`-backed builders, owned message types (`OwnedMessage`, ...) |
| `dnssec-digest`  |         | DS digests and NSEC3 hashing (no `alloc`); ZONEMD digests (with `alloc`) |
| `dnssec`         |         | DNSSEC and SIG(0) signature verification and signing (implies `alloc`, `dnssec-digest`) |
| `tsig`           |         | TSIG HMAC backend (HMAC-MD5/SHA-1/SHA-2) |
| `cookie-siphash` |         | RFC 9018 server cookie generation and verification |
| `serde`          |         | `Serialize`/`Deserialize` (`no_std`): protocol numbers as mnemonics, names as text, owned types with `alloc` |

dnsbox never implements cryptography itself: the crypto features pull in
the optional, `no_std`-capable [`purecrypto`](https://crates.io/crates/purecrypto)
crate. Every crypto-using API sits behind a trait, so other backends can be
plugged in, and all wire-format work (signed data, MAC input, canonical
forms) is available without these features.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the design and extension guide.

## Assurance and performance

dnsbox is continuously fuzzed ([`fuzz/`](fuzz)), property-tested, and
checked against real responses from BIND, NSD, Knot, PowerDNS, Unbound and
public resolvers ([`tests/corpus/`](tests/corpus)). The threat model —
what is guaranteed on hostile input and what callers must do — is in
[SECURITY.md](SECURITY.md). Benchmarks against
`hickory-proto` and `domain` are in [BENCH.md](BENCH.md).

## Minimum supported Rust version

Rust 1.89, edition 2024.

## License

MIT — see [LICENSE](LICENSE).
