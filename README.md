# dnsbox

[![CI](https://github.com/KarpelesLab/dnsbox/actions/workflows/ci.yml/badge.svg)](https://github.com/KarpelesLab/dnsbox/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/dnsbox.svg)](https://crates.io/crates/dnsbox)
[![docs.rs](https://docs.rs/dnsbox/badge.svg)](https://docs.rs/dnsbox)

High-performance DNS message parsing and building for Rust — queries and
responses, zero-copy, `no_std`, with broad RFC extension coverage (EDNS(0),
DNSSEC, SVCB/HTTPS, TSIG, and more).

> **Status:** feature-complete for 1.0. Every [roadmap](ROADMAP.md)
> milestone is done: wire formats, EDNS(0), DNSSEC (validation, denial of
> existence, chain of trust, ZONEMD), SVCB/HTTPS, TSIG, SIG(0), UPDATE,
> zone transfers, zone files and the long tail of record types, all
> documented with examples, fuzzed, security-audited
> ([SECURITY.md](SECURITY.md)) and checked against BIND, ldns, dnspython
> and live servers, and against Knot DNS and Unbound in CI. The API went
> through its 1.0 review; until 1.0 is tagged, releases may still break it
> (see [Stability and MSRV policy](#stability-and-msrv-policy)).

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

### More

The [crate documentation](https://docs.rs/dnsbox) starts with a guided
tour (parsing, typed RDATA, building, EDNS, truncation, TCP framing, zone
files, DNSSEC, TSIG), and every public item has its own example. The
[`examples/`](examples) directory holds small complete programs:

| Example | Run with | What it does |
|---------|----------|--------------|
| [`stub_resolver`](examples/stub_resolver.rs) | `cargo run --example stub_resolver -- example.com AAAA` | queries a resolver over UDP with EDNS, falls back to TCP on truncation, prints the answer like `dig` |
| [`zone2wire`](examples/zone2wire.rs) | `cargo run --example zone2wire -- db.example` | turns a zone file into the AXFR message stream a server would send, and reads it back |
| [`dnssec_dig`](examples/dnssec_dig.rs) | `cargo run --example dnssec_dig --features dnssec` | validates captured responses from a trust anchor down (DS → DNSKEY → RRset) |
| [`tsig_axfr`](examples/tsig_axfr.rs) | `cargo run --example tsig_axfr --features tsig` | a TSIG-signed zone transfer, over loopback or from a real server |
| [`interop_probe`](examples/interop_probe.rs) | (CI only, against `knotd` and `unbound`) | dnsbox-built queries with EDNS options, cookies, TSIG, AXFR/IXFR and UPDATE, checked against Knot DNS and Unbound |

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
- **Record types**: about 90 typed RDATA formats — the RFC 1035 set, SRV,
  NAPTR, CAA, SSHFP, TLSA, SMIMEA, OPENPGPKEY, DNAME, URI, CERT, DHCID, LOC,
  RP, AFSDB, ILNP, EUI48/64, CSYNC, ZONEMD, APL, IPSECKEY, HIP, KX, SVCB and
  HTTPS (all RFC 9460 SvcParams), AMTRELAY, DSYNC, TKEY, HHIT/BRID, DOA,
  the draft-defined IPN/CLA and UNECE/ISO, the DNSSEC types and the legacy
  types —
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
  TKEY (RFC 2930: the messages, key deletion, and with the `tkey` feature
  Diffie-Hellman and RSA-assigned key agreement yielding TSIG keys),
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
| `tkey`           |         | TKEY key agreement producing TSIG keys: Diffie-Hellman (RFC 2930 §4.1, RFC 2539) and RSA-encrypted server/resolver assigned keys (implies `alloc`, `tsig`) |
| `serde`          |         | `Serialize`/`Deserialize` (`no_std`): protocol numbers as mnemonics, names as text, owned types with `alloc` |

dnsbox never implements cryptography itself: the crypto features pull in
the optional, `no_std`-capable [`purecrypto`](https://crates.io/crates/purecrypto)
crate. Every crypto-using API sits behind a trait, so other backends can be
plugged in, and all wire-format work (signed data, MAC input, canonical
forms) is available without these features.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the design and extension guide.

## Assurance and performance

dnsbox is continuously fuzzed with overflow checks (ten
[`fuzz/`](fuzz) targets, from message parsing to the DNSSEC and TSIG trust
decisions), property-tested, and checked against real responses from BIND,
NSD, Knot, PowerDNS, Unbound and public resolvers, against BIND 9.18, ldns
and dnspython (zone files, signed zones for every algorithm, TSIG, UPDATE,
ZONEMD), against Knot DNS 3.5 and Unbound 1.19 running in CI (Knot-signed
zones, `knotd` and `kdig` exchanges, dnsbox's validation verdicts against
Unbound's, dnsbox-signed zones accepted by `kzonecheck`), and by
validating the captured DNSSEC data from the IANA root trust anchors
([`tests/corpus/`](tests/corpus)). The threat model — what
is guaranteed on hostile input, the work bounds, what callers must do —
and the findings of the security audit are in [SECURITY.md](SECURITY.md).
dnsbox parses and builds faster than `hickory-proto` and `domain` on every
benchmark ([BENCH.md](BENCH.md)).

## Stability and MSRV policy

dnsbox follows [Semantic Versioning](https://semver.org/).

- **Before 1.0** (the 0.0.x releases), any release may change the public
  API; every such change is listed under "Breaking changes" in the
  [changelog](CHANGELOG.md). The Milestone 9 API review settled the API
  meant for 1.0, so further breaks are expected to be rare and small.
- **From 1.0 on**, breaking changes need a new major version. The public
  API is everything documented on docs.rs. These are not breaking and may
  come in minor releases:
  - new variants of `#[non_exhaustive]` enums (including `Error`, `RData`
    and `EdnsOption`) and new fields of `#[non_exhaustive]` structs;
  - new methods with default bodies on the open extension traits
    (`ParseRdata`, `ComposeRdata`, `Verifier`, `TsigKey`, ...);
    `dnssec::DenialProof` is sealed;
  - new registry constants, record types, EDNS options and SvcParam keys
    (a value that used to be `Unknown` becomes typed);
  - presentation-format (`Display`) output aligned with the RFCs or with
    BIND where they disagree with an older dnsbox spelling; parsing keeps
    accepting the old spelling.
- **Security fixes** that make parsing or verification stricter (rejecting
  input that should never have been accepted, see [SECURITY.md](SECURITY.md))
  may land in patch releases.
- **Features** are additive and keep their names; enabling a feature never
  removes API. The `alloc`-free, `std`-free core stays `no_std`.
- **MSRV:** Rust 1.89 (edition 2024), tested in CI on every push, with all
  features (the optional `purecrypto` and `serde` dependencies included).
  Raising the MSRV is a minor-version change, never a patch release, and
  never to a Rust release less than six months old; the new MSRV is noted
  in the changelog. The fuzz targets (nightly) and benchmarks (their own
  workspace) are not covered by the MSRV.

## License

MIT — see [LICENSE](LICENSE).
