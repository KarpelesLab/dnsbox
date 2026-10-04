# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial scaffold: DNS header parsing and encoding (`Header`, `Flags`,
  `Opcode`, `Rcode`).
- Foundation (RFC 1035, 3596, 3597, 4343): bounds-checked `WireReader` /
  `WireWriter` / `Composer`, open `Rtype` / `Class` newtypes with the full
  IANA registries and text mnemonics, hardened name decompression (`Name`,
  `NameBuf`, canonical order, case-insensitive equality), zero-copy
  `Message` views with lazy section iterators and `validate`, typed RDATA
  registry (`RData`, `ParseRdata`, `ComposeRdata`) with the RFC 1035 types
  and AAAA, and `MessageBuilder` with allocation-free name compression.
- Builder (Milestone 2): RRset-level truncation with `Truncation::Error` /
  `SetTc` policies and a reserve for OPT/TSIG (RFC 2181 §9);
  `copy_section` / `copy_message`; `start_query` / `start_response`,
  `response_flags`, `set_rcode`, `MessageBuilder::query` / `response`
  (and `_vec` variants); `push_raw_records`; `new_vec_with_capacity`;
  length-prefixed TCP builders (`new_tcp`, `new_tcp_vec`, `from_buf_tcp`).
- `tcp` module (RFC 1035 §4.2.2, RFC 7766): length-prefix helpers, frame
  splitting and iteration, allocation-free `FrameReassembler`, and
  `read_message` / `write_message` with `std`.
- EDNS(0) (RFC 6891, `edns` module): `Opt` view, `OptHeader` / `EdnsFlags`,
  `Message::edns()` and `Message::effective_rcode()`, the full IANA
  `OptionCode` registry and typed options: NSID, DAU/DHU/N3U, Padding,
  Client Subnet, Cookie (plus RFC 9018 `ServerCookie`; SipHash-2-4 behind
  the `cookie-siphash` feature), TCP keepalive, Extended DNS Errors, Chain,
  Key tag, Expire, Zone version, Report-Channel; unknown options pass
  through. Builder: `push_edns`, `push_edns_padded` with RFC 8467
  `PaddingPolicy`, and the response echo `start_response_edns` /
  `push_reserved_edns` (`OptHeader::response_to`).
- Record types: SRV, NAPTR, CAA, SSHFP, TLSA, SMIMEA, OPENPGPKEY, DNAME, URI,
  CERT, DHCID, LOC, RP, AFSDB, X25, ISDN, RT, NID/L32/L64/LP, EUI48/EUI64,
  CSYNC, ZONEMD, APL, IPSECKEY, HIP, KX, GPOS, NSAP, NSAP-PTR, PX, A6, NXT,
  EID, NIMLOC, ATMA, SINK, NINFO, RKEY, TALINK, SPF, AVC, RESINFO and
  WALLET, each with presentation-format `Display`, with new open
  registries (`SshfpAlgorithm`, `SshfpFpType`, TLSA fields, `CertType`,
  `IpseckeyAlgorithm`, `ZonemdScheme`, `ZonemdHashAlg`).
- SVCB and HTTPS (RFC 9460): `SvcParamKey` registry, validated `SvcParams`
  view with typed values for every registered key (mandatory, alpn,
  no-default-alpn, port, ipv4hint, ech, ipv6hint, dohpath, ohttp,
  tls-supported-groups, docpath, pvd, oots), `SvcbBuilder`, and
  presentation-format parsing (`Svcb::from_text`, `Https::from_text`).
- DNSSEC (`dnssec` module, RFC 4034, 4035, 5155, 6840, 7344, 8078): DNSKEY,
  CDNSKEY, KEY, DS, CDS, DLV, TA, RRSIG, SIG, NSEC, NSEC3, NSEC3PARAM;
  `Algorithm`, `DigestType`, `Nsec3HashAlgorithm` registries; RFC 1982
  serial arithmetic and `Timestamp`; key tags; RFC 3110 RSA keys;
  allocation-free `CanonicalRrset`; DS digest input; RRSIG signed data,
  wildcard handling and checks (`check_rrsig`, `verify_rrsig`,
  `sign_rrset`); pluggable `Verifier` / `Signer` traits. Features
  `dnssec-digest` (DS digests, NSEC3 hashing) and `dnssec` (RSA, ECDSA
  P-256/P-384, Ed25519, Ed448 verification and signing via purecrypto).
- TSIG (RFC 8945, `tsig` module): TSIG RDATA and `TsigRcode`, MAC input,
  `TsigSigner` (requests, responses, streams), `verify_request` /
  `Rejected::sign_response`, `TsigVerifier`, pluggable `TsigKey` / `TsigMac`;
  `HmacKey` (HMAC-MD5/SHA-1/SHA-224/256/384/512 and truncated variants)
  behind the `tsig` feature.
- SIG(0) (RFC 2931, `sig0` module): `SignedData`, `sign`, `find`, `verify`,
  `Validity`, `Sig0Signer` / `Sig0Verifier`, and `DnssecSig0Signer` /
  `DnssecSig0Verifier` adapters over the DNSSEC backend (`alloc`).
- Dynamic UPDATE (RFC 2136, `update`), NOTIFY (RFC 1996, `notify`),
  AXFR/IXFR (RFC 5936, RFC 1995, `xfr`: query builders and the streaming
  `XfrProcessor`) and DNS Stateful Operations (RFC 8490, `dso`).
- New `Error` variants: `MessageTooLong`, `InvalidOption`, `DuplicateOpt`,
  `OptNotRoot`, `UnsupportedAlgorithm`, `InvalidKey`, `BadSignature`,
  `SignatureExpired`, `SignatureNotYetValid`, `KeyMismatch`,
  `RrsetMismatch`, `MisplacedSignature`, `BadMacSize`, `BadKey`, `BadTime`,
  `BadTrunc`, `Unsigned`, `TsigErrorResponse`, `MalformedUpdate`,
  `MalformedXfr`, `ErrorResponse`, `MalformedDso`.
- Optional dependency on `purecrypto` 0.9 (`default-features = false`) for
  all cryptography; dnsbox implements none itself.
- Assurance: cargo-fuzz targets (`edns`, `message`, `name`, `rdata`,
  `roundtrip`, `text`) with seeds replayed on stable, property tests, an
  interop corpus of real responses (BIND, NSD, Knot, PowerDNS, Unbound,
  Knot Resolver, public resolvers), BIND 9.18 interop tests for TSIG,
  SIG(0), UPDATE and XFR, an allocation-free hot-path test, and criterion
  benchmarks against hickory-proto and domain (`BENCH.md`).
