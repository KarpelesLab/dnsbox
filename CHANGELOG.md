# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking changes (1.0 API review)

The Milestone 9 API review renamed and tightened parts of the public API.
Every change that can break a caller is listed here:

- `Opcode::name` and `Rcode::name` are renamed `mnemonic`, as on every
  other registry newtype (they also gain `from_mnemonic`, `FromStr` and
  `Default`).
- `WireWriter::written` is renamed `as_bytes` (the `OutBuf` name, now
  also inherent, as on every other buffer type).
- `edns::Opt::as_bytes` and `OwnedRData::as_bytes` are renamed `as_wire`:
  `as_wire` is the wire form of a structured value (pairing with
  `from_wire`), `as_bytes` the contents of a buffer or an opaque field.
- `dnssec::ZoneRecord` (the input of ZONEMD collation) is renamed
  `dnssec::ZonemdRecord`, so it no longer shares its name with
  `zone::ZoneRecord`.
- The owner-name field of `zone::ZoneRecord`, `zone::ZoneRecordBuf` and
  `dnssec::ZonemdRecord` is renamed from `owner` to `name`, as in
  `OwnedRecord`, `OwnedQuestion` and `Record::name`.
- `xfr::XfrProcessor::messages` and `records` are renamed
  `message_count` and `record_count` (`records` returns an iterator
  everywhere else).
- `tsig::TsigVerifier::finish` takes `self`: it ends the stream.
- The `builder::compress` module is private; its tuning constants
  (`CAPACITY`, `MAX_PROBES`) are implementation details, described in the
  `builder` documentation.
- `#[non_exhaustive]` on the enums that may gain variants
  (`zone::Entry`, `xfr::XfrEvent`, `rdata::IpseckeyGateway`) and on the
  result structs the library produces (`zone::ZoneRecord`, `zone::Include`,
  `zone::ZoneRecordBuf`, `dnssec::Verified`, `dnssec::ZonemdVerified`,
  `dnssec::ClosestEncloser`, `tsig::TsigRecord`, `sig0::Sig0Record`): match
  them with a wildcard arm, and read their fields rather than building
  them with struct literals.
- `dnssec::DenialProof` is sealed: only `NsecProof` and `Nsec3Proof` (and
  references to them) implement it.


### Added

- API review (Rust API Guidelines): `IntoIterator` for references to the
  collection-like views (`&CharStrs`, `&TypeBitmap`, `&HipServers`,
  `&SvcParams`, `Apl`/`&Apl`, `Dau`/`Dhu`/`N3u` and references);
  `Display` for `Section` (`ANSWER`, ...); `Hash` for `XfrStyle`,
  `sig0::Validity` and `ZoneError`; `ZoneError` implements
  `core::error::Error` without `std`; `tests/api.rs` checks that the
  public types are `Send + Sync` and implement the common traits.
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
- Presentation-format parsing (RFC 1035 §5.1, RFC 3597 §5): the
  `ParseRdataText` trait implemented by every registered record type (NULL
  and OPT take only the generic `\# <length> <hex>` form, which every type
  accepts), `RData::parse_text` / `RData::from_text` /
  `RData::text_to_wire`, and the reusable `zone::Scanner` field readers
  (numbers, TTL units, DNSSEC timestamps, names relative to an origin,
  character-strings, hex, base64, base32hex, type bitmaps).
- Master files (`zone` module, RFC 1035 §5, RFC 2308 §4): the
  allocation-free streaming `ZoneReader` (quotes, escapes, parentheses,
  comments, blank owners, `@`, `$ORIGIN`, `$TTL`, BIND's `$GENERATE`,
  `$INCLUDE` reported as an `Entry`), errors with line and column and
  recovery to the next entry; with `alloc`, the `Records` iterator with
  `IncludeResolver` (bounded depth and count; `FsIncludes` with `std`),
  `ZoneRecordBuf` and `zone::parse`.
- Owned types (`alloc`): `OwnedMessage`, `OwnedQuestion`, `OwnedRecord`
  and `OwnedRData` (uncompressed wire RDATA with the typed view decoded on
  demand), converted from the views and written back through the builder;
  from text with `OwnedRData::from_text`, `OwnedRecord`'s `FromStr` (one
  master-file entry) and `From<ZoneRecord>` / `From<ZoneRecordBuf>`.
- `dig`-style `Display` for `Message` and `OwnedMessage` (no allocation):
  header and flags lines with `dig`'s warnings, the OPT pseudosection in
  `dig` 9.18's option formats, the sections in BIND's columns and the
  TSIG / SIG(0) pseudosections; checked against real `dig` output.
- Optional `serde` feature (`no_std`): registries as mnemonics (integers in
  compact formats), names as presentation strings, `Flags`, and the owned
  types, whose RDATA is written in the RFC 3597 generic form and read in
  that form, in the type's presentation format or as bytes.
- Authenticated denial of existence (`dnssec::denial`): `NsecProof` and
  `Nsec3Proof` (RFC 4035 §5.4, RFC 5155 §8, RFC 6840 §4, RFC 7129) for
  NXDOMAIN, NODATA, empty non-terminals, wildcard answers and NODATA and
  insecure delegations, returning `DenialStatus` (Secure / Insecure /
  Bogus with a reason); Opt-Out is insecure (RFC 5155 §9.2); RFC 9276
  iteration limits (`Nsec3Limits`) are checked before any hashing.
- Chain of trust (`dnssec::chain`): `TrustedKeys` authenticates a DNSKEY
  RRset from a DS RRset or trust anchors, verifies RRsets and wildcard
  answers with their denial proof, never uses revoked keys, and caps the
  signature work per call (`MAX_CRYPTO_OPERATIONS`, KeyTrap).
- ZONEMD (RFC 8976, `dnssec::zonemd`): `ZoneCollation` for the SIMPLE
  scheme, SHA-384/SHA-512 digests via purecrypto and verification per
  §4; all RFC 8976 Appendix A examples reproduce.
- New `Error` variants: `NoTextFormat`, `MissingTtl`, `BadInclude`.

### Changed

- Faster parsing and building, with the same results and hardening
  (`BENCH.md`): a tighter name decoder with a suffix cache in the record
  iterators, single-check fixed-field parsing, and a label-trie name
  compression table checked against the message bytes. dnsbox is now
  faster than `domain` and `hickory-proto` on every benchmark.
- `MessageBuilder::new_vec()` starts with 512 bytes of capacity;
  `MAX_PROBES` now limits only wrong compression candidates per name.
- SVCB/HTTPS: the reserved SvcParamKey 65535 ("Invalid key", RFC 9460
  §14.3.2) is refused in wire RDATA too, as it already was in
  presentation text and by `SvcbBuilder`.
- SVCB/HTTPS `from_text` reports a missing priority or target as
  `UnexpectedEof` instead of `InvalidText`.
