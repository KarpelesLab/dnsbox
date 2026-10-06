# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.3](https://github.com/KarpelesLab/dnsbox/compare/v0.0.2...v0.0.3) - 2026-10-06

### Other

- Roadmap, changelog and security notes for the TKEY, draft-type and BIND round
- Interop corpus: keep BIND run 37396071664 (DH TKEY, draft types)
- BIND interop: Diffie-Hellman TKEY, TKEY text and the draft types
- Interop CI: BIND 9 (signing, zone tools, named, dig, nsupdate)
- dnspython cross-check: TKEY in dnspython's layout, older dnspython
- read BIND 9.18's relay-less type-0 form
- key agreement, deletion mode and dnspython's text form
- Type IPN, CLA, UNECE and ISO record data from their drafts
- :pad_to: refuse padding that cannot fit before writing it
- OwnedRData serde: read back class-specific data of other classes
- keep interleaved additional RRsets whole or set TC
- Zone lexer: a quote inside a token does not run past the line
- bound the templates like their expansion
- keep an included file's state after a bad $INCLUDE path
- :from_ds: disregard DS digest types we cannot compute
- :edns: reject an OPT record outside the additional section
- pad up to the limit minus the reserve
- reject empty blocks and trailing zero octets
- Interop corpus: no directory names ending in a dot
- knotd refuses TKEY unsigned; Knot 3.5 reads DSYNC only
- Roadmap, changelog and security notes for the known-gaps round
- Interop CI: new record types, TKEY and the default limits
- Interop with Knot DNS 3.5 and Unbound 1.19 in CI
- Clean docs in every feature combination; doctest every method
- Built-in work limits: ZoneLimits, ValidationBudget, bounded owned/serde/XFR
- Type AMTRELAY, DSYNC, TKEY, DOA, HHIT and BRID record data
- Check out text files with LF on every platform
- Milestone 9: roadmap, changelog, stability and MSRV policy
- sync Cargo.lock with dnsbox 0.0.2
- CERT example writes the algorithm as a mnemonic
- Enforce the documentation: clippy doc lints, stricter rustdoc in CI
- guided tour in the crate documentation
- stub resolver, zone file to wire, DNSSEC dig, TSIG AXFR
- `# Errors` sections and runnable examples on every public item
- Interop corpus: document every source in tests/corpus/README.md
- Interop corpus: dnspython RDATA, TSIG, UPDATE, EDNS and ZONEMD
- Interop corpus: BIND 9.18 and ldns zones, signers and named responses
- Interop corpus: live captures of more types, EDE, ECS, compact denial
- SIG/RRSIG text: accept a bare number as the type covered
- algorithm mnemonics as BIND and dnspython write them
- final threat model and audit report
- targets for the trust decisions, overflow checks in CI
- Security audit: fix signature, DNSSEC, ZONEMD and LOC findings

### Security

Findings of the post-1.0-review code review, each fixed with a
regression test:

- **High**: a malformed `$INCLUDE` path inside an `$INCLUDE`d file
  reset that file to its start, so `Records` never ended (or repeated the
  file's records up to the record limit). The file's state is kept and
  the error names the file.
- **Medium**: `TrustedKeys::from_ds` counted DS records of digest types
  it cannot compute (GOST R 34.11-2012, SM3) as usable. One such DS
  ahead of a matching SHA-256 one made a secure zone insecure, its
  presence dropped SHA-1 DS records (RFC 4509 §3), and a forged DNSKEY
  RRset whose key tag matched it came out insecure instead of bogus. Only
  SHA-1, SHA-256 and SHA-384 DS records count now; others are
  disregarded (RFC 4035 §5.2).
- **Medium**: `$GENERATE` rescanned its templates for every record, so a
  256 KiB `${000…0}` modifier cost about 20 s of CPU for one directive.
  Templates longer than 1024 characters are `LimitExceeded`.
- **Low**: a quote inside an unquoted token grouped everything up to the
  next quote, whole lines included, silently folding the records in
  between into one string. The grouping now ends at the line
  (`InvalidText`).
- **Low**: `copy_section` / `copy_message` treated only consecutive
  records as an RRset, so truncation could keep part of an interleaved
  additional-section RRset without setting TC. Its other parts are
  dropped too, or TC is set (bounded: 8 split RRsets, 65 536 record
  visits per section).
- **Low**: `DsoBuilder::pad_to` on a `Vec` wrote the whole padding (any
  size the caller asked) before checking it against the 65 535-octet
  limit; it now checks first.

Findings of the Milestone 9 security audit (`SECURITY.md`), each fixed
with a regression test in `tests/security_audit.rs`:

- **Medium**: ZONEMD collation and verification compared every apex
  ZONEMD record with every other (RFC 8976 §4 duplicate removal and
  tuple check), so a zone with tens of thousands of them took minutes of
  CPU to reject. Both now sort: O(n log n).
- **Low**: `tsig::find` and `sig0::find` (and so TSIG and SIG(0)
  verification) accepted octets after the signature record, which no MAC
  or signature covers, when the message was parsed lazily. They now
  return `Error::TrailingData` (answered with FORMERR).
- **Low**: an RRSIG whose labels field is smaller than the signer's label
  count was accepted, turning an answer into the expansion of a wildcard
  above the zone. Such signatures fail with `RrsetMismatch`, and
  `sign_rrset` refuses to produce them.
- **Low**: NSEC3 records with hashes shorter than the hash output (one
  octet, say) appeared to deny almost every name. Hashes of another length
  never match or cover; `Nsec3::covers` requires equal lengths.
- **Low**: a LOC altitude close to 2^63 cm in presentation format
  overflowed (a panic with overflow checks); it is now `InvalidText`.
- **Info**: `TrustedKeys` verified RRsets of another class than its keys;
  they are now `RrsetMismatch`.
- **Info**: denial proofs accepted a zone's apex as one of its own
  delegations, and the zone's own records as denying the DS at its apex;
  both are now `Bogus(ZoneCut)`.

Findings of the work-limits round (`SECURITY.md`): the work an attacker
controls is now bounded by library limits, on by default, instead of
caller duties.

- **Medium**: KeyTrap (CVE-2023-50387). `TrustedKeys` bounded each call
  to 16 verifications, but not a response, and tried every (RRSIG, key)
  pair. A `ValidationBudget` now bounds a whole response (the
  `*_with_budget` methods; 32 verifications by default), and each call
  tries at most 8 RRSIGs per RRset, 4 keys per RRSIG (key tag collisions)
  and the first 32 DNSKEYs (`ValidationLimits`).
- **Medium**: NSEC3 closest-encloser hashing (CVE-2023-50868): proofs
  hashed through `ValidationBudget::nsec3_hasher` stop at 64 hashes per
  budget, as `BogusReason::LimitExceeded`.
- **Medium**: one `$GENERATE` line yields up to 65 536 records, and
  `zone::parse` collected them without limit. `ZoneLimits` (on
  `ZoneReader`, `Records` and `zone::parse_with_limits`) caps records
  (1 000 000), records per `$GENERATE`, `$INCLUDE` depth and count, total
  input, line and token length by default.
- **Medium**: `FsIncludes` opened any path a zone file named (absolute
  paths, `..`, symbolic links, devices and FIFOs). `FsIncludes::new` is
  now confined to its directory and reads regular files only, within the
  input limit.
- **Low**: `OwnedMessage::from_message` reserved room for what the header
  counts claimed (some 70 MB for a 12-octet header); it now reserves what
  the message can hold.
- **Low**: `serde` read message sections of any length; it refuses more
  than 65535 entries while reading.
- `SECURITY.md` is the threat model: attacker model, guarantees, the
  work bound and default limit of every operation, every authentication
  check, the caller duties (one `ValidationBudget` per response, the
  confined `FsIncludes` or an own `IncludeResolver` for untrusted zone
  files, transfer limits for untrusted servers) and the audit findings.

### Added

- Typed RDATA for the last types that had a mnemonic but no format:
  AMTRELAY (RFC 8777, `Amtrelay` with `AmtrelayRelay`; relay types 4-127
  are kept and written in the RFC 3597 form), DSYNC (RFC 9859, `Dsync`
  and the `DsyncScheme` registry, `Dsync::is_usable`), TKEY (RFC 2930,
  `Tkey` and the `TkeyMode` registry, `Tkey::with_error`,
  `Tkey::is_valid_at`), HHIT and BRID (RFC 9886) and DOA
  (draft-durand-doa-over-dns, as BIND implements it), each with wire and
  presentation format, tested with the RFC examples and BIND's and
  dnspython's vectors.
- `tkey` module: `build_query`, `build_response` and `find` for the
  RFC 2930 §4 message shapes.
- Typed RDATA for the types only Internet-Drafts define: IPN and CLA
  (draft-johnson-dns-ipn-cla-07: `Ipn`, a 64-bit node number written as
  one number or two dotted halves; `Cla`, convergence-layer adapter
  names) and UNECE and ISO
  (draft-woodcock-faltstrom-external-registry-rrtypes-01: `Unece`, `Iso`,
  with `RegistryValue` and `Precision` for the value grammar), with wire
  and presentation format and the drafts' examples. Each names its draft
  version; a later one may change the format.
- TKEY key agreement and the rest of RFC 2930:
  - without features: `tkey::build_query_with_key`, `find_request` and
    `find_answer` (enforcing §3/§4: one TKEY record, its section and
    owner; `Error::InvalidTkey`, answered FORMERR), `keys`, key deletion
    (`build_deletion_query`, `build_deletion_response`,
    `push_deletion_notice`, `find_deletion`), and the RFC 2539
    Diffie-Hellman KEY format (`DhKey`, `DhPrime`, `well_known_prime`:
    groups 1, 2 and BIND's 3);
  - with the new `tkey` feature (purecrypto DH, RSA and MD5; implies
    `alloc` and `tsig`): Diffie-Hellman exchanged keying (§4.1:
    `DhGroup`, `DhKeyPair::build_query` / `respond` / `complete`,
    `dh_keying_material`), server and resolver assigned keying (§4.4,
    §4.5, RSAES-PKCS1-v1_5 with implicit rejection:
    `respond_server_assigned`, `server_assigned_key`,
    `build_resolver_assigned_query`, `accept_resolver_assigned`,
    `resolver_assigned_key`, `encrypt_keying_material`,
    `decrypt_keying_material`, `rsa_public_key`, `MAX_ENCRYPTED_BLOCKS`),
    all yielding a `SharedKey` (wiped on drop, `hmac_key()` for TSIG)
    under a `KeyGrant`; `tkey::purecrypto` re-exports the crate for its
    RSA key and RNG types. GSS-API (RFC 3645) is out of scope.
- TKEY presentation format reads dnspython's form (without the key and
  other-data sizes) as well as BIND's, which `Display` still writes.
- `Error::MisplacedOpt` and `Error::InvalidTkey`.
- Tool-level interop with BIND 9.18 in CI (`.github/workflows/interop.yml`,
  `tests/corpus/bind/run.sh`, the `bind_probe` example): zones signed by
  `dnssec-signzone` with every algorithm BIND supports (NSEC, NSEC3,
  Opt-Out) that dnsbox verifies and re-signs to BIND's bytes, BIND's
  checkers and `named-compilezone` on dnsbox's zones, `named` serving
  dnsbox's text of every type (draft-only types in the RFC 3597 form),
  `dig` (EDNS, cookies, TSIG with six HMACs, transfers, truncation),
  `nsupdate` (TSIG and SIG(0)), a Diffie-Hellman TKEY exchange with
  `named` whose key signs a query and deletes itself, and 116 validating
  resolver cases whose verdicts dnsbox must match;
  `tests/interop_bind.rs` checks a kept subset offline. The dnspython
  cross-check rewrites dnsbox's TKEY text to dnspython's layout instead
  of skipping it, and runs on the CI runner's older dnspython.
- Work limits: `Error::LimitExceeded`; `ZoneLimits` with
  `ZoneReader::with_limits`, `Records::with_limits` and
  `zone::parse_with_limits`; `IncludeResolver::load_limited` (a default
  method) and `FsIncludes::unconfined`; `ValidationBudget`,
  `ValidationLimits`, `TrustedKeys::from_ds_with_budget`,
  `from_anchors_with_budget`, `verify_rrset_with_budget`,
  `verify_answer_with_budget`, `ValidationBudget::nsec3_hasher` and
  `BogusReason::LimitExceeded`; `XfrProcessor::with_max_records` and
  `with_max_messages` (opt-in).
- Tool-level interop with Knot DNS 3.5 and Unbound 1.19 in CI
  (`.github/workflows/interop.yml`, `tests/corpus/knot/run.sh`):
  Knot-signed zones for six algorithms and three denial chains, `knotd`
  and `kdig` exchanges (EDNS, TSIG with six HMACs, AXFR/IXFR, UPDATE,
  JSON), the `interop_probe` example's own queries (TKEY included), 96
  Unbound validation cases whose verdicts dnsbox must match within the
  default `ValidationBudget`, Knot's reading of dnsbox's text of every
  type, and dnsbox-signed zones checked by `kzonecheck`, ldns and BIND;
  `tests/interop_knot.rs` checks a kept subset offline.
- Every public item has a doctest example (the nightly
  `rustdoc::missing_doc_code_examples` lint is denied in CI), and
  intra-doc links resolve in every feature combination (CI checks the
  feature powerset with `cargo hack`: build, clippy, docs, and every
  `no_std` combination for Cortex-M).
- Documentation (Milestone 9): an `# Errors` section on every fallible
  public function and a runnable example on every public module, type,
  trait and free function and on the main methods, using RFC test vectors
  and real captures; a guided tour in the crate documentation (parse,
  iterate, typed RDATA, build, EDNS, truncation, TCP framing, zone files,
  DNSSEC, TSIG); the stability and MSRV policy in `README.md`.
- Example programs (`examples/`, with `required-features`):
  `stub_resolver` (UDP with EDNS, TCP fallback on truncation, `dig`-style
  output), `zone2wire` (zone file to the AXFR message stream and back),
  `dnssec_dig` (validates real captures from the IANA root anchor) and
  `tsig_axfr` (a TSIG-signed AXFR over loopback or from a real server).
- SIG and RRSIG presentation format accept a bare number as the type
  covered, as BIND writes it (`SIG 0 ...`).
- CERT presentation format reads BIND's and dnspython's spellings of the
  algorithm.
- Fuzzing: four targets for the trust decisions (`denial`, `dnssec`,
  `sign`, `zone`), and the `rdata` target checks that every type
  re-encodes to the exact octets it was parsed from; all targets run with
  overflow checks (`-a`), in CI too.
- Interop corpus (Milestone 8): 175 messages (from 52), with live captures
  of more types (SVCB with dohpath, CAA, TLSA, URI, CDS/CDNSKEY, ZONEMD),
  Extended DNS Errors, Client Subnet and compact denial; zone files,
  signed zones for all eight algorithms (NSEC, NSEC3, Opt-Out) and 96
  local `named` responses from BIND 9.18; ldns-rewritten and ZONEMD-signed
  zones; 139 dnspython RDATA examples, TSIG with nine HMACs, UPDATE, EDNS
  and ZONEMD; DNSSEC validation of the captures from the IANA root
  anchors; an ignored test that verifies a full root zone (ZONEMD and
  every RRSIG). `tests/corpus/README.md` documents every source.

### Changed

- **Breaking**: AMTRELAY, DSYNC, TKEY, DOA, HHIT, BRID, IPN, CLA, UNECE
  and ISO parse to their new `RData` variants instead of
  `RData::Unknown`, and display in their presentation format instead of
  the RFC 3597 form.
- **Breaking**: type bitmaps (NSEC, NSEC3, CSYNC: `TypeBitmap::new`)
  with a block that ends in a zero octet (an empty block, or trailing
  zero octets, RFC 4034 §4.1.2) are `InvalidRdata`; they gave one type
  set several encodings that compared unequal and changed on a text
  round trip.
- **Breaking**: `Message::edns` (and so `start_response_edns` and
  `effective_rcode`) walks every section and returns
  `Error::MisplacedOpt` for an OPT record in the answer or authority
  section (RFC 6891 §6.1.1), which it used to ignore (`Ok(None)`).
- **Breaking**: a quote inside an unquoted presentation-format token
  groups only up to the end of its line; an unescaped newline before the
  closing quote is `InvalidText`.
- **Breaking**: a `$GENERATE` template longer than 1024 characters is
  `LimitExceeded`.
- `push_edns_padded` pads up to the size limit minus the reserve
  (`set_reserve`), leaving room for a TSIG or SIG(0) record, instead of
  failing with `BufferTooSmall`.
- `copy_section` / `copy_message` keep an RRset whose records are not
  consecutive whole: dropped altogether from the additional section, or
  TC set.
- `OwnedRData` deserialization also accepts the opaque data its
  serialization writes for a class-specific type of another class than
  IN.
- `Error::BadKey` also stands for TKEY error BADKEY.
- The `bind_probe` example needs the `tkey` feature.
- **Breaking**: `zone::parse`, `ZoneReader` and `Records` apply
  `ZoneLimits::DEFAULT`; going over a limit is `Error::LimitExceeded`
  (`ZoneLimits::UNLIMITED` for trusted files; it keeps the `$INCLUDE`
  depth at 8). Too deep or too many `$INCLUDE`s are now `LimitExceeded`
  instead of `BadInclude`.
- **Breaking**: `FsIncludes::new` serves only regular files inside its
  directory; `FsIncludes::unconfined` keeps the previous, BIND-like
  behaviour for trusted files.
- **Breaking**: `TrustedKeys` calls cut short by a limit return
  `Error::LimitExceeded` instead of `BadSignature`, and look at no more
  RRSIGs, keys per RRSIG and DNSKEYs than `ValidationLimits` allow. The
  methods without a budget use a fresh default one per call.
- `ValidationBudget` is `Send` but not `Sync` (it counts in `Cell`s so
  that one budget is shared by reference across the calls of a
  response), the one exception to the crate's `Send + Sync` types.
- The documentation of `CharStr::compose` says that the length octet can
  be written when the buffer is too small for the rest.
- CERT `Display` writes the algorithm as a mnemonic (`RSASHA256`,
  `ECDSAP256SHA256`, `ED25519`, ...) where IANA, BIND and dnspython agree,
  and as a number otherwise; it used to always write a number.
- `tsig::find`, `sig0::find`, RRSIG checks, `Nsec3::covers`, `TrustedKeys`
  and the denial proofs reject the inputs listed under Security.
- Clippy's `missing_errors_doc` and `missing_panics_doc` lints are
  enforced, and the CI docs builds deny `missing_docs`,
  `rustdoc::private_doc_tests` and `rustdoc::unescaped_backticks`; CI also
  runs the `alloc`-only doctests and the offline examples.

### Fixed

- AMTRELAY presentation format reads BIND 9.18's relay-less type-0 form
  (`0 0 0`) as well as RFC 8777's `0 0 0 .`, which it still writes.
- `TrustedKeys::from_ds`, `Records` with `$INCLUDE`, `$GENERATE`, the
  zone lexer, `copy_section` and `DsoBuilder::pad_to`: see Security.
- `push_edns_padded` failed whenever a reserve was set (Maximal padding
  always, block padding near the limit), against its documentation.
- `OwnedRData`'s serde form of a class-specific type held in another
  class than IN did not deserialize.

## [0.0.2](https://github.com/KarpelesLab/dnsbox/compare/v0.0.1...v0.0.2) - 2026-10-04

### Other

- Drop #[must_use] where newer clippy treats the return type as must_use
- API review: Display/FromStr pairs, Copy RData, documented conventions
- API review: one error policy, documented features and conventions
- API review: #[must_use] on pure functions and iterator types
- API review: non_exhaustive where growth is expected, seal DenialProof
- API review: common traits, iteration by reference, Send/Sync checks
- API review: consistent naming for registries, buffers and records
- sync Cargo.lock with dnsbox's optional serde dependency
- build fuzz targets for the gnu target
- Wire the zone-file parser into the owned types and serde; reject SVCB key 65535
- before/after benchmarks, decoder cache and compression trie
- Builder hot path: label-trie compression table, leaner record writes
- Parse hot path: tight name decoder, suffix cache in the record iterators
- Document the chain of trust, denial proofs and ZONEMD
- Add ZONEMD zone digest computation and verification (RFC 8976)
- Add DNSSEC denial-of-existence proofs and the chain of trust
- Add owned message types, dig-style message display and serde support
- Add presentation-format parsing for DNSSEC, TSIG and remaining types
- Parse the presentation format of LOC, ILNP, EUI, CSYNC, ZONEMD, APL, IPSECKEY, HIP and legacy types
- Add presentation-format parsing for batch-A and RFC 1183 record types
- Document text parsing: the ParseRdataText recipe and zone files
- Add presentation-format and master-file parsing (RFC 1035 §5)
- roadmap, changelog, README and architecture for the integrated state
- Wire cross-branch seams: EDNS response echo, SIG(0) over the DNSSEC backend, typed algorithms, fuzzing of the new protocols
- Deduplicate after integration: one SIG type, one signature error, shared decoders
- Document the assurance infrastructure
- Add criterion benchmarks against hickory-proto and domain
- Add an interop corpus of real DNS responses
- Add property tests and an allocation-free hot path test
- Add cargo-fuzz targets with shared property checks and seed corpora
- Integrate feat/tsig: module order after merge
- sign_buf interop test without the alloc feature
- Milestone 6 polish: UPDATE section aliases, ARCHITECTURE notes, CI no_std+tsig build
- DSO (RFC 8490): message view, TLV iteration and validation, builder, Keepalive/Retry Delay/Encryption Padding TLVs
- AXFR/IXFR (RFC 5936, RFC 1995): query builders and a streaming response processor
- NOTIFY (RFC 1996): query/response builders and parsed view
- Dynamic UPDATE (RFC 2136): builder for every prerequisite/update form, classified parsed view
- SIG(0) (RFC 2931): signed data construction, signing, verification
- protocol tests with a stand-in MAC, refuse to generate sub-floor MACs
- TSIG (RFC 8945): RDATA, MAC input, signing/verification, HMAC backend
- *(0)* OPT record, option registry, typed options, padding, cookies
- Add SVCB and HTTPS record data (RFC 9460)
- Milestone 4 batch B: LOC, RFC 1183 types, ILNP, EUI, CSYNC, ZONEMD, APL, IPSECKEY, HIP and legacy types
- Typed RDATA batch A: SRV, NAPTR, CAA, SSHFP, TLSA, SMIMEA, OPENPGPKEY, DNAME, URI, CERT, DHCID
- document the wildcard caveat of verify_rrsig
- O(n log n) canonical RRset sort, hostile-input tests, docs
- RFC example vectors, real signed captures, sign/verify round trips
- record types, registries, canonical form, key tags, DS/NSEC3 digests, RRSIG flows
- truncation, query/response constructors, raw records, TCP framing
- wire primitives, names, message views, RDATA registry, builder

### Breaking changes (1.0 API review)

The Milestone 9 API review renamed and tightened parts of the public API.
Every change that can break a caller is listed here:

- `Opcode::name` and `Rcode::name` are renamed `mnemonic`, as on every
  other registry newtype (they also gain `from_mnemonic`, `FromStr` and
  `Default`).
- `WireWriter::written` is renamed `as_bytes` (the `OutBuf` name, now
  also inherent, as on every other buffer type).
- `edns::Opt::as_bytes`, `OwnedRData::as_bytes` and `TsigAlgorithm::wire`
  are renamed `as_wire`: `as_wire` is the wire form of a structured value
  (pairing with `from_wire`), `as_bytes` the contents of a buffer or an
  opaque field.
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
- `#[must_use]` on the pure functions and methods (constructors,
  accessors, conversions, `with_*` builders) and on the iterator types:
  ignoring their result is now a warning.
- `Error::MalformedUpdate`, `MalformedXfr` and `MalformedDso` are renamed
  `InvalidUpdate`, `InvalidXfr` and `InvalidDso`: one `Error` for the
  whole crate, with `Invalid*` for malformed input (as `InvalidRdata`,
  `InvalidText`, `InvalidOption`) and `Bad*` for failed checks.

### Added

- API review (Rust API Guidelines): `IntoIterator` for references to the
  collection-like views (`&CharStrs`, `&TypeBitmap`, `&HipServers`,
  `&SvcParams`, `Apl`/`&Apl`, `Dau`/`Dhu`/`N3u` and references);
  `Display` for `Section` (`ANSWER`, ...); `Hash` for `XfrStyle`,
  `sig0::Validity` and `ZoneError`; `ZoneError` implements
  `core::error::Error` without `std`; `tests/api.rs` checks that the
  public types are `Send + Sync` and implement the common traits.
- `Copy` and `Hash` for `RData` and `EdnsOption` (every typed view already
  was).
- `FromStr` for `dnssec::Nsec3Hash` (base32hex) and `tsig::TsigAlgorithm`
  (algorithm name), the inverses of their `Display`.
- `From<ZonemdFailure> for Error` (and `ZonemdFailure::source`), so ZONEMD
  verification composes with `?` like every other error of the crate.
- Crate documentation: the Cargo features table, the error policy and
  the API conventions.
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
  `BadTrunc`, `Unsigned`, `TsigErrorResponse`, `InvalidUpdate`,
  `InvalidXfr`, `ErrorResponse`, `InvalidDso`.
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
