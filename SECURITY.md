# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[security advisory form](https://github.com/KarpelesLab/dnsbox/security/advisories/new)
rather than opening a public issue.

## Threat model

`dnsbox` is written for an attacker who controls the bytes it is given:

- **DNS messages** from the network (UDP datagrams, TCP streams), in any
  role: queries reaching a server, responses reaching a client or
  resolver, zone transfers, dynamic updates, DSO sessions;
- **presentation-format text**: master (zone) files and their
  `$INCLUDE`d parts, record text, and the human-readable `serde` forms;
- **DNSSEC, TSIG and SIG(0) material**: arbitrary keys, signatures,
  NSEC/NSEC3 chains and ZONEMD records, including validly signed but stale
  or contradictory records replayed from elsewhere, and messages forged or
  altered on the path.

The attacker wins if they can crash the process, read or corrupt memory,
make it spend work out of proportion to their input, or get data accepted
as authenticated (or a negative answer accepted as proven) that the
signer did not vouch for.

Out of scope: denial of service by volume (the caller decides how much
input to accept; dnsbox bounds what one input can cost), side channels of the private-key operations in
`purecrypto` (signing is done on the caller's own data), and what a
holder of a zone's keys can sign about that zone's own names (DNSSEC
trusts the zone for them; dnsbox still rejects records no correct signer
produces, as defence in depth).

## What dnsbox guarantees

### Memory safety and no panics

- dnsbox is `#![forbid(unsafe_code)]`. (Its optional `purecrypto`
  dependency has its own policy; dnsbox only calls its safe API.)
- No input makes a public function panic: parsers, iterators, `Display`,
  builders, presentation-format and zone-file parsing, DNSSEC, TSIG and
  SIG(0) checks all return an `Error` (or a `DenialStatus`) instead. Slices
  are read with checked accessors, arithmetic on lengths and counts cannot
  overflow, and this also holds with overflow checks on (debug builds);
  the fuzzers run with them.
- Buffers larger than a DNS message (a whole read buffer passed to
  `Message::parse`) are handled like any other input.

### Bounded work

Every operation does work proportional to its input, with these limits.
Where an input could make dnsbox work or allocate out of proportion to
its size (`$GENERATE`, `$INCLUDE`, colliding DNSSEC keys, NSEC3 proofs for
deep names), the bound is a library limit that is **on by default** and
that callers can raise for trusted input; going over it is
`Error::LimitExceeded` (or `BogusReason::LimitExceeded` for a denial
proof), never unbounded work.

| Area | Bound |
|------|-------|
| Name decompression | pointers must point strictly before the labels they end (no loops, no forward or self pointers), at most 128 hops, 255 octets and 127 labels per name; the record iterators' suffix cache never skips a check |
| Message iteration | linear in the message; `answers()` / `additional()` re-skip the earlier sections once per call (use `records()` to walk everything in one pass) |
| Building | name compression verifies one table entry per label and at most 32 false candidates per name (the table holds 128 labels); messages stop at 65535 octets; RDLENGTH and section counts are never truncated (`BufferTooSmall`, `CountOverflow`) |
| Presentation text | linear in the text; parentheses nest at most 16 deep |
| Zone files | linear in the text, within `ZoneLimits` (defaults): at most 1 000 000 records in all (`$GENERATE`d and `$INCLUDE`d ones included; the reader then stops), 65 536 per `$GENERATE` directive (`MAX_GENERATE`) of at most 1024 characters each, `$INCLUDE` 8 deep and 256 files, 256 MiB of text in all files together, lines of 1 MiB and tokens of 256 KiB; errors carry line and column |
| `$INCLUDE` from files | `FsIncludes::new` serves only regular files inside its directory: relative paths without `..`, root or drive prefix, and no symbolic link leading out (checked on the canonical path); no devices or pipes (both constructors), and never more than the input limit left (read with a bound, not after the fact) |
| Canonical RRsets | heapsort in the output buffer: O(n log n) comparisons, no allocation |
| `TrustedKeys` (chain of trust) | a `ValidationBudget` (KeyTrap, CVE-2023-50387): per call at most 8 RRSIGs over the RRset's type, 4 keys per RRSIG (key tag collisions), the first 32 DNSKEYs and 16 signature verifications and DS digests (`MAX_CRYPTO_OPERATIONS`), plus one key-tag computation per (RRSIG, key) pair looked at; per budget (one per response, `*_with_budget`) at most 32 verifications and DS digests in all. All configurable (`ValidationLimits`) |
| Signature backend | RSA moduli of 512–4096 bits (1024–4096 for RSASHA512) and public exponents of at most 256 bits; ECDSA points must be on the curve |
| NSEC proofs | a constant number of passes over the records |
| NSEC3 proofs | at most one hash per label of the name plus one wildcard, each after the iteration count was checked against `Nsec3Limits` (default: insecure above 100, bogus above 500, RFC 9276); one pass over the records per hash; with `ValidationBudget::nsec3_hasher`, at most 64 hashes per budget across all checks (CVE-2023-50868) |
| ZONEMD | collation and verification in O(n log n), however many apex ZONEMD records there are |
| TSIG streams | at most 99 unsigned messages in a row |
| Zone transfers | constant state per transfer, linear work per message; `XfrProcessor::with_max_records` / `with_max_messages` bound the stream (no default: zones range from one record to millions) |
| Owned messages | `OwnedMessage::from_message` reserves no more entries than the message can hold, whatever its header counts claim; `serde` refuses sections of more than 65535 entries while reading them, and RDATA of more than 65535 octets |

### Strict parsing and one encoding per value

- Malformed input is rejected, not repaired: wrong lengths, octets left
  over inside RDATA, oversized labels and names, compression pointers
  where RFC 3597 §4 forbids them, reserved label types, out-of-range
  fields (ECS prefixes and address bits beyond them, LOC coordinates,
  cookie lengths, ...).
- Every record type parses to a value that re-encodes to exactly the
  octets it came from (when they contain no compression pointer). DNSSEC
  signs the re-encoded form of parsed records, so a signature can never
  vouch for a different encoding of the data (checked by the `rdata`
  fuzzer).
- `Message::parse` is lazy and ignores octets after the last record;
  `Message::parse_validated` and `Message::validate` reject them
  (`TrailingData`), and so does every signature check (below).

### Authentication checks

- **TSIG** (RFC 8945): the record must be the last of the message, with
  nothing after it, CLASS ANY and TTL 0; key name **and** algorithm must
  match a configured key (no algorithm substitution); the MAC must be
  between max(10, half the digest) octets and the full digest, and is
  compared in constant time by `purecrypto`; the time window is checked
  after the MAC; MACs shorter than the key's policy are BADTRUNC. Responses
  and streams chain from the request MAC; unsigned error responses are
  reported, never accepted.
- **SIG(0)** (RFC 2931): last record, nothing after it, owner root, CLASS
  ANY, TTL 0, labels and original TTL 0; validity window in serial
  arithmetic; the KEY must match signer name, algorithm and key tag.
- **RRSIG** (RFC 4035 §5.3): the signer is the key's owner and the zone,
  the RRset owner is in the zone, the labels field lies between the
  signer's and the owner's label counts (a wildcard expansion is always
  from a wildcard inside the zone), validity window in serial arithmetic,
  algorithm and key tag match, protocol 3, Zone Key flag set, every
  record of the RRset of the type covered; `TrustedKeys` also never uses
  revoked keys (RFC 5011) and only verifies RRsets of its own class.
- **DS / chain of trust**: digests of unsupported types are ignored, SHA-1
  ones too when a stronger digest is present (RFC 4509 §3); no usable DS
  means insecure, never secure.
- **Denial of existence** (RFC 4035 §5.4, RFC 5155 §8, RFC 6840 §4,
  RFC 7129): records from the parent side of a zone cut or at a DNAME
  never deny names below them; parent-side records deny nothing but DS;
  child-apex records never deny DS; a zone's apex is never its own
  delegation; NSEC3 records must agree on parameters and have hashes of
  the hash function's length (a short hash covers nothing); Opt-Out and
  over-limit iteration counts give `Insecure`, never `Secure`; a spent
  hash budget gives `Bogus`, never `Insecure` or `Secure`.
- **Work limits** never turn a failure into a success: a limit reached
  before a valid signature is found is `Error::LimitExceeded`, which a
  validator treats like bogus (SERVFAIL), not as insecure; a valid
  signature found within the limits is accepted as before.
- **ZONEMD** (RFC 8976 §4): SOA and ZONEMD serials, unique (scheme,
  algorithm) tuples, digest length, then the digest.
- **Cookies** (RFC 7873, RFC 9018): server cookies are checked in constant
  time (SipHash-2-4 from `purecrypto`); lengths are enforced on parse.

## What callers must do

dnsbox checks messages and records; deciding what to trust is the
caller's job:

- **Use `now` from a trustworthy clock** for every time check (TSIG,
  SIG(0), RRSIG, cookies).
- **Select and authenticate inputs.** `verify_rrsig` and `verify_rrset`
  check the RRset you give them; you choose it (owner, class, type) and
  the keys: authenticate keys through `TrustedKeys::from_ds` /
  `from_anchors` (or your own configuration) before use. Denial proofs
  (`NsecProof`, `Nsec3Proof`) take records you have already verified,
  from one zone, as the zone's signer.
- **Check wildcard answers** with `TrustedKeys::verify_answer` (or
  `DenialProof::wildcard_answer`): a verified wildcard expansion only
  proves the wildcard exists.
- **Apply the TTL rules** of RFC 4035 §5.3.3: cap TTLs at the RRSIG's
  original TTL and never cache past its expiration (`Verified` carries
  both).
- **Treat `Insecure` as unauthenticated.** It does not mean bogus, but
  nothing in the response is proven. RFC 9276 and Opt-Out make this
  verdict reachable by replaying still-valid NSEC3 records of an older
  chain (high iteration count or Opt-Out); use `Nsec3Limits::new(n, n)` to
  turn over-limit iteration counts into `Bogus` if you prefer to fail
  closed.
- **Use one `ValidationBudget` per response.** Each `TrustedKeys` call is
  bounded on its own, but a validator calls it once per RRset: pass the
  same budget to the `*_with_budget` methods for every RRset of a
  response, and hash NSEC3 proofs with its `nsec3_hasher`, so that the
  whole response is bounded. Treat `Error::LimitExceeded` and
  `BogusReason::LimitExceeded` as bogus (SERVFAIL), never as insecure.
- **TSIG**: replay protection beyond the time window (remember the last
  Time Signed per key), and matching responses to queries (ID, question)
  are yours. A custom `TsigMac::verify` must compare in constant time.
- **Validate early** when you need to: `Message::parse` is lazy and reports
  an error only when the faulty part is reached; `parse_validated` checks
  everything up front.
- **Zone files**: the default `ZoneLimits` suit untrusted files; raise
  them (or use `ZoneLimits::UNLIMITED`) only for trusted ones. Resolve
  `$INCLUDE`s of untrusted files with `FsIncludes::new` (confined to one
  directory, which must hold nothing the uploader may not read) or with an
  `IncludeResolver` of your own that decides which paths it serves and
  implements `load_limited`; `FsIncludes::unconfined` opens any path, as
  BIND does, and is for trusted files only. The confinement holds against
  the zone file, not against someone changing the directory concurrently.
- **Zone transfers from servers you do not trust**: set
  `XfrProcessor::with_max_records` / `with_max_messages`.
- **Cap input sizes** for the allocating conveniences (`OwnedMessage`,
  `serde`, `Records`), which allocate in proportion to their input (never
  more than it can hold).
- **Custom backends** (`Verifier`, `Signer`, `TsigKey`/`TsigMac`,
  `Nsec3Hasher`, `Sig0Verifier`) must not panic and must bound their own
  work; the RSA and exponent limits above are the bundled backend's.

## Assurance

- **Fuzzing**: ten cargo-fuzz targets (`fuzz/`), run with overflow
  checks for 60 seconds each on every push: `message`, `name`, `rdata`,
  `edns`, `roundtrip` and `text` for parsing, building and presentation
  format; `denial`, `dnssec`, `sign` and `zone` for the trust decisions
  (proof consistency, every non-cryptographic RRSIG check, tamper
  detection of TSIG and SIG(0), zone files with includes and ZONEMD).
  Seeds and every fixed finding are replayed by `cargo test`
  (`tests/fuzz_regressions.rs`). For the audit below, after earlier
  rounds, every target ran for 400 seconds on four workers with overflow
  checks against the final code (0.6 to 9.6 million executions per
  target) without a crash.
- **Tests**: truncation at every offset for every parser, property tests
  (`tests/proptest_roundtrip.rs`), a corpus of real responses from BIND,
  NSD, Knot, PowerDNS and Unbound (`tests/corpus/`), RFC test vectors,
  and one regression test per audit finding (`tests/security_audit.rs`).

## Audit history

### Work-limits round (October 2026)

The caller duties of the Milestone 9 policy that concerned work were
turned into library limits, on by default, and the remaining APIs were
reviewed for work or allocation an attacker controls. Each change has
regression tests next to the code (`zone/tests.rs`, `dnssec/chain/tests.rs`,
`dnssec/denial/tests.rs`, `owned/tests.rs`, `xfr/tests.rs`,
`tests/serde.rs`) and the `dnssec` fuzz target checks the budgets.

| Severity | Finding | Fix |
|----------|---------|-----|
| Medium | KeyTrap (CVE-2023-50387): the 16 verifications per `TrustedKeys` call bounded each RRset, but not a response (the caller's duty), and every (RRSIG, key) pair of a response cost a key tag computation | `ValidationBudget` shared by the calls of a response; RRSIGs per RRset, keys per RRSIG and DNSKEYs looked at are capped (`ValidationLimits`); `Error::LimitExceeded` |
| Medium | NSEC3 closest-encloser proofs (CVE-2023-50868): one hash per label of the name, in every check of a response | `ValidationBudget::nsec3_hasher` caps the hashes of all checks; `BogusReason::LimitExceeded` |
| Medium | `$GENERATE` let a short zone file yield 65 536 records per line, which `zone::parse` collected without limit (the caller's duty) | `ZoneLimits` on `ZoneReader`, `Records` and `zone::parse_with_limits`, with a default record limit |
| Medium | `FsIncludes` opened any path a zone file named: absolute paths, `..`, symbolic links, and devices or pipes (`/dev/zero` read until memory ran out, a FIFO blocked forever) | confined to its directory by default (`FsIncludes::unconfined` for trusted files), regular files only, read with the input limit as bound |
| Low | `OwnedMessage::from_message` reserved room for the entries the header counts claimed: a 12-octet header made it allocate some 70 MB before failing | room reserved for what the message can hold |
| Low | `serde` read message sections of any length (a section has at most 65535 entries) | refused beyond 65535 entries while reading |
| Info | The length of a zone transfer was unbounded | opt-in `XfrProcessor::with_max_records` / `with_max_messages` |

### Milestone 9 audit (October 2026)

An adversarial review of the whole crate (parsing, building, text and
zone files, DNSSEC, denial proofs, TSIG, SIG(0), cookies, ECS, ZONEMD)
and a fuzzing campaign with overflow checks. Findings, all fixed, each
with a regression test in `tests/security_audit.rs`:

| Severity | Finding | Fix |
|----------|---------|-----|
| Medium | ZONEMD collation and verification compared every apex ZONEMD record with every other (duplicate removal, RFC 8976 §4 step 4 tuple check): a zone with 40 000 of them took minutes of CPU to reject | duplicates removed and tuples counted with a sort: O(n log n) |
| Low | TSIG and SIG(0) verification accepted octets after the signature record, which no MAC or signature covers, when the message was parsed lazily | the record must end the message (`Error::TrailingData`, FORMERR) |
| Low | An RRSIG labels field smaller than the signer's label count was accepted, making the RRset a "wildcard expansion" of a name above the zone (`*.` for 0) | the labels field must be at least the signer's label count (`RrsetMismatch`); signing refuses such templates too |
| Low | An NSEC3 record whose hashes were shorter than the hash output (e.g. one octet, `00` to `ff`) covered almost every name of the zone | hashes of another length never match or cover (also `Nsec3::covers`) |
| Low | LOC presentation format: an altitude close to 2^63 cm overflowed (a panic with overflow checks) | checked addition (`InvalidText`) |
| Info | `TrustedKeys` verified RRsets of another class than its keys' | `RrsetMismatch` |
| Info | Denial proofs accepted a zone's own apex as one of its delegations, and its own records as denying the DS at its apex | `Bogus(ZoneCut)` |

The `rdata` fuzzer now also checks that every type re-encodes to the
octets it was parsed from, and all fuzzers run with overflow checks.
