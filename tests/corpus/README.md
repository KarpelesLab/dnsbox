# Interop corpus

Real DNS data from other implementations, and the scripts that produced it.
Nothing here is written by dnsbox except the two golden files named below;
every test reads the files as they are, so the tests never need the
network or the tools. Regenerating is only needed to refresh the data.

Everything was produced on 2026-10-04 with BIND 9.18.49 (`named`, `dig`,
`named-checkzone`, `dnssec-keygen`, `dnssec-signzone`, `dnssec-dsfromkey`),
ldns 1.8.4 (built from the NLnet Labs release tarball without root:
`./configure --prefix=$HOME/ldns --with-examples --with-drill && make install`),
dnspython 2.8.0 and Python 3.14, plus queries to public servers. The Knot
DNS 3.5 and Unbound 1.19 tools, and Ubuntu's BIND 9.18.39 serving and
validating, run on a GitHub Actions runner instead (`knot/` and `bind/`,
below); NSD, PowerDNS and the large resolvers are covered by live
captures.

## Layout

| Path | What | Made by | Tests |
|---|---|---|---|
| `*.hex` | one DNS message each: `#` comment lines saying where it came from, then hex | below | `corpus.rs`, `dig_display.rs`, `serde.rs`, ... |
| `capture.py` | live captures from public servers | Python stdlib | |
| `dig_reference.py` | dig's rendering of a `*.hex` message into `../data/dig/<label>.dig` | dig 9.18 | `dig_display.rs` |
| `bind9/` | BIND zone files, signed zones, keys, DS sets; `named-*.hex` | `bind9/gen.sh`, `bind9/capture_local.py` | `interop_zones.rs` |
| `ldns/` | ldns-written zone text, ldns-signed zones with ZONEMD | `ldns/gen.sh` | `interop_zones.rs` |
| `dnspython/` | RDATA text/wire pairs, TSIG, UPDATE, ZONEMD; `dnspython-*.hex` | `dnspython/gen_*.py` | `interop_dnspython.rs` |
| `knot/` | Knot-signed zones, keys, DS; knotd and Unbound exchanges (a subset of a CI run) | `knot/run.sh` in `.github/workflows/interop.yml`, `knot/keep.py` | `interop_knot.rs` |
| `bind/` | BIND-signed zones (every algorithm, NSEC/NSEC3/Opt-Out), keys, DS, `named-compilezone` output; exchanges with `named` (authoritative, validating resolver); `named-ci-*.hex` (a subset of a CI run) | `bind/run.sh` in `.github/workflows/interop.yml`, `bind/keep.py` | `interop_bind.rs` |

Every message of the corpus (207 of them) must validate, survive
parse → build → parse (and rebuild to a fixed point), reject every
truncation (`tests/corpus.rs`), round-trip through serde
(`tests/serde.rs`) and display exactly as `dig` 9.18 shows it, up to the
documented differences (`tests/dig_display.rs`; the AXFR message aside).

## Live captures (`capture.py`)

`python3 tests/corpus/capture.py [label-prefix...]` sends one query per
entry of its `ENTRIES` table (UDP, then TCP if truncated) and writes the
raw response, unmodified, with its server, query and date in the comment
lines, then refreshes its dig reference. Sources:

- **Authoritative servers:** BIND 9.20 (`ns1.isc.org`: DNSSEC, NSID,
  cookies, NXDOMAIN/NODATA with NSEC, CHAOS, RFC 8482 ANY, REFUSED, no
  EDNS), PowerDNS Authoritative 4.9/5.1, NSD 4.3 (`ns.nlnetlabs.nl`) and the
  root servers (`k.root-servers.net`: priming, referral with DS, DNSKEY,
  ZONEMD, NXDOMAIN with NSEC), Knot DNS 3 (`a.iana-servers.net`,
  `f.nic.de`: NSEC3 and NSEC3 Opt-Out), Cloudflare's servers (compact
  denial of existence, RFC 9824: an NSEC with NXNAME).
- **Resolvers:** Unbound 1.26, PowerDNS Recursor 5.4, Knot Resolver, and
  1.1.1.1, 8.8.8.8 and 9.9.9.9: HTTPS with ECH, SVCB (DDR,
  `_dns.resolver.arpa`, with `dohpath`), CAA, TLSA, URI, LOC, NAPTR, SRV,
  CDS/CDNSKEY, DS and DNSKEY (`com`, `de`, `nlnetlabs.nl`), NSEC3PARAM,
  ZONEMD of the root and of `se`, NXDOMAIN under `com` (NSEC3 Opt-Out),
  Extended DNS Errors (`dnssec-failed.org`), Client Subnet, NSID, a
  truncated response, CNAME chains, large TXT RRsets, PTR.

`tests/dnssec_corpus.rs` validates the DNSSEC captures: the root DNSKEY
RRset from the IANA trust anchors (KSK-2017, KSK-2024), `com` from the
root's DS, the other zones from their own KSKs, then every signed RRset,
and the denial-of-existence proofs (root, isc.org, powerdns.com,
nlnetlabs.nl: NSEC; example.com: NSEC3; com, de: NSEC3 Opt-Out, which
dnsbox reports as insecure, RFC 5155 §9.2; Cloudflare: compact denial,
a NODATA). It checks signatures at 2026-10-04T14:15Z, so re-capturing
those entries means moving its `NOW`. Its ignored `root_zone` test checks
a fresh copy of the whole root zone (`DNSBOX_ROOT_ZONE`): ZONEMD and every
RRSIG verified (done for the 2026100400 zone: 2792 RRsets).

## BIND 9.18 (`bind9/`)

`sh tests/corpus/bind9/gen.sh` (BIND 9.18 and python3; runs `named` as the
current user on 127.0.0.1:53535):

- `alltypes.zone`: one or more records of every type BIND reads, written
  by hand the way zone files are (relative names, parentheses, comments,
  TTL units, mnemonics, generic `\#` forms, escapes in owner names);
  `alltypes.canonical` is `named-checkzone -D` of it, and
  `../named-alltypes-axfr.hex` its AXFR from `named` (BIND's wire form of
  every type). dnsbox must read both texts to the same records as the
  AXFR, list names in the same canonical order, and display every record
  as BIND does.
- `alltypes.dnsbox` is dnsbox's display of `alltypes.canonical` (golden
  file; `DNSBOX_WRITE_ALLTYPES=1 cargo test --test interop_zones` rewrites
  it), and `alltypes.dnsbox.canonical` what `named-checkzone -D` made of
  it: BIND reads dnsbox's presentation of every type back to its own dump.
- `signed.zone` (wildcard, empty non-terminals, CNAME, DNAME, secure and
  unsigned delegations) signed by `dnssec-signzone` once per algorithm:
  RSASHA1 and RSASHA512 (NSEC), NSEC3RSASHA1 (NSEC3, salt, 5 iterations),
  RSASHA256 (NSEC3 Opt-Out), ECDSAP256SHA256 (NSEC3), ECDSAP384SHA384
  (NSEC), ED25519 (NSEC3 Opt-Out, salt, 1 iteration), ED448 (NSEC); with
  `<alg>.ds` (`dnssec-dsfromkey`, SHA-1/SHA-256/SHA-384) and `<alg>.keys`
  (the throwaway keys, private halves included). Signatures are valid
  2026-01-01 to 2036-01-01.
- `capture_local.py` queries `named` serving those zones, with DO, for 12
  cases per zone (DNSKEY, SOA, NXDOMAIN, NODATA, empty non-terminal,
  wildcard answer, wildcard NODATA, CNAME, DNAME, secure and insecure
  referrals, DS at an unsigned delegation): `../named-<alg>-<case>.hex`.

`tests/interop_zones.rs` verifies every RRSIG with the purecrypto backend,
authenticates the keys from each DS digest, re-signs every RRset with
dnsbox to BIND's exact bytes for the deterministic algorithms (RSA,
EdDSA), checks that the NSEC and NSEC3 chains are what dnsbox's canonical
order and NSEC3 hashing predict, and that every `named` response verifies
and its denial proof gives the expected status.

## ldns 1.8 (`ldns/`)

`LDNS=/path/to/ldns/bin sh tests/corpus/ldns/gen.sh`:

- `alltypes.ldns`: BIND's dump of `alltypes.zone` rewritten by
  `ldns-read-zone` (unquoted SvcParam values, expanded IPv6 in APL, WKS
  service names, raw tabs in strings, trailing blanks, `;{id = ...}`
  comments), minus what ldns cannot read (listed in `gen.sh`). dnsbox
  reads it to BIND's records.
- `signed.zone` signed by `ldns-signzone` with ED25519 (NSEC3),
  RSASHA256 (NSEC3 Opt-Out flag) and ECDSAP256SHA256 (NSEC), each with
  signed ZONEMD records (SHA-384 and SHA-512); `.ds` from `ldns-key2ds`,
  `.keys` as for BIND. The same checks as for BIND apply, plus dnsbox
  computing both ZONEMD digests.

## dnspython 2.8 (`dnspython/`)

- `gen_rdata.py` → `rdata.txt`: 142 examples covering every record type
  dnspython implements, as dnspython's text and wire forms. dnsbox reads
  the text to the same wire, and displays the wire as dnspython does
  (up to spacing, quoting and hex case, and the listed style
  differences); `rdata.dnsbox.txt` is dnsbox's display (golden file,
  `DNSBOX_WRITE_DNSPYTHON=1`), which `gen_rdata.py` has dnspython read
  back to the same bytes.
- `gen_messages.py` → `tsig.txt` (a signed query and response for each of
  the nine HMAC algorithms, truncated ones included; a BADTIME error; a
  signed three-message AXFR stream), `update.txt` (every RFC 2136
  prerequisite and update form) and `../dnspython-edns-*.hex` (NSID, ECS
  v4/v6, cookies, EDE, EXPIRE, keepalive, padding, Report-Channel, DAU,
  DHU, N3U, CHAIN). dnsbox verifies the MACs and re-signs to the same
  bytes, classifies the updates, and decodes every option.
- `gen_zonemd.py` → `alltypes.zonemd` (from the AXFR), `ed25519.zonemd`,
  `nsec3rsasha1.zonemd` (BIND's signed zones): ZONEMD SHA-384 and SHA-512
  by dnspython, written by dnspython's zone writer; dnsbox reads them and
  computes the same digests.

## Knot DNS 3.5 and Unbound 1.19 (`knot/`)

Knot and Unbound run only on the GitHub Actions runner
(`.github/workflows/interop.yml`, on pushes to `master`, pull requests
and on demand): it
installs Knot DNS 3.5.8 from CZ.NIC's Ubuntu packages (`knotd`, `knotc`,
`keymgr`, `kzonesign`, `kzonecheck`, `kdig`, `knsupdate`), Unbound
1.19.2, ldns 1.8.3 and BIND 9.18's `dnssec-verify` from Ubuntu 24.04, and
runs `knot/run.sh`:

- **sign**: `child.zone` (wildcard, empty non-terminal, CNAME, DNAME,
  secure and unsigned delegations, SVCB/HTTPS, LOC, NAPTR, SSHFP, TLSA,
  escapes in owner names and strings) as 18 zones
  `<algorithm>-<chain>.interop.`: RSASHA256, RSASHA512, ECDSAP256SHA256,
  ECDSAP384SHA384, ED25519, ED448, each with NSEC, NSEC3 (5 iterations,
  no salt; ZONEMD SHA-384, CDS/CDNSKEY) and NSEC3 Opt-Out (ZONEMD
  SHA-512). `keymgr` makes the keys (KSK and ZSK) and DS records (SHA-256,
  SHA-384), `kzonesign` signs (signatures valid ten years). Three zones are
  broken after signing: `bogus.` (an A record changed), `bogus-nsec.`
  (every NSEC bitmap changed) and `bogus-ds.` (the parent's DS digests
  changed). The parent `interop.` (ECDSAP256SHA256, NSEC) delegates to
  all of them and holds their DS records; its DS is the trust anchor.
  `kzonecheck`, `ldns-verify-zone` and `dnssec-verify` accept every Knot
  zone.
- **serve**: `knotd` (127.0.0.1:5301) serves them, an unsigned
  `unsigned.<zone>` below each, `insecure.interop.` (no DS), a zone of
  503 records for multi-message transfers, `dyn.interop.` (signed by
  `knotd` itself, dynamic updates), and dnsbox's presentation of every type
  BIND reads (`bind9/alltypes.dnsbox`) and of the types typed since
  (`knot/newtypes.zone`: AMTRELAY, DSYNC, HHIT, BRID, DOA), each but for
  the records Knot cannot read; NSID, CHAOS identity, Client Subnet, RFC 9018 cookies
  (mod-cookies with a fixed secret) and six TSIG keys (HMAC-MD5 to
  HMAC-SHA512, all with the secret `00 01 .. 1f`) for transfers and
  updates. `unbound` (127.0.0.1:5335) validates with the trust anchor,
  one stub zone per zone `knotd` serves. `knot/proxy.py` sits in front of
  both (5300, 5400) and records every message in both directions, with
  the client's text output.
- **capture**: `kdig` asks `knotd` 12 questions per signed zone (the
  `named` cases of `bind9/`), an AXFR of each (text and RFC 8427 JSON),
  EDNS (NSID, cookies and BADCOOKIE, Client Subnet v4 and v6, Padding and
  block alignment, EXPIRE, ZONEVERSION, an unknown option, version 1, no
  EDNS), TCP, truncation and the TCP retry, ANY, CHAOS, REFUSED,
  TSIG-signed queries and AXFRs with every HMAC, a wrong secret and an
  unknown key; `knsupdate` sends six TSIG-signed UPDATEs (and one with a
  failing prerequisite) to `dyn.interop.`, then `kdig` asks for the IXFR
  with every HMAC, an up-to-date IXFR and one over UDP. Unbound answers 96
  cases (positive answers, NXDOMAIN, NODATA, wildcards in every zone, the
  unsigned zones below them, the three bogus zones, the parent: 62
  secure, 31 insecure, 3 bogus), each
  asked once with DO and again with CD, with the DS and DNSKEY RRsets of
  every zone from `interop.` down; Unbound's own queries to `knotd` are
  recorded too (`knot/unbound-upstream/`).
- **probe**: dnsbox's `interop_probe` example sends its own queries
  (EDNS options, padding, cookies whose RFC 9018 hash it checks, TCP,
  TSIG with every HMAC, a TSIG-signed TKEY query (RFC 2930 §4.2, built
  by `dnsbox::tkey`; `knotd` does no TKEY but must answer it
  well-formed), AXFR streams, UPDATEs added, deleted, refused or
  failing a prerequisite, the IXFR they make) to `knotd` and `unbound`,
  and checks the answers (`knotd` verified dnsbox's TSIG MACs and applied
  its updates; Unbound validated, gave insecure answers without AD, and
  SERVFAIL with Extended DNS Error 6 for the bogus zone).
- **check-dnsbox**: `tests/interop_knot.rs` (with
  `DNSBOX_INTEROP_DIR` pointing at the run and `DNSBOX_INTEROP_WRITE` set)
  writes every zone again, displayed by dnsbox and re-signed by dnsbox
  with Knot's keys (new ZONEMD digests included); `kzonecheck` (with
  ZONEMD), `ldns-verify-zone` and `dnssec-verify` accept all 19 of them,
  and reject the tampered zones (so the checks are not vacuous). (ldns
  1.8.3 never returns on some of the zones with a ZONEMD record, Knot's
  as well as dnsbox's, though `kzonecheck`, `ldns-verify-zone -Z` on the
  others and dnsbox agree on their digests: `ldns-verify-zone` checks
  them without their ZONEMD, and its `-Z` result is only logged.)

The whole run is uploaded as the `interop-knot-unbound` artifact.
`knot/keep.py` copied a subset of run 37229639496 (2026-10-04) here, so
that `cargo test --test interop_knot` checks it offline (nothing in this
directory but `run.sh`, `proxy.py`, `keep.py`, `child.zone` and
`newtypes.zone` is written by hand): six of the signed zones (each algorithm, each chain twice), the
parent and the bogus zones with their keys (throwaway; PKCS #8 PEM as
`keymgr` stores them), DS records, `knotd`'s answers and transfers, the
EDNS, CHAOS, truncation and TSIG exchanges, the dynamic zone's updates and
two of its IXFRs, the `alltypes` transfers, the probe's exchanges (but its
bulk transfers), Unbound's cases for one zone per denial chain and for
the bogus, insecure and parent zones (21 of 96), and Unbound's own
queries for one zone; fifteen single responses are also kept as
`knotd-ci-*.hex` and `unbound-ci-*.hex` for the corpus tests, with their
`dig` rendering (made on the runner by `dig_reference.py`). To refresh:
`gh run download <run> -n interop-knot-unbound -D /tmp/interop && python3
tests/corpus/knot/keep.py /tmp/interop "run <run>, <date>"`. The
`newtypes` transfers and queries, `newtypes-omitted.txt` and
`probe/tkey` were added by hand from run 37232865423 (2026-10-04), the
first with them (unsigned or TSIG-signed with the fixed secret, so
independent of the run's keys).

`tests/interop_knot.rs` checks, as of the run's time (`knot/now`):

- dnsbox reads every Knot zone file; keymgr's DS records authenticate the
  keys, every RRSIG verifies (the tampered ones fail), the NSEC and NSEC3
  chains are those dnsbox's canonical order and NSEC3 hashing predict
  (Knot leaves unsigned delegations out of Opt-Out chains), CDS/CDNSKEY
  are the KSK's, dnsbox computes Knot's ZONEMD digests, and dnsbox,
  signing with the private keys read from keymgr's PEM files, reproduces
  every RSA, Ed25519 and Ed448 signature byte for byte;
- each zone file holds exactly the records of `knotd`'s AXFR, and `kdig`'s
  text and JSON (RFC 8427) of every response read back, with dnsbox's
  zone reader and RDATA parser, to the wire records; dnsbox's own
  presentation reads back to the same RDATA and matches Knot's but for
  the styles listed in `KNOT_STYLE`;
- every captured message (2222 in a run: kdig's, Unbound's and dnsbox's
  queries, knotd's and Unbound's answers) validates, passes the shared
  fuzz checks and rebuilds to the same message (96% byte for byte);
- every `knotd` answer verifies and its denial proof gives the expected
  status; every TSIG MAC verifies, every transfer stream is complete, the
  IXFR applied to the AXFR before the updates gives the AXFR after them;
  knsupdate's UPDATEs decode as sent; the EDNS options decode as sent
  and as `knotd` answered them (its server cookies recomputed with
  SipHash-2-4 from the configured secret);
- for every Unbound case, dnsbox validating the data Unbound fetched (CD)
  from the trust anchor down reaches Unbound's verdict (AD: secure; no AD:
  insecure; SERVFAIL: bogus), which is also the one the case was made for,
  each response validated within one default `ValidationBudget` (the
  KeyTrap limits must not reject legitimate chains; the zones are read
  with the default `ZoneLimits` too);
- `knotd` read dnsbox's text of every type it knows to BIND's wire form,
  and of the types of `knot/newtypes.zone` it knows to dnsbox's (the
  test prints which).

Differences found, none a dnsbox bug: Knot writes CERT types and
algorithms as numbers and LOC without decimals (both sides read the
other); Knot keeps no TTL of its own for an RRSIG but its original TTL
field: it serves that as the TTL and computes ZONEMD digests with it, so
for a zone file whose RRSIG TTLs differ from their RRsets' (an early
version of the re-signing test wrote such files) `kzonecheck -z` finds
the ZONEMD invalid where dnsbox and ldns find it valid;
Knot answers an unknown TSIG key with NOTAUTH without a TSIG record
(RFC 8945 §5.3.2 has an unsigned TSIG record), and a query with only a
client cookie with BADCOOKIE (mod-cookies' default); Knot 3.5 has no
mnemonic for A6, ATMA, AVC, DLV, EID, GID, GPOS, HIP, ISDN, MB, MG, MR,
NIMLOC, NINFO, NSAP, NSAP-PTR, NULL, NXT, PX, RKEY, SIG, SINK, TA,
TALINK, UID, UINFO, UNSPEC, WKS and X25, nor for AMTRELAY, HHIT, BRID
and DOA (it reads and writes DSYNC as dnsbox does), and rejects a KEY
without key data; `knotd` does no TKEY and answers dnsbox's TSIG-signed
TKEY query REFUSED without signing the answer. With a single stub zone for `interop.`, Unbound timed out (then
SERVFAIL) on NXDOMAIN, wildcard and unsigned-delegation answers of the
child zones, and on DS queries for names that are not zone cuts: `knotd`
answers for every zone it serves with authority, so Unbound never saw the
cuts (hence one stub zone per zone).

## BIND 9.18 on the CI runner (`bind/`)

The `bind` job of `.github/workflows/interop.yml` (on pushes to `master`,
pull requests and on demand) installs Ubuntu 24.04's BIND 9.18.39
(`bind9`, `bind9-utils`, `bind9-dnsutils`) and dnspython 2.6.1, and runs
`bind/run.sh` (BIND's own servers and tools, never on a workstation):

- **sign**: `dnssec-keygen` is tried with every DNSSEC algorithm mnemonic
  BIND has had (`algorithms.txt`): RSAMD5, DSA, NSEC3DSA and ECCGOST are
  refused, the eight others (RSASHA1, NSEC3RSASHA1, RSASHA256, RSASHA512,
  ECDSAP256SHA256, ECDSAP384SHA384, ED25519, ED448) make a KSK and a ZSK
  for `../knot/child.zone` signed by `dnssec-signzone -S` with NSEC, NSEC3
  (salt `aabbccdd`, 5 iterations, CDS/CDNSKEY published with `-P sync`)
  and NSEC3 Opt-Out (`-A`, no salt): 22 zones
  `<algorithm>-<chain>.interop.` (RSASHA1 has NSEC only), valid ten years.
  `dnssec-dsfromkey` gives SHA-1, SHA-256 and SHA-384 DS records; the
  parent `interop.` holds the SHA-256 and SHA-384 ones, and its own DS is
  the trust anchor. Three zones are broken after signing (`bogus.`: an A
  record changed, `bogus-nsec.`: every NSEC bitmap, `bogus-ds.`: the
  parent's DS digests; signed with `-O full`, one record per line).
  `named-checkzone -i full` and `dnssec-verify` accept every BIND zone
  and `dnssec-verify` rejects the tampered ones. `named-compilezone`
  writes the zones, `bulk.interop.`, `../bind9/alltypes.zone` and
  `../knot/newtypes.zone` in both text styles (`-s full`, `-s relative`).
  `named-checkzone` reads dnsbox's presentation of every type BIND
  knows (`../bind9/alltypes.dnsbox`), of the types typed since
  (`../knot/newtypes.zone`) and of the types only Internet-Drafts define
  (`bind/drafttypes.zone`: IPN, CLA, UNECE, ISO, each also in the RFC
  3597 generic form), but for the lines it cannot read (listed in
  `alltypes-omitted.txt`, `newtypes-omitted.txt`,
  `drafttypes-omitted.txt`). `dnssec-keygen -a DH -b 1024 -n HOST`
  makes `named`'s Diffie-Hellman KEY for TKEY (`tkey/`).
- **serve**: an authoritative `named` (127.0.0.1:5351) serves them, an
  unsigned zone below each child, `insecure.interop.`, a 503-record
  `bulk.interop.`, `alltypes.example.`, `newtypes.example.` and
  `drafttypes.example.` (dnsbox's text), and `dyn.interop.` (dynamic: an update policy for six TSIG keys,
  HMAC-MD5 to HMAC-SHA512 with the secret `00 01 .. 1f`, and three SIG(0)
  KEYs, `dnssec-keygen -T KEY`), with NSID, CHAOS identity and version,
  RFC 9018 cookies (`cookie-secret 00 01 .. 0f`), response padding (128)
  and TSIG-only transfers; TKEY Diffie-Hellman exchanged keying with
  that KEY (`tkey-dhkey`, `tkey-domain "tkey.interop."`). A second
  `named` (127.0.0.1:5355) is a
  validating resolver: `interop.`'s DS as a static trust anchor, the zone
  forwarded to the first. `../knot/proxy.py` sits in front of both (5350,
  5450) and records every message with the client's output.
- **capture**: `dig` asks the 12 questions of `bind9/` in every signed
  zone and an AXFR of each (also with `+multiline`), every RRset of
  `alltypes.example.`, the new types and the draft types, EDNS (NSID, cookies with and
  without a server cookie, Client Subnet v4/v6/0, Padding over UDP and
  TCP, EXPIRE, TCP keepalive, an unknown option and flag, version 1 with
  and without negotiation, no EDNS), TCP, truncation and the retry, ANY,
  CHAOS, REFUSED, NOTIMP, TSIG-signed queries and AXFRs with every HMAC, a
  wrong secret, an unknown key and none; `nsupdate` sends seven
  TSIG-signed UPDATEs (one over TCP), one with a failing prerequisite,
  an unsigned one and three signed with SIG(0); `dig` asks for the IXFR
  with every HMAC, an up-to-date IXFR and one over UDP. The resolver
  answers 116 cases (the Unbound cases of `knot/`, for 22 zones: 76
  secure, 37 insecure, 3 bogus), with DO and again with CD, with the DS
  and DNSKEY RRsets of every zone from `interop.` down.
- **probe**: dnsbox's `bind_probe` example sends its own queries (EDNS
  options, padding, cookies it recomputes, TCP, TSIG with every HMAC,
  BADSIG and BADKEY, a TSIG-signed TKEY deletion query, a Diffie-Hellman
  TKEY exchange (RFC 2930 §4.1) whose HMAC-MD5 key then signs a query
  and its own deletion, AXFR streams, UPDATEs
  added, deleted, refused or failing a prerequisite, the IXFR they make,
  an UPDATE signed with SIG(0) from BIND's private key) to both `named`
  and checks their answers.
- **check-dnsbox**: `tests/interop_bind.rs` (with `DNSBOX_INTEROP_DIR`
  and `DNSBOX_INTEROP_WRITE`) writes every intact zone again, displayed by
  dnsbox and re-signed by dnsbox with BIND's keys; `named-checkzone -i
  full` and `dnssec-verify` accept all 24, and `named-compilezone`'s
  output of them in both styles reads back to dnsbox's records.
- The same job runs `dnspython/gen_rdata.py --check` with the
  distribution's dnspython (below).

The whole run is uploaded as the `interop-bind` artifact. `bind/keep.py`
copied a subset of run 37396071664 (2026-10-06) here, so that `cargo test
--test interop_bind` checks it offline (nothing in this directory but
`run.sh`, `keep.py` and `drafttypes.zone` is written by hand): eight of the signed zones (each
algorithm, each chain at least twice), the parent and the bogus zones with
their keys (throwaway; BIND's private key format v1.3), DS records,
`named`'s answers and transfers, `named-compilezone`'s output of three of
them, of `alltypes.zone`, `newtypes.zone` and the bulk zone, the EDNS,
CHAOS, truncation and TSIG exchanges, the dynamic zone's updates (TSIG and
SIG(0), with the SIG(0) keys) and two of its IXFRs, the `alltypes`,
`newtypes` and `drafttypes` transfers and queries, `named`'s DH key, the
probe's exchanges (one of its bulk transfers), the resolver's cases for one zone per denial chain and for
the bogus, insecure and parent zones (21 of 116), its queries for one
zone, and two of the zones dnsbox re-signed with BIND's verdicts; 21
single responses are also kept as `named-ci-*.hex` (TKEY and draft-type
answers among them), with their `dig` rendering from the same run (the
workflow writes them with `keep.py --toplevel` and has
`dig_reference.py` render them). To refresh: `gh run download <run> -n
interop-bind -D /tmp/interop-bind && python3 tests/corpus/bind/keep.py
/tmp/interop-bind "run <run>, <date>"`.

`tests/interop_bind.rs` checks, as of the run's time (`bind/now`):

- `dnssec-keygen` supports exactly the algorithms dnsbox signs and
  verifies; dnsbox reads every BIND zone file in both of `dnssec-signzone`'s
  output formats; the DS records authenticate the keys, every RRSIG
  verifies (the tampered ones fail), the NSEC and NSEC3 chains are those
  dnsbox's canonical order and NSEC3 hashing predict (BIND leaves unsigned
  delegations out of Opt-Out chains), CDS/CDNSKEY are the KSK's, and
  dnsbox, signing with the private keys read from BIND's `.private` files,
  reproduces every RSA, Ed25519 and Ed448 signature byte for byte;
- each zone file holds exactly the records of `named`'s AXFR, dnsbox reads
  `named-compilezone`'s output in both styles to the records BIND loaded,
  and `dig`'s text of every response (one-line and `+multiline`, TSIG
  records included) reads back to its wire records;
- every captured message (2756 in a run) validates, passes the shared
  fuzz checks and rebuilds to the same message (84% byte for byte, the
  rest within 5% of BIND's size: dnsbox's compression table holds 128
  labels and it never points into names it may not compress, RRSIG
  signers, NSEC next names, DNAME targets, where BIND does; BIND leaves
  some authority owners uncompressed, where dnsbox's are smaller);
- every `named` answer verifies and its denial proof gives the expected
  status; every TSIG MAC verifies and `named`'s BADSIG and BADKEY answers
  carry the error with an empty MAC; every transfer stream is complete,
  the IXFR applied to the AXFR before the updates gives the AXFR after
  them; nsupdate's UPDATEs decode as sent; every SIG(0) of nsupdate and of
  the probe verifies with its KEY, and dnsbox reproduces the Ed25519 and
  RSA ones from the private keys; the EDNS options decode as sent and as
  `named` answered them (its server cookies recomputed with SipHash-2-4
  from the configured secret);
- for every resolver case, dnsbox validating the data `named` fetched
  (CD) from the trust anchor down reaches `named`'s verdict (AD: secure;
  no AD: insecure; SERVFAIL: bogus), which is also the one the case was
  made for, within one default `ValidationBudget`;
- `named` read dnsbox's text of every type BIND 9.18 knows to BIND's own
  wire form (`named-alltypes-axfr.hex`), and of AMTRELAY, DSYNC and DOA
  to dnsbox's; it serves the generic form of IPN, CLA, UNECE and ISO as
  dnsbox's wire form, and dig's generic text of them reads back to it
  (dnsbox displays dig's octets as its own typed text, `dig_display.rs`);
  `named-checkzone`, `named-compilezone` and `dnssec-verify` accept the
  zones dnsbox re-signed;
- TKEY: dnsbox reads named's Diffie-Hellman answer and derives the key
  named made, which verifies named's answers to the query and to the
  deletion it signed; playing the server with named's private key and
  nonce, dnsbox derives the same secret; dig's text of named's TKEY
  answers (deletion and Diffie-Hellman) is dnsbox's display of them, and
  reads back to their wire form.

What BIND 9.18.39 does that dnsbox now tests for: `named` echoes Client
Subnet with scope 0 as an authoritative server; it pads responses over
TCP, and over UDP only for a client with a valid server cookie; it never
sends BADCOOKIE without `require-server-cookie`; it answers a TKEY
deletion of a configured key NOERROR with a TKEY record carrying BADNAME,
signed; since 9.18.28 (CVE-2024-1975) it no longer verifies SIG(0) and its
update policy refuses SIG(0)-signed updates as unsigned (dnsbox verifies
them); it does not know HHIT or BRID, nor IPN, CLA, UNECE or ISO; its
resolver gives no Extended DNS Error for bogus answers. Its
Diffie-Hellman TKEY (`tkey-dhkey`, deprecated in 9.18, removed in 9.20)
requires a signed query, offers only HMAC-MD5, names the key after the
question name under its `tkey-domain` (`dnsbox-dh.` becomes
`dnsbox-dh.tkey.interop.`), puts the resolver's KEY, its own KEY and the
TKEY record (16 octets of nonce) in the answer section, and mixes the
1024-bit DH value without leading zero octets; it lets a key delete
itself, a TSIG under it counting as the identity that created it.

## Discrepancies found

Fixed in dnsbox (with tests):

- **CERT algorithm** (RFC 4398 §2.2): BIND and dnspython write the
  algorithm as a mnemonic; dnsbox wrote a number. dnsbox now writes the
  mnemonics all three agree on (`RSASHA256`, `ED25519`, ...) and reads
  BIND's and dnspython's own spellings (`NSEC3RSASHA1`, `NSEC3DSA`,
  `ECCGOST`, `ECDSA256`, `ECDSA384`, `RSASHA1NSEC3SHA1`, `DSANSEC3SHA1`,
  `ECC`), keeping numbers for 4, 6, 7 and 12 where they differ.
- **SIG/RRSIG type covered**: BIND writes `SIG 0 ...` (a bare number) for
  SIG(0) records and reads numbers there; dnsbox now reads them too.
- **AMTRELAY relay type 0** (RFC 8777 §4.3.1): BIND 9.18 writes no relay
  for type 0 (`0 0 0`) and reads only that, where the RFC (and dnsbox,
  and dnspython) has `.`; dnsbox rejected BIND's form. dnsbox now reads
  both and keeps writing `.` (found by the BIND CI run; `named` serves
  both forms there, and dig's text of them reads back).

Differences of style, left as they are (both sides read each other):
LOC sizes (dnspython always writes decimals and drops default fields),
ILNP groups (BIND drops leading zeros), `TYPE0` vs BIND's bare `0` in SIG,
`dohpath` vs `key7` (dig 9.18 predates RFC 9461), CERT algorithms 4/6/7/12
as numbers, dnspython's upper-case `HMAC-MD5.SIG-ALG.REG.INT` (MACs agree:
the name is canonicalized), dig 9.18 not decoding NXNAME, DAU/DHU/N3U,
CHAIN and Report-Channel, BIND applying RFC 2181 §5.2 (one TTL per
RRset) when loading while dnsbox's streaming reader returns TTLs as
written, and BIND leaving unsigned delegations out of Opt-Out chains where
ldns keeps them.

Found in the other tools (worked around in the generators): dnspython
writes quotes and backslashes in URI targets unescaped, has no MB, MG, MR
or MINFO class and keeps their compressed RDATA as opaque bytes, and
accepts ZONEMD digests shorter than 12 octets (BIND and dnsbox reject
them, RFC 8976 §2.2.4); ldns writes UINFO/UID/GID/UNSPEC as `TYPE0` and
the NSAP-PTR name as a quoted string, and cannot read A6, ATMA, AVC,
NINFO, NXT, RKEY, SINK or TA; BIND refuses MD and MF as obsolete. BIND
9.18.39 takes the key of a KEY, DNSKEY or RKEY of algorithm 253
(PRIVATEDNS) to start with a domain name (RFC 4034 Appendix A.1.1): it
loads `alltypes.zone`'s RKEY, whose key does not, but `named-compilezone
-s relative` then aborts (an assertion in `dns_name_fromregion`) and dig
rejects `named`'s answers holding it ("bad label type"), while dnsbox and
dnspython read it as opaque key data (`bind/run.sh` compiles the zone
without it, and the tests pin both failures). dnspython 2.6.1 has no
DSYNC, RESINFO or WALLET class nor the `ohttp` SvcParamKey (2.8 has).

TKEY has no zone-file form, and dnsbox writes BIND's text for it (with
the key and other data sizes), which dnspython does not read; dnsbox reads
both BIND's and dnspython's form, so dnspython's TKEY text is checked like
any other type's, and `interop_dnspython.rs` pins dnsbox's display of those
examples. `gen_rdata.py --check` checks the sizes against the data and
rewrites dnsbox's text to dnspython's layout (error number, no sizes)
before dnspython reads it. With an older dnspython (the CI runner's),
`--check` skips the types and SvcParamKeys it does not implement and
lists them, which is an error with a dnspython at least as recent as the
one that wrote `rdata.txt`.
