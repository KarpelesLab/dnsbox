# Interop corpus

Real DNS data from other implementations, and the scripts that produced it.
Nothing here is written by dnsbox except the two golden files named below;
every test reads the files as they are, so the tests never need the
network or the tools. Regenerating is only needed to refresh the data.

Everything was produced on 2026-10-04 with BIND 9.18.49 (`named`, `dig`,
`named-checkzone`, `dnssec-keygen`, `dnssec-signzone`, `dnssec-dsfromkey`),
ldns 1.8.4 (built from the NLnet Labs release tarball without root:
`./configure --prefix=$HOME/ldns --with-examples --with-drill && make install`),
dnspython 2.8.0 and Python 3.14, plus queries to public servers. Knot's
`kdig`/`keymgr`/`kzonecheck` and the Unbound tools were not available; Knot,
Unbound, NSD, PowerDNS and the large resolvers are covered by live
captures instead.

## Layout

| Path | What | Made by | Tests |
|---|---|---|---|
| `*.hex` | one DNS message each: `#` comment lines saying where it came from, then hex | below | `corpus.rs`, `dig_display.rs`, `serde.rs`, ... |
| `capture.py` | live captures from public servers | Python stdlib | |
| `dig_reference.py` | dig's rendering of a `*.hex` message into `../data/dig/<label>.dig` | dig 9.18 | `dig_display.rs` |
| `bind9/` | BIND zone files, signed zones, keys, DS sets; `named-*.hex` | `bind9/gen.sh`, `bind9/capture_local.py` | `interop_zones.rs` |
| `ldns/` | ldns-written zone text, ldns-signed zones with ZONEMD | `ldns/gen.sh` | `interop_zones.rs` |
| `dnspython/` | RDATA text/wire pairs, TSIG, UPDATE, ZONEMD; `dnspython-*.hex` | `dnspython/gen_*.py` | `interop_dnspython.rs` |

Every message of the corpus (175 of them) must validate, survive
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

- `gen_rdata.py` → `rdata.txt`: 139 examples covering every record type
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
NINFO, NXT, RKEY, SINK or TA; BIND refuses MD and MF as obsolete.

TKEY has no zone-file form, and dnsbox writes BIND's text for it (with
the key and other data sizes), which dnspython does not read (nor does
dnsbox read dnspython's); `interop_dnspython.rs` pins dnsbox's text for
those examples and `gen_rdata.py --check` skips them.
