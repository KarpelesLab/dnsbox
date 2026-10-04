# Security Policy

## Threat model

`dnsbox` parses DNS messages from **untrusted sources** (network peers,
captures, zone data). Its parsers are written to that bar:

- **No panic, no out-of-bounds reads on malformed input.** Malformed
  messages are rejected with an `Error` variant rather than aborting.
- **No memory-unsafety.** The crate is `#![forbid(unsafe_code)]`.
- **Bounded work per message.** Name decompression only accepts pointers
  that point strictly before the run of labels they terminate (which rejects
  forward pointers, self pointers and every loop) and caps the number of
  hops per name, so a small message cannot cause unbounded CPU use. The
  builder's compression lookup likewise verifies a bounded number of
  candidates per name.

The crate does **not** claim any cryptographic property of its own; DNSSEC
and TSIG verification delegate to pluggable crypto backends.

DNSSEC hardening: the bundled `purecrypto` backend accepts RSA moduli of
512–4096 bits (1024–4096 for RSASHA512) and public exponents of at most
256 bits, so a hostile key cannot make a signature check arbitrarily
expensive; ECDSA points are checked to be on the curve; RSA/MD5 is never
validated (RFC 8624). NSEC3 hashing costs one hash per iteration (at most
65536): callers should apply an iteration limit before hashing
(RFC 9276).

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[security advisory form](https://github.com/KarpelesLab/dnsbox/security/advisories/new)
rather than opening a public issue.
