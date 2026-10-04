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
and TSIG verification, when added, delegate to pluggable crypto backends.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[security advisory form](https://github.com/KarpelesLab/dnsbox/security/advisories/new)
rather than opening a public issue.
