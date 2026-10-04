#!/usr/bin/env python3
"""Adds ZONEMD records (RFC 8976) computed by dnspython to BIND's zones.

    python3 tests/corpus/dnspython/gen_zonemd.py

For each zone below, dnspython loads it, computes the SIMPLE-scheme
digests with SHA-384 and SHA-512 (dns.zone.Zone.compute_digest), puts
both ZONEMD records at the apex, checks them (verify_digest) and writes
the zone with dnspython's own master-file writer to <name>.zonemd here:

- alltypes: tests/corpus/named-alltypes-axfr.hex, the AXFR of
  ../bind9/alltypes.zone (every type BIND reads; dnspython keeps the ones
  it does not know as RFC 3597 generic data);
- ed25519 and nsec3rsasha1: ../bind9/<name>.signed, signed zones (RRSIG,
  NSEC3, delegations and glue, all covered by the digest).

tests/interop_dnspython.rs verifies them with dnsbox.
"""

import os

import dns.message
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.version
import dns.zone
import dns.zonetypes

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.dirname(HERE)


def from_axfr(label, origin):
    with open(os.path.join(CORPUS, label + ".hex")) as f:
        wire = bytes.fromhex("".join(l.strip() for l in f if not l.startswith("#")))
    msg = dns.message.from_wire(wire)
    zone = dns.zone.Zone(origin, relativize=False)
    for rrset in msg.answer:
        # dnspython 2.8 has no MB, MG, MR or MINFO class and keeps their
        # RDATA as opaque bytes, compression pointers included (BIND
        # compresses these RFC 1035 types, as RFC 3597 §4 allows), which
        # corrupts them; leave them out.
        if dns.rdatatype.to_text(rrset.rdtype) in ("MB", "MG", "MR", "MINFO"):
            continue
        node = zone.find_node(rrset.name, create=True)
        rds = node.find_rdataset(rrset.rdclass, rrset.rdtype, rrset.covers, create=True)
        rds.update_ttl(rrset.ttl)
        for rd in rrset:
            # dnspython 2.8 writes quotes and backslashes in URI targets
            # unescaped (its output would not read back); leave those out.
            if rd.rdtype == dns.rdatatype.URI and any(c in rd.target for c in b'"\\'):
                continue
            rds.add(rd)
    return zone


def add_zonemd(zone, name):
    soa = zone.get_rdataset(zone.origin, "SOA")[0]
    # A placeholder first, so the apex has a ZONEMD RRset to replace.
    digests = [zone.compute_digest(alg) for alg in
               (dns.zonetypes.DigestHashAlgorithm.SHA384,
                dns.zonetypes.DigestHashAlgorithm.SHA512)]
    rds = zone.find_rdataset(zone.origin, "ZONEMD", create=True)
    rds.update_ttl(3600)
    for d in digests:
        assert d.serial == soa.serial
        rds.add(d)
    zone.verify_digest()
    path = os.path.join(HERE, name + ".zonemd")
    with open(path, "w") as f:
        f.write(f"; {name}: ZONEMD (SHA-384, SHA-512) by dnspython {dns.version.version}, "
                "written by dnspython (gen_zonemd.py).\n")
        zone.to_file(f, relativize=False, want_origin=True)
    print(f"{name}: {len(list(zone.iterate_rdatas()))} records")


def main():
    add_zonemd(from_axfr("named-alltypes-axfr", "alltypes.example."), "alltypes")
    for name in ("ed25519", "nsec3rsasha1"):
        zone = dns.zone.from_file(os.path.join(CORPUS, "bind9", name + ".signed"),
                                  origin=f"{name}.example.", relativize=False)
        add_zonemd(zone, name)


if __name__ == "__main__":
    main()
