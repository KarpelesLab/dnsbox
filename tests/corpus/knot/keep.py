#!/usr/bin/env python3
"""Keeps a subset of an interop run in tests/corpus/knot/ (the offline data
of tests/interop_knot.rs).

    gh run download RUN_ID -n interop-knot-unbound -D /tmp/interop
    python3 tests/corpus/knot/keep.py /tmp/interop "run RUN_ID, DATE"

Replaces the kept data (everything in this directory but the scripts and
child.zone and newtypes.zone) with: six of the eighteen signed zones (every algorithm and
every denial chain twice), the parent and the three tampered zones, with
their keys, DS records, knotd's answers and transfers, and Unbound's cases
for three of them and for the others; knotd's EDNS, CHAOS, truncation and
TSIG exchanges; the dynamic
zone's updates and two of its IXFRs; knotd's transfers of alltypes.example
and newtypes.example; the
interop_probe exchanges but the bulk transfers; and the unbound-to-knotd
queries of one zone. A few single responses also go to
tests/corpus/knotd-ci-*.hex and unbound-ci-*.hex. Python standard library
only.
"""

import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
KEEP_SCRIPTS = {"run.sh", "proxy.py", "keep.py", "child.zone", "newtypes.zone"}

CHILDREN = [
    "rsasha256-optout.interop",
    "rsasha512-nsec.interop",
    "ecdsap256-nsec3.interop",
    "ecdsap384-optout.interop",
    "ed25519-nsec.interop",
    "ed448-nsec3.interop",
]
ZONES = CHILDREN + [
    "interop",
    "bogus.interop",
    "bogus-nsec.interop",
    "bogus-ds.interop",
]
# Unbound's cases kept: those of one zone per denial chain, and those
# outside the children (bogus, insecure, parent).
UNBOUND_ZONES = ["rsasha256-optout", "ecdsap256-nsec3", "ed25519-nsec"]
# knot/<label> directories kept whole: every case of the children (but
# one RFC 8427 JSON transfer), the transfers of the others.
KNOT = [
    z + "/" + case
    for z in CHILDREN
    for case in (
        "dnskey", "soa", "nxdomain", "nodata", "ent", "wildcard", "wildcard-nodata",
        "cname", "dname", "referral-secure", "referral-insecure", "ds-unsigned", "axfr",
    )
] + [z + "/axfr" for z in ZONES if z not in CHILDREN] + [
    "ecdsap256-nsec3.interop/axfr-json",
    "edns",
    "chaos",
    "transport",
    "refused",
    "dyn/axfr-before",
    "dyn/axfr-after",
    "dyn/ixfr-md5",
    "dyn/ixfr-sha512",
    "dyn/ixfr-uptodate",
    "dyn/ixfr-udp",
    "dyn/update-yxdomain",
    "alltypes",
    "newtypes",
    "tsig/axfr-sha256",
    "tsig/axfr-badsig",
    "tsig/axfr-badkey",
    "tsig/axfr-unsigned",
    "probe/edns",
    "probe/tcp-dnskey",
    "probe/tsig-badsig",
    "probe/tkey",
    "probe/update",
    "unbound-upstream/ed25519-nsec",
] + ["tsig/soa-" + h for h in ("md5", "sha1", "sha224", "sha256", "sha384", "sha512")] + [
    "dyn/update-" + h for h in ("md5", "sha1", "sha224", "sha256", "sha384", "sha512")
] + [
    "probe/tsig-" + h for h in ("md5", "sha1", "sha224", "sha256", "sha384", "sha512")
]


# Single responses also kept as tests/corpus/<name>.hex, for the corpus
# tests (corpus.rs, serde.rs, dig_display.rs): name -> (label, which
# response of the exchange).
TOPLEVEL = {
    "knotd-ci-ed448-nsec3-nxdomain": ("knot/ed448-nsec3.interop/nxdomain", -1),
    "knotd-ci-ed25519-nsec-wildcard": ("knot/ed25519-nsec.interop/wildcard", -1),
    "knotd-ci-ecdsap384-optout-referral": ("knot/ecdsap384-optout.interop/referral-insecure", -1),
    "knotd-ci-rsasha256-optout-dname": ("knot/rsasha256-optout.interop/dname", -1),
    "knotd-ci-ecdsap256-nsec3-dnskey": ("knot/ecdsap256-nsec3.interop/dnskey", -1),
    "knotd-ci-zoneversion": ("knot/edns/zoneversion", -1),
    "knotd-ci-expire": ("knot/edns/expire", -1),
    "knotd-ci-badcookie": ("knot/edns/badcookie", 0),
    "knotd-ci-subnet6": ("knot/edns/subnet6", -1),
    "knotd-ci-chaos-id": ("knot/chaos/id.server", -1),
    "knotd-ci-truncated": ("knot/transport/truncated", -1),
    "unbound-ci-secure": ("unbound/ed25519-nsec/a/answer", -1),
    "unbound-ci-nxdomain": ("unbound/ed448-nsec3/nxdomain/answer", -1),
    "unbound-ci-insecure": ("unbound/insecure/a/answer", -1),
    "unbound-ci-bogus-ede": ("unbound/bogus/rdata/answer", -1),
}


def toplevel(src, run):
    corpus = os.path.dirname(HERE)
    for name, (label, which) in TOPLEVEL.items():
        d = os.path.join(src, label)
        responses = sorted(f for f in os.listdir(d) if f.endswith("-r.hex"))
        with open(os.path.join(d, responses[which])) as f:
            hexdigits = "".join(l.strip() for l in f if not l.startswith("#"))
        with open(os.path.join(d, "command.txt")) as f:
            command = f.read().strip()
        server = "unbound 1.19" if label.startswith("unbound/") else "knotd 3.5"
        with open(os.path.join(corpus, name + ".hex"), "w") as f:
            f.write("# %s on the interop CI runner (%s): %s\n" % (server, run, command))
            f.write("# tests/corpus/knot/keep.py from %s (tests/corpus/README.md)\n" % label)
            for i in range(0, len(hexdigits), 96):
                f.write(hexdigits[i:i + 96] + "\n")


def copy(src, rel):
    a, b = os.path.join(src, rel), os.path.join(HERE, rel)
    if os.path.isdir(a):
        shutil.copytree(a, b)
    elif os.path.exists(a):
        os.makedirs(os.path.dirname(b), exist_ok=True)
        shutil.copy(a, b)
    else:
        sys.exit("missing in the run: " + rel)


def main():
    src = sys.argv[1]
    for name in os.listdir(HERE):
        if name in KEEP_SCRIPTS:
            continue
        path = os.path.join(HERE, name)
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.remove(path)

    for rel in ["versions.txt", "now", "anchor.ds", "alltypes-omitted.txt", "newtypes-omitted.txt",
                "zones/bulk.interop.zone"]:
        copy(src, rel)
    for z in ZONES:
        copy(src, "zones/%s.zone" % z)
        copy(src, "ds/%s.ds" % z)
        copy(src, "keys/" + z)
    for rel in KNOT:
        copy(src, "knot/" + rel)

    with open(os.path.join(src, "manifest.txt")) as f:
        manifest = [l for l in f if l.split()[0].rstrip(".") in ZONES]
    with open(os.path.join(HERE, "manifest.txt"), "w") as f:
        f.writelines(manifest)

    # Unbound: the cases of the kept zones (their zone, or the unsigned
    # zone below one of them).
    cases = []
    with open(os.path.join(src, "unbound", "cases.txt")) as f:
        for line in f:
            case, _, _, zone, _ = line.split()
            zone = zone.rstrip(".")
            if zone.startswith("unsigned."):
                zone = zone[len("unsigned."):]
            if case.split("/")[0] in UNBOUND_ZONES + ["bogus", "insecure", "parent"]:
                cases.append(line)
                copy(src, "unbound/" + case)
    with open(os.path.join(HERE, "unbound", "cases.txt"), "w") as f:
        f.writelines(cases)
    copy(src, "unbound/extra")
    copy(src, "unbound/probe")
    toplevel(src, sys.argv[2] if len(sys.argv) > 2 else "interop run")


if __name__ == "__main__":
    main()
