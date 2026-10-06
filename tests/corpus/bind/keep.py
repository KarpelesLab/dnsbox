#!/usr/bin/env python3
"""Keeps a subset of a BIND interop run in tests/corpus/bind/ (the offline
data of tests/interop_bind.rs).

    gh run download RUN_ID -n interop-bind -D /tmp/interop-bind
    python3 tests/corpus/bind/keep.py /tmp/interop-bind "run RUN_ID, DATE"
    python3 tests/corpus/bind/keep.py --toplevel OUT "run RUN_ID, DATE"

Replaces the kept data (everything in this directory but the scripts) with:
eight of the twenty-two signed zones (every algorithm, every denial chain
at least twice), the parent and the three tampered zones, with their keys,
DS records, named's answers and transfers, named-compilezone's output of
three of them in both styles, and the resolver's cases for three of them and for the
others; named's EDNS, CHAOS, truncation and TSIG exchanges; the dynamic
zone's updates (TSIG and SIG(0), with the SIG(0) keys) and two of its
IXFRs; named's transfers of alltypes.example, newtypes.example and
drafttypes.example and its answers for each RRset of alltypes.example and
each draft type; named's Diffie-Hellman TKEY key; the bind_probe
exchanges but five of its six bulk transfers; the resolver-to-named queries of one zone;
two of the zones dnsbox re-signed, with named-compilezone's output of them
and dnssec-verify's verdict. A few single responses also go to
tests/corpus/named-ci-*.hex, with dig's rendering of them when the run made
it (the workflow writes them with --toplevel, which writes only those
files and prints their names, and has dig render them). Python standard
library only.
"""

import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# Not run output: the scripts and the zone run.sh serves.
KEEP_SCRIPTS = {"run.sh", "keep.py", "drafttypes.zone"}

CHILDREN = [
    "rsasha1-nsec.interop",
    "nsec3rsasha1-nsec3.interop",
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
# The resolver's cases kept: those of one zone per denial chain, and those
# outside the children (bogus, insecure, parent).
RESOLVER_ZONES = ["rsasha256-optout", "ecdsap256-nsec3", "ed25519-nsec"]
# The zones whose named-compilezone output is kept (both styles).
COMPILED = ["rsasha1-nsec.interop", "ecdsap256-nsec3.interop", "rsasha256-optout.interop"]
# The zones dnsbox re-signed that are kept, with BIND's verdicts.
DNSBOX = ["ed25519-nsec.interop", "rsasha256-optout.interop"]
CASES = (
    "dnskey", "soa", "nxdomain", "nodata", "ent", "wildcard", "wildcard-nodata",
    "cname", "dname", "referral-secure", "referral-insecure", "ds-unsigned", "axfr",
)
HMACS = ("md5", "sha1", "sha224", "sha256", "sha384", "sha512")
# named/<label> directories kept whole.
NAMED = [z + "/" + case for z in CHILDREN for case in CASES] + [
    z + "/axfr" for z in ZONES if z not in CHILDREN
] + [
    "ecdsap256-optout.interop/nxdomain-multiline",
    "ed25519-nsec3.interop/dnskey-multiline",
    "ed25519-nsec3.interop/axfr-multiline",
    "edns",
    "chaos",
    "transport",
    "refused",
    "notimp",
    "alltypes",
    "newtypes",
    "drafttypes",
    "dyn/axfr-before",
    "dyn/axfr-after",
    "dyn/ixfr-md5",
    "dyn/ixfr-sha512",
    "dyn/ixfr-uptodate",
    "dyn/ixfr-udp",
    "dyn/update-yxdomain",
    "dyn/update-unsigned",
    "dyn/update-tcp",
    "dyn/update-sha256",
    "dyn/sig0-ed25519",
    "tsig/axfr-sha256",
    "tsig/axfr-badsig",
    "tsig/axfr-badkey",
    "tsig/axfr-unsigned",
    "probe/edns",
    "probe/tcp-dnskey",
    "probe/tsig-badsig",
    "probe/tsig-badkey",
    "probe/tkey",
    "probe/tkey-dh",
    "probe/axfr-sha384",
    "probe/update",
    "probe/sig0",
    "resolver-upstream/ed25519-nsec",
] + ["tsig/soa-" + h for h in HMACS] + ["probe/tsig-" + h for h in HMACS]

# Single responses also kept as tests/corpus/<name>.hex, for the corpus
# tests (corpus.rs, serde.rs, dig_display.rs): name -> (label, which
# response of the exchange).
TOPLEVEL = {
    "named-ci-ed448-nsec3-nxdomain": ("named/ed448-nsec3.interop/nxdomain", -1),
    "named-ci-rsasha1-nsec-wildcard": ("named/rsasha1-nsec.interop/wildcard", -1),
    "named-ci-ecdsap384-optout-referral": ("named/ecdsap384-optout.interop/referral-insecure", -1),
    "named-ci-nsec3rsasha1-nsec3-dname": ("named/nsec3rsasha1-nsec3.interop/dname", -1),
    "named-ci-cookie-subnet-expire": ("named/edns/all", -1),
    "named-ci-padding-tcp": ("named/edns/padding-tcp", -1),
    "named-ci-keepalive": ("named/edns/keepalive", -1),
    "named-ci-badvers": ("named/edns/version1-nonegotiation", -1),
    "named-ci-subnet6": ("named/edns/subnet6", -1),
    "named-ci-chaos-version": ("named/chaos/version.bind", -1),
    "named-ci-truncated": ("named/transport/truncated", -1),
    "named-ci-dsync": ("named/newtypes/dsync", -1),
    "named-ci-doa": ("named/newtypes/doa", -1),
    "named-ci-drafttypes-iso": ("named/drafttypes/iso-generic", -1),
    "named-ci-drafttypes-cla": ("named/drafttypes/cla-generic", -1),
    "named-ci-tkey": ("named/probe/tkey", -1),
    "named-ci-tkey-dh": ("named/probe/tkey-dh/exchange", -1),
    "named-ci-resolver-secure": ("resolver/ed25519-nsec/a/answer", -1),
    "named-ci-resolver-nxdomain": ("resolver/ed448-nsec3/nxdomain/answer", -1),
    "named-ci-resolver-insecure": ("resolver/insecure/a/answer", -1),
    "named-ci-resolver-bogus": ("resolver/bogus/rdata/answer", -1),
}


def version(src):
    with open(os.path.join(src, "versions.txt")) as f:
        for line in f:
            if line.startswith("BIND "):
                return "named " + line.split()[1]
    return "named"


def toplevel(src, run, dig=True):
    corpus = os.path.dirname(HERE)
    named = version(src)
    for name, (label, which) in TOPLEVEL.items():
        d = os.path.join(src, label)
        responses = sorted(f for f in os.listdir(d) if f.endswith("-r.hex"))
        with open(os.path.join(d, responses[which])) as f:
            hexdigits = "".join(l.strip() for l in f if not l.startswith("#"))
        try:
            with open(os.path.join(d, "command.txt")) as f:
                command = f.read().strip()
        except FileNotFoundError:
            command = "examples/bind_probe.rs, " + label.split("/", 2)[2]
        server = named + (" (validating resolver)" if label.startswith("resolver/") else "")
        with open(os.path.join(corpus, name + ".hex"), "w") as f:
            f.write("# %s on the interop CI runner (%s): %s\n" % (server, run, command))
            f.write("# tests/corpus/bind/keep.py from %s (tests/corpus/README.md)\n" % label)
            for i in range(0, len(hexdigits), 96):
                f.write(hexdigits[i:i + 96] + "\n")
        # dig's rendering of it, if the run made one (its workflow renders
        # the kept files that have none).
        rendered = os.path.join(src, "dig", name + ".dig")
        if dig and os.path.exists(rendered):
            shutil.copy(rendered, os.path.join(os.path.dirname(corpus), "data", "dig"))


def copy(src, rel, required=True):
    a, b = os.path.join(src, rel), os.path.join(HERE, rel)
    if os.path.isdir(a):
        shutil.copytree(a, b)
    elif os.path.exists(a):
        os.makedirs(os.path.dirname(b), exist_ok=True)
        shutil.copy(a, b)
    elif required:
        sys.exit("missing in the run: " + rel)


def main():
    if sys.argv[1] == "--toplevel":
        # Only the single responses, for dig to render on the runner.
        src = sys.argv[2]
        toplevel(src, sys.argv[3] if len(sys.argv) > 3 else "interop run", dig=False)
        print(" ".join(TOPLEVEL))
        return
    src = sys.argv[1]
    run = sys.argv[2] if len(sys.argv) > 2 else "interop run"
    for name in os.listdir(HERE):
        if name in KEEP_SCRIPTS:
            continue
        path = os.path.join(HERE, name)
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.remove(path)

    for rel in ["versions.txt", "now", "anchor.ds", "algorithms.txt", "alltypes-omitted.txt",
                "newtypes-omitted.txt", "drafttypes-omitted.txt", "zones/bulk.interop.zone",
                "zones/newtypes.example.zone", "zones/drafttypes.example.zone",
                "zones/alltypes.example.zone", "sig0", "tkey"]:
        copy(src, rel)
    for z in ZONES:
        copy(src, "zones/%s.zone" % z)
        copy(src, "ds/%s.ds" % z)
        copy(src, "keys/" + z)
    for name in COMPILED + ["alltypes", "newtypes", "drafttypes.example", "bulk.interop"]:
        for style in ("full", "relative"):
            copy(src, "compiled/%s.%s" % (name, style))
            copy(src, "compiled/%s.%s.omitted" % (name, style), required=False)
    for rel in NAMED:
        copy(src, "named/" + rel)
    for z in DNSBOX:
        copy(src, "dnsbox/%s.zone" % z)
        for style in ("full", "relative"):
            copy(src, "dnsbox-compiled/%s.%s" % (z, style))
        copy(src, "checks/dnsbox-%s.dnssec-verify" % z)

    with open(os.path.join(src, "manifest.txt")) as f:
        manifest = [l for l in f if l.split()[0].rstrip(".") in ZONES]
    with open(os.path.join(HERE, "manifest.txt"), "w") as f:
        f.writelines(manifest)

    # The resolver: the cases of the kept zones (their zone, or the
    # unsigned zone below one of them).
    cases = []
    with open(os.path.join(src, "resolver", "cases.txt")) as f:
        for line in f:
            case = line.split()[0]
            if case.split("/")[0] in RESOLVER_ZONES + ["bogus", "insecure", "parent"]:
                cases.append(line)
                copy(src, "resolver/" + case)
    with open(os.path.join(HERE, "resolver", "cases.txt"), "w") as f:
        f.writelines(cases)
    copy(src, "resolver/extra")
    copy(src, "resolver/probe")
    toplevel(src, run)


if __name__ == "__main__":
    main()
