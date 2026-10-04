#!/usr/bin/env python3
"""Captures responses of a local named serving the zones of gen.sh.

    python3 tests/corpus/bind9/capture_local.py PORT

For every signed zone <alg>.example it sends the queries in CASES (DO bit
set, EDNS buffer 1232, retried over TCP when truncated) and writes each
response to tests/corpus/named-<alg>-<case>.hex, in the corpus format of
../capture.py, with dig's rendering of it (../dig_reference.py). It also
transfers alltypes.example (AXFR over TCP) into named-alltypes-axfr.hex.
Only the Python standard library (and dig) is used.
"""

import datetime
import os
import random
import socket
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.dirname(HERE)
sys.path.insert(0, CORPUS)
sys.dont_write_bytecode = True
import dig_reference  # noqa: E402 (tests/corpus/dig_reference.py)

ZONES = ["rsasha1", "nsec3rsasha1", "rsasha256", "rsasha512",
         "ecdsap256", "ecdsap384", "ed25519", "ed448"]

# (case, name relative to the zone, type)
CASES = [
    ("dnskey", "", "DNSKEY"),
    ("soa", "", "SOA"),
    ("nxdomain", "nosuch", "A"),
    ("nodata", "www", "MX"),
    ("ent", "b.ent", "A"),
    ("wildcard", "host.wild", "A"),
    ("wildcard-nodata", "host.wild", "MX"),
    ("cname", "alias", "A"),
    ("dname", "x.dname", "A"),
    ("referral-secure", "host.secure", "A"),
    ("referral-insecure", "host.insecure", "A"),
    ("ds-unsigned", "other", "DS"),
]

TYPES = {"A": 1, "SOA": 6, "MX": 15, "DS": 43, "DNSKEY": 48, "AXFR": 252}


def encode_name(name):
    out = b""
    for label in name.strip(".").split("."):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b"\0"


def query(qname, qtype, edns=True):
    qid = random.getrandbits(16)
    header = struct.pack(">HHHHHH", qid, 0, 1, 0, 0, 1 if edns else 0)
    msg = header + encode_name(qname) + struct.pack(">HH", TYPES[qtype], 1)
    if edns:
        msg += b"\0" + struct.pack(">HHIH", 41, 1232, 0x8000, 0)
    return msg


def tcp_messages(port, msg):
    """Sends `msg` over TCP and yields the responses (until EOF or two
    seconds of silence)."""
    with socket.create_connection(("127.0.0.1", port), timeout=2) as t:
        t.sendall(struct.pack(">H", len(msg)) + msg)
        buf = b""
        while True:
            try:
                chunk = t.recv(65535)
            except TimeoutError:
                break
            if not chunk:
                break
            buf += chunk
            while len(buf) >= 2 and len(buf) >= 2 + struct.unpack(">H", buf[:2])[0]:
                n = struct.unpack(">H", buf[:2])[0]
                yield buf[2:2 + n]
                buf = buf[2 + n:]


def exchange(port, msg):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(4)
        s.sendto(msg, ("127.0.0.1", port))
        resp, _ = s.recvfrom(65535)
    if resp[2] & 0x02:
        return next(tcp_messages(port, msg)), "TCP (UDP response was truncated)"
    return resp, "UDP"


def write(label, lines, resp):
    hexed = resp.hex()
    lines = lines + [hexed[i:i + 64] for i in range(0, len(hexed), 64)]
    with open(os.path.join(CORPUS, label + ".hex"), "w") as f:
        f.write("\n".join(lines) + "\n")


def main():
    port = int(sys.argv[1])
    today = datetime.date.today().isoformat()
    version = subprocess.run(["named", "-v"], capture_output=True, text=True).stdout.strip()
    for zone in ZONES:
        for case, rel, qtype in CASES:
            qname = f"{rel}.{zone}.example." if rel else f"{zone}.example."
            resp, transport = exchange(port, query(qname, qtype))
            label = f"named-{zone}-{case}"
            write(label, [
                "# dnsbox interop corpus: a real DNS response, unmodified.",
                f"# server:   127.0.0.1 ({version}, local; tests/corpus/bind9/gen.sh)",
                f"# zone:     tests/corpus/bind9/{zone}.signed",
                f"# query:    {qname} IN {qtype} (options: DO)",
                f"# captured: {today} over {transport}, {len(resp)} bytes",
            ], resp)
            print(f"{label}: {len(resp)} bytes, rcode {resp[3] & 15}")
            dig_reference.render(label)
    msgs = list(tcp_messages(port, query("alltypes.example.", "AXFR", edns=False)))
    assert len(msgs) == 1, f"AXFR took {len(msgs)} messages"
    write("named-alltypes-axfr", [
        "# dnsbox interop corpus: a real DNS response, unmodified.",
        f"# server:   127.0.0.1 ({version}, local; tests/corpus/bind9/gen.sh)",
        "# zone:     tests/corpus/bind9/alltypes.zone",
        "# query:    alltypes.example. IN AXFR (options: none)",
        f"# captured: {today} over TCP, {len(msgs[0])} bytes",
    ], msgs[0])
    print(f"named-alltypes-axfr: {len(msgs[0])} bytes")


if __name__ == "__main__":
    main()
