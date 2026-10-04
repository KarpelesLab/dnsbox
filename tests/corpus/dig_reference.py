#!/usr/bin/env python3
"""Writes BIND dig's rendering of corpus messages to tests/data/dig/.

    python3 tests/corpus/dig_reference.py LABEL...   # these corpus files
    python3 tests/corpus/dig_reference.py --missing  # every one without

For each tests/corpus/LABEL.hex, a local UDP responder answers dig's query
for the message's question with the stored message (its ID set to dig's),
and the output of `dig +nocookie +notcp +ignore` (+notcp: dig 9.18 sends
ANY queries over TCP otherwise) from the `;; ->>HEADER<<-` line up to the
statistics is saved as tests/data/dig/LABEL.dig, with the ID put back.
Zone transfers are skipped. tests/dig_display.rs compares dnsbox's
`Display` of every message with these files. Needs dig (BIND 9.18) and the
Python standard library.
"""

import os
import socket
import struct
import subprocess
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
DIG_DIR = os.path.join(os.path.dirname(HERE), "data", "dig")


def load(label):
    with open(os.path.join(HERE, label + ".hex")) as f:
        digits = "".join(line.strip() for line in f if not line.startswith("#"))
    return bytes.fromhex(digits)


def question(wire):
    """The first question as (name, type, class) in dig's syntax."""
    labels, i = [], 12
    while wire[i]:
        n = wire[i]
        labels.append(wire[i + 1:i + 1 + n])
        i += 1 + n
    qtype, qclass = struct.unpack(">HH", wire[i + 1:i + 5])
    name = ".".join(
        "".join(chr(c) if 0x21 <= c <= 0x7e and c not in b'.\\();"$@' else f"\\{c:03d}"
                for c in label)
        for label in labels) + "."
    return name, f"TYPE{qtype}", f"CLASS{qclass}"


def render(label):
    wire = load(label)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]

    sock.settimeout(5)

    def serve():
        try:
            q, addr = sock.recvfrom(65535)
        except TimeoutError:
            return
        sock.sendto(q[:2] + wire[2:], addr)

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    name, qtype, qclass = question(wire)
    out = subprocess.run(
        ["dig", "+nocookie", "+notcp", "+ignore", "+tries=1", "+time=3", "-p", str(port), "@127.0.0.1",
         name, qtype, qclass],
        capture_output=True, text=True, check=True).stdout
    t.join()
    sock.close()
    lines = out.splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith(";; ->>HEADER<<-"))
    end = next(i for i, l in enumerate(lines) if l.startswith(";; Query time:"))
    body = lines[start:end]
    while body and not body[-1].strip():
        body.pop()
    qid = struct.unpack(">H", wire[:2])[0]
    head = body[0].rsplit("id: ", 1)
    body[0] = f"{head[0]}id: {qid}"
    with open(os.path.join(DIG_DIR, label + ".dig"), "w") as f:
        f.write("\n".join(body) + "\n")
    print(f"{label}: {len(body)} lines")


def main():
    args = sys.argv[1:]
    if args == ["--missing"]:
        have = {f[:-4] for f in os.listdir(DIG_DIR) if f.endswith(".dig")}
        args = sorted(f[:-4] for f in os.listdir(HERE)
                      if f.endswith(".hex") and f[:-4] not in have)
        # dig transfers zones over TCP and shows them differently.
        args = [a for a in args if question(load(a))[1] not in ("TYPE251", "TYPE252")]
    for label in args:
        try:
            render(label)
        except (subprocess.CalledProcessError, OSError, StopIteration) as e:
            print(f"{label}: no reference ({e})", file=sys.stderr)


if __name__ == "__main__":
    main()
