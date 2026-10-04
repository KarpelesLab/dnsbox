#!/usr/bin/env python3
"""A recording DNS proxy for the Knot/Unbound interop run (CI only).

    python3 proxy.py LISTEN_PORT UPSTREAM_HOST UPSTREAM_PORT OUT_DIR LABEL_FILE

Listens on 127.0.0.1:LISTEN_PORT (UDP and TCP) and forwards everything to
UPSTREAM, unchanged. Every message that passes is also written to
OUT_DIR/<label>/NN-<udp|tcp>-<q|r>.hex (NN counts the messages of that
label; q: client to server, r: server to client), where <label> is the
first line of LABEL_FILE when the datagram or connection arrives. The
files have the format of tests/corpus/*.hex: `#` comment lines, then the
message in hex.

TCP messages are split on their RFC 1035 §4.2.2 length prefix, so a zone
transfer gives one file per message. Python standard library only.
"""

import os
import socket
import struct
import sys
import threading
import time

LOCK = threading.Lock()
COUNTERS = {}


def label(label_file):
    try:
        with open(label_file) as f:
            return f.readline().strip() or "unlabelled"
    except OSError:
        return "unlabelled"


def record(out_dir, lab, transport, direction, wire):
    with LOCK:
        n = COUNTERS.get(lab, 0) + 1
        COUNTERS[lab] = n
    path = os.path.join(out_dir, lab)
    os.makedirs(path, exist_ok=True)
    name = os.path.join(path, "%02d-%s-%s.hex" % (n, transport, direction))
    when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open(name, "w") as f:
        f.write("# %s %s %s, %s\n" % (lab, transport,
                                       "query" if direction == "q" else "response", when))
        h = wire.hex()
        for i in range(0, len(h), 96):
            f.write(h[i:i + 96] + "\n")


def udp_exchange(sock, data, client, upstream, out_dir, lab):
    record(out_dir, lab, "udp", "q", data)
    up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    up.settimeout(5)
    try:
        up.sendto(data, upstream)
        # Forward every datagram the server sends for this query until it
        # goes quiet (one, normally).
        while True:
            reply, _ = up.recvfrom(65535)
            record(out_dir, lab, "udp", "r", reply)
            sock.sendto(reply, client)
            up.settimeout(0.3)
    except socket.timeout:
        pass
    finally:
        up.close()


def serve_udp(port, upstream, out_dir, label_file):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    while True:
        data, client = sock.recvfrom(65535)
        lab = label(label_file)
        threading.Thread(target=udp_exchange,
                         args=(sock, data, client, upstream, out_dir, lab),
                         daemon=True).start()


def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def pump(src, dst, out_dir, lab, direction):
    try:
        while True:
            head = recv_exact(src, 2)
            if head is None:
                break
            (n,) = struct.unpack("!H", head)
            body = recv_exact(src, n)
            if body is None:
                break
            record(out_dir, lab, "tcp", direction, body)
            dst.sendall(head + body)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def tcp_connection(conn, upstream, out_dir, lab):
    try:
        up = socket.create_connection(upstream, timeout=10)
    except OSError:
        conn.close()
        return
    up.settimeout(None)
    conn.settimeout(None)
    t = threading.Thread(target=pump, args=(up, conn, out_dir, lab, "r"), daemon=True)
    t.start()
    pump(conn, up, out_dir, lab, "q")
    t.join(timeout=30)
    conn.close()
    up.close()


def serve_tcp(port, upstream, out_dir, label_file):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(64)
    while True:
        conn, _ = srv.accept()
        lab = label(label_file)
        threading.Thread(target=tcp_connection, args=(conn, upstream, out_dir, lab),
                         daemon=True).start()


def main():
    port = int(sys.argv[1])
    upstream = (sys.argv[2], int(sys.argv[3]))
    out_dir, label_file = sys.argv[4], sys.argv[5]
    os.makedirs(out_dir, exist_ok=True)
    threading.Thread(target=serve_udp, args=(port, upstream, out_dir, label_file),
                     daemon=True).start()
    serve_tcp(port, upstream, out_dir, label_file)


if __name__ == "__main__":
    main()
