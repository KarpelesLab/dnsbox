#!/usr/bin/env python3
"""Captures the dnsbox interop corpus: real DNS responses from real servers.

Each entry below sends one query (UDP, retried over TCP when the response is
truncated, unless the entry asks to keep the truncated UDP answer) and
writes the raw response as `tests/corpus/<label>.hex`: a few `#` comment
lines saying where it came from, then the message in hex. Only the Python
standard library is used.

    python3 tests/corpus/capture.py            # (re)capture everything
    python3 tests/corpus/capture.py bind-      # only labels starting so

Responses change over time (TTLs, signatures, addresses), so re-capturing
rewrites the files; `tests/corpus.rs` only checks properties that hold for
any valid message, so a fresh capture never needs test changes.
"""

import datetime
import os
import random
import socket
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# (label, server, server software as identified by CHAOS TXT queries,
#  qname, qtype, options). Options: "rd" recursion desired, "do" DNSSEC OK,
#  "nsid" request NSID (RFC 5001), "cookie" send a client cookie (RFC 7873),
#  "noedns" plain RFC 1035 query, "tc" keep the truncated UDP response,
#  "ch" CHAOS class.
ENTRIES = [
    # BIND 9 (authoritative), DNSSEC-signed isc.org.
    ("bind-isc-soa-dnssec", "ns1.isc.org", "BIND 9.20", "isc.org", "SOA", "do nsid cookie"),
    ("bind-isc-dnskey", "ns1.isc.org", "BIND 9.20", "isc.org", "DNSKEY", "do"),
    ("bind-isc-mx", "ns1.isc.org", "BIND 9.20", "isc.org", "MX", "do"),
    ("bind-isc-ns", "ns1.isc.org", "BIND 9.20", "isc.org", "NS", ""),
    ("bind-isc-txt", "ns1.isc.org", "BIND 9.20", "isc.org", "TXT", ""),
    ("bind-isc-nxdomain", "ns1.isc.org", "BIND 9.20", "no-such-name.isc.org", "A", "do"),
    ("bind-isc-nodata", "ns1.isc.org", "BIND 9.20", "isc.org", "NAPTR", "do"),
    ("bind-isc-version-chaos", "ns1.isc.org", "BIND 9.20", "version.bind", "TXT", "ch"),
    ("bind-isc-noedns", "ns1.isc.org", "BIND 9.20", "www.isc.org", "AAAA", "noedns"),
    ("bind-isc-any-rfc8482", "ns1.isc.org", "BIND 9.20", "isc.org", "ANY", ""),
    ("bind-isc-refused", "ns1.isc.org", "BIND 9.20", "example.net", "A", ""),
    # PowerDNS Authoritative Server.
    ("pdns-auth-soa", "pdns-public-ns1.powerdns.com", "PowerDNS Authoritative 4.9", "powerdns.com", "SOA", "do nsid"),
    ("pdns-auth-dnskey", "pdns-public-ns1.powerdns.com", "PowerDNS Authoritative 4.9", "powerdns.com", "DNSKEY", "do"),
    ("pdns-auth-mx", "pdns-public-ns1.powerdns.com", "PowerDNS Authoritative 4.9", "powerdns.com", "MX", ""),
    ("pdns-auth-nxdomain", "pdns-public-ns2.powerdns.com", "PowerDNS Authoritative 5.1", "no-such-name.powerdns.com", "A", "do"),
    ("pdns-auth-txt", "pdns-public-ns2.powerdns.com", "PowerDNS Authoritative 5.1", "powerdns.com", "TXT", ""),
    # NSD.
    ("nsd-nlnetlabs-soa", "ns.nlnetlabs.nl", "NSD 4.3", "nlnetlabs.nl", "SOA", "do nsid"),
    ("nsd-nlnetlabs-mx", "ns.nlnetlabs.nl", "NSD 4.3", "nlnetlabs.nl", "MX", ""),
    ("nsd-nlnetlabs-nxdomain", "ns.nlnetlabs.nl", "NSD 4.3", "no-such-name.nlnetlabs.nl", "AAAA", "do"),
    ("nsd-kroot-referral-com", "k.root-servers.net", "NSD", "example.com", "A", "do"),
    ("nsd-kroot-dnskey", "k.root-servers.net", "NSD", ".", "DNSKEY", "do"),
    ("nsd-kroot-zonemd", "k.root-servers.net", "NSD", ".", "ZONEMD", "do"),
    ("nsd-kroot-nxdomain", "k.root-servers.net", "NSD", "no-such-tld", "A", "do"),
    ("nsd-kroot-priming", "k.root-servers.net", "NSD", ".", "NS", ""),
    # Knot DNS.
    ("knot-iana-example-soa", "a.iana-servers.net", "Knot DNS 3", "example.com", "SOA", "do nsid"),
    ("knot-iana-example-dnskey", "a.iana-servers.net", "Knot DNS 3", "example.com", "DNSKEY", "do"),
    ("knot-iana-example-nxdomain", "a.iana-servers.net", "Knot DNS 3", "no-such-name.example.com", "A", "do"),
    ("knot-denic-referral", "f.nic.de", "Knot DNS", "denic.de", "NS", "do"),
    ("knot-denic-nxdomain-nsec3", "f.nic.de", "Knot DNS", "no-such-name-dnsbox.de", "A", "do"),
    # Unbound (recursive).
    ("unbound-example-a", "77.88.8.8", "Unbound 1.26", "example.com", "A", "rd"),
    ("unbound-ietf-cname", "77.88.8.8", "Unbound 1.26", "www.ietf.org", "AAAA", "rd do"),
    ("unbound-jabber-srv", "77.88.8.8", "Unbound 1.26", "_xmpp-server._tcp.jabber.org", "SRV", "rd"),
    ("unbound-isc-mx-dnssec", "77.88.8.8", "Unbound 1.26", "isc.org", "MX", "rd do cookie"),
    ("unbound-nxdomain", "77.88.8.8", "Unbound 1.26", "no-such-name.example.com", "A", "rd"),
    # PowerDNS Recursor.
    ("pdns-recursor-cloudflare-https", "185.222.222.222", "PowerDNS Recursor 5.4", "cloudflare.com", "HTTPS", "rd"),
    ("pdns-recursor-google-caa", "185.222.222.222", "PowerDNS Recursor 5.4", "google.com", "CAA", "rd"),
    ("pdns-recursor-ds", "185.222.222.222", "PowerDNS Recursor 5.4", "isc.org", "DS", "rd do"),
    # Knot Resolver (CZ.NIC ODVR).
    ("knot-resolver-nic-dnskey", "193.17.47.1", "Knot Resolver", "nic.cz", "DNSKEY", "rd do"),
    ("knot-resolver-tlsa", "193.17.47.1", "Knot Resolver", "_443._tcp.www.nic.cz", "TLSA", "rd do"),
    ("knot-resolver-aaaa", "193.17.47.1", "Knot Resolver", "www.nic.cz", "AAAA", "rd"),
    # Large public resolvers.
    ("cloudflare-https-ech", "1.1.1.1", "Cloudflare", "crypto.cloudflare.com", "HTTPS", "rd do nsid"),
    ("cloudflare-any-notimp", "1.1.1.1", "Cloudflare", "cloudflare.com", "ANY", "rd"),
    ("cloudflare-naptr", "1.1.1.1", "Cloudflare", "sip2sip.info", "NAPTR", "rd"),
    ("cloudflare-loc", "1.1.1.1", "Cloudflare", "ckdhr.com", "LOC", "rd"),
    ("cloudflare-tc", "1.1.1.1", "Cloudflare", "google.com", "TXT", "rd noedns tc"),
    ("google-txt-large", "8.8.8.8", "Google Public DNS", "google.com", "TXT", "rd"),
    ("google-mx", "8.8.8.8", "Google Public DNS", "gmail.com", "MX", "rd"),
    ("google-cname-chain", "8.8.8.8", "Google Public DNS", "www.microsoft.com", "A", "rd"),
    ("quad9-rrsig", "9.9.9.9", "Quad9", "example.com", "A", "rd do"),
    ("quad9-ptr", "9.9.9.9", "Quad9", "8.8.8.8.in-addr.arpa", "PTR", "rd"),
    ("quad9-aaaa-ptr", "9.9.9.9", "Quad9",
     "1.1.1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.4.0.0.7.4.6.0.6.2.ip6.arpa", "PTR", "rd"),
]

TYPES = {"A": 1, "NS": 2, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28,
         "LOC": 29, "SRV": 33, "NAPTR": 35, "DS": 43, "SSHFP": 44, "DNSKEY": 48,
         "TLSA": 52, "ZONEMD": 63, "HTTPS": 65, "ANY": 255, "CAA": 257}


def encode_name(name):
    out = b""
    for label in name.strip(".").split("."):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b"\0"


def query(qname, qtype, opts):
    qid = random.getrandbits(16)
    flags = 0x0100 if "rd" in opts else 0
    edns = "noedns" not in opts
    header = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 1 if edns else 0)
    qclass = 3 if "ch" in opts else 1
    msg = header + encode_name(qname) + struct.pack(">HH", TYPES[qtype], qclass)
    if edns:
        options = b""
        if "nsid" in opts:
            options += struct.pack(">HH", 3, 0)
        if "cookie" in opts:
            options += struct.pack(">HH", 10, 8) + random.randbytes(8)
        ttl = 0x8000 if "do" in opts else 0
        msg += b"\0" + struct.pack(">HHIH", 41, 1232, ttl, len(options)) + options
    return qid, msg


def resolve(server):
    return socket.getaddrinfo(server, 53, socket.AF_INET, socket.SOCK_DGRAM)[0][4]


def exchange(server, msg, qid, opts):
    addr = resolve(server)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(4)
        s.sendto(msg, addr)
        while True:
            resp, _ = s.recvfrom(65535)
            if resp[:2] == msg[:2]:
                break
    if resp[2] & 0x02 and "tc" not in opts:
        with socket.create_connection(addr, timeout=6) as t:
            t.sendall(struct.pack(">H", len(msg)) + msg)
            data = b""
            while len(data) < 2 or len(data) < 2 + struct.unpack(">H", data[:2])[0]:
                chunk = t.recv(65535)
                if not chunk:
                    break
                data += chunk
        return data[2:], "TCP (UDP response was truncated)"
    return resp, "UDP"


def main():
    prefix = sys.argv[1] if len(sys.argv) > 1 else ""
    today = datetime.date.today().isoformat()
    for label, server, software, qname, qtype, opts in ENTRIES:
        if not label.startswith(prefix):
            continue
        opts = opts.split()
        qid, msg = query(qname, qtype, opts)
        try:
            resp, transport = exchange(server, msg, qid, opts)
        except OSError as e:
            print(f"{label}: {e}", file=sys.stderr)
            continue
        qclass = "CH" if "ch" in opts else "IN"
        flags = " ".join(o.upper() for o in opts) or "none"
        lines = [
            "# dnsbox interop corpus: a real DNS response, unmodified.",
            f"# server:   {server} ({software})",
            f"# query:    {qname}. {qclass} {qtype} (options: {flags})",
            f"# captured: {today} over {transport}, {len(resp)} bytes",
        ]
        hexed = resp.hex()
        lines += [hexed[i:i + 64] for i in range(0, len(hexed), 64)]
        with open(os.path.join(HERE, label + ".hex"), "w") as f:
            f.write("\n".join(lines) + "\n")
        rcode = resp[3] & 0x0F
        an = struct.unpack(">H", resp[6:8])[0]
        print(f"{label}: {len(resp)} bytes, rcode {rcode}, {an} answers, {transport}")


if __name__ == "__main__":
    main()
