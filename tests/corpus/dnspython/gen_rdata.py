#!/usr/bin/env python3
"""Generates tests/corpus/dnspython/rdata.txt: RDATA in presentation format
and in wire form, both produced by dnspython, for every record type
dnspython implements.

Each example below is read by dnspython (`dns.rdata.from_text`, class IN
unless the entry names another), then written out again as text
(`to_text()`) and as uncompressed wire data (`to_wire()`). The output file
holds one line per example:

    TYPE <TAB> CLASS <TAB> dnspython text <TAB> wire hex

`tests/interop_dnspython.rs` reads it back with dnsbox in both directions.

    python3 tests/corpus/dnspython/gen_rdata.py          # regenerate, check
    python3 tests/corpus/dnspython/gen_rdata.py --check  # only check

The check is the reverse direction: rdata.dnsbox.txt is dnsbox's own
presentation of every wire example, in the same layout (written by
`DNSBOX_WRITE_DNSPYTHON=1 cargo test --test interop_dnspython`; rerun that
after changing the examples). Each of dnsbox's texts must be accepted by
dnspython and produce the same wire bytes, except for the types in
TEXT_DIFFERS.
"""

import os
import sys

import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.version

HERE = os.path.dirname(os.path.abspath(__file__))

# Types whose text form differs between dnspython and BIND, where dnsbox
# writes BIND's: dnspython cannot read dnsbox's display of these, so the
# check below skips them (TKEY has no zone-file form; BIND writes the key
# and other data sizes, dnspython does not). dnsbox reads both forms, so
# the other direction, dnspython's text read by dnsbox, is checked for
# these types too (tests/interop_dnspython.rs, which also pins dnsbox's
# text for them).
TEXT_DIFFERS = {"TKEY"}

B64_KEY = (
    "AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/"
    "RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68"
    "LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQ"
    "dXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0="
)
ED_KEY = "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4="
SIG = (
    "oJB1W6WNGv+ldvQ3WDG0MQkg5IEhjRipPYGv07h108dUKGMeDPKijVCHX3DDKdfb+v6o"
    "B9wfuh3DTJXUAfI/M0zmO/zz8bW0Rznl8O3tGNazPwQKkRN20XPXV6nwwfoXmJQbsLNrLfkG"
)
HIP_KEY = (
    "AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwkUs7lBu+Up"
    "r1gsNrut79ryra+bSRGQb1slImA8YVJyuIDsj7kwzG7jnERNqnWxZ48AWkskmdHaVDP4BcelrTI3rMXdXF5D"
)

# (type, text) or (type, text, class). Names are absolute so the output
# does not depend on an origin.
EXAMPLES = [
    # RFC 1035
    ("A", "192.0.2.1"),
    ("A", "0.0.0.0"),
    ("A", "255.255.255.255"),
    ("NS", "ns1.example."),
    ("CNAME", "www.example."),
    ("CNAME", "."),
    ("SOA", "ns.example. hostmaster.example. 2026100401 7200 3600 1209600 3600"),
    ("SOA", "a.root-servers.net. nstld.verisign-grs.com. 4294967295 0 0 0 0"),
    ("PTR", "host.example."),
    ("HINFO", '"RFC8482" ""'),
    ("HINFO", '"Generic PC" "Linux \\"6.18\\""'),
    ("MX", "10 mail.example."),
    ("MX", "0 ."),
    ("TXT", '"v=spf1 -all"'),
    ("TXT", '"hello" "world" ""'),
    ("TXT", '"semi;colon" "back\\\\slash" "tab\\009" "utf8 \\195\\169"'),
    ("TXT", '"' + "x" * 255 + '"'),
    ("SPF", '"v=spf1 ip4:192.0.2.0/24 -all"'),
    ("WKS", "10.0.0.1 6 25 80 443"),
    ("WKS", "192.0.2.1 17 53"),
    # RFC 1183, RFC 1706, RFC 1712
    ("RP", "mbox.example. txt.example."),
    ("RP", ". ."),
    ("AFSDB", "1 afs.example."),
    ("X25", '"311061700956"'),
    ("ISDN", '"150862028003217" "004"'),
    ("ISDN", '"150862028003217"'),
    ("RT", "10 relay.example."),
    ("NSAP", "0x47.0005.80.005a00.0000.0001.e133.ffffff000161.00"),
    ("NSAP-PTR", "foo.example."),
    ("PX", "10 map822.example. mapx400.example."),
    ("GPOS", "-32.6882 116.8652 10.0"),
    # RFC 3596, RFC 1876, RFC 2782, RFC 3403, RFC 2230
    ("AAAA", "2001:db8::1"),
    ("AAAA", "::"),
    ("AAAA", "::ffff:192.0.2.1"),
    ("LOC", "52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m"),
    ("LOC", "42 21 54 N 71 06 18 W -24m 30m"),
    ("LOC", "0 0 0.000 S 0 0 0.000 W 0m"),
    ("LOC", "90 0 0 N 180 0 0 E 42849672.95m 90000000m 90000000m 90000000m"),
    ("SRV", "10 60 5060 sip.example."),
    ("SRV", "0 0 0 ."),
    ("NAPTR", '100 10 "S" "SIP+D2U" "" _sip._udp.example.'),
    ("NAPTR", '100 50 "u" "E2U+sip" "!^.*$!sip:info@example.com!" .'),
    ("KX", "10 kx.example."),
    # RFC 4398, RFC 4701, RFC 3123, RFC 4025
    ("CERT", "1 12345 8 MIIBkjCB/KADAgECAgEAMA0GCSqGSIb3DQEBBQUA"),
    ("CERT", "PGP 0 0 AQID"),
    ("CERT", "65535 65535 255 AQID"),
    # dnspython's own spellings of algorithms 4, 6, 7 and 12.
    ("CERT", "SPKI 1 4 AQID"),
    ("CERT", "IPGP 1 6 AQID"),
    ("CERT", "ACPKIX 1 7 AQID"),
    ("CERT", "OID 1 12 AQID"),
    ("CERT", "URI 1 15 AQID"),
    ("DHCID", "AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA="),
    ("APL", "1:192.168.32.0/21 !1:192.168.38.0/28"),
    ("APL", "1:224.0.0.0/4 2:ff00::/8"),
    ("APL", "1:0.0.0.0/0 !2:2001:db8::/32"),
    ("APL", ""),
    ("IPSECKEY", "10 0 2 . AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ=="),
    ("IPSECKEY", "10 1 2 192.0.2.38 AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ=="),
    ("IPSECKEY", "10 2 2 2001:db8:0:8002::2000:1 AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ=="),
    ("IPSECKEY", "10 3 2 mygateway.example. AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ=="),
    # DNSSEC: RFC 4034, RFC 5155, RFC 7344, RFC 8078, RFC 4431
    ("DS", "60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118"),
    ("DS", "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"),
    ("DS", "12345 13 4 " + "AB" * 48),
    ("DLV", "60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118"),
    ("CDS", "60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118"),
    ("CDS", "0 0 0 00"),
    ("DNSKEY", "257 3 8 " + B64_KEY),
    ("DNSKEY", "256 3 15 " + ED_KEY),
    ("DNSKEY", "385 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=="),
    ("CDNSKEY", "257 3 15 " + ED_KEY),
    ("CDNSKEY", "0 3 0 AA=="),
    ("RRSIG", "A 5 3 86400 20030322173103 20030220173103 2642 example.com. " + SIG),
    ("RRSIG", "TYPE65534 15 0 0 20261004090347 20261004085347 43160 . " + SIG),
    ("RRSIG", "NSEC3 13 2 3600 20380119031407 19700101000000 1 example. AAAA"),
    ("NSEC", "host.example.com. A MX RRSIG NSEC TYPE1234"),
    ("NSEC", "\\000.example. NS SOA RRSIG NSEC DNSKEY TYPE65534"),
    ("NSEC", "a.example. CAA"),
    ("NSEC", "b.example."),
    ("NSEC3", "1 1 12 aabbccdd 2t7b4g4vsa5smi47k61mv5bv1a22bojr MX DNSKEY NS SOA NSEC3PARAM RRSIG"),
    ("NSEC3", "1 0 0 - 2t7b4g4vsa5smi47k61mv5bv1a22bojr"),
    ("NSEC3", "1 1 0 - 2t7b4g4vsa5smi47k61mv5bv1a22bojr A RRSIG"),
    ("NSEC3PARAM", "1 0 12 aabbccdd"),
    ("NSEC3PARAM", "1 0 0 -"),
    # RFC 4255, RFC 6698, RFC 8162, RFC 7929, RFC 6672, RFC 7553
    ("SSHFP", "4 2 123456789ABCDEF67890123456789ABCDEF67890123456789ABCDEF123456789"),
    ("SSHFP", "1 1 DC2A7A1F15B1BA1F4E5D2D8A6E7E4F7E3B1C2D3E"),
    ("TLSA", "3 1 1 0C72AC70B745AC19998811B131D662C9AC69DBDBE7CB23E5B514B56664C5D3D6"),
    ("TLSA", "0 0 0 30820122300D06092A864886F70D01010105000382010F003082010A"),
    ("SMIMEA", "3 0 1 " + "AB" * 32),
    ("OPENPGPKEY", "mQINBFit2jsBEADrbl5vjVxYeAE0g0IDYCBpHirv1Sjlqxx5gjtPhb2YhvyDMXjq"),
    ("DNAME", "example.net."),
    ("URI", '10 1 "ftp://ftp1.example.com/public"'),
    # (dnspython 2.8 writes quotes and backslashes inside a URI target
    # unescaped, so its output does not read back; such targets are left
    # out.)
    ("URI", '0 0 "https://example.com/a b;c"'),
    # RFC 7043, RFC 6742, RFC 7477, RFC 8976, RFC 8005
    ("EUI48", "00-00-5e-00-53-2a"),
    ("EUI64", "00-00-5e-ef-10-00-00-2a"),
    ("NID", "10 0014:4fff:ff20:ee64"),
    ("L32", "10 10.1.2.0"),
    ("L64", "10 2001:0db8:1140:1000"),
    ("LP", "10 l64-subnet1.example."),
    ("CSYNC", "66 3 A NS AAAA"),
    ("CSYNC", "0 0"),
    ("ZONEMD", "2018031900 1 1 FEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEE7EB1A7B641A47BA7FED2DD5B97AE499FAFA4F22C6BD647DE"),
    ("ZONEMD", "2018031900 1 2 " + "AB" * 64),
    # Unassigned scheme and algorithm, shortest digest allowed (12 octets,
    # RFC 8976 §2.2.4; dnspython would also take shorter ones, dnsbox and
    # BIND reject them).
    ("ZONEMD", "1 240 241 000102030405060708090A0B"),
    ("HIP", "2 200100107B1A74DF365639CC39F1D578 " + HIP_KEY),
    ("HIP", "2 200100107B1A74DF365639CC39F1D578 " + HIP_KEY + " rvs.example.com. rvs2.example.com."),
    # RFC 9460, RFC 9461, RFC 9540
    ("SVCB", "0 svc.example."),
    ("SVCB", "1 ."),
    ("SVCB", "16 foo.example.org. alpn=h2,h3-19 mandatory=ipv4hint,alpn ipv4hint=192.0.2.1"),
    ("SVCB", "1 foo.example.com. port=53"),
    ("SVCB", "1 foo.example.com. key667=hello"),
    ("SVCB", '1 foo.example.com. key667="hello\\210qoo"'),
    ("SVCB", "1 foo.example.com. ipv6hint=2001:db8::1,2001:db8::53:1"),
    ("SVCB", "1 example.com. ipv6hint=::ffff:198.51.100.100"),
    # RFC 9460 Appendix D.2, Figure 9: a value list with escapes on both
    # levels: the values are `f\oo,bar` and `h2`.
    ("SVCB", r'16 foo.example.org. alpn="f\\\\oo\\,bar,h2"'),
    ("SVCB", "1 dot.example. alpn=dot no-default-alpn port=853 ech=AEX+DQBBpQAgACCW2/dfOBZAtQU55/KYxUYStyuA6Yg+1Sjqb4o1q7HY0wAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="),
    ("SVCB", "1 doh.example. alpn=h2 dohpath=/dns-query{?dns}"),
    ("SVCB", "1 . ohttp"),
    ("HTTPS", "1 . alpn=h3,h2 ipv4hint=104.16.132.229,104.16.133.229 ipv6hint=2606:4700::6810:84e5,2606:4700::6810:85e5"),
    ("HTTPS", "0 cdn.example."),
    ("HTTPS", "1 . alpn=h2 ech=AEX+DQBBpQAgACCW2/dfOBZAtQU55/KYxUYStyuA6Yg+1Sjqb4o1q7HY0wAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="),
    # RFC 8659
    ("CAA", '0 issue "letsencrypt.org"'),
    ("CAA", '128 tbs "Unknown"'),
    ("CAA", '0 iodef "mailto:security@example.com"'),
    ("CAA", '0 issuewild ";"'),
    ("CAA", '0 issue "ca.example.net; account=230123"'),
    # Others
    ("AVC", '"app-name:WOLFGANG|app-class:OAM|business=yes"'),
    ("NINFO", '"Zone Status" "OK"'),
    ("RESINFO", "qnamemin exterr=15,16,17 infourl=https://resolver.example.com/guide"),
    ("WALLET", '"BTC" "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"'),
    ("TSIG", "hmac-sha256. 1791104299 300 32 " + "A" * 43 + "= 4660 NOERROR 0"),
    ("TSIG", "hmac-md5.sig-alg.reg.int. 1791104299 300 16 AAAAAAAAAAAAAAAAAAAAAA== 1 BADTIME 6 AABqwhUr"),
    # RFC 8777, RFC 9859, RFC 2930 (TKEY: dnspython writes no key/other
    # sizes, dnsbox reads that and writes BIND's form; see TEXT_DIFFERS)
    ("AMTRELAY", "0 0 0 ."),
    ("AMTRELAY", "128 1 1 203.0.113.15"),
    ("AMTRELAY", "10 0 2 2001:db8::15"),
    ("AMTRELAY", "128 1 3 amtrelays.example.com."),
    ("DSYNC", "CDS 1 5359 cds-scanner.example.net."),
    ("TKEY", "gss-tsig. 1791104299 1791107899 3 0 AAEC"),
    ("TKEY", "hmac-sha256. 1791104299 1791107899 2 17 AAEC AQID"),
    # A BIND-style 16-octet Diffie-Hellman nonce; a key whose base64 is all
    # digits (dnsbox must not take it for BIND's key size); GSS-API
    # zero times with a long token and other data.
    ("TKEY", "hmac-md5.sig-alg.reg.int. 1791104299 1791190699 2 0 ESIzRFVmd4iZqrvM3e7/AA=="),
    ("TKEY", "server.example. 1791104299 1791107899 1 0 12345678"),
    ("TKEY", "gss-tsig. 0 0 3 0 YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGhw== AQIDBAUGBwg="),
    ("A", "chaos.example. 1234", "CH"),
]


def main():
    out = [
        f"# Generated by gen_rdata.py with dnspython {dns.version.version}:",
        "# TYPE<TAB>CLASS<TAB>dnspython to_text()<TAB>dnspython to_wire() in hex",
    ]
    for entry in EXAMPLES:
        rtype, text = entry[0], entry[1]
        rclass = entry[2] if len(entry) > 2 else "IN"
        rd = dns.rdata.from_text(
            dns.rdataclass.from_text(rclass), dns.rdatatype.from_text(rtype), text
        )
        shown = rd.to_text()
        assert "\t" not in shown and "\n" not in shown, (rtype, shown)
        wire = rd.to_wire()
        # dnspython must read its own output back to the same bytes.
        again = dns.rdata.from_text(rd.rdclass, rd.rdtype, shown)
        assert again.to_wire() == wire, (rtype, text)
        out.append(f"{rtype}\t{rclass}\t{shown}\t{wire.hex()}")
    with open(os.path.join(HERE, "rdata.txt"), "w") as f:
        f.write("\n".join(out) + "\n")
    print(f"{len(EXAMPLES)} examples")


def check(path):
    """Reads dnsbox's presentation of every example back with dnspython."""
    bad = 0
    n = 0
    with open(path) as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            rtype, rclass, text, hexed = line.rstrip("\n").split("\t")
            if rtype in TEXT_DIFFERS:
                continue
            n += 1
            try:
                rd = dns.rdata.from_text(
                    dns.rdataclass.from_text(rclass), dns.rdatatype.from_text(rtype), text
                )
                wire = rd.to_wire().hex()
            except Exception as e:  # noqa: BLE001 - report every failure
                wire = f"error: {e}"
            if wire != hexed:
                bad += 1
                print(f"{rtype} {text!r}\n  dnspython: {wire}\n  expected:  {hexed}")
    print(f"{n - bad} of {n} dnsbox texts read back identically by dnspython")
    return bad == 0


if __name__ == "__main__":
    if sys.argv[1:] != ["--check"]:
        main()
    sys.exit(0 if check(os.path.join(HERE, "rdata.dnsbox.txt")) else 1)
