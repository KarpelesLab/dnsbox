//! Presentation-format parsing of the location, ILNP, EUI, CSYNC, ZONEMD,
//! APL, IPSECKEY, HIP and legacy record types in a master file
//! (RFC 1035 §5): every record reads, displays as expected, and the
//! displayed zone reads back to the same wire form. The reserved types
//! without a defined format (UINFO, UID, GID, UNSPEC) accept only the
//! RFC 3597 §5 generic form.

use dnsbox::rdata::RData;
use dnsbox::zone::{Scanner, ZoneReader};
use dnsbox::{Class, Error, NameBuf, Rtype, WireWriter};

/// A zone using every covered type, mostly with the examples of their
/// RFCs, in the forms zone files use (relative names, parentheses,
/// comments, split base64 and hex).
const ZONE: &str = r#"
$ORIGIN example.
$TTL 3600
@               SOA     ns hostmaster ( 1 2h 15m 2w 1h )
                NS      ns
ns              A       192.0.2.1
; RFC 1876 §3
cambridge-net   LOC     42 21 54 N 71 06 18 W -24m 30m
loiosh          LOC     ( 42 21 43.952 N 71 5 6.344 W
                          -24m 1m 200m 10m )        ; precisions
; RFC 6742 §2
host1           NID     10 0014:4fff:ff20:ee64
                L32     10 10.1.2.0
                L64     10 2001:0DB8:1140:1000
                LP      10 l64-subnet1
; RFC 7043 §3.2, §4.2
host2           EUI48   00-00-5e-00-53-2a
                EUI64   00-00-5e-ef-10-00-00-2a
; RFC 7477 §2.2
                CSYNC   66 3 A NS AAAA
; RFC 8976 Appendix A.1
@               ZONEMD  2018031900 1 1 (
                        c68090d90a7aed716bc459f9340e3d7c1370d4d24b7e2fc3
                        a1ddc0b9a87153b9a9713b3c9ae5cc27777f98b8e730044c )
; RFC 3123 §5
apl             APL     1:192.168.32.0/21 !1:192.168.38.0/28
                APL     1:224.0.0.0/4 2:FF00:0:0:0:0:0:0:0/8
                APL
; RFC 4025 §3.3
38.2.0.192.in-addr.arpa. IPSECKEY ( 10 1 2
                        192.0.2.38
                        AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ== )
ipsec           IPSECKEY 10 0 2 . AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==
                IPSECKEY 10 3 2 mygateway.example.com. AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==
                IPSECKEY 10 2 2 2001:0DB8:0:8002::2000:1 AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==
; RFC 8005 §6
www             HIP     ( 2 200100107B1A74DF365639CC39F1D578
                        AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwkUs7lBu+Upr1gsNrut79ryra+bSRGQb1slImA8YVJyuIDsj7kwzG7jnERNqnWxZ48AWkskmdHaVDP4BcelrTI3rMXdXF5D
                        rvs.example.com. )
; Legacy types
gpos            GPOS    -32.6882 116.8652 10.0      ; RFC 1712 §3
nsap            NSAP    0x47.0005.80.005a00.0000.0001.e133.ffffff000161.00
1.6.1.0.0.0.f.f.f.f.f.f.3.3.1.e.1.0.0.0.0.0.0.0.0.0.a.5.0.0.0.8.5.0.0.0.7.4 NSAP-PTR host.school.de.
px              PX      50 it. ADMD-garr.C-it.      ; RFC 2163 §4
a6              A6      64 ::2:3:4:5 subnet-1.ip6.a.net.
                A6      0 2001:db8::1
                A6      128 prefix
sink            SINK    1 2 3 AQ ID
rkey            RKEY    0 3 RSASHA256 AQID
talink          TALINK  . next
eid             EID     12 89 AB
nimloc          NIMLOC  1289AB
atma            ATMA    47.0005.80.ffde00.0000.0000.ffff.ffffffffffff.00
                ATMA    +1.2345
spf             SPF     "v=spf1 -all"
ninfo           NINFO   a "b c"
avc             AVC     app
resinfo         RESINFO qnamemin exterr=15,16,17
wallet          WALLET  "x" "y"
; Reserved types without a defined format: generic form only
opaque          UINFO   \# 4 03666F6F
                UID     \# 4 000004D2
                GID     \# 4 000004D2
                UNSPEC  \# 3 616263
                TYPE103 \# 0
"#;

/// What each record of [`ZONE`] displays as.
const EXPECTED: &[&str] = &[
    "example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 900 1209600 3600",
    "example. 3600 IN NS ns.example.",
    "ns.example. 3600 IN A 192.0.2.1",
    "cambridge-net.example. 3600 IN LOC 42 21 54.000 N 71 6 18.000 W -24.00m 30m 10000m 10m",
    "loiosh.example. 3600 IN LOC 42 21 43.952 N 71 5 6.344 W -24.00m 1m 200m 10m",
    "host1.example. 3600 IN NID 10 0014:4fff:ff20:ee64",
    "host1.example. 3600 IN L32 10 10.1.2.0",
    "host1.example. 3600 IN L64 10 2001:0db8:1140:1000",
    "host1.example. 3600 IN LP 10 l64-subnet1.example.",
    "host2.example. 3600 IN EUI48 00-00-5e-00-53-2a",
    "host2.example. 3600 IN EUI64 00-00-5e-ef-10-00-00-2a",
    "host2.example. 3600 IN CSYNC 66 3 A NS AAAA",
    "example. 3600 IN ZONEMD 2018031900 1 1 C68090D90A7AED716BC459F9340E3D7C1370D4D24B7E2FC3A1DDC0B9A87153B9A9713B3C9AE5CC27777F98B8E730044C",
    "apl.example. 3600 IN APL 1:192.168.32.0/21 !1:192.168.38.0/28",
    "apl.example. 3600 IN APL 1:224.0.0.0/4 2:ff00::/8",
    "apl.example. 3600 IN APL ",
    "38.2.0.192.in-addr.arpa. 3600 IN IPSECKEY 10 1 2 192.0.2.38 AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==",
    "ipsec.example. 3600 IN IPSECKEY 10 0 2 . AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==",
    "ipsec.example. 3600 IN IPSECKEY 10 3 2 mygateway.example.com. AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==",
    "ipsec.example. 3600 IN IPSECKEY 10 2 2 2001:db8:0:8002::2000:1 AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==",
    "www.example. 3600 IN HIP 2 200100107B1A74DF365639CC39F1D578 AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwkUs7lBu+Upr1gsNrut79ryra+bSRGQb1slImA8YVJyuIDsj7kwzG7jnERNqnWxZ48AWkskmdHaVDP4BcelrTI3rMXdXF5D rvs.example.com.",
    "gpos.example. 3600 IN GPOS \"-32.6882\" \"116.8652\" \"10.0\"",
    "nsap.example. 3600 IN NSAP 0x47000580005a0000000001e133ffffff00016100",
    "1.6.1.0.0.0.f.f.f.f.f.f.3.3.1.e.1.0.0.0.0.0.0.0.0.0.a.5.0.0.0.8.5.0.0.0.7.4.example. 3600 IN NSAP-PTR host.school.de.",
    "px.example. 3600 IN PX 50 it. ADMD-garr.C-it.",
    "a6.example. 3600 IN A6 64 ::2:3:4:5 subnet-1.ip6.a.net.",
    "a6.example. 3600 IN A6 0 2001:db8::1",
    "a6.example. 3600 IN A6 128 prefix.example.",
    "sink.example. 3600 IN SINK 1 2 3 AQID",
    "rkey.example. 3600 IN RKEY 0 3 8 AQID",
    "talink.example. 3600 IN TALINK . next.example.",
    "eid.example. 3600 IN EID 1289AB",
    "nimloc.example. 3600 IN NIMLOC 1289AB",
    "atma.example. 3600 IN ATMA 47000580ffde0000000000ffffffffffffffff00",
    "atma.example. 3600 IN ATMA +12345",
    "spf.example. 3600 IN SPF \"v=spf1 -all\"",
    "ninfo.example. 3600 IN NINFO \"a\" \"b c\"",
    "avc.example. 3600 IN AVC \"app\"",
    "resinfo.example. 3600 IN RESINFO \"qnamemin\" \"exterr=15,16,17\"",
    "wallet.example. 3600 IN WALLET \"x\" \"y\"",
    "opaque.example. 3600 IN UINFO \\# 4 03666F6F",
    "opaque.example. 3600 IN UID \\# 4 000004D2",
    "opaque.example. 3600 IN GID \\# 4 000004D2",
    "opaque.example. 3600 IN UNSPEC \\# 3 616263",
    "opaque.example. 3600 IN UNSPEC \\# 0",
];

/// Reads `text` (origin `example.`), returning each record's display
/// form and wire RDATA.
fn read(text: &str) -> Vec<(String, Rtype, Vec<u8>)> {
    let origin: NameBuf = "example.".parse().unwrap();
    let mut r = ZoneReader::new(text).with_origin(&origin);
    let mut buf = [0u8; 65535];
    let mut out = Vec::new();
    while let Some(rr) = r.next_record(&mut buf).unwrap_or_else(|e| panic!("{e}")) {
        out.push((rr.to_string(), rr.rtype, rr.rdata.to_vec()));
    }
    out
}

#[test]
fn zone_with_every_type() {
    let records = read(ZONE);
    let shown: Vec<&str> = records.iter().map(|(s, _, _)| s.as_str()).collect();
    assert_eq!(shown, EXPECTED);
    // Every typed record is parsed as its type, not kept opaque.
    for (text, rtype, rdata) in &records {
        let d = RData::parse(*rtype, Class::IN, dnsbox::WireReader::new(rdata)).unwrap();
        assert_eq!(
            matches!(d, RData::Unknown(_)),
            !RData::is_known(*rtype),
            "{text}"
        );
    }
    // The displayed zone reads back to the same records.
    let again = read(&EXPECTED.join("\n"));
    assert_eq!(again, records);
}

#[test]
fn reserved_types_accept_only_the_generic_form() {
    for (rtype, text) in [
        (Rtype::UINFO, "\"foo\""),
        (Rtype::UID, "1234"),
        (Rtype::GID, "1234"),
        (Rtype::UNSPEC, "abc"),
    ] {
        let mut buf = [0u8; 64];
        let mut w = WireWriter::new(&mut buf);
        assert_eq!(
            RData::parse_text(rtype, Class::IN, &mut Scanner::new(text), &mut w),
            Err(Error::NoTextFormat),
            "{rtype}"
        );
        assert!(w.as_bytes().is_empty());
        let d = RData::from_text(rtype, Class::IN, "\\# 2 0102", &mut buf).unwrap();
        assert_eq!(d.to_string(), "\\# 2 0102");
    }
}

#[test]
fn errors_point_at_the_bad_record() {
    let zone = "$ORIGIN example.\n$TTL 60\n\
                a LOC 91 N 0 E 0\n\
                b APL 1:1.2.3.4/33\n\
                c IPSECKEY 10 4 0 .\n\
                d HIP 2 2001 AQID rvs..example.\n\
                e EUI48 00-00-5e-00-53\n\
                f A6 129 x.\n\
                g ZONEMD 1 1 1 0011\n\
                h NSAP 47\n\
                i NID 10 1::2:3\n";
    let origin: NameBuf = "example.".parse().unwrap();
    let mut r = ZoneReader::new(zone).with_origin(&origin);
    let mut buf = [0u8; 512];
    let mut errors = Vec::new();
    loop {
        match r.next_record(&mut buf) {
            Ok(Some(rr)) => panic!("{rr} accepted"),
            Ok(None) => break,
            Err(e) => errors.push((e.error(), e.line())),
        }
    }
    assert_eq!(
        errors,
        [
            (Error::InvalidText, 3),
            (Error::InvalidText, 4),
            (Error::InvalidRdata, 5),
            (Error::EmptyLabel, 6),
            (Error::InvalidText, 7),
            (Error::InvalidRdata, 8),
            (Error::InvalidRdata, 9),
            (Error::InvalidText, 10),
            (Error::InvalidText, 11),
        ]
    );
}
