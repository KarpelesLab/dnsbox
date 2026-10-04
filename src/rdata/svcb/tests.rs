//! SVCB/HTTPS tests: RFC 9460 Appendix D test vectors (success and failure
//! cases), examples from RFC 9461/9540/9848/9953 and the drafts, malformed
//! wire data, the builder, and randomized wire/text round trips.

use core::net::{Ipv4Addr, Ipv6Addr};

use super::svcparam::*;
use super::*;
use crate::rdata::tests::{compose, parse, round_trip};
use crate::rdata::{RData, UnknownRdata};
use crate::testutil::hex;
use crate::wire::{Canonical, WireWriter};
use crate::{Error, Message, MessageBuilder, NameBuf, Record, Section};
use std::format;
use std::string::{String, ToString};
use std::vec::Vec;

/// Parses `text` with [`Svcb::from_text`] and returns the wire form.
fn from_text(text: &str) -> Result<Vec<u8>> {
    let mut buf = [0u8; 2048];
    let svcb = Svcb::from_text(text, &mut buf)?;
    Ok(compose(&svcb))
}

/// Checks a test vector: `text` parses to `wire`, `wire` round-trips (both
/// as SVCB and HTTPS) and displays as `display`, and `display` parses back
/// to `wire`.
fn vector(text: &str, wire: &[u8], display: &str) {
    assert_eq!(from_text(text).unwrap(), wire, "{text}");
    round_trip(Rtype::SVCB, wire, display);
    round_trip(Rtype::HTTPS, wire, display);
    assert_eq!(from_text(display).unwrap(), wire, "{display}");
    let mut buf = [0u8; 2048];
    let https = Https::from_text(display, &mut buf).unwrap();
    assert_eq!(compose(&https), wire);
    assert_eq!(https.rtype(), Rtype::HTTPS);
}

// RFC 9460 Appendix D.1, Figure 2.
#[test]
fn rfc9460_d1_alias_mode() {
    let wire = b"\x00\x00\x03foo\x07example\x03com\x00";
    vector("0 foo.example.com.", wire, "0 foo.example.com.");
    let mut r = WireReader::new(wire);
    let s = Svcb::parse_rdata(&mut r).unwrap();
    assert!(s.is_alias_mode() && !s.is_service_mode());
    assert!(s.params.is_empty());
    assert_eq!(s, Svcb::alias(s.target));
    let owner: NameBuf = "example.com".parse().unwrap();
    assert_eq!(s.effective_target(owner.as_name()), Some(s.target));
}

// RFC 9460 Appendix D.2, Figure 3.
#[test]
fn rfc9460_d2_root_target() {
    vector("1 .", b"\x00\x01\x00", "1 .");
    let mut sbuf = [0u8; 8];
    let s = Svcb::from_text("1 .", &mut sbuf).unwrap();
    let owner: NameBuf = "svc2.example.net".parse().unwrap();
    // ServiceMode: "." is the owner name (§2.5.2).
    assert_eq!(s.effective_target(owner.as_name()), Some(owner.as_name()));
    // AliasMode: "." means the service does not exist (§2.5.1).
    let alias = Svcb::alias(Name::ROOT);
    assert_eq!(alias.effective_target(owner.as_name()), None);
}

// RFC 9460 Appendix D.2, Figure 4.
#[test]
fn rfc9460_d2_port() {
    let wire = hex("0010 03666f6f076578616d706c6503636f6d00 0003 0002 0035");
    vector(
        "16 foo.example.com. port=53",
        &wire,
        "16 foo.example.com. port=53",
    );
    let mut sbuf = [0u8; 64];
    let s = Svcb::from_text("16 foo.example.com. port=53", &mut sbuf).unwrap();
    assert_eq!(s.priority, 16);
    assert_eq!(s.params.port(), Some(53));
    assert_eq!(s.params.len(), 1);
}

// RFC 9460 Appendix D.2, Figure 5.
#[test]
fn rfc9460_d2_generic_key_unquoted() {
    let wire = hex("0001 03666f6f076578616d706c6503636f6d00 029b 0005 68656c6c6f");
    vector(
        "1 foo.example.com. key667=hello",
        &wire,
        "1 foo.example.com. key667=\"hello\"",
    );
}

// RFC 9460 Appendix D.2, Figure 6.
#[test]
fn rfc9460_d2_generic_key_quoted_escape() {
    let wire = hex("0001 03666f6f076578616d706c6503636f6d00 029b 0009 68656c6c6fd2716f6f");
    vector(
        r#"1 foo.example.com. key667="hello\210qoo""#,
        &wire,
        r#"1 foo.example.com. key667="hello\210qoo""#,
    );
    let mut sbuf = [0u8; 64];
    let s = Svcb::from_text(r#"1 foo.example.com. key667="hello\210qoo""#, &mut sbuf)
        .unwrap();
    let p = s.params.get(SvcParamKey::new(667)).unwrap();
    assert_eq!(p.raw_value(), b"hello\xd2qoo");
    assert_eq!(p.value(), SvcParamValue::Unknown(b"hello\xd2qoo"));
}

// RFC 9460 Appendix D.2, Figure 7.
#[test]
fn rfc9460_d2_two_ipv6_hints() {
    let wire = hex(
        "0001 03666f6f076578616d706c6503636f6d00 0006 0020
         20010db8000000000000000000000001 20010db8000000000000000000530001",
    );
    vector(
        "1 foo.example.com. (\n    ipv6hint=\"2001:db8::1,2001:db8::53:1\"\n    )",
        &wire,
        "1 foo.example.com. ipv6hint=2001:db8::1,2001:db8::53:1",
    );
    let mut sbuf = [0u8; 64];
    let s = Svcb::from_text("1 foo.example.com. ipv6hint=2001:db8::1,2001:db8::53:1", &mut sbuf)
        .unwrap();
    let hints: Vec<Ipv6Addr> = s.params.ipv6_hints().collect();
    assert_eq!(
        hints,
        [
            "2001:db8::1".parse::<Ipv6Addr>().unwrap(),
            "2001:db8::53:1".parse().unwrap()
        ]
    );
    assert_eq!(s.params.ipv4_hints().count(), 0);
}

// RFC 9460 Appendix D.2, Figure 8.
#[test]
fn rfc9460_d2_ipv6_hint_embedded_ipv4() {
    let wire = hex("0001 076578616d706c6503636f6d00 0006 0010 20010db8012203440000 0000c0000221");
    vector(
        "1 example.com. (\n  ipv6hint=\"2001:db8:122:344::192.0.2.33\"\n  )",
        &wire,
        "1 example.com. ipv6hint=2001:db8:122:344::c000:221",
    );
}

// RFC 9460 Appendix D.2, Figure 9.
#[test]
fn rfc9460_d2_key_order() {
    let wire = hex(
        "0010 03666f6f076578616d706c65036f726700
         0000 0004 0001 0004
         0001 0009 02 6832 05 68332d3139
         0004 0004 c0000201",
    );
    vector(
        "16 foo.example.org. (\n  alpn=h2,h3-19 mandatory=ipv4hint,alpn\n  ipv4hint=192.0.2.1\n  )",
        &wire,
        "16 foo.example.org. mandatory=alpn,ipv4hint alpn=\"h2,h3-19\" ipv4hint=192.0.2.1",
    );
    let mut sbuf = [0u8; 128];
    let s = Svcb::from_text(
        "16 foo.example.org. alpn=h2,h3-19 mandatory=ipv4hint,alpn ipv4hint=192.0.2.1",
        &mut sbuf,
    )
    .unwrap();
    let keys: Vec<SvcParamKey> = s.params.iter().map(|p| p.key()).collect();
    assert_eq!(
        keys,
        [SvcParamKey::MANDATORY, SvcParamKey::ALPN, SvcParamKey::IPV4HINT]
    );
    let m = s.params.mandatory().unwrap();
    assert_eq!(
        m.iter().collect::<Vec<_>>(),
        [SvcParamKey::ALPN, SvcParamKey::IPV4HINT]
    );
    assert!(m.contains(SvcParamKey::ALPN) && !m.contains(SvcParamKey::PORT));
    let alpn = s.params.alpn().unwrap();
    assert!(alpn.contains(b"h3-19") && !alpn.contains(b"h3"));
    assert_eq!(
        s.params.ipv4_hints().collect::<Vec<_>>(),
        [Ipv4Addr::new(192, 0, 2, 1)]
    );
}

// RFC 9460 Appendix D.2, Figure 10: both presentation forms.
#[test]
fn rfc9460_d2_alpn_escapes() {
    let wire = hex(
        "0010 03666f6f076578616d706c65036f726700
         0001 000c 08 665c6f6f2c626172 02 6832",
    );
    let display = r#"16 foo.example.org. alpn="f\\\\oo\\,bar,h2""#;
    vector(r#"16 foo.example.org. alpn="f\\\\oo\\,bar,h2""#, &wire, display);
    vector(r#"16 foo.example.org. alpn=f\\\092oo\092,bar,h2"#, &wire, display);
    let mut sbuf = [0u8; 64];
    let s = Svcb::from_text(display, &mut sbuf).unwrap();
    let ids: Vec<&[u8]> = s.params.alpn().unwrap().iter().collect();
    assert_eq!(ids, [&b"f\\oo,bar"[..], b"h2"]);
}

// RFC 9460 Appendix A.1: the two equivalent value-list encodings.
#[test]
fn rfc9460_appendix_a1() {
    let a = from_text(r#"1 . key1="part1,part2,part3\\,part4\\\\""#).unwrap();
    let b = from_text(r#"1 . alpn=part1\,\p\a\r\t2\044part3\092,part4\092\\"#).unwrap();
    assert_eq!(a, b);
    let mut sbuf = [0u8; 64];
    let s = Svcb::from_text(r#"1 . alpn="part1,part2,part3\\,part4\\\\""#, &mut sbuf).unwrap();
    let ids: Vec<&[u8]> = s.params.alpn().unwrap().iter().collect();
    assert_eq!(ids, [&b"part1"[..], b"part2", b"part3,part4\\"]);
}

// RFC 9460 Appendix D.3, Figures 11-16.
#[test]
fn rfc9460_d3_failure_cases() {
    let cases: &[(&str, Error)] = &[
        // Figure 11: multiple instances of the same SvcParamKey.
        (
            "1 foo.example.com. (\n key123=abc key123=def\n )",
            Error::InvalidRdata,
        ),
        // Figure 12: missing SvcParamValues that must be non-empty.
        ("1 foo.example.com. mandatory", Error::InvalidText),
        ("1 foo.example.com. alpn", Error::InvalidRdata),
        ("1 foo.example.com. port", Error::InvalidText),
        ("1 foo.example.com. ipv4hint", Error::InvalidText),
        ("1 foo.example.com. ipv6hint", Error::InvalidText),
        // Figure 13: the no-default-alpn value must be empty.
        ("1 foo.example.com. no-default-alpn=abc", Error::InvalidRdata),
        // Figure 14: a mandatory SvcParam is missing.
        ("1 foo.example.com. mandatory=key123", Error::InvalidRdata),
        // Figure 15: "mandatory" must not be in the mandatory list.
        ("1 foo.example.com. mandatory=mandatory", Error::InvalidRdata),
        // Figure 16: the same key twice in the mandatory list.
        (
            "1 foo.example.com. (\n mandatory=key123,key123 key123=abc\n )",
            Error::InvalidRdata,
        ),
    ];
    for (text, err) in cases {
        assert_eq!(from_text(text), Err(*err), "{text}");
    }
}

/// The wire forms of the D.3 failure cases are rejected by the parser too.
#[test]
fn rfc9460_d3_failure_cases_wire() {
    let target = "03666f6f076578616d706c6503636f6d00";
    for params in [
        "007b0003616263 007b0003646566", // key123 twice
        "00000000",                      // empty mandatory
        "00010000",                      // empty alpn
        "00030000",                      // empty port
        "00040000",                      // empty ipv4hint
        "00060000",                      // empty ipv6hint
        "00010003026832 00020003616263", // no-default-alpn=abc
        "00000002007b",                  // mandatory key123 missing
        "000000020000",                  // mandatory=mandatory
        "00000004007b007b 007b0003616263", // mandatory=key123,key123
    ] {
        let wire = hex(&format!("0001 {target} {params}"));
        assert_eq!(
            parse(Rtype::SVCB, Class::IN, &wire),
            Err(Error::InvalidRdata),
            "{params}"
        );
    }
}

#[test]
fn malformed_wire() {
    let bad: &[(&str, Error)] = &[
        // Truncated inside a SvcParam (RFC 9460 §2.2).
        ("0001 00 0003", Error::UnexpectedEof),
        ("0001 00 000300", Error::UnexpectedEof),
        ("0001 00 00030002", Error::UnexpectedEof),
        ("0001 00 0003000200", Error::UnexpectedEof),
        // Keys not strictly increasing.
        ("0001 00 00030002 0035 00010003026832", Error::InvalidRdata),
        ("0001 00 00030002 0035 00030002 0035", Error::InvalidRdata),
        // mandatory: odd length, unsorted, contains key 0.
        ("0001 00 0000000300 0100 00010003026832", Error::InvalidRdata),
        (
            "0001 00 00000004 00030001 00010003026832 000300020035",
            Error::InvalidRdata,
        ),
        // alpn: zero-length ID, overrunning ID.
        ("0001 00 00010001 00", Error::InvalidRdata),
        ("0001 00 00010002 0368", Error::InvalidRdata),
        // no-default-alpn without alpn (RFC 9460 §7.1.1).
        ("0001 00 00020000", Error::InvalidRdata),
        // port of the wrong length.
        ("0001 00 00030001 35", Error::InvalidRdata),
        ("0001 00 00030003 003500", Error::InvalidRdata),
        // ipv4hint / ipv6hint of the wrong length.
        ("0001 00 00040005 c000020101", Error::InvalidRdata),
        (
            concat!("0001 00 0006000f 20010db8", "0000000000000000000000"),
            Error::InvalidRdata,
        ),
        // dohpath must be UTF-8.
        ("0001 00 00070002 c328", Error::InvalidRdata),
        // ohttp and pvd values must be empty.
        ("0001 00 00080001 00", Error::InvalidRdata),
        ("0001 00 000b0001 00", Error::InvalidRdata),
        // tls-supported-groups: empty, odd, duplicates.
        ("0001 00 00090000", Error::InvalidRdata),
        ("0001 00 00090003 001d00", Error::InvalidRdata),
        ("0001 00 00090006 001d 0017 001d", Error::InvalidRdata),
        // docpath: zero-length or overrunning segment.
        ("0001 00 000a0001 00", Error::InvalidRdata),
        ("0001 00 000a0002 0264", Error::InvalidRdata),
        // oots: empty, zero-length protocol, weight > 100, truncated.
        ("0001 00 000c0000", Error::InvalidRdata),
        ("0001 00 000c0002 0064", Error::InvalidRdata),
        ("0001 00 000c0005 03646f74 65", Error::InvalidRdata),
        ("0001 00 000c0004 03646f74", Error::InvalidRdata),
        // The TargetName must not be compressed (RFC 9460 §2.2).
        ("0001 c000", Error::UnexpectedPointer),
        // Truncated fixed fields.
        ("00", Error::UnexpectedEof),
        ("0001", Error::UnexpectedEof),
    ];
    for (h, err) in bad {
        let wire = hex(h);
        assert_eq!(parse(Rtype::SVCB, Class::IN, &wire), Err(*err), "{h}");
        assert_eq!(parse(Rtype::HTTPS, Class::IN, &wire), Err(*err), "{h}");
    }
    // Long duplicate-free and duplicated tls-supported-groups lists take the
    // bitmap path.
    let mut groups: Vec<u8> = (0u16..100).flat_map(|g| g.to_be_bytes()).collect();
    assert!(TlsSupportedGroups::new(&groups).is_ok());
    groups.extend_from_slice(&[0, 42]);
    assert_eq!(TlsSupportedGroups::new(&groups), Err(Error::InvalidRdata));
    let all: Vec<u8> = (0u16..=u16::MAX).flat_map(|g| g.to_be_bytes()).collect();
    assert!(TlsSupportedGroups::new(&all[..65534]).is_ok());
}

#[test]
fn accepted_wire_edge_cases() {
    // Unknown and reserved keys pass through with any value.
    round_trip(
        Rtype::SVCB,
        &hex("0001 00 ff000000 fffe0001 7f ffff0002 0022"),
        r#"1 . key65280 key65534="\127" key65535="\000\"""#,
    );
    // AliasMode with SvcParams parses (recipients ignore them, §2.4.2).
    round_trip(Rtype::HTTPS, &hex("0000 00 000300020035"), "0 . port=53");
    // An empty docpath is the root path (RFC 9953 §3).
    round_trip(
        Rtype::SVCB,
        &hex("0001 00 00010003026361 000a0000"),
        r#"1 . alpn="ca" docpath"#,
    );
    // Empty ech is opaque data.
    round_trip(Rtype::HTTPS, &hex("0001 00 00050000"), "1 . ech");
}

// RFC 9461 §5 / §7 and a real capture (see tests/svcb_captures.rs).
#[test]
fn rfc9461_dohpath() {
    let text = r#"1 one.one.one.one. alpn=h3,h2 dohpath=/dns-query{?dns}"#;
    let wire = hex(
        "0001 036f6e65036f6e65036f6e65036f6e6500
         00010006 026833 026832
         00070010 2f646e732d71756572797b3f646e737d",
    );
    vector(
        text,
        &wire,
        r#"1 one.one.one.one. alpn="h3,h2" dohpath="/dns-query{?dns}""#,
    );
    let mut sbuf = [0u8; 128];
    let s = Svcb::from_text(text, &mut sbuf).unwrap();
    assert_eq!(s.params.dohpath().unwrap().as_str(), "/dns-query{?dns}");
    // Non-ASCII UTF-8 is written as \DDD escapes and parses back.
    let mut buf = [0u8; 64];
    let mut b = SvcbBuilder::new(&mut buf, 1, Name::ROOT).unwrap();
    b.dohpath("/q{?dns}é").unwrap();
    let s = b.finish().unwrap();
    assert_eq!(s.to_string(), r#"1 . dohpath="/q{?dns}\195\169""#);
    assert_eq!(from_text(&s.to_string()).unwrap(), compose(&s));
}

// RFC 9540 §4.
#[test]
fn rfc9540_ohttp() {
    let text = "1 . alpn=h2 ohttp mandatory=ohttp";
    let wire = hex("0001 00 00000002 0008 00010003 026832 00080000");
    vector(text, &wire, r#"1 . mandatory=ohttp alpn="h2" ohttp"#);
    let mut sbuf = [0u8; 64];
    let s = Svcb::from_text(text, &mut sbuf).unwrap();
    assert!(s.params.ohttp() && !s.params.pvd() && !s.params.no_default_alpn());
    assert_eq!(from_text("1 . ohttp=x"), Err(Error::InvalidRdata));
}

// RFC 9848 §3, Figure 1.
#[test]
fn rfc9848_ech() {
    let b64 = "AEj+DQBEAQAgACAdd+scUi0IYFsXnUIU7ko2Nd9+F8M26pAGZVpz/KrWPgAEAAEAAWQVZWNoLXNpdGVzLmV4YW1wbGUubmV0AAA=";
    let text = format!("1 . ech=\"{b64}\"");
    let wire = from_text(&text).unwrap();
    let display = round_trip(Rtype::HTTPS, &wire, &format!("1 . ech={b64}"));
    assert_eq!(from_text(&display).unwrap(), wire);
    let mut buf = [0u8; 128];
    let s = Https::from_text(&text, &mut buf).unwrap();
    let ech = s.params.ech().unwrap().as_bytes();
    // The ECHConfigList's own length prefix covers the rest.
    assert_eq!(usize::from(u16::from_be_bytes([ech[0], ech[1]])), ech.len() - 2);
    assert!(ech.windows(21).any(|w| w == b"ech-sites.example.net"));
    // Escapes are not allowed in ech; bad base64 is rejected.
    assert_eq!(from_text(r"1 . ech=\065AAA"), Err(Error::InvalidText));
    assert_eq!(from_text("1 . ech=AAA"), Err(Error::InvalidText));
    assert_eq!(from_text("1 . ech=AA*A"), Err(Error::InvalidText));
}

// draft-ietf-tls-key-share-prediction §3.1.
#[test]
fn tls_supported_groups() {
    let text = r#"3 server.example.net. ( port="8004" tls-supported-groups=29,23 )"#;
    let wire = from_text(text).unwrap();
    assert!(wire.ends_with(&hex("0003 0002 1f44 0009 0004 001d0017")));
    round_trip(
        Rtype::SVCB,
        &wire,
        "3 server.example.net. port=8004 tls-supported-groups=29,23",
    );
    let mut sbuf = [0u8; 64];
    let s = Svcb::from_text(text, &mut sbuf).unwrap();
    // Preference order is kept.
    let g: Vec<u16> = s.params.tls_supported_groups().unwrap().iter().collect();
    assert_eq!(g, [29, 23]);
    assert_eq!(
        from_text("1 . tls-supported-groups=29,29"),
        Err(Error::InvalidRdata)
    );
    assert_eq!(
        from_text("1 . tls-supported-groups=29,"),
        Err(Error::InvalidText)
    );
    assert_eq!(
        from_text("1 . tls-supported-groups=65536"),
        Err(Error::InvalidText)
    );
}

// RFC 9953 §3.2.1: three complete resource records.
#[test]
fn rfc9953_docpath() {
    let examples = [
        (
            "045f646e73076578616d706c65036f726700004000010000062800 1e
             0001 03646e73076578616d706c65036f726700 0001000302636f 000a0000",
            r#"_dns.example.org. 1576 IN SVCB 1 dns.example.org. alpn="co" docpath"#,
            &[][..],
        ),
        (
            "045f646e73076578616d706c65036f726700004000010000005500 22
             0001 03646e73076578616d706c65036f726700 0001000302636f 000a0004 03646e73",
            r#"_dns.example.org. 85 IN SVCB 1 dns.example.org. alpn="co" docpath="dns""#,
            &[&b"dns"[..]][..],
        ),
        (
            "045f646e73076578616d706c65036f726700004000010000066b00 22
             0001 03646e73076578616d706c65036f726700 0001000302636f 000a0004 016e0173",
            r#"_dns.example.org. 1643 IN SVCB 1 dns.example.org. alpn="co" docpath="n,s""#,
            &[&b"n"[..], b"s"][..],
        ),
    ];
    for (h, display, segments) in examples {
        let wire = hex(h);
        let mut r = WireReader::new(&wire);
        let rr = Record::parse(&mut r).unwrap();
        assert!(r.is_empty());
        assert_eq!(rr.to_string(), display);
        let svcb: Svcb<'_> = rr.data_as().unwrap();
        let got: Vec<&[u8]> = svcb.params.docpath().unwrap().iter().collect();
        assert_eq!(got, segments);
        // The presentation forms of the RFC parse to the same RDATA.
        let rdata_text = display.split_once("SVCB ").unwrap().1;
        assert_eq!(from_text(rdata_text).unwrap(), rr.rdata());
    }
    assert_eq!(
        from_text("1 dns.example.org ( alpn=co docpath=n,s )").unwrap(),
        hex("0001 03646e73076578616d706c65036f726700 0001000302636f 000a0004 016e0173")
    );
    assert_eq!(from_text("1 . docpath=a,,b"), Err(Error::InvalidText));
}

// draft-johani-dnsop-svcb-oots §2.2.
#[test]
fn oots() {
    for (text, h) in [
        (
            r#"1 . oots="do53:100,dot:10""#,
            "0001 00 000c000b 04646f353364 03646f740a",
        ),
        (
            r#"1 . oots="do53:100,dot:5,doq:5""#,
            "0001 00 000c0010 04646f353364 03646f7405 03646f7105",
        ),
        (
            r#"1 . oots="do53:100,dot:25,doh:10,doq:10""#,
            "0001 00 000c0015 04646f353364 03646f7419 03646f680a 03646f710a",
        ),
    ] {
        vector(text, &hex(h), text);
    }
    let mut sbuf = [0u8; 64];
    let s = Svcb::from_text(r#"1 . oots="do53:100,dot:10""#, &mut sbuf).unwrap();
    let entries: Vec<(&[u8], u8)> = s.params.oots().unwrap().iter().collect();
    assert_eq!(entries, [(&b"do53"[..], 100), (&b"dot"[..], 10)]);
    for bad in [
        r#"1 . oots="do53""#,
        r#"1 . oots="do53:""#,
        r#"1 . oots=":5""#,
        r#"1 . oots="do53:1000""#,
        r#"1 . oots="do53:x""#,
        "1 . oots",
    ] {
        assert!(from_text(bad).is_err(), "{bad}");
    }
    assert_eq!(from_text(r#"1 . oots="do53:101""#), Err(Error::InvalidRdata));
}

#[test]
fn pvd_and_no_default_alpn() {
    // draft-ietf-intarea-proxy-config §2.1 example.
    vector(
        r#"1 . alpn="h3,h2" pvd"#,
        &hex("0001 00 00010006 026833 026832 000b0000"),
        r#"1 . alpn="h3,h2" pvd"#,
    );
    vector(
        "1 . no-default-alpn alpn=h3",
        &hex("0001 00 00010003 026833 00020000"),
        r#"1 . alpn="h3" no-default-alpn"#,
    );
    let mut sbuf = [0u8; 32];
    let s = Svcb::from_text("1 . no-default-alpn= alpn=h3", &mut sbuf).unwrap();
    assert!(s.params.no_default_alpn() && s.params.alpn().is_some());
    assert_eq!(from_text("1 . no-default-alpn"), Err(Error::InvalidRdata));
}

#[test]
fn presentation_parsing_details() {
    // Generic keyNNNNN forms of registered keys and case-insensitive keys.
    assert_eq!(
        from_text("1 . key3=53").unwrap(),
        from_text("1 . PORT=53").unwrap()
    );
    // Quoted values, values with spaces, comments, line continuations.
    assert_eq!(
        from_text("1 . ( key667=\"a b\" ; comment\n port=\"443\" )").unwrap(),
        hex("0001 00 000300 0201bb 029b0003 612062")
    );
    // Escaped characters in the target name.
    assert_eq!(
        from_text(r"1 a\.b.example.").unwrap(),
        b"\x00\x01\x03a.b\x07example\x00"
    );
    // Case is preserved in the TargetName.
    assert_eq!(from_text("1 Foo.").unwrap(), b"\x00\x01\x03Foo\x00");
    for (text, err) in [
        ("", Error::InvalidText),
        ("1", Error::InvalidText),
        ("65536 .", Error::InvalidText),
        ("+1 .", Error::InvalidText),
        ("1 \"foo\"", Error::InvalidText),
        ("1 . foo=bar", Error::UnknownMnemonic),
        ("1 . key=bar", Error::InvalidText),
        ("1 . =bar", Error::InvalidText),
        ("1 . port=+53", Error::InvalidText),
        ("1 . port=65536", Error::InvalidText),
        (r"1 . port=\053", Error::InvalidText),
        ("1 . port=53,54", Error::InvalidText),
        (r"1 . ipv4hint=192.0.2.\049", Error::InvalidText),
        ("1 . ipv4hint=192.0.2.1,", Error::InvalidText),
        ("1 . ipv4hint=2001:db8::1", Error::InvalidText),
        ("1 . ipv6hint=192.0.2.1", Error::InvalidText),
        ("1 . mandatory=port,", Error::InvalidText),
        ("1 . mandatory=nope", Error::UnknownMnemonic),
        (r"1 . mandatory=\112ort port=1", Error::InvalidText),
        ("1 . key667=\"abc", Error::InvalidText),
        ("1 . key667=a\"b\"", Error::InvalidText),
        ("1 . key667=ab\\", Error::InvalidText),
        (r"1 . key667=\256", Error::InvalidText),
        (r"1 . key667=\25", Error::InvalidText),
        ("1 . alpn=h2,", Error::InvalidText),
        ("1 . alpn=,h2", Error::InvalidText),
        (r"1 . alpn=h\\2", Error::InvalidText),
        (r"1 . alpn=h2\\", Error::InvalidText),
        ("1 . key65535", Error::InvalidRdata),
        ("1 . key65536", Error::InvalidText),
        ("1 . port=1 key3=2", Error::InvalidRdata),
    ] {
        assert_eq!(from_text(text), Err(err), "{text:?}");
    }
    let long = format!("1 . alpn={}", "a".repeat(256));
    assert_eq!(from_text(&long), Err(Error::InvalidText));
    let key = format!("1 . {}=1", "k".repeat(64));
    assert_eq!(from_text(&key), Err(Error::InvalidText));
    // The buffer must hold the result.
    assert_eq!(
        Svcb::from_text("1 foo.example.com. port=53", &mut [0u8; 10]),
        Err(Error::BufferTooSmall)
    );
    assert_eq!(
        Svcb::from_text("1 . ech=AAAA", &mut [0u8; 8]),
        Err(Error::BufferTooSmall)
    );
}

#[test]
fn builder_sorts_and_validates() {
    let target: NameBuf = "foo.example.org".parse().unwrap();
    let mut buf = [0u8; 128];
    let mut b = SvcbBuilder::new(&mut buf, 16, &target).unwrap();
    assert!(b.is_empty());
    b.ipv4hint([Ipv4Addr::new(192, 0, 2, 1)])
        .unwrap()
        .alpn(["h2", "h3-19"])
        .unwrap()
        .mandatory(&[SvcParamKey::IPV4HINT, SvcParamKey::ALPN])
        .unwrap();
    assert!(!b.is_empty());
    // Figure 9 of RFC 9460, built from params in reverse order.
    let fig9 = hex(
        "0010 03666f6f076578616d706c65036f726700 0000000400010004
         00010009026832056833 2d3139 00040004c0000201",
    );
    assert_eq!(b.as_bytes(), &fig9[..]);
    assert_eq!(b.len(), fig9.len());

    // Failed additions leave the builder untouched.
    let before = b.as_bytes().to_vec();
    assert_eq!(b.port(1).map(|_| ()), Ok(()));
    let with_port = b.as_bytes().to_vec();
    assert_ne!(before, with_port);
    for r in [
        b.port(2).map(|_| ()),
        b.alpn(["x"]).map(|_| ()),
        b.mandatory(&[SvcParamKey::PORT]).map(|_| ()),
    ] {
        assert_eq!(r, Err(Error::InvalidRdata));
    }
    for r in [
        b.alpn::<[&str; 0]>([]).map(|_| ()),
        b.param(SvcParamKey::INVALID, b"").map(|_| ()),
        b.param(SvcParamKey::IPV6HINT, &[0; 15]).map(|_| ()),
        b.tls_supported_groups([1, 1]).map(|_| ()),
        b.docpath([""]).map(|_| ()),
        b.oots([("dot", 101)]).map(|_| ()),
        b.oots([("", 1)]).map(|_| ()),
        b.ipv6hint([]).map(|_| ()),
    ] {
        assert_eq!(r, Err(Error::InvalidRdata));
    }
    assert_eq!(
        b.param(SvcParamKey::new(1000), &[0; 100]).map(|_| ()),
        Err(Error::BufferTooSmall)
    );
    assert_eq!(b.as_bytes(), &with_port[..]);
    let s = b.finish().unwrap();
    assert_eq!(s.params.port(), Some(1));
    assert_eq!(s.priority, 16);
    assert_eq!(s.target, target);

    // Everything the builder offers, in shuffled order.
    let mut buf = [0u8; 512];
    let mut b = SvcbBuilder::new(&mut buf, 1, Name::ROOT).unwrap();
    b.oots([("do53", 100u8), ("dot", 10)])
        .unwrap()
        .pvd()
        .unwrap()
        .docpath(["dns"])
        .unwrap()
        .tls_supported_groups([29, 23])
        .unwrap()
        .ohttp()
        .unwrap()
        .dohpath("/q{?dns}")
        .unwrap()
        .ipv6hint(["2001:db8::1".parse().unwrap()])
        .unwrap()
        .ech(b"\x00\x01\x02")
        .unwrap()
        .ipv4hint([Ipv4Addr::LOCALHOST])
        .unwrap()
        .port(443)
        .unwrap()
        .no_default_alpn()
        .unwrap()
        .alpn([b"h2".as_slice()])
        .unwrap()
        .mandatory(&[SvcParamKey::PORT, SvcParamKey::OHTTP])
        .unwrap()
        .param(SvcParamKey::new(65000), b"x")
        .unwrap();
    let h = b.finish_https().unwrap();
    let keys: Vec<u16> = h.params.iter().map(|p| p.key().get()).collect();
    assert_eq!(keys, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 65000]);
    let text = h.to_string();
    assert_eq!(
        text,
        "1 . mandatory=port,ohttp alpn=\"h2\" no-default-alpn port=443 ipv4hint=127.0.0.1 \
         ech=AAEC ipv6hint=2001:db8::1 dohpath=\"/q{?dns}\" ohttp tls-supported-groups=29,23 \
         docpath=\"dns\" pvd oots=\"do53:100,dot:10\" key65000=\"x\""
    );
    assert_eq!(from_text(&text).unwrap(), compose(&h));
    // Every typed accessor finds its value.
    let p = h.params;
    assert!(p.mandatory().is_some() && p.alpn().is_some() && p.no_default_alpn());
    assert!(p.port().is_some() && p.ipv4hint().is_some() && p.ech().is_some());
    assert!(p.ipv6hint().is_some() && p.dohpath().is_some() && p.ohttp());
    assert!(p.tls_supported_groups().is_some() && p.docpath().is_some());
    assert!(p.pvd() && p.oots().is_some());
    assert!(p.get(SvcParamKey::new(13)).is_none());
    assert_eq!(p.len(), 14);
    let debug = format!("{p:?}");
    assert!(debug.contains("alpn: Alpn([\"h2\"])"), "{debug}");
    assert!(debug.contains("oots: Oots([(\"do53\", 100), (\"dot\", 10)])"), "{debug}");

    // Self-consistency is checked by finish().
    let mut buf = [0u8; 64];
    let mut b = SvcbBuilder::new(&mut buf, 1, Name::ROOT).unwrap();
    b.mandatory(&[SvcParamKey::PORT]).unwrap();
    assert_eq!(b.finish(), Err(Error::InvalidRdata));
    let mut b = SvcbBuilder::new(&mut buf, 1, Name::ROOT).unwrap();
    b.no_default_alpn().unwrap();
    assert_eq!(b.finish(), Err(Error::InvalidRdata));
    let mut b = SvcbBuilder::new(&mut buf, 1, Name::ROOT).unwrap();
    assert_eq!(
        b.mandatory(&[SvcParamKey::PORT, SvcParamKey::PORT])
            .map(|_| ()),
        Err(Error::InvalidRdata)
    );
    assert_eq!(
        b.alpn([[b'a'; 256].as_slice()]).map(|_| ()),
        Err(Error::InvalidRdata)
    );
    // Too small for the target name.
    assert_eq!(
        SvcbBuilder::new(&mut [0u8; 4], 1, &target).map(|_| ()),
        Err(Error::BufferTooSmall)
    );
}

#[test]
fn builder_size_limits() {
    // A value over 65535 bytes cannot be represented.
    let mut big = std::vec![0u8; 70_000];
    let mut b = SvcbBuilder::new(&mut big, 1, Name::ROOT).unwrap();
    assert_eq!(
        b.param(SvcParamKey::new(1000), &[0; 65_532]).map(|_| ()),
        Err(Error::BufferTooSmall)
    );
    b.param(SvcParamKey::new(1000), &[0; 65_528]).unwrap();
    assert_eq!(b.len(), 65_535);
    assert_eq!(b.pvd().map(|_| ()), Err(Error::BufferTooSmall));
    assert!(b.finish().is_ok());
}

#[test]
fn typed_values() {
    let m = Mandatory::new(&[0, 1, 0, 3]).unwrap();
    assert_eq!(m.to_string(), "alpn,port");
    assert_eq!(format!("{m:?}"), "[alpn, port]");
    assert_eq!(m.as_wire(), [0, 1, 0, 3]);
    assert_eq!(m.iter().len(), 2);
    let a = Alpn::new(b"\x02h2\x03a,\\").unwrap();
    assert_eq!(a.to_string(), r#""h2,a\\,\\\\""#);
    assert_eq!(a.as_wire(), b"\x02h2\x03a,\\");
    let a = Alpn::new(b"\x03a\"\x01").unwrap();
    assert_eq!(a.to_string(), r#""a\"\001""#);
    let v4 = Ipv4Hint::new(&[192, 0, 2, 1, 192, 0, 2, 2]).unwrap();
    assert_eq!(v4.to_string(), "192.0.2.1,192.0.2.2");
    assert_eq!(format!("{v4:?}"), "[192.0.2.1, 192.0.2.2]");
    assert_eq!(v4.iter().len(), 2);
    assert_eq!(v4.as_wire().len(), 8);
    let v6 = Ipv6Hint::new(&[0; 16]).unwrap();
    assert_eq!(v6.to_string(), "::");
    assert_eq!(format!("{v6:?}"), "[::]");
    assert_eq!(v6.as_wire().len(), 16);
    let ech = Ech(b"\x00\x01\xff");
    assert_eq!(ech.to_string(), "AAH/");
    assert_eq!(format!("{ech:?}"), "Ech(AAH/)");
    let g = TlsSupportedGroups::new(&[0, 29]).unwrap();
    assert_eq!((g.to_string(), format!("{g:?}")), ("29".into(), "[29]".into()));
    assert_eq!(g.as_wire(), [0, 29]);
    let d = DocPath::new(b"\x01n\x01s").unwrap();
    assert_eq!((d.to_string(), format!("{d:?}")), (r#""n,s""#.into(), r#"["n", "s"]"#.into()));
    assert_eq!(d.as_wire(), b"\x01n\x01s");
    let o = Oots::new(b"\x03d,t\x05").unwrap();
    assert_eq!(o.to_string(), r#""d\\,t:5""#);
    assert_eq!(o.as_wire(), b"\x03d,t\x05");
    let p = DohPath::new(b"/x").unwrap();
    assert_eq!(p.to_string(), "\"/x\"");

    for (key, value, display) in [
        (SvcParamKey::NO_DEFAULT_ALPN, &b""[..], ""),
        (SvcParamKey::OHTTP, b"", ""),
        (SvcParamKey::PVD, b"", ""),
        (SvcParamKey::PORT, b"\x01\xbb", "443"),
        (SvcParamKey::new(9999), b"a b", "\"a b\""),
    ] {
        let v = SvcParamValue::parse(key, value).unwrap();
        assert_eq!(v.to_string(), display);
        let p = SvcParam::new(key, value).unwrap();
        assert_eq!((p.key(), p.raw_value(), p.value()), (key, value, v));
        let _ = format!("{p:?}");
    }
    assert_eq!(
        SvcParam::new(SvcParamKey::PORT, b"").map(|_| ()),
        Err(Error::InvalidRdata)
    );
    assert_eq!(SvcParams::EMPTY.len(), 0);
    assert_eq!(SvcParams::new(b"").unwrap(), SvcParams::default());
    assert_eq!(SvcParams::EMPTY.to_string(), "");
    let pw = hex("000300020035 029b0000");
    let params = SvcParams::new(&pw).unwrap();
    assert_eq!(params.as_wire().len(), 10);
    assert_eq!(params.into_iter().count(), 2);
    assert_eq!(params.to_string(), "port=53 key667");
    assert_eq!(params.value(SvcParamKey::PORT), Some(SvcParamValue::Port(53)));
}

#[test]
fn class_and_dispatch() {
    let wire = hex("0001 00 000300020035");
    // RFC 9460 §2.1: defined in class IN only.
    assert_eq!(
        parse(Rtype::SVCB, Class::CH, &wire).unwrap(),
        RData::Unknown(UnknownRdata::new(Rtype::SVCB, &wire))
    );
    assert!(matches!(
        parse(Rtype::HTTPS, Class::IN, &wire).unwrap(),
        RData::Https(_)
    ));
    assert!(matches!(
        parse(Rtype::SVCB, Class::IN, &wire).unwrap(),
        RData::Svcb(_)
    ));
    assert!(RData::is_known(Rtype::SVCB) && RData::is_known(Rtype::HTTPS));
    let mut sbuf = [0u8; 16];
    let s = Svcb::from_text("1 . port=53", &mut sbuf).unwrap();
    let h: Https<'_> = s.into();
    let back: Svcb<'_> = h.into();
    assert_eq!(back, s);
    assert_eq!(s.rtype(), Rtype::SVCB);
}

#[test]
fn canonical_form_keeps_target_case() {
    // SVCB is not in the RFC 4034 §6.2 list: the TargetName keeps its case.
    let target: NameBuf = "Foo.Example.".parse().unwrap();
    let s = Svcb::new(1, target.as_name(), SvcParams::EMPTY);
    let mut buf = [0u8; 64];
    let mut w = WireWriter::new(&mut buf);
    s.compose_rdata(&mut Canonical::new(&mut w)).unwrap();
    assert_eq!(w.written(), b"\x00\x01\x03Foo\x07Example\x00");
}

#[test]
fn in_messages() {
    // The TargetName equals the owner name: the builder must not compress
    // it (RFC 9460 §2.2), and the message must validate.
    let owner: NameBuf = "example.com".parse().unwrap();
    let mut rd = [0u8; 64];
    let mut sb = SvcbBuilder::new(&mut rd, 1, &owner).unwrap();
    sb.alpn(["h3", "h2"]).unwrap().port(443).unwrap();
    let https = sb.finish_https().unwrap();

    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.push_question(&owner, Rtype::HTTPS, Class::IN).unwrap();
    b.push_answer(&owner, Class::IN, 300, &https).unwrap();
    b.push_answer(&owner, Class::IN, 300, &Https::alias(owner.as_name()))
        .unwrap();
    let wire = b.finish().to_vec();
    let msg = Message::parse_validated(&wire).unwrap();
    let rrs: Vec<Record<'_>> = msg.answers().map(|r| r.unwrap()).collect();
    assert_eq!(
        rrs[0].to_string(),
        r#"example.com. 300 IN HTTPS 1 example.com. alpn="h3,h2" port=443"#
    );
    assert_eq!(rrs[1].to_string(), "example.com. 300 IN HTTPS 0 example.com.");
    assert!(rrs[0].rdata().starts_with(b"\x00\x01\x07example\x03com\x00"));
    let parsed: Https<'_> = rrs[0].data_as().unwrap();
    assert_eq!(parsed, https);
    assert_eq!(rrs[0].data_as::<Svcb<'_>>(), Err(Error::WrongType));

    // copy_record re-emits it identically.
    let mut buf2 = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf2).unwrap();
    for q in msg.questions() {
        b.copy_question(&q.unwrap()).unwrap();
    }
    for rr in msg.records() {
        let (s, rr) = rr.unwrap();
        assert_eq!(s, Section::Answer);
        b.copy_record(s, &rr).unwrap();
    }
    assert_eq!(b.finish(), &wire[..]);
}

/// Deterministic xorshift64* generator.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

/// Mutated RDATA never panics, and whatever parses survives a trip through
/// presentation format unchanged.
#[test]
fn random_mutations_round_trip_through_text() {
    let corpus: Vec<Vec<u8>> = [
        "0010 03666f6f076578616d706c65036f726700 0000000400010004 00010009026832056833 2d3139 00040004c0000201",
        "0001 00 0000000400030008 00010006026832026833 00020000 000300020035 00040004c0000201 \
         00050004000102ff 00060010 20010db8000000000000000000000001 000700052f717b3f7d \
         00080000 00090004001d0017 000a0004016e0173 000b0000 000c000704646f74330a00 029b0003616263",
        "0010 03666f6f076578616d706c65036f726700 0001000c 08665c6f6f2c626172 026832",
    ]
    .iter()
    .map(|h| hex(h))
    .collect();
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    let mut parsed = 0;
    for _ in 0..30_000 {
        let mut wire = corpus[(rng.next() % corpus.len() as u64) as usize].clone();
        for _ in 0..1 + rng.next() % 3 {
            if wire.is_empty() {
                break;
            }
            let i = (rng.next() % wire.len() as u64) as usize;
            match rng.next() % 5 {
                0 => wire[i] = rng.next() as u8,
                1 => wire[i] ^= 1 << (rng.next() % 8),
                2 => wire.truncate(i),
                3 => {
                    wire.insert(i, rng.next() as u8);
                }
                _ => {
                    wire.remove(i);
                }
            }
        }
        let Ok(RData::Svcb(s)) = parse(Rtype::SVCB, Class::IN, &wire) else {
            continue;
        };
        parsed += 1;
        let text = s.to_string();
        let _ = format!("{s:?}");
        if s.params.contains(SvcParamKey::INVALID) {
            continue;
        }
        let mut buf = [0u8; 1024];
        let again = Svcb::from_text(&text, &mut buf).unwrap_or_else(|e| panic!("{text}: {e}"));
        assert_eq!(compose(&again), wire, "{text}");
    }
    assert!(parsed > 1000, "{parsed}");
}

/// Random presentation text never panics.
#[test]
fn random_text_never_panics() {
    let alphabet = b"0123456789 .=,\\\"();\nabcdefghijklmnopqrstuvwxyz-:/+";
    let seeds = [
        "16 foo.example.org. alpn=h2,h3-19 mandatory=ipv4hint,alpn ipv4hint=192.0.2.1",
        r#"1 . alpn="f\\\\oo\\,bar,h2" key667="hello\210qoo" ech=AAEC"#,
        "1 . ipv6hint=2001:db8::1 docpath=a,b oots=\"dot:5\" tls-supported-groups=1,2",
    ];
    let mut rng = Rng(42);
    for _ in 0..20_000 {
        let mut text: Vec<u8> = seeds[(rng.next() % 3) as usize].as_bytes().to_vec();
        for _ in 0..1 + rng.next() % 4 {
            let i = (rng.next() % (text.len() as u64 + 1)) as usize;
            let c = alphabet[(rng.next() % alphabet.len() as u64) as usize];
            match rng.next() % 3 {
                0 if i < text.len() => text[i] = c,
                1 if i < text.len() => {
                    text.remove(i);
                }
                _ => text.insert(i, c),
            }
        }
        let text = String::from_utf8(text).unwrap();
        let mut buf = [0u8; 512];
        if let Ok(s) = Svcb::from_text(&text, &mut buf) {
            // Anything accepted is valid wire data.
            let wire = compose(&s);
            assert!(parse(Rtype::SVCB, Class::IN, &wire).is_ok(), "{text}");
        }
    }
}
