//! Real EDNS(0) wire captures (October 2026): EDE from 1.1.1.1, NSID from
//! k.root-servers.net, cookies from ns1.isc.org (BIND, RFC 9018 server
//! cookies), Client Subnet from 8.8.8.8 and ns1.google.com, ZONEVERSION
//! from a.ns.nic.cz (Knot DNS), and a padded DNS-over-TLS exchange with
//! 1.1.1.1. Each is decoded field by field, rebuilt through the builder, and
//! truncated and mutated to make sure the EDNS accessors never panic.

use std::net::IpAddr;

use dnsbox::edns::{
    ClientSubnet, Cookie, Edns, EdnsOption, InfoCode, Nsid, OptionCode, PaddingPolicy,
    TcpKeepalive, ZoneVersion,
};
use dnsbox::{Message, MessageBuilder, Rcode, Section};

const EDE_RESPONSE: &str = "beef818200010000000000010d646e737365632d6661696c6564036f7267000001000100\
     002904d0000080000039000f003500096e6f20534550206d61746368696e672074686520\
     445320666f756e6420666f7220646e737365632d6661696c65642e6f72672e";

const NSID_QUERY: &str = "beef00000001000000000001000006000100002904d000000000000400030000";

const NSID_RESPONSE: &str = "beef840000010001000000010000060001000006000100015180004001610c726f6f742d\
     73657276657273036e657400056e73746c640c766572697369676e2d67727303636f6d00\
     78c3d6b0000007080000038400093a800001518000002904d0000000000019000300156e\
     73312e6a702d74796f2e6b2e726970652e6e6574";

const COOKIE_QUERY: &str = "beef0000000100000000000103697363036f7267000006000100002904d000000000000c\
     000a00082464c4abcf10c957";

const COOKIE_RESPONSE: &str = "beef8400000100010005000703697363036f72670000060001c00c0006000100001c2000\
     2a066e732d696e74c00c0a686f73746d6173746572c00c78c3d60500001c2000000e1001\
     7a5e8000000e10c00c0002000100001c200019026e73036973630b6166696c6961732d6e\
     737404696e666f00c00c0002000100001c200011036e737007646e736e6f6465036e6574\
     00c00c0002000100001c200006036e7331c00cc00c0002000100001c200006036e7332c0\
     0cc00c0002000100001c200006036e7333c00cc09d0001000100001c2000049514021ac0\
     af0001000100001c200004c7060134c0c10001000100001c200004334b4f8fc09d001c00\
     0100001c20001020010500006b00020000000000000026c0af001c000100001c20001020\
     0105000060000d0000000000000052c0c1001c000100001c200010200141d00701110000\
     00000000002c9200002904d000000000001c000a00182464c4abcf10c957010000006ac2\
     14d3ecbb6558184b96aa";

const ECS_REFUSED: &str = "beef818500010000000000010377777706676f6f676c6503636f6d000001000100002902\
     0000000000000b0008000700011800c00002";

const DOT_QUERY: &str = "beef01000001000000000001076578616d706c6503636f6d000001000100002904d00000\
     00000058000b0000000c0050000000000000000000000000000000000000000000000000\
     000000000000000000000000000000000000000000000000000000000000000000000000\
     0000000000000000000000000000000000000000";

const DOT_RESPONSE: &str = "beef81800001000200000001076578616d706c6503636f6d0000010001c00c0001000100\
     0000bf0004ac4293f3c00c00010001000000bf00046814179a00002904d000000000018c\
     000c01880000000000000000000000000000000000000000000000000000000000000000\
     000000000000000000000000000000000000000000000000000000000000000000000000\
     000000000000000000000000000000000000000000000000000000000000000000000000\
     000000000000000000000000000000000000000000000000000000000000000000000000\
     000000000000000000000000000000000000000000000000000000000000000000000000\
     000000000000000000000000000000000000000000000000000000000000000000000000\
     000000000000000000000000000000000000000000000000000000000000000000000000\
     000000000000000000000000000000000000000000000000000000000000000000000000\
     000000000000000000000000000000000000000000000000000000000000000000000000\
     000000000000000000000000000000000000000000000000000000000000000000000000\
     000000000000000000000000000000000000000000000000000000000000000000000000";

const ZONEVERSION_REFERRAL: &str = "beef80000001000000030001086b6e6f742d646e7302637a0000060001c00c0002000100\
     000e10000e04736c6431026e73036e6963c015c00c0002000100000e10000704736c6432\
     c02ec00c0002000100000e10000704736c6433c02e00002904d000000000000a00130006\
     01006ac2129d";

const ZONEVERSION_ANSWER: &str = "beef84000001000100000001036e696302637a0000060001c00c00060001000007080028\
     0161026e73c00c0a686f73746d6173746572c00c6ac207da0000384000000e1000127500\
     00001c2000002904d000000000000a0013000602006ac207da";

const ECS_RESPONSE: &str = "beef840000010008000000010377777706676f6f676c6503636f6d0000010001c00c0001\
     00010000012c00048efb9777c00c000100010000012c00048efb9977c00c000100010000\
     012c00048efb9b77c00c000100010000012c00048efb9677c00c000100010000012c0004\
     8efb9c77c00c000100010000012c00048efb9a77c00c000100010000012c00048efb9877\
     c00c000100010000012c00048efb9d77000029020000000000000b0008000700011800c6\
     3364";

fn hex(s: &str) -> Vec<u8> {
    let d: Vec<u8> = s
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| (b as char).to_digit(16).unwrap() as u8)
        .collect();
    d.chunks(2).map(|p| p[0] << 4 | p[1]).collect()
}

const ALL: &[(&str, &str)] = &[
    ("EDE response", EDE_RESPONSE),
    ("NSID query", NSID_QUERY),
    ("NSID response", NSID_RESPONSE),
    ("COOKIE query", COOKIE_QUERY),
    ("COOKIE response", COOKIE_RESPONSE),
    ("ECS refused", ECS_REFUSED),
    ("ECS response", ECS_RESPONSE),
    ("DoT query", DOT_QUERY),
    ("DoT response", DOT_RESPONSE),
    ("ZONEVERSION referral", ZONEVERSION_REFERRAL),
    ("ZONEVERSION answer", ZONEVERSION_ANSWER),
];

fn edns(wire: &[u8]) -> (Message<'_>, Edns<'_>) {
    let msg = Message::parse_validated(wire).unwrap();
    let edns = msg.edns().unwrap().expect("OPT record");
    edns.opt().validate().unwrap();
    (msg, edns)
}

fn only_option<'a>(e: &Edns<'a>) -> EdnsOption<'a> {
    let mut it = e.options();
    let o = it.next().expect("one option").unwrap();
    assert!(it.next().is_none());
    o
}

#[test]
fn extended_dns_error() {
    let wire = hex(EDE_RESPONSE);
    let (msg, e) = edns(&wire);
    assert_eq!(msg.effective_rcode(), Ok(Rcode::SERVFAIL));
    assert!(e.dnssec_ok());
    assert_eq!(e.udp_payload_size(), 1232);
    let EdnsOption::ExtendedError(ede) = only_option(&e) else {
        panic!()
    };
    assert_eq!(ede.info_code, InfoCode::DNSKEY_MISSING);
    assert_eq!(
        ede.extra_text_str(),
        Some("no SEP matching the DS found for dnssec-failed.org.")
    );
    assert_eq!(
        e.to_string(),
        "version: 0, flags: do; udp: 1232; EDE=9 (DNSKEY Missing) \
         \"no SEP matching the DS found for dnssec-failed.org.\""
    );
}

#[test]
fn nsid() {
    let wire = hex(NSID_QUERY);
    let (_, e) = edns(&wire);
    assert_eq!(e.get::<Nsid<'_>>(), Some(Ok(Nsid::REQUEST)));
    let wire = hex(NSID_RESPONSE);
    let (msg, e) = edns(&wire);
    assert!(msg.flags().aa());
    let nsid: Nsid<'_> = e.get().unwrap().unwrap();
    assert_eq!(nsid.as_str(), Some("ns1.jp-tyo.k.ripe.net"));
}

#[test]
fn cookies() {
    let wire = hex(COOKIE_QUERY);
    let (_, e) = edns(&wire);
    let q: Cookie<'_> = e.get().unwrap().unwrap();
    assert_eq!(q.server(), None);
    let wire = hex(COOKIE_RESPONSE);
    let (_, e) = edns(&wire);
    let r: Cookie<'_> = e.get().unwrap().unwrap();
    assert_eq!(r.client(), q.client());
    // BIND uses RFC 9018 server cookies.
    let sc = r.server_cookie_v1().expect("RFC 9018 cookie");
    assert_eq!(sc.reserved, [0; 3]);
    assert_eq!(sc.timestamp, 0x6ac2_14d3);
    assert!(sc.is_fresh(0x6ac2_14d3 + 60));
}

#[test]
fn client_subnet() {
    // 8.8.8.8 refuses ECS from clients but echoes it with scope 0.
    let wire = hex(ECS_REFUSED);
    let (msg, e) = edns(&wire);
    assert_eq!(msg.effective_rcode(), Ok(Rcode::REFUSED));
    assert_eq!(e.udp_payload_size(), 512);
    let ecs: ClientSubnet = e.get().unwrap().unwrap();
    assert_eq!(ecs.to_string(), "ECS=192.0.2.0/24/0");
    // An authoritative server answering with scope 0: the answer is valid
    // for every client subnet (RFC 7871 §7.2.1).
    let wire = hex(ECS_RESPONSE);
    let (msg, e) = edns(&wire);
    assert_eq!(msg.header().ancount, 8);
    let ecs: ClientSubnet = e.get().unwrap().unwrap();
    assert_eq!(ecs.addr(), IpAddr::from([198, 51, 100, 0]));
    assert_eq!((ecs.source_prefix(), ecs.scope_prefix()), (24, 0));
}

#[test]
fn zone_version() {
    let wire = hex(ZONEVERSION_REFERRAL);
    let (msg, e) = edns(&wire);
    assert_eq!(msg.header().nscount, 3);
    let EdnsOption::ZoneVersion(z) = only_option(&e) else {
        panic!()
    };
    // A referral from cz: the version is the parent zone's (1 label).
    let ZoneVersion::Version { label_count, .. } = z else {
        panic!()
    };
    assert_eq!(label_count, 1);
    assert_eq!(z.serial(), Some(0x6ac2_129d));
    let wire = hex(ZONEVERSION_ANSWER);
    let (_, e) = edns(&wire);
    assert_eq!(
        only_option(&e).to_string(),
        "ZONEVERSION=2,SOA-SERIAL,1791100890"
    );
}

#[test]
fn padded_dot_exchange() {
    // Query padded to 128 octets, with a keepalive request (RFC 8467).
    let query = hex(DOT_QUERY);
    assert_eq!(query.len(), 128);
    let (msg, e) = edns(&query);
    let codes: Vec<_> = e.raw_options().map(|o| o.code).collect();
    assert_eq!(codes, [OptionCode::TCP_KEEPALIVE, OptionCode::PADDING]);
    // The builder pads identically.
    let q = msg.questions().next().unwrap().unwrap();
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.set_id(msg.id());
    b.set_flags(msg.flags());
    b.copy_question(&q).unwrap();
    b.push_edns_padded(e.header(), &TcpKeepalive::REQUEST, PaddingPolicy::QUERY)
        .unwrap();
    assert_eq!(b.finish(), &query[..]);

    // 1.1.1.1 pads its response to 468 octets.
    let resp = hex(DOT_RESPONSE);
    assert_eq!(resp.len(), 468);
    let (msg, e) = edns(&resp);
    let EdnsOption::Padding(p) = only_option(&e) else {
        panic!()
    };
    assert_eq!(p.len(), 392);
    let mut buf = [0u8; 1232];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.set_id(msg.id());
    b.set_flags(msg.flags());
    for q in msg.questions() {
        b.copy_question(&q.unwrap()).unwrap();
    }
    for rr in msg.answers() {
        b.copy_record(Section::Answer, &rr.unwrap()).unwrap();
    }
    b.push_edns_padded(e.header(), &(), PaddingPolicy::RESPONSE)
        .unwrap();
    assert_eq!(b.finish(), &resp[..]);
}

#[test]
fn opt_records_rebuild() {
    // Re-emitting every record (the OPT one included) keeps the options
    // and header fields byte for byte.
    for (what, h) in ALL {
        let wire = hex(h);
        let msg = Message::parse_validated(&wire).unwrap();
        let mut buf = [0u8; 4096];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.set_id(msg.id());
        b.set_flags(msg.flags());
        for q in msg.questions() {
            b.copy_question(&q.unwrap()).unwrap();
        }
        for rr in msg.records() {
            let (s, rr) = rr.unwrap();
            b.copy_record(s, &rr).unwrap();
        }
        let out = b.finish();
        let again = Message::parse_validated(out).unwrap();
        let (a, z) = (msg.edns().unwrap().unwrap(), again.edns().unwrap().unwrap());
        assert_eq!(a.header(), z.header(), "{what}");
        assert_eq!(a.opt(), z.opt(), "{what}");
        assert_eq!(out.len(), wire.len(), "{what}");
    }
}

#[test]
fn truncation_and_mutation_never_panic() {
    let exercise = |w: &[u8]| {
        let Ok(msg) = Message::parse(w) else { return };
        let _ = msg.effective_rcode();
        if let Ok(Some(e)) = msg.edns() {
            let _ = e.to_string();
            for o in e.options().flatten() {
                let _ = o.to_string();
            }
        }
    };
    let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for (_, h) in ALL {
        let wire = hex(h);
        for end in 0..wire.len() {
            exercise(&wire[..end]);
        }
        for _ in 0..3000 {
            let mut m = wire.clone();
            for _ in 0..1 + next() % 3 {
                let i = next() as usize % m.len();
                m[i] = next() as u8;
            }
            exercise(&m);
        }
    }
}
