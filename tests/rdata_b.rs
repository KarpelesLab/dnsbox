//! Record types of Milestone 4 batch B (LOC, RP, AFSDB, X25, ISDN, RT,
//! NSAP, NSAP-PTR, PX, GPOS, NXT, EID, NIMLOC, ATMA, KX, A6, SINK, APL,
//! IPSECKEY, HIP, NINFO, RKEY, TALINK, CSYNC, ZONEMD, SPF, NID, L32, L64,
//! LP, EUI48, EUI64, AVC, RESINFO, WALLET): real wire captures, a message
//! built with every type, and hostile variations of both.

use dnsbox::rdata::{
    A6, Afsdb, AplItem, AplItems, Atma, Csync, CsyncParts, Eid, Eui48, Eui64, Gpos, HipParts,
    Ipseckey, IpseckeyAlgorithm, IpseckeyGateway, Isdn, Kx, L32, L64, Loc, Lp, Nid, Nimloc, Nsap,
    NsapPtr, Nxt, Px, RData, Rkey, Rp, Rt, Sink, Spf, Talink, UnknownRdata, X25, Zonemd,
    ZonemdHashAlg, ZonemdScheme,
};
use dnsbox::{
    CharStr, Class, ComposeRdata, Message, MessageBuilder, NameBuf, Rtype, WireReader, WireWriter,
};

fn hex(s: &str) -> Vec<u8> {
    let d: Vec<u8> = s
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| (b as char).to_digit(16).unwrap() as u8)
        .collect();
    d.chunks(2).map(|p| p[0] << 4 | p[1]).collect()
}

/// (description, hex, expected answers in presentation format). Responses
/// from 1.1.1.1, October 2026, queried with EDNS (the OPT record is in the
/// additional section).
const CAPTURES: &[(&str, &str, &[&str])] = &[
    (
        "caida.org LOC",
        "f25c81800001000100000001056361696461036f726700001d0001c00c001d00010000\
         3840001000331313870e59c866d7cc980098c04c00002904d0000000000000",
        &["caida.org. 14400 IN LOC 32 53 1.000 N 117 14 25.000 W 107.00m 30m 10m 10m"],
    ),
    (
        "ckdhr.com LOC",
        "6d508180000100010000000105636b64687203636f6d00001d0001c00c001d00010000\
         5460001000123513891704e870bf2e1400988cbc00002904d0000000000000",
        &["ckdhr.com. 21600 IN LOC 42 21 43.528 N 71 5 6.284 W -25.00m 1m 3000m 10m"],
    ),
    (
        "andrew.cmu.edu AFSDB",
        "88d78180000100030000000106616e6472657703636d75036564750000120001c00c00\
         12000100005460001b00010841465344422d303106414e4452455703434d5503454455\
         00c00c0012000100005460001b00010841465344422d303206414e4452455703434d55\
         0345445500c00c0012000100005460001b00010841465344422d303306414e44524557\
         03434d55034544550000002904d0000000000000",
        &[
            "andrew.cmu.edu. 21600 IN AFSDB 1 AFSDB-01.ANDREW.CMU.EDU.",
            "andrew.cmu.edu. 21600 IN AFSDB 1 AFSDB-02.ANDREW.CMU.EDU.",
            "andrew.cmu.edu. 21600 IN AFSDB 1 AFSDB-03.ANDREW.CMU.EDU.",
        ],
    ),
    (
        ". ZONEMD",
        "61d88180000100010000000100003f000100003f000100015180003678c3d6b0010130\
         ce110999820378348dcaeb4c97aa56a9eebed43e85a7c85e6d5e711361d692e1c13648\
         abb6e48a2a9bbd8adb42745f00002904d0000000000000",
        &[". 86400 IN ZONEMD 2026100400 1 1 \
           30CE110999820378348DCAEB4C97AA56A9EEBED43E85A7C85E6D5E71\
           1361D692E1C13648ABB6E48A2A9BBD8ADB42745F"],
    ),
];

#[test]
fn captures_parse_and_display() {
    for (what, h, expected) in CAPTURES {
        let wire = hex(h);
        let msg = Message::parse_validated(&wire).unwrap_or_else(|e| panic!("{what}: {e}"));
        let got: Vec<String> = msg.answers().map(|r| r.unwrap().to_string()).collect();
        assert_eq!(&got, expected, "{what}");
        for rr in msg.answers() {
            assert!(
                !matches!(rr.unwrap().data().unwrap(), RData::Unknown(_)),
                "{what}"
            );
        }
    }
}

#[test]
fn captures_rebuild_byte_identical() {
    for (what, h, _) in CAPTURES {
        let wire = hex(h);
        let msg = Message::parse(&wire).unwrap();
        let mut buf = [0u8; 1024];
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
        assert_eq!(b.finish(), &wire[..], "{what}");
    }
}

#[test]
fn typed_capture_fields() {
    let wire = hex(CAPTURES[1].1);
    let msg = Message::parse(&wire).unwrap();
    let loc: Loc = msg.answers().next().unwrap().unwrap().data_as().unwrap();
    assert_eq!(loc.altitude_cm(), -2500);
    assert_eq!(loc.size_cm(), Some(100));
    assert_eq!(loc.horiz_pre_cm(), Some(300_000));
    assert_eq!(loc.latitude_mas(), (42 * 3600 + 21 * 60 + 43) * 1000 + 528);

    let wire = hex(CAPTURES[2].1);
    let msg = Message::parse(&wire).unwrap();
    let afsdb: Afsdb<'_> = msg.answers().next().unwrap().unwrap().data_as().unwrap();
    assert_eq!(afsdb.subtype, Afsdb::AFS);
    let host: NameBuf = "afsdb-01.andrew.cmu.edu".parse().unwrap();
    assert_eq!(afsdb.hostname, host);

    let wire = hex(CAPTURES[3].1);
    let msg = Message::parse(&wire).unwrap();
    let z: Zonemd<'_> = msg.answers().next().unwrap().unwrap().data_as().unwrap();
    assert_eq!(z.serial, 2_026_100_400);
    assert_eq!(
        (z.scheme, z.hash_alg),
        (ZonemdScheme::SIMPLE, ZonemdHashAlg::SHA384)
    );
    assert_eq!(z.digest.len(), 48);
}

/// Builds a response holding one record of every batch-B type, through the
/// typed compose implementations and compose-only helpers.
fn build_all(buf: &mut [u8]) -> (usize, Vec<String>) {
    let owner: NameBuf = "Host.Example".parse().unwrap();
    let a: NameBuf = "a.Example".parse().unwrap();
    let b: NameBuf = "b.example".parse().unwrap();
    let a = a.as_name();
    let b = b.as_name();
    let digest = [0x5a; 48];
    let net = [192, 168, 32, 0];
    let net6 = [0xff, 0, 0, 0];
    let items = [
        AplItem {
            family: AplItem::IPV4,
            prefix: 21,
            negation: false,
            afdpart: &net,
        },
        AplItem {
            family: AplItem::IPV6,
            prefix: 8,
            negation: true,
            afdpart: &net6,
        },
    ];
    let mut nxt_bits = [0u8; 16];
    let nxt_bits = Nxt::encode_bitmap(&[Rtype::A, Rtype::NXT], &mut nxt_bits).unwrap();
    let spf = Spf::from_wire(b"\x0bv=spf1 -all").unwrap();

    let mut mb = MessageBuilder::new(buf).unwrap();
    mb.set_id(0x4242);
    mb.push_question(&owner, Rtype::ANY, Class::IN).unwrap();
    let mut expected = Vec::new();
    macro_rules! push {
        ($data:expr, $text:expr) => {{
            let data = $data;
            mb.push_answer(&owner, Class::IN, 300, &data).unwrap();
            expected.push(format!("Host.Example. 300 IN {} {}", data.rtype(), $text));
        }};
    }
    push!(
        Loc::new(1_000, -2_000, 1234, 100, 1_000_000, 1000).unwrap(),
        "0 0 1.000 N 0 0 2.000 W 12.34m 1m 10000m 10m"
    );
    push!(Rp { mbox: a, txt: b }, "a.Example. b.example.");
    push!(
        Afsdb {
            subtype: 1,
            hostname: a
        },
        "1 a.Example."
    );
    push!(
        X25::new(CharStr::new(b"311061700956").unwrap()).unwrap(),
        "\"311061700956\""
    );
    push!(
        Isdn {
            address: CharStr::new(b"150862028003217").unwrap(),
            subaddress: Some(CharStr::new(b"004").unwrap()),
        },
        "\"150862028003217\" \"004\""
    );
    push!(
        Rt {
            preference: 2,
            intermediate: b
        },
        "2 b.example."
    );
    push!(
        Nsap {
            address: &[0x47, 0x00, 0x05]
        },
        "0x470005"
    );
    push!(NsapPtr { ptrdname: a }, "a.Example.");
    push!(
        Px {
            preference: 50,
            map822: a,
            mapx400: b
        },
        "50 a.Example. b.example."
    );
    push!(
        Gpos {
            longitude: CharStr::new(b"-32.6882").unwrap(),
            latitude: CharStr::new(b"116.8652").unwrap(),
            altitude: CharStr::new(b"10.0").unwrap(),
        },
        "\"-32.6882\" \"116.8652\" \"10.0\""
    );
    push!(
        Nxt {
            next: b,
            bitmap: nxt_bits
        },
        "b.example. A NXT"
    );
    push!(
        Eid {
            data: &[0x12, 0x89]
        },
        "1289"
    );
    push!(Nimloc { data: &[0xab] }, "AB");
    push!(
        Atma {
            format: Atma::E164,
            address: b"12345"
        },
        "+12345"
    );
    push!(
        Kx {
            preference: 10,
            exchanger: a
        },
        "10 a.Example."
    );
    push!(
        A6 {
            prefix_len: 64,
            suffix: "::2:3:4:5".parse().unwrap(),
            prefix: Some(b),
        },
        "64 ::2:3:4:5 b.example."
    );
    push!(
        Sink {
            meaning: 1,
            coding: 2,
            subcoding: 3,
            data: &[1, 2, 3]
        },
        "1 2 3 AQID"
    );
    push!(AplItems(&items), "1:192.168.32.0/21 !2:ff00::/8");
    push!(
        Ipseckey {
            precedence: 10,
            algorithm: IpseckeyAlgorithm::RSA,
            gateway: IpseckeyGateway::Name(a),
            public_key: &[1, 2, 3],
        },
        "10 3 2 a.Example. AQID"
    );
    push!(
        HipParts {
            pk_algorithm: IpseckeyAlgorithm::RSA,
            hit: &[0x20, 0x01],
            public_key: &[1, 2, 3, 4],
            servers: &[a, b],
        },
        "2 2001 AQIDBA== a.Example. b.example."
    );
    push!(
        dnsbox::rdata::Ninfo::from_wire(b"\x03a b").unwrap(),
        "\"a b\""
    );
    push!(
        Rkey {
            flags: 0,
            protocol: 1,
            algorithm: 7,
            public_key: &[1, 2, 3]
        },
        "0 1 7 AQID"
    );
    push!(
        Talink {
            previous: a,
            next: b
        },
        "a.Example. b.example."
    );
    push!(
        CsyncParts {
            serial: 66,
            flags: Csync::IMMEDIATE | Csync::SOA_MINIMUM,
            types: &[Rtype::A, Rtype::NS, Rtype::AAAA],
        },
        "66 3 A NS AAAA"
    );
    push!(
        Zonemd {
            serial: 7,
            scheme: ZonemdScheme::SIMPLE,
            hash_alg: ZonemdHashAlg::SHA384,
            digest: &digest,
        },
        format!("7 1 1 {}", "5A".repeat(48))
    );
    push!(spf, "\"v=spf1 -all\"");
    push!(
        Nid {
            preference: 10,
            node_id: 0x0014_4fff_ff20_ee64
        },
        "10 0014:4fff:ff20:ee64"
    );
    push!(
        L32 {
            preference: 10,
            locator: [10, 1, 2, 0].into()
        },
        "10 10.1.2.0"
    );
    push!(
        L64 {
            preference: 10,
            locator: 0x2001_0db8_1140_1000
        },
        "10 2001:0db8:1140:1000"
    );
    push!(
        Lp {
            preference: 10,
            fqdn: b
        },
        "10 b.example."
    );
    push!(Eui48::new([0, 0, 0x5e, 0, 0x53, 0x2a]), "00-00-5e-00-53-2a");
    push!(
        Eui64::new([0, 0, 0x5e, 0xef, 0x10, 0, 0, 0x2a]),
        "00-00-5e-ef-10-00-00-2a"
    );
    push!(
        dnsbox::rdata::Avc::from_wire(b"\x03app").unwrap(),
        "\"app\""
    );
    push!(
        dnsbox::rdata::Resinfo::from_wire(b"\x08qnamemin").unwrap(),
        "\"qnamemin\""
    );
    push!(dnsbox::rdata::Wallet::from_wire(b"\x01x").unwrap(), "\"x\"");
    let len = mb.finish().len();
    (len, expected)
}

#[test]
fn build_every_type() {
    let mut buf = [0u8; 4096];
    let (len, expected) = build_all(&mut buf);
    let wire = &buf[..len];
    let msg = Message::parse_validated(wire).unwrap();
    let got: Vec<String> = msg.answers().map(|r| r.unwrap().to_string()).collect();
    assert_eq!(got, expected);
    for rr in msg.answers() {
        let rr = rr.unwrap();
        assert!(
            !matches!(rr.data().unwrap(), RData::Unknown(_)),
            "{}",
            rr.rtype()
        );
        assert!(RData::is_known(rr.rtype()));
    }
    // Names in the new types are never compressed (RFC 3597 §4): only the
    // owner names use pointers, so every RDATA reparses standalone.
    for rr in msg.answers() {
        let rr = rr.unwrap();
        let standalone = RData::parse(rr.rtype(), Class::IN, WireReader::new(rr.rdata()));
        assert!(standalone.is_ok(), "{}", rr.rtype());
    }
}

/// Visits everything reachable from a message; must never panic, and
/// whatever parses must re-emit into a message that validates.
fn exercise(wire: &[u8]) {
    let Ok(msg) = Message::parse(wire) else {
        return;
    };
    for (_, rr) in msg.records().flatten() {
        let _ = rr.to_string();
        if let Ok(data) = rr.data() {
            let _ = format!("{data:?} {data}");
        }
    }
    let mut buf = [0u8; 8192];
    if let Ok(mut b) = MessageBuilder::new(&mut buf) {
        for q in msg.questions().flatten() {
            let _ = b.copy_question(&q);
        }
        for (s, rr) in msg.records().flatten() {
            let _ = b.copy_record(s, &rr);
        }
        let out = b.finish();
        Message::parse_validated(out).expect("builder output must validate");
    }
    let _ = msg.validate();
}

fn corpus() -> Vec<Vec<u8>> {
    let mut all: Vec<Vec<u8>> = CAPTURES.iter().map(|c| hex(c.1)).collect();
    let mut buf = [0u8; 4096];
    let (len, _) = build_all(&mut buf);
    all.push(buf[..len].to_vec());
    all
}

#[test]
fn truncation_at_every_offset() {
    for wire in corpus() {
        for end in 0..wire.len() {
            let prefix = &wire[..end];
            assert!(
                Message::parse(prefix).and_then(|m| m.validate()).is_err(),
                "prefix of {end} bytes validated"
            );
            exercise(prefix);
        }
        exercise(&wire);
    }
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

#[test]
fn random_mutations_never_panic() {
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    let corpus = corpus();
    for _ in 0..20_000 {
        let mut wire = corpus[(rng.next() % corpus.len() as u64) as usize].clone();
        for _ in 0..1 + rng.next() % 4 {
            let i = (rng.next() % wire.len() as u64) as usize;
            match rng.next() % 4 {
                0 => wire[i] = rng.next() as u8,
                1 => wire[i] = 0xc0 | (rng.next() as u8 & 0x3f),
                2 => wire.truncate(i),
                _ => wire[i] ^= 1 << (rng.next() % 8),
            }
            if wire.is_empty() {
                break;
            }
        }
        exercise(&wire);
    }
}

/// Parsing any RDATA bytes as any batch-B type never panics, and whatever
/// parses composes back to the same bytes and displays.
#[test]
fn arbitrary_rdata_round_trips() {
    const TYPES: &[Rtype] = &[
        Rtype::LOC,
        Rtype::RP,
        Rtype::AFSDB,
        Rtype::X25,
        Rtype::ISDN,
        Rtype::RT,
        Rtype::NSAP,
        Rtype::NSAP_PTR,
        Rtype::PX,
        Rtype::GPOS,
        Rtype::NXT,
        Rtype::EID,
        Rtype::NIMLOC,
        Rtype::ATMA,
        Rtype::KX,
        Rtype::A6,
        Rtype::SINK,
        Rtype::APL,
        Rtype::IPSECKEY,
        Rtype::HIP,
        Rtype::NINFO,
        Rtype::RKEY,
        Rtype::TALINK,
        Rtype::CSYNC,
        Rtype::ZONEMD,
        Rtype::SPF,
        Rtype::NID,
        Rtype::L32,
        Rtype::L64,
        Rtype::LP,
        Rtype::EUI48,
        Rtype::EUI64,
        Rtype::AVC,
        Rtype::RESINFO,
        Rtype::WALLET,
    ];
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    let mut parsed = 0;
    for i in 0..200_000u32 {
        let rtype = TYPES[i as usize % TYPES.len()];
        let len = (rng.next() % 40) as usize;
        // Bias towards small values so lengths and names are often valid.
        let data: Vec<u8> = (0..len)
            .map(|_| match rng.next() % 4 {
                0 => (rng.next() % 4) as u8,
                1 => b'0' + (rng.next() % 10) as u8,
                _ => rng.next() as u8,
            })
            .collect();
        let Ok(rdata) = RData::parse(rtype, Class::IN, WireReader::new(&data)) else {
            continue;
        };
        parsed += 1;
        let _ = rdata.to_string();
        let mut out = [0u8; 128];
        let mut w = WireWriter::new(&mut out);
        rdata.compose_rdata(&mut w).unwrap();
        assert_eq!(w.written(), &data[..], "{rtype}");
    }
    assert!(parsed > 1000, "only {parsed} parsed");
}

#[test]
fn reserved_and_unspecified_types_stay_opaque() {
    // UINFO, UID, GID and UNSPEC are IANA-reserved without a specified
    // format: they keep their mnemonics but stay opaque (RFC 3597).
    for t in [Rtype::UINFO, Rtype::UID, Rtype::GID, Rtype::UNSPEC] {
        assert!(!RData::is_known(t));
        let d = RData::parse(t, Class::IN, WireReader::new(&[0, 0, 0, 1])).unwrap();
        assert_eq!(d, RData::Unknown(UnknownRdata::new(t, &[0, 0, 0, 1])));
        assert_eq!(d.to_string(), "\\# 4 00000001");
    }
    assert_eq!(Rtype::UNSPEC.to_string(), "UNSPEC");
    // Class-IN-only types stay opaque in other classes.
    for t in [Rtype::A6, Rtype::APL, Rtype::KX, Rtype::PX, Rtype::NSAP_PTR] {
        let d = RData::parse(t, Class::CH, WireReader::new(&[0])).unwrap();
        assert!(matches!(d, RData::Unknown(_)), "{t}");
    }
}
