//! Real wire captures (responses from 1.1.1.1, October 2026), checked
//! field by field, rebuilt through the builder, and then truncated and
//! mutated to make sure hostile variations never panic.

use dnsbox::rdata::RData;
use dnsbox::{Class, Message, MessageBuilder, Name, NameBuf, Rtype, Section};

fn hex(s: &str) -> Vec<u8> {
    let d: Vec<u8> = s
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| (b as char).to_digit(16).unwrap() as u8)
        .collect();
    d.chunks(2).map(|p| p[0] << 4 | p[1]).collect()
}

/// (description, hex, expected records in presentation format)
const CAPTURES: &[(&str, &str, &[&str])] = &[
    (
        "example.com A",
        "beef81800001000200000000076578616d706c6503636f6d0000010001c00c00010001\
         0000003500046814179ac00c00010001000000350004ac4293f3",
        &[
            "example.com. 53 IN A 104.20.23.154",
            "example.com. 53 IN A 172.66.147.243",
        ],
    ),
    (
        "example.com AAAA",
        "beef81800001000200000000076578616d706c6503636f6d00001c0001c00c001c0001\
         0000003300102606470000100000000000006814179ac00c001c000100000033001026\
         0647000010000000000000ac4293f3",
        &[
            "example.com. 51 IN AAAA 2606:4700:10::6814:179a",
            "example.com. 51 IN AAAA 2606:4700:10::ac42:93f3",
        ],
    ),
    (
        "example.com SOA",
        "beef81800001000100000000076578616d706c6503636f6d0000060001c00c00060001\
         0000036d003207656c6c696f7474026e730a636c6f7564666c617265c01403646e73c0\
         349006f398000027100000096000093a8000000708",
        &[
            "example.com. 877 IN SOA elliott.ns.cloudflare.com. dns.cloudflare.com. 2416374680 10000 2400 604800 1800",
        ],
    ),
    (
        "example.com TXT",
        "beef81800001000200000000076578616d706c6503636f6d0000100001c00c00100001\
         0000012c000c0b763d73706631202d616c6cc00c001000010000012c0021205f6b326e\
         31793476773371746234736b6478396537647874393771726d6d7139",
        &[
            "example.com. 300 IN TXT \"v=spf1 -all\"",
            "example.com. 300 IN TXT \"_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9\"",
        ],
    ),
    (
        "1.1.1.1.in-addr.arpa PTR",
        "beef81800001000100000000013101310131013107696e2d61646472046172706100000c\
         0001c00c000c0001000005e90011036f6e65036f6e65036f6e65036f6e6500",
        &["1.1.1.1.in-addr.arpa. 1513 IN PTR one.one.one.one."],
    ),
    (
        ". NS +edns",
        "beef81800001000d00000001000002000100000200010007ceac001401610c726f6f74\
         2d73657276657273036e65740000000200010007ceac00040162c01e00000200010007\
         ceac00040163c01e00000200010007ceac00040164c01e00000200010007ceac000401\
         65c01e00000200010007ceac00040166c01e00000200010007ceac00040167c01e0000\
         0200010007ceac00040168c01e00000200010007ceac00040169c01e00000200010007\
         ceac0004016ac01e00000200010007ceac0004016bc01e00000200010007ceac000401\
         6cc01e00000200010007ceac0004016dc01e00002904d0000000000000",
        &[
            ". 511660 IN NS a.root-servers.net.",
            ". 511660 IN NS b.root-servers.net.",
            ". 511660 IN NS c.root-servers.net.",
            ". 511660 IN NS d.root-servers.net.",
            ". 511660 IN NS e.root-servers.net.",
            ". 511660 IN NS f.root-servers.net.",
            ". 511660 IN NS g.root-servers.net.",
            ". 511660 IN NS h.root-servers.net.",
            ". 511660 IN NS i.root-servers.net.",
            ". 511660 IN NS j.root-servers.net.",
            ". 511660 IN NS k.root-servers.net.",
            ". 511660 IN NS l.root-servers.net.",
            ". 511660 IN NS m.root-servers.net.",
            ". 0 CLASS1232 OPT \\# 0",
        ],
    ),
];

/// Visits everything reachable from a message; must never panic.
fn exercise(wire: &[u8]) -> usize {
    let Ok(msg) = Message::parse(wire) else {
        return 0;
    };
    let mut n = 0;
    for q in msg.questions().flatten() {
        n += q.to_string().len();
        let _ = q.name().to_buf();
    }
    for (_, rr) in msg.records().flatten() {
        n += rr.to_string().len();
        if let Ok(data) = rr.data() {
            n += format!("{data:?}").len();
        }
        let name = rr.name();
        n += name.labels().count();
        let _ = name.parent();
        let _ = name.cmp(&Name::ROOT);
    }
    for s in Section::ALL {
        n += msg.section(s).count();
    }
    // Re-emitting whatever parses must also be safe.
    let mut buf = [0u8; 4096];
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
    n
}

#[test]
fn captures_parse_and_display() {
    for (what, h, expected) in CAPTURES {
        let wire = hex(h);
        let msg = Message::parse_validated(&wire).unwrap_or_else(|e| panic!("{what}: {e}"));
        let got: Vec<String> = msg.records().map(|r| r.unwrap().1.to_string()).collect();
        assert_eq!(&got, expected, "{what}");
        assert_eq!(msg.questions().count(), 1);
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
fn typed_access() {
    let wire = hex(CAPTURES[2].1);
    let msg = Message::parse(&wire).unwrap();
    let rr = msg.answers().next().unwrap().unwrap();
    let RData::Soa(soa) = rr.data().unwrap() else {
        panic!("not SOA")
    };
    assert_eq!(soa.serial, 2_416_374_680);
    let ns: NameBuf = "elliott.ns.cloudflare.com".parse().unwrap();
    assert_eq!(soa.mname, ns);
    assert_eq!(rr.class(), Class::IN);
    assert_eq!(rr.rtype(), Rtype::SOA);
}

#[test]
fn truncation_at_every_offset() {
    for (what, h, _) in CAPTURES {
        let wire = hex(h);
        for end in 0..wire.len() {
            let prefix = &wire[..end];
            assert!(
                Message::parse(prefix).and_then(|m| m.validate()).is_err(),
                "{what}: prefix of {end} bytes validated"
            );
            exercise(prefix);
        }
        assert!(exercise(&wire) > 0);
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
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let corpus: Vec<Vec<u8>> = CAPTURES.iter().map(|c| hex(c.1)).collect();
    for _ in 0..20_000 {
        let mut wire = corpus[(rng.next() % corpus.len() as u64) as usize].clone();
        let mutations = 1 + rng.next() % 4;
        for _ in 0..mutations {
            let i = (rng.next() % wire.len() as u64) as usize;
            match rng.next() % 4 {
                0 => wire[i] = rng.next() as u8,
                // Pointers are the interesting part: aim them anywhere.
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
