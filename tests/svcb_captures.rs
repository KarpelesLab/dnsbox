//! Real SVCB/HTTPS responses (from 1.1.1.1, October 2026, queries without
//! EDNS): parsed, displayed, checked through the typed accessors, rebuilt
//! byte for byte, re-parsed from presentation format, and then truncated
//! and mutated to make sure hostile variations never panic.

use core::net::Ipv4Addr;

use dnsbox::rdata::{Https, RData, SvcParamKey, Svcb};
use dnsbox::{ComposeRdata, Message, MessageBuilder, Rtype, WireWriter};

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
        "crypto.cloudflare.com HTTPS (ech)",
        "beef818000010001000000000663727970746f0a636c6f7564666c61726503636f6d00\
         00410001c00c004100010000012c00850001000001000302683200040008a29f874fa2\
         9f884f000500470045fe0d00416400200020abb1f80b6856d475e8615238480b57a1c3\
         c7eb94f80cb97159f5f7e690e7b96d0004000100010012636c6f7564666c6172652d65\
         63682e636f6d000000060020260647000007000000000000a29f874f26064700000700\
         0000000000a29f884f",
        &["crypto.cloudflare.com. 300 IN HTTPS 1 . alpn=\"h2\" \
             ipv4hint=162.159.135.79,162.159.136.79 \
             ech=AEX+DQBBZAAgACCrsfgLaFbUdehhUjhIC1ehw8frlPgMuXFZ9ffmkOe5bQAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA= \
             ipv6hint=2606:4700:7::a29f:874f,2606:4700:7::a29f:884f"],
    ),
    (
        "cloudflare.com HTTPS",
        "beef818000010001000000000a636c6f7564666c61726503636f6d0000410001c00c00\
         4100010000012c003d0001000001000602683302683200040008681084e5681085e500\
         060020260647000000000000000000681084e5260647000000000000000000681085e5",
        &["cloudflare.com. 300 IN HTTPS 1 . alpn=\"h3,h2\" \
             ipv4hint=104.16.132.229,104.16.133.229 \
             ipv6hint=2606:4700::6810:84e5,2606:4700::6810:85e5"],
    ),
    (
        "google.com HTTPS",
        "beef8180000100010000000006676f6f676c6503636f6d0000410001c00c0041000100\
         00479c000d00010000010006026832026833",
        &["google.com. 18332 IN HTTPS 1 . alpn=\"h2,h3\""],
    ),
    (
        "_dns.one.one.one.one SVCB (DDR, RFC 9461/9462)",
        "beef81800001000200000000045f646e73036f6e65036f6e65036f6e65036f6e650000\
         400001c00c004000010000012c00310001036f6e65036f6e65036f6e65036f6e650000\
         010006026833026832000700102f646e732d71756572797b3f646e737dc00c00400001\
         0000012c001b0002036f6e65036f6e65036f6e65036f6e65000001000403646f74",
        &[
            "_dns.one.one.one.one. 300 IN SVCB 1 one.one.one.one. alpn=\"h3,h2\" \
             dohpath=\"/dns-query{?dns}\"",
            "_dns.one.one.one.one. 300 IN SVCB 2 one.one.one.one. alpn=\"dot\"",
        ],
    ),
    (
        "www.facebook.com HTTPS (CNAME, two priorities)",
        "beef81800001000300000000037777770866616365626f6f6b03636f6d0000410001c0\
         0c00050001000008ea001109737461722d6d696e690463313072c010c02e0041000100\
         0016fa0032000209737461722d6d696e690866616c6c6261636b046331307208666163\
         65626f6f6b03636f6d0000010006026832026833c02e00410001000016fa000d000100\
         00010006026832026833",
        &[
            "www.facebook.com. 2282 IN CNAME star-mini.c10r.facebook.com.",
            "star-mini.c10r.facebook.com. 5882 IN HTTPS 2 \
             star-mini.fallback.c10r.facebook.com. alpn=\"h2,h3\"",
            "star-mini.c10r.facebook.com. 5882 IN HTTPS 1 . alpn=\"h2,h3\"",
        ],
    ),
];

/// Visits everything reachable from a message; must never panic.
fn exercise(wire: &[u8]) -> usize {
    let Ok(msg) = Message::parse(wire) else {
        return 0;
    };
    let mut n = 0;
    for (_, rr) in msg.records().flatten() {
        n += rr.to_string().len();
        match rr.data() {
            Ok(RData::Svcb(s)) => {
                n += format!("{s:?}").len();
                n += s
                    .params
                    .iter()
                    .map(|p| p.value().to_string().len())
                    .sum::<usize>();
            }
            Ok(RData::Https(h)) => {
                n += format!("{h:?}").len();
                n += h.params.ipv4_hints().count() + h.params.ipv6_hints().count();
            }
            _ => {}
        }
    }
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

/// The presentation form of every captured SVCB/HTTPS record parses back
/// to the captured RDATA.
#[test]
fn captures_text_round_trip() {
    for (what, h, _) in CAPTURES {
        let wire = hex(h);
        let msg = Message::parse(&wire).unwrap();
        for rr in msg.answers() {
            let rr = rr.unwrap();
            let mut buf = [0u8; 512];
            let rdata = match rr.data().unwrap() {
                RData::Svcb(s) => s.to_string(),
                RData::Https(h) => h.to_string(),
                _ => continue,
            };
            let parsed = Https::from_text(&rdata, &mut buf).unwrap();
            let mut out = [0u8; 512];
            let mut w = WireWriter::new(&mut out);
            parsed.compose_rdata(&mut w).unwrap();
            assert_eq!(w.written(), rr.rdata(), "{what}: {rdata}");
        }
    }
}

#[test]
fn typed_access() {
    let wire = hex(CAPTURES[0].1);
    let msg = Message::parse(&wire).unwrap();
    let rr = msg.answers().next().unwrap().unwrap();
    assert_eq!(rr.rtype(), Rtype::HTTPS);
    let https: Https<'_> = rr.data_as().unwrap();
    assert!(https.is_service_mode() && https.target.is_root());
    assert_eq!(https.effective_target(rr.name()), Some(rr.name()));
    let p = https.params;
    let alpn: Vec<&[u8]> = p.alpn().unwrap().iter().collect();
    assert_eq!(alpn, [b"h2"]);
    assert_eq!(
        p.ipv4_hints().collect::<Vec<_>>(),
        [
            Ipv4Addr::new(162, 159, 135, 79),
            Ipv4Addr::new(162, 159, 136, 79)
        ]
    );
    let ech = p.ech().unwrap().as_bytes();
    assert_eq!(ech.len(), 0x47);
    assert!(ech.windows(19).any(|w| w == b"cloudflare-ech.com\0"));
    assert_eq!(p.port(), None);
    assert!(p.mandatory().is_none());

    let wire = hex(CAPTURES[3].1);
    let msg = Message::parse(&wire).unwrap();
    let svcbs: Vec<Svcb<'_>> = msg
        .answers()
        .map(|rr| rr.unwrap().data_as().unwrap())
        .collect();
    assert_eq!(
        svcbs[0].params.dohpath().unwrap().as_str(),
        "/dns-query{?dns}"
    );
    assert_eq!(svcbs[1].priority, 2);
    assert!(svcbs[1].params.get(SvcParamKey::DOHPATH).is_none());
    assert_eq!(svcbs[0].target.to_string(), "one.one.one.one.");
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
    let mut rng = Rng(0x5eed_5eed_5eed_5eed);
    let corpus: Vec<Vec<u8>> = CAPTURES.iter().map(|c| hex(c.1)).collect();
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
