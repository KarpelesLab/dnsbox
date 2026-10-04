//! Truncation (RFC 2181 §9), response skeletons and TCP framing exercised
//! on real captures (responses from 1.1.1.1, October 2026) and on
//! randomized inputs.

use dnsbox::builder::{Outcome, Truncation};
use dnsbox::rdata::{A, TxtParts};
use dnsbox::tcp::{self, FrameReassembler};
use dnsbox::{Class, Message, MessageBuilder, Name, NameBuf, Rtype, Section};

fn hex(s: &str) -> Vec<u8> {
    let d: Vec<u8> = s
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| (b as char).to_digit(16).unwrap() as u8)
        .collect();
    d.chunks(2).map(|p| p[0] << 4 | p[1]).collect()
}

/// `. NS` with EDNS: 13 NS records (one RRset) and an OPT record.
const ROOT_NS: &str = "beef81800001000d00000001000002000100000200010007ceac001401610c726f6f74\
     2d73657276657273036e65740000000200010007ceac00040162c01e00000200010007\
     ceac00040163c01e00000200010007ceac00040164c01e00000200010007ceac000401\
     65c01e00000200010007ceac00040166c01e00000200010007ceac00040167c01e0000\
     0200010007ceac00040168c01e00000200010007ceac00040169c01e00000200010007\
     ceac0004016ac01e00000200010007ceac0004016bc01e00000200010007ceac000401\
     6cc01e00000200010007ceac0004016dc01e00002904d0000000000000";

/// `example.com TXT`: one RRset of two records.
const EXAMPLE_TXT: &str = "beef81800001000200000000076578616d706c6503636f6d0000100001c00c00100001\
     0000012c000c0b763d73706631202d616c6cc00c001000010000012c0021205f6b326e\
     31793476773371746234736b6478396537647874393771726d6d7139";

/// Copies `src` into a builder limited to `limit` bytes with the SetTc
/// policy and checks the RFC 2181 §9 invariants.
fn check_truncated_copy(src: &[u8], limit: usize) -> Option<Vec<u8>> {
    let msg = Message::parse_validated(src).unwrap();
    let mut buf = [0u8; 1024];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.set_limit(limit);
    b.set_truncation(Truncation::SetTc);
    let out = b.copy_message(&msg).ok()?;
    let wire = b.finish().to_vec();
    assert!(wire.len() <= limit);
    let m = Message::parse_validated(&wire).unwrap();
    assert_eq!(m.id(), msg.id());
    let h = m.header();
    let full = msg.header();
    match out {
        Outcome::Added => {
            assert_eq!(wire, src);
        }
        Outcome::Truncated => {
            assert!(m.flags().tc());
            // Single-RRset answers: all or nothing.
            assert_eq!(h.ancount, 0);
        }
        Outcome::Dropped => unreachable!("captures have no optional data"),
    }
    // The OPT record survives truncation (RFC 6891 §7).
    let opts = |m: &Message<'_>| {
        m.additional()
            .filter(|r| r.as_ref().unwrap().rtype() == Rtype::OPT)
            .count()
    };
    assert_eq!(opts(&m), opts(&msg));
    assert_eq!(h.qdcount, full.qdcount);
    Some(wire)
}

#[test]
fn captures_truncated_at_every_limit() {
    for capture in [ROOT_NS, EXAMPLE_TXT] {
        let src = hex(capture);
        let mut smallest_ok = None;
        for limit in 0..=src.len() + 3 {
            if check_truncated_copy(&src, limit).is_some() && smallest_ok.is_none() {
                smallest_ok = Some(limit);
            }
        }
        // Header + question (+ OPT) is the floor.
        let msg = Message::parse(&src).unwrap();
        let q_end = msg.section_offset(Section::Answer).unwrap();
        let opt_len = if capture == ROOT_NS { 11 } else { 0 };
        assert_eq!(smallest_ok, Some(q_end + opt_len));
    }
}

#[test]
fn root_ns_fits_512_untruncated() {
    // The real response is 239 bytes: it must survive a 512-byte UDP
    // limit unchanged, and be truncated (keeping OPT) at 200.
    let src = hex(ROOT_NS);
    assert_eq!(check_truncated_copy(&src, 512).unwrap(), src);
    let small = check_truncated_copy(&src, 200).unwrap();
    assert_eq!(small.len(), 12 + 5 + 11);
}

#[test]
fn response_from_query_over_tcp_stream() {
    // A client pipelines three queries over one TCP connection; the server
    // reassembles them from arbitrary read sizes, answers each with a
    // response skeleton, and frames the responses.
    let names = ["example.com", "example.net", "example.org"];
    let mut stream = Vec::new();
    for (i, n) in names.iter().enumerate() {
        let n: NameBuf = n.parse().unwrap();
        let mut qbuf = [0u8; 64];
        let mut b = MessageBuilder::new_tcp(&mut qbuf).unwrap();
        b.start_query(100 + i as u16, &n, Rtype::A, Class::IN)
            .unwrap();
        stream.extend_from_slice(b.finish());
    }
    for read_size in 1..=stream.len() {
        let mut storage = [0u8; 64];
        let mut r = FrameReassembler::new(&mut storage);
        let mut out = Vec::new();
        for chunk in stream.chunks(read_size) {
            let mut chunk = chunk;
            while !chunk.is_empty() {
                let n = r.extend(chunk);
                chunk = &chunk[n..];
                while let Some(q) = r.next_frame().unwrap() {
                    let q = Message::parse_validated(q).unwrap();
                    let mut resp = [0u8; 600];
                    let mut b = MessageBuilder::new_tcp(&mut resp).unwrap();
                    b.start_response(&q).unwrap();
                    let qname = q.questions().next().unwrap().unwrap().name();
                    b.push_answer(qname, Class::IN, 60, &A::new([192, 0, 2, 1].into()))
                        .unwrap();
                    out.extend_from_slice(b.finish());
                }
            }
        }
        let responses: Vec<_> = tcp::frames(&out).collect();
        assert_eq!(responses.len(), 3);
        for (i, resp) in responses.iter().enumerate() {
            let m = Message::parse_validated(resp).unwrap();
            assert_eq!(m.id(), 100 + i as u16);
            assert!(m.flags().qr() && m.flags().rd());
            let rr = m.answers().next().unwrap().unwrap();
            assert_eq!(rr.name().to_string(), format!("{}.", names[i]));
        }
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
fn random_rrset_sequences_always_validate() {
    // Random RRsets in random sections under random limits, reserves and
    // policies: the output always validates, stays within the limit, and
    // TC is set exactly when a required RRset was cut.
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    let owners: Vec<NameBuf> = [
        "example.com",
        "www.example.com",
        "a.b.example.com",
        "example.net",
        ".",
    ]
    .iter()
    .map(|s| s.parse().unwrap())
    .collect();
    let texts: [&[u8]; 3] = [b"short", &[b'x'; 100], &[b'y'; 255]];
    let mut seen = [0usize; 4];
    for _ in 0..3000 {
        let limit = 12 + (rng.next() % 600) as usize;
        let mut buf = [0u8; 700];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.set_limit(limit);
        let policy = if rng.next().is_multiple_of(2) {
            Truncation::SetTc
        } else {
            Truncation::Error
        };
        b.set_truncation(policy);
        b.set_compression(!rng.next().is_multiple_of(4));
        let _ = b.push_question(&owners[0], Rtype::A, Class::IN);
        let mut tc_expected = false;
        let mut section = Section::Answer;
        for _ in 0..(rng.next() % 12) {
            if rng.next().is_multiple_of(4) && section < Section::Additional {
                section = match section {
                    Section::Answer => Section::Authority,
                    _ => Section::Additional,
                };
            }
            let owner = &owners[(rng.next() % owners.len() as u64) as usize];
            let before = b.as_bytes().to_vec();
            let res = if rng.next().is_multiple_of(2) {
                let count = (rng.next() % 6) as u8;
                let addrs: Vec<A> = (0..count).map(|i| A::new([10, 0, 0, i].into())).collect();
                b.push_rrset(section, owner, Class::IN, 300, &addrs)
            } else {
                let t = texts[(rng.next() % 3) as usize];
                let parts = [t, t];
                let n = 1 + (rng.next() % 2) as usize;
                b.push_rrset(section, owner, Class::IN, 300, [TxtParts(&parts[..n])])
            };
            seen[match res {
                Ok(Outcome::Added) => 0,
                Ok(Outcome::Truncated) => 1,
                Ok(Outcome::Dropped) => 2,
                Err(_) => 3,
            }] += 1;
            match res {
                Ok(Outcome::Added) => assert!(!b.is_truncated()),
                Ok(Outcome::Truncated) => {
                    assert_eq!(policy, Truncation::SetTc);
                    if !tc_expected {
                        assert_eq!(b.as_bytes()[12..], before[12..]);
                    }
                    tc_expected = true;
                }
                Ok(Outcome::Dropped) => {
                    assert_eq!(section, Section::Additional);
                    assert_eq!(b.as_bytes(), &before[..]);
                }
                Err(e) => {
                    assert_eq!(e, dnsbox::Error::BufferTooSmall);
                    assert_eq!(policy, Truncation::Error);
                    assert_eq!(b.as_bytes(), &before[..]);
                }
            }
        }
        if rng.next().is_multiple_of(2) {
            let _ = b.push_additional(
                Name::ROOT,
                Class::new(1232),
                0,
                &dnsbox::rdata::UnknownRdata::new(Rtype::OPT, &[]),
            );
        }
        assert_eq!(b.is_truncated(), tc_expected);
        let wire = b.finish();
        assert!(wire.len() <= limit);
        let m = Message::parse_validated(wire).unwrap();
        assert_eq!(m.flags().tc(), tc_expected);
    }
    assert!(seen.iter().all(|&n| n > 100), "{seen:?}");
}
