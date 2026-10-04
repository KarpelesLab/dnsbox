use super::*;
use crate::message::Message;
use crate::name::NameBuf;
use crate::rdata::{A, Mx, Ns, TxtParts, UnknownRdata};
use crate::testutil::hex;
use crate::{Flags, Name};
use std::vec::Vec;

fn name(s: &str) -> NameBuf {
    s.parse().unwrap()
}

fn addrs(n: u8) -> Vec<A> {
    (0..n).map(|i| A::new([192, 0, 2, i].into())).collect()
}

/// The captured gmail.com MX response (1.1.1.1): one question, one MX
/// RRset of five records.
fn gmail_mx() -> Vec<u8> {
    hex(
        "beef8180000100050000000005676d61696c03636f6d00000f0001c00c000f00\
         0100000bbc0020001e04616c74330d676d61696c2d736d74702d696e016c06676f6f676c65c0\
         12c00c000f000100000bbc0009000a04616c7431c02ec00c000f000100000bbc0009001404616c\
         7432c02ec00c000f000100000bbc0009002804616c7434c02ec00c000f000100000bbc00040005c02e",
    )
}

#[test]
fn error_policy_is_atomic() {
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    assert_eq!(b.truncation(), Truncation::Error);
    b.set_limit(80);
    b.push_question(name("example.com"), Rtype::A, Class::IN)
        .unwrap();
    let before = b.as_bytes().to_vec();
    assert_eq!(
        b.push_rrset(
            Section::Answer,
            name("example.com"),
            Class::IN,
            60,
            addrs(4)
        ),
        Err(Error::BufferTooSmall)
    );
    assert_eq!(b.as_bytes(), &before[..]);
    assert!(!b.is_truncated() && !b.header().flags.tc());
    // Three fit: 29 + 3 × 16 = 77.
    assert_eq!(
        b.push_rrset(
            Section::Answer,
            name("example.com"),
            Class::IN,
            60,
            addrs(3)
        ),
        Ok(Outcome::Added)
    );
    assert_eq!(b.len(), 77);
    assert_eq!(b.remaining(), 3);
    // The question section cannot be a unit.
    assert_eq!(
        b.push_rrset_with(Section::Question, |_| Ok(())),
        Err(Error::SectionOrder)
    );
}

#[test]
fn set_tc_policy() {
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.set_limit(100);
    b.set_truncation(Truncation::SetTc);
    b.push_question(name("example.com"), Rtype::A, Class::IN)
        .unwrap();
    let ok = b
        .push_rrset(
            Section::Answer,
            name("example.com"),
            Class::IN,
            60,
            addrs(2),
        )
        .unwrap();
    assert!(ok.is_added());
    let mid = b.len();
    // 61 + 4 × 16 > 100: the second RRset goes entirely.
    let out = b
        .push_rrset(
            Section::Answer,
            name("www.example.com"),
            Class::IN,
            60,
            addrs(4),
        )
        .unwrap();
    assert_eq!(out, Outcome::Truncated);
    assert!(out.is_truncated() && !out.is_added());
    assert_eq!(b.len(), mid);
    assert!(b.is_truncated() && b.header().flags.tc());
    assert_eq!(b.header().ancount, 2);
    // Later RRset-level pushes are skipped, even if they would fit...
    let skipped = b
        .push_rrset_with(Section::Authority, |_| panic!("not called"))
        .unwrap();
    assert_eq!(skipped, Outcome::Truncated);
    let empty = Message::parse(b"\0\0\0\0\0\0\0\0\0\0\0\0").unwrap();
    assert_eq!(
        b.copy_section(&empty, Section::Answer),
        Ok(Outcome::Truncated)
    );
    // ...but record-level pushes still work (OPT).
    b.push_additional(
        Name::ROOT,
        Class::new(1232),
        0,
        &UnknownRdata::new(Rtype::OPT, &[]),
    )
    .unwrap();
    let wire = b.finish();
    let msg = Message::parse_validated(wire).unwrap();
    assert!(msg.flags().tc());
    assert_eq!((msg.header().ancount, msg.header().arcount), (2, 1));
}

#[test]
fn additional_data_is_dropped_without_tc() {
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.set_limit(120);
    b.set_truncation(Truncation::SetTc);
    b.push_question(name("example.com"), Rtype::NS, Class::IN)
        .unwrap();
    let target = name("ns1.example.com");
    let ns = [Ns::new(target.as_name())];
    assert!(
        b.push_rrset(Section::Answer, name("example.com"), Class::IN, 60, ns)
            .unwrap()
            .is_added()
    );
    // Glue: too big, dropped silently (RFC 2181 §9)...
    let out = b
        .push_rrset(
            Section::Additional,
            name("ns1.example.com"),
            Class::IN,
            60,
            addrs(5),
        )
        .unwrap();
    assert_eq!(out, Outcome::Dropped);
    assert!(!b.is_truncated() && !b.header().flags.tc());
    // ...and later, smaller additional data is still tried.
    let out = b
        .push_rrset(
            Section::Additional,
            name("ns1.example.com"),
            Class::IN,
            60,
            addrs(1),
        )
        .unwrap();
    assert_eq!(out, Outcome::Added);
    // Callers that consider the glue required can truncate explicitly.
    b.truncate();
    assert!(b.header().flags.tc());
    let msg = Message::parse_validated(b.finish()).unwrap();
    assert_eq!(msg.header().arcount, 1);
}

#[test]
fn closure_errors_roll_back() {
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.set_truncation(Truncation::SetTc);
    b.push_question(name("example.com"), Rtype::A, Class::IN)
        .unwrap();
    let before = b.as_bytes().to_vec();
    let res = b.push_rrset_with(Section::Answer, |b| {
        b.push_answer(
            name("example.com"),
            Class::IN,
            0,
            &A::new([1, 1, 1, 1].into()),
        )?;
        // Going back to the question section is an error, not truncation.
        b.push_question(name("x"), Rtype::A, Class::IN)
    });
    assert_eq!(res, Err(Error::SectionOrder));
    assert_eq!(b.as_bytes(), &before[..]);
    assert!(!b.is_truncated());
    assert_eq!(b.section(), Section::Question);
    // An empty RRset is trivially added.
    assert_eq!(
        b.push_rrset(Section::Answer, name("a"), Class::IN, 0, Vec::<A>::new()),
        Ok(Outcome::Added)
    );
}

#[test]
fn reserve_keeps_room() {
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.set_limit(100);
    b.set_reserve(11);
    assert_eq!(b.reserve(), 11);
    b.push_question(name("example.com"), Rtype::A, Class::IN)
        .unwrap();
    assert_eq!(b.remaining(), 100 - 11 - 29);
    // 29 + 4 × 16 = 93 > 89.
    assert_eq!(
        b.push_rrset(Section::Answer, name("example.com"), Class::IN, 0, addrs(4)),
        Err(Error::BufferTooSmall)
    );
    b.set_reserve(0);
    assert!(
        b.push_rrset(Section::Answer, name("example.com"), Class::IN, 0, addrs(4))
            .unwrap()
            .is_added()
    );
    b.set_reserve(1000);
    assert_eq!(b.remaining(), 0);
    assert_eq!(
        b.push_answer(name("example.com"), Class::IN, 0, &A::new([0; 4].into())),
        Err(Error::BufferTooSmall)
    );
}

#[test]
fn copy_message_identity_and_every_limit() {
    let original = gmail_mx();
    let msg = Message::parse_validated(&original).unwrap();
    // Unlimited: identical bytes.
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.set_truncation(Truncation::SetTc);
    assert_eq!(b.copy_message(&msg), Ok(Outcome::Added));
    assert_eq!(b.finish(), &original[..]);

    let question_end = 12 + 15;
    for limit in 0..=original.len() + 5 {
        // SetTc: the whole RRset or nothing, TC iff cut.
        let mut buf = [0u8; 512];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.set_limit(limit);
        b.set_truncation(Truncation::SetTc);
        match b.copy_message(&msg) {
            Ok(out) => {
                assert!(limit >= question_end);
                let wire = b.finish();
                let m = Message::parse_validated(wire).unwrap();
                assert_eq!(m.id(), 0xbeef);
                if limit >= original.len() {
                    assert_eq!(out, Outcome::Added);
                    assert_eq!(wire, &original[..]);
                } else {
                    assert_eq!(out, Outcome::Truncated);
                    assert!(m.flags().tc());
                    assert_eq!(m.header().ancount, 0);
                    assert_eq!(wire.len(), question_end);
                }
            }
            Err(e) => {
                assert!(limit < question_end, "limit {limit}");
                assert_eq!(e, Error::BufferTooSmall);
                assert_eq!(b.len(), Header::LEN);
                assert_eq!(b.header(), Header::default());
            }
        }
        // Error policy: all or nothing.
        let mut buf = [0u8; 512];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.set_limit(limit);
        let res = b.copy_message(&msg);
        if limit >= original.len() {
            assert_eq!(res, Ok(Outcome::Added));
        } else {
            assert_eq!(res, Err(Error::BufferTooSmall));
            assert_eq!(b.header(), Header::default());
            assert_eq!(b.len(), Header::LEN);
        }
    }
}

/// Builds a signed-looking response: an A RRset with its RRSIG, an MX
/// record, NS + glue, and an OPT record.
fn signed_response() -> Vec<u8> {
    let zone = name("example.com");
    let mut rrsig = Vec::new();
    rrsig.extend_from_slice(&Rtype::A.get().to_be_bytes()); // type covered
    rrsig.extend_from_slice(&[13, 2, 0, 0, 0, 60]); // alg, labels, orig TTL
    rrsig.extend_from_slice(&[0; 8]); // expiration, inception
    rrsig.extend_from_slice(&[0x12, 0x34]); // key tag
    rrsig.extend_from_slice(zone.as_wire());
    rrsig.extend_from_slice(&[0xab; 64]); // signature
    let mut buf = [0u8; 1024];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.set_id(42);
    b.set_flags(Flags::default().with_qr(true));
    b.push_question(&zone, Rtype::A, Class::IN).unwrap();
    let _ = b
        .push_rrset(Section::Answer, &zone, Class::IN, 60, addrs(3))
        .unwrap();
    b.push_answer(
        &zone,
        Class::IN,
        60,
        &UnknownRdata::new(Rtype::RRSIG, &rrsig),
    )
    .unwrap();
    b.push_answer(
        &zone,
        Class::IN,
        60,
        &Mx {
            preference: 10,
            exchange: name("mail.example.com").as_name(),
        },
    )
    .unwrap();
    b.push_authority(
        &zone,
        Class::IN,
        60,
        &Ns::new(name("ns.example.com").as_name()),
    )
    .unwrap();
    b.push_additional(
        name("ns.example.com"),
        Class::IN,
        60,
        &A::new([192, 0, 2, 53].into()),
    )
    .unwrap();
    b.push_additional(
        name("ns.example.com"),
        Class::IN,
        60,
        &TxtParts(&[b"a big optional additional record"]),
    )
    .unwrap();
    b.push_additional(
        Name::ROOT,
        Class::new(1232),
        0x8000,
        &UnknownRdata::new(Rtype::OPT, &[]),
    )
    .unwrap();
    b.finish().to_vec()
}

#[test]
fn copy_section_keeps_rrsig_with_rrset() {
    let src = signed_response();
    let msg = Message::parse_validated(&src).unwrap();
    let answers: Vec<_> = msg.answers().map(|r| r.unwrap()).collect();
    assert_eq!(answers.len(), 5);
    let a_rrset_end = answers[3].end(); // 3 A + RRSIG
    // Limits between "A records fit" and "A + RRSIG fit": nothing of the
    // RRset may remain.
    for limit in 29..src.len() {
        let mut buf = [0u8; 512];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.set_truncation(Truncation::SetTc);
        let _ = b.copy_section(&msg, Section::Question).unwrap();
        b.set_limit(limit);
        let out = b.copy_section(&msg, Section::Answer).unwrap();
        let wire = b.finish();
        let m = Message::parse_validated(wire).unwrap();
        let n = m.header().ancount;
        if limit < a_rrset_end {
            assert_eq!((n, out), (0, Outcome::Truncated), "limit {limit}");
        } else if n == 4 {
            assert_eq!(out, Outcome::Truncated);
            assert!(m.answers().all(|r| r.unwrap().rtype() != Rtype::MX));
        } else {
            assert_eq!((n, out), (5, Outcome::Added));
        }
    }
}

#[test]
fn copy_message_keeps_opt() {
    let src = signed_response();
    let msg = Message::parse_validated(&src).unwrap();
    let mut seen_dropped = false;
    for limit in 0..=src.len() {
        let mut buf = [0u8; 1024];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.set_limit(limit);
        b.set_truncation(Truncation::SetTc);
        b.set_reserve(3);
        let Ok(out) = b.copy_message(&msg) else {
            assert_eq!(b.len(), Header::LEN);
            continue;
        };
        assert_eq!(b.reserve(), 3, "reserve restored");
        let wire = b.finish();
        let m = Message::parse_validated(wire).unwrap();
        assert!(wire.len() <= limit - 3);
        let opts = m
            .additional()
            .filter(|r| r.as_ref().unwrap().rtype() == Rtype::OPT)
            .count();
        assert_eq!(opts, 1, "OPT always kept (limit {limit})");
        let last = m.additional().last().unwrap().unwrap();
        assert_eq!(last.rtype(), Rtype::OPT);
        assert_eq!((last.class(), last.ttl()), (Class::new(1232), 0x8000));
        match out {
            Outcome::Added => assert_eq!(wire, &src[..]),
            Outcome::Truncated => assert!(m.flags().tc()),
            Outcome::Dropped => {
                seen_dropped = true;
                assert!(!m.flags().tc());
                assert_eq!(m.header().ancount, 5);
                assert_eq!(m.header().nscount, 1);
            }
        }
    }
    assert!(seen_dropped);
}

#[test]
fn copy_message_errors() {
    let src = signed_response();
    let msg = Message::parse_validated(&src).unwrap();
    // Not fresh.
    let mut buf = [0u8; 1024];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.push_question(Name::ROOT, Rtype::NS, Class::IN).unwrap();
    assert_eq!(b.copy_message(&msg), Err(Error::SectionOrder));

    // Malformed sources, cut at every offset: errors leave nothing behind.
    for end in 12..src.len() {
        let Ok(m) = Message::parse(&src[..end]) else {
            continue;
        };
        let mut buf = [0u8; 1024];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.set_truncation(Truncation::SetTc);
        match b.copy_message(&m) {
            Ok(_) => {
                Message::parse_validated(b.finish()).unwrap();
            }
            Err(_) => {
                assert_eq!(b.header(), Header::default());
                assert_eq!(b.len(), Header::LEN);
                assert!(!b.is_truncated());
            }
        }
        // Copying sections individually from a broken source.
        let mut buf = [0u8; 1024];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        for s in Section::ALL {
            let cp = b.checkpoint();
            if b.copy_section(&m, s).is_err() {
                assert_eq!(b.checkpoint(), cp);
            }
        }
        Message::parse_validated(b.finish()).unwrap();
    }
}

#[test]
fn rrsig_helper() {
    let src = signed_response();
    let msg = Message::parse_validated(&src).unwrap();
    let covers: Vec<_> = msg.answers().map(|r| rrsig_covers(&r.unwrap())).collect();
    assert_eq!(covers, [None, None, None, Some(Rtype::A), None]);
    // A truncated RRSIG RDATA covers nothing.
    let mut buf = [0u8; 64];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.push_answer(
        Name::ROOT,
        Class::IN,
        0,
        &UnknownRdata::new(Rtype::RRSIG, &[1]),
    )
    .unwrap();
    let m = Message::parse(b.finish()).unwrap();
    assert_eq!(rrsig_covers(&m.answers().next().unwrap().unwrap()), None);
}
