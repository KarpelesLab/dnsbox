use core::fmt;

use super::*;
use crate::message::Message;
use crate::name::NameBuf;
use crate::rdata::{A, Cname, Mx, Ns, Null, RData, Soa, TxtParts};
use crate::testutil::hex;
use crate::wire::WireReader;
use std::string::ToString;
use std::vec::Vec;

fn name(s: &str) -> NameBuf {
    s.parse().unwrap()
}

/// A post-RFC 3597 style record type whose names must never be compressed:
/// one `Lowercase` name and one `Plain` name.
#[derive(Debug)]
struct TwoNames<'a>(Name<'a>, Name<'a>);

impl ComposeRdata for TwoNames<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::new(65400)
    }
    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_name(self.0, NameEncoding::Lowercase)?;
        c.put_name(self.1, NameEncoding::Plain)
    }
}

impl fmt::Display for TwoNames<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.0, self.1)
    }
}

#[test]
fn query() {
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    assert!(b.is_empty());
    b.set_id(0xbeef);
    b.set_flags(Flags::default().with_rd(true));
    b.push_question(name("example.com"), Rtype::A, Class::IN)
        .unwrap();
    assert!(!b.is_empty());
    assert_eq!(b.header().qdcount, 1);
    let wire = b.finish();
    assert_eq!(
        wire,
        &hex("beef01000001000000000000076578616d706c6503636f6d0000010001")[..]
    );
}

/// Rebuilding the captured gmail.com MX response reproduces it byte for
/// byte: same compression decisions as the original server.
#[test]
fn rebuild_capture_identically() {
    let original = hex(
        "beef8180000100050000000005676d61696c03636f6d00000f0001c00c000f00\
         0100000bbc0020001e04616c74330d676d61696c2d736d74702d696e016c06676f6f676c65c0\
         12c00c000f000100000bbc0009000a04616c7431c02ec00c000f000100000bbc0009001404616c\
         7432c02ec00c000f000100000bbc0009002804616c7434c02ec00c000f000100000bbc00040005c02e",
    );
    let msg = Message::parse_validated(&original).unwrap();
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.set_id(msg.id());
    b.set_flags(msg.flags());
    for q in msg.questions() {
        b.copy_question(&q.unwrap()).unwrap();
    }
    for rr in msg.records() {
        let (section, rr) = rr.unwrap();
        b.copy_record(section, &rr).unwrap();
    }
    assert_eq!(b.finish(), &original[..]);
}

#[test]
fn compression_round_trip() {
    let zone = name("example.com");
    let www = name("www.example.com");
    let mail = name("mail.example.com");
    let other = name("example.org");
    let mut buf = [0u8; 1024];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.push_question(&www, Rtype::A, Class::IN).unwrap();
    b.push_answer(&www, Class::IN, 60, &Cname::new(mail.as_name()))
        .unwrap();
    b.push_answer(&mail, Class::IN, 60, &A::new([192, 0, 2, 1].into()))
        .unwrap();
    b.push_authority(
        &zone,
        Class::IN,
        60,
        &Ns::new(name("ns1.example.org").as_name()),
    )
    .unwrap();
    let soa = Soa {
        mname: other.as_name(),
        rname: zone.as_name(),
        serial: 1,
        refresh: 2,
        retry: 3,
        expire: 4,
        minimum: 5,
    };
    b.push_authority(&zone, Class::IN, 60, &soa).unwrap();
    b.push_additional(
        &other,
        Class::IN,
        60,
        &Mx {
            preference: 1,
            exchange: Name::ROOT,
        },
    )
    .unwrap();
    let wire = b.finish().to_vec();

    let msg = Message::parse_validated(&wire).unwrap();
    let text: Vec<_> = msg.records().map(|r| r.unwrap().1.to_string()).collect();
    assert_eq!(
        text,
        [
            "www.example.com. 60 IN CNAME mail.example.com.",
            "mail.example.com. 60 IN A 192.0.2.1",
            "example.com. 60 IN NS ns1.example.org.",
            "example.com. 60 IN SOA example.org. example.com. 1 2 3 4 5",
            "example.org. 60 IN MX 1 .",
        ]
    );
    // question 12 + (4+8+5 + 4); CNAME: ptr + 10 + "mail"+ptr; A: ptr + 10 + 4;
    // NS: ptr(example.com) + 10 + "ns1" "example" "org" root;
    // SOA: ptr + 10 + ptr(example.org) + ptr + 20; MX: ptr + 10 + 2 + 1.
    let expected =
        12 + 21 + (2 + 10 + 7) + (2 + 10 + 4) + (2 + 10 + 17) + (2 + 10 + 24) + (2 + 10 + 3);
    assert_eq!(wire.len(), expected);
}

#[test]
fn compression_disabled() {
    let www = name("www.example.com");
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.set_compression(false);
    assert!(!b.compression());
    b.push_question(&www, Rtype::CNAME, Class::IN).unwrap();
    b.push_answer(&www, Class::IN, 0, &Cname::new(www.as_name()))
        .unwrap();
    let wire = b.finish();
    assert!(!wire.iter().any(|&b| b >= 0xc0), "no pointers");
    assert_eq!(wire.len(), 12 + 21 + 17 + 10 + 17);
    Message::parse_validated(wire).unwrap();
}

#[test]
fn rfc3597_names_are_never_compressed_nor_targets() {
    let n = name("Host.Example.com");
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    // The names inside TwoNames are written in full even though "example.com"
    // could be compressed against nothing yet...
    b.push_answer(
        name("a.b"),
        Class::IN,
        0,
        &TwoNames(n.as_name(), n.as_name()),
    )
    .unwrap();
    // ...and later names must not point into them.
    b.push_answer(&n, Class::IN, 0, &Null { data: b"" })
        .unwrap();
    let wire = b.finish();
    let msg = Message::parse_validated(wire).unwrap();
    let rrs: Vec<_> = msg.answers().map(|r| r.unwrap()).collect();
    assert_eq!(
        rrs[0].rdata(),
        b"\x04Host\x07Example\x03com\x00\x04Host\x07Example\x03com\x00"
    );
    let owner_at = rrs[1].start();
    assert_eq!(
        &wire[owner_at..owner_at + 18],
        b"\x04Host\x07Example\x03com\x00"
    );
}

#[test]
fn compression_is_case_preserving() {
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.push_question(name("ExAmPlE.com"), Rtype::A, Class::IN)
        .unwrap();
    b.push_answer(
        name("example.com"),
        Class::IN,
        0,
        &A::new([1, 2, 3, 4].into()),
    )
    .unwrap();
    b.push_answer(
        name("www.ExAmPlE.com"),
        Class::IN,
        0,
        &A::new([1, 2, 3, 4].into()),
    )
    .unwrap();
    let wire = b.finish();
    let msg = Message::parse_validated(wire).unwrap();
    let names: Vec<_> = msg
        .answers()
        .map(|r| r.unwrap().name().to_string())
        .collect();
    assert_eq!(names, ["example.com.", "www.ExAmPlE.com."]);
    // "example.com" shares only "com" with the question; "www.ExAmPlE.com"
    // compresses to "www" + pointer.
    assert_eq!(wire.len(), 12 + 17 + (8 + 2 + 14) + (4 + 2 + 14));
}

#[test]
fn section_order_is_enforced() {
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    let a = A::new([1, 1, 1, 1].into());
    b.push_additional(Name::ROOT, Class::IN, 0, &a).unwrap();
    assert_eq!(b.section(), Section::Additional);
    let before = b.as_bytes().to_vec();
    assert_eq!(
        b.push_answer(Name::ROOT, Class::IN, 0, &a),
        Err(Error::SectionOrder)
    );
    assert_eq!(
        b.push_question(Name::ROOT, Rtype::A, Class::IN),
        Err(Error::SectionOrder)
    );
    assert_eq!(
        b.push_record(Section::Question, Name::ROOT, Class::IN, 0, &a),
        Err(Error::SectionOrder)
    );
    assert_eq!(b.as_bytes(), &before[..]);
    assert_eq!(b.section(), Section::Additional);
}

#[test]
fn limits_and_rollback() {
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.set_limit(40);
    assert_eq!(b.limit(), 40);
    b.push_question(name("example.com"), Rtype::TXT, Class::IN)
        .unwrap();
    let full = b.as_bytes().to_vec();
    let txt = TxtParts(&[b"some text that does not fit"]);
    assert_eq!(
        b.push_answer(name("example.com"), Class::IN, 0, &txt),
        Err(Error::BufferTooSmall)
    );
    assert_eq!(b.as_bytes(), &full[..], "failed push left no trace");
    assert_eq!(b.header().ancount, 0);
    assert_eq!(b.section(), Section::Question);

    b.set_limit(usize::MAX);
    assert_eq!(b.limit(), 512);
    let cp = b.checkpoint();
    b.push_answer(name("a.example.com"), Class::IN, 0, &txt)
        .unwrap();
    b.push_authority(name("b.example.com"), Class::IN, 0, &txt)
        .unwrap();
    assert_eq!(b.header().nscount, 1);
    b.rollback(cp);
    assert_eq!(b.as_bytes(), &full[..]);
    assert_eq!(b.section(), Section::Question);
    // The compression table forgot the rolled-back names: this one must
    // not point into the discarded bytes.
    b.push_answer(name("b.example.com"), Class::IN, 0, &txt)
        .unwrap();
    Message::parse_validated(b.as_bytes()).unwrap();

    // A buffer too small for a header.
    assert_eq!(
        MessageBuilder::new(&mut [0u8; 11]).unwrap_err(),
        Error::BufferTooSmall
    );
}

#[test]
fn buffer_exhaustion_at_every_size() {
    // Whatever the buffer size, pushes either succeed or fail cleanly and
    // the result always parses.
    let a = A::new([10, 0, 0, 1].into());
    for size in 12..200 {
        let mut buf = std::vec![0u8; size];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        let _ = b.push_question(name("www.example.com"), Rtype::A, Class::IN);
        for i in 0..5u8 {
            let owner = NameBuf::from_labels([&[b'a' + i][..], b"example", b"com"]).unwrap();
            let _ = b.push_answer(&owner, Class::IN, 0, &a);
        }
        let len = b.len();
        let wire = b.finish();
        assert_eq!(wire.len(), len);
        Message::parse_validated(wire).unwrap();
    }
}

#[test]
fn table_overflow_and_far_offsets() {
    // More distinct names than the table holds, and records beyond the
    // 0x3fff pointer range: still a valid message.
    let mut buf = std::vec![0u8; 65535];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    let big = [0u8; 4000];
    for i in 0..300u16 {
        let label = std::format!("host{i}");
        let owner = NameBuf::from_labels([label.as_bytes(), b"example", b"net"]).unwrap();
        b.push_answer(
            &owner,
            Class::IN,
            0,
            &Null {
                data: if i % 50 == 0 { &big } else { b"" },
            },
        )
        .unwrap();
    }
    assert!(b.len() > 0x4000);
    let wire = b.finish();
    let msg = Message::parse_validated(wire).unwrap();
    for (i, rr) in msg.answers().enumerate() {
        assert_eq!(
            rr.unwrap().name().to_string(),
            std::format!("host{i}.example.net.")
        );
    }
}

#[test]
fn base_offset() {
    let mut buf = [0u8; 128];
    let mut w = WireWriter::new(&mut buf);
    w.put_u16(0).unwrap(); // TCP length prefix placeholder
    let mut b = MessageBuilder::from_buf(w).unwrap();
    b.push_question(name("example.com"), Rtype::NS, Class::IN)
        .unwrap();
    b.push_answer(
        name("example.com"),
        Class::IN,
        0,
        &Ns::new(name("ns.example.com").as_name()),
    )
    .unwrap();
    let len = b.len() as u16;
    let out = b.finish();
    out[..2].copy_from_slice(&len.to_be_bytes());
    let msg = Message::parse_validated(&out[2..]).unwrap();
    let rr = msg.answers().next().unwrap().unwrap();
    assert_eq!(rr.to_string(), "example.com. 0 IN NS ns.example.com.");
    // The owner name is a pointer to offset 12 of the message proper.
    assert_eq!(&out[2 + 29..2 + 31], &[0xc0, 0x0c]);
}

#[cfg(feature = "alloc")]
#[test]
fn vec_builder() {
    let mut b = MessageBuilder::new_vec();
    b.set_id(1);
    b.push_question(name("example.com"), Rtype::SOA, Class::IN)
        .unwrap();
    assert_eq!(b.limit(), MAX_MESSAGE_LEN);
    let v: alloc::vec::Vec<u8> = b.finish();
    assert_eq!(v.len(), 29);
    assert!(std::format!("{:?}", MessageBuilder::new_vec()).starts_with("MessageBuilder"));

    // Appending a message to a non-empty Vec.
    let mut b = MessageBuilder::from_buf(std::vec![0xaa, 0xbb]).unwrap();
    b.push_question(name("a"), Rtype::A, Class::IN).unwrap();
    b.push_answer(name("a"), Class::IN, 0, &A::new([1, 2, 3, 4].into()))
        .unwrap();
    let v = b.finish();
    assert_eq!(&v[..2], &[0xaa, 0xbb]);
    Message::parse_validated(&v[2..]).unwrap();
}

#[test]
fn copy_unknown_and_opt_records() {
    // OPT and an unknown type are copied verbatim.
    let mut buf = [0u8; 256];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.push_answer(
        name("x"),
        Class::IN,
        7,
        &crate::rdata::UnknownRdata::new(Rtype::new(4000), b"\x01\x02"),
    )
    .unwrap();
    b.push_additional(
        Name::ROOT,
        Class::new(1232),
        0,
        &crate::rdata::UnknownRdata::new(Rtype::OPT, b""),
    )
    .unwrap();
    let wire = b.finish().to_vec();
    let msg = Message::parse_validated(&wire).unwrap();
    let mut buf2 = [0u8; 256];
    let mut b2 = MessageBuilder::new(&mut buf2).unwrap();
    for rr in msg.records() {
        let (s, rr) = rr.unwrap();
        b2.copy_record(s, &rr).unwrap();
    }
    assert_eq!(b2.finish(), &wire[..]);
    let rr = msg.answers().next().unwrap().unwrap();
    assert!(matches!(rr.data().unwrap(), RData::Unknown(_)));
    let mut r = WireReader::new(&wire);
    r.skip(12).unwrap();
    assert_eq!(crate::Record::parse(&mut r).unwrap().ttl(), 7);
}

/// A reference compressor without size limits: every suffix written
/// literally is remembered with its offset, and each name uses the longest
/// remembered suffix (RFC 1035 §4.1.4).
struct ReferenceCompressor {
    suffixes: Vec<(Vec<u8>, usize)>,
}

impl ReferenceCompressor {
    fn write(&mut self, out: &mut Vec<u8>, wire: &[u8]) {
        let mut starts = Vec::new();
        let mut pos = 0;
        while wire[pos] != 0 {
            starts.push(pos);
            pos += 1 + usize::from(wire[pos]);
        }
        let base = out.len();
        for (i, &s) in starts.iter().enumerate() {
            let found = self.suffixes.iter().find(|(suf, _)| suf[..] == wire[s..]);
            if let Some(&(_, off)) = found {
                out.extend_from_slice(&wire[..s]);
                out.extend_from_slice(&(0xc000 | off as u16).to_be_bytes());
                self.register(wire, &starts[..i], base);
                return;
            }
        }
        out.extend_from_slice(wire);
        self.register(wire, &starts, base);
    }

    fn register(&mut self, wire: &[u8], starts: &[usize], base: usize) {
        for &s in starts {
            if base + s <= 0x3fff {
                self.suffixes.push((wire[s..].to_vec(), base + s));
            }
        }
    }
}

#[test]
fn compression_matches_a_reference_compressor() {
    // Random names over a few labels (in two cases, so that matching must
    // be case-sensitive), as owners and as CNAME targets, until about as
    // many labels have been written as the table holds: the output is
    // byte for byte what an unbounded longest-suffix compressor writes.
    let mut state = 0x9e37_79b9u32;
    let mut rand = move |n: u32| {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        (state >> 16) % n
    };
    const LABELS: [&str; 7] = ["a", "b", "www", "WWW", "mail", "example", "com"];
    let mut random_name = move || {
        let labels: Vec<&[u8]> = (0..1 + rand(4))
            .map(|_| LABELS[rand(LABELS.len() as u32) as usize].as_bytes())
            .collect();
        (NameBuf::from_labels(labels).unwrap(), rand(3) == 0)
    };
    for _ in 0..200 {
        let mut buf = [0u8; 4096];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        let mut reference = ReferenceCompressor {
            suffixes: Vec::new(),
        };
        let mut expected = std::vec![0u8; 12];
        let mut records = 0u16;
        while reference.suffixes.len() < compress::CAPACITY - 8 {
            let (owner, cname) = random_name();
            reference.write(&mut expected, owner.as_wire());
            if cname {
                let (target, _) = random_name();
                b.push_answer(&owner, Class::IN, 7, &Cname::new(target.as_name()))
                    .unwrap();
                expected.extend_from_slice(&[0, 5, 0, 1, 0, 0, 0, 7, 0, 0]);
                let at = expected.len();
                reference.write(&mut expected, target.as_wire());
                let len = (expected.len() - at) as u16;
                expected[at - 2..at].copy_from_slice(&len.to_be_bytes());
            } else {
                b.push_answer(&owner, Class::IN, 7, &A::new([192, 0, 2, 1].into()))
                    .unwrap();
                expected.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 7, 0, 4, 192, 0, 2, 1]);
            }
            records += 1;
        }
        expected[6..8].copy_from_slice(&records.to_be_bytes());
        let wire = b.finish();
        assert_eq!(wire, &expected[..]);
        Message::parse_validated(wire).unwrap();
    }
}
