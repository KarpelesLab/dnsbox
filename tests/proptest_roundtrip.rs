//! Property tests: build → parse and parse → build → parse identity of
//! generated messages (RFC 1035 §4.1), with and without name compression.
//!
//! Record data is generated as wire bytes per type and decoded through the
//! generic `RData` dispatch, so a generated record is exactly what a parser
//! would produce. Besides the hand-written generators for the RFC 1035
//! types, one generator draws any *registered* type and random bytes, which
//! covers record types added to the registry later without touching this
//! file.

#[path = "../fuzz/src/lib.rs"]
#[allow(dead_code)]
mod checks;

use dnsbox::{Class, Flags, Message, MessageBuilder, NameBuf, RData, Rtype, Section, WireReader};
use proptest::prelude::*;

/// Labels shared between names (so compression has suffixes to find), in
/// several spellings (compression is case-sensitive).
const POOL: &[&[u8]] = &[
    b"example",
    b"Example",
    b"EXAMPLE",
    b"com",
    b"org",
    b"www",
    b"mail",
    b"ns1",
    b"_tcp",
    b"*",
    b"a.b",
    b"\x00\xff",
];

fn label() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        3 => prop::sample::select(POOL).prop_map(<[u8]>::to_vec),
        1 => prop::collection::vec(any::<u8>(), 1..=63),
    ]
}

/// Names of up to 4 labels (at most 4 × 64 = 256 octets would be one too
/// many, hence the length filter).
fn name() -> impl Strategy<Value = NameBuf> {
    prop::collection::vec(label(), 0..=4).prop_filter_map("name too long", |labels| {
        NameBuf::from_labels(labels.iter().map(Vec::as_slice)).ok()
    })
}

fn char_string() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=40).prop_map(|s| {
        let mut out = vec![s.len() as u8];
        out.extend_from_slice(&s);
        out
    })
}

/// Record data as `(type, wire)`; every value parses as that type.
fn rdata() -> impl Strategy<Value = (Rtype, Vec<u8>)> {
    let names = prop::sample::select(vec![
        Rtype::NS,
        Rtype::CNAME,
        Rtype::PTR,
        Rtype::MB,
        Rtype::MD,
        Rtype::MF,
        Rtype::MG,
        Rtype::MR,
    ]);
    let registered: Vec<Rtype> = Rtype::all()
        .map(|(t, _)| t)
        .filter(|&t| RData::is_known(t))
        .collect();
    prop_oneof![
        any::<[u8; 4]>().prop_map(|a| (Rtype::A, a.to_vec())),
        any::<[u8; 16]>().prop_map(|a| (Rtype::AAAA, a.to_vec())),
        (names, name()).prop_map(|(t, n)| (t, n.as_wire().to_vec())),
        (any::<u16>(), name()).prop_map(|(pref, n)| {
            let mut w = pref.to_be_bytes().to_vec();
            w.extend_from_slice(n.as_wire());
            (Rtype::MX, w)
        }),
        (name(), name(), any::<[u32; 5]>()).prop_map(|(m, r, nums)| {
            let mut w = m.as_wire().to_vec();
            w.extend_from_slice(r.as_wire());
            for n in nums {
                w.extend_from_slice(&n.to_be_bytes());
            }
            (Rtype::SOA, w)
        }),
        (name(), name()).prop_map(|(a, b)| {
            let mut w = a.as_wire().to_vec();
            w.extend_from_slice(b.as_wire());
            (Rtype::MINFO, w)
        }),
        prop::collection::vec(char_string(), 1..4).prop_map(|s| (Rtype::TXT, s.concat())),
        (char_string(), char_string()).prop_map(|(a, b)| (Rtype::HINFO, [a, b].concat())),
        prop::collection::vec(any::<u8>(), 0..64).prop_map(|d| (Rtype::NULL, d)),
        (any::<[u8; 5]>(), prop::collection::vec(any::<u8>(), 0..16))
            .prop_map(|(h, bm)| (Rtype::WKS, [&h[..], &bm].concat())),
        (65280u16..=65534, prop::collection::vec(any::<u8>(), 0..64))
            .prop_map(|(t, d)| (Rtype::new(t), d)),
        // Any registered type with random bytes; when they do not parse,
        // fall back to opaque data of a private-use type.
        (
            prop::sample::select(registered),
            prop::collection::vec(any::<u8>(), 0..48)
        )
            .prop_map(|(t, d)| {
                if RData::parse(t, Class::IN, WireReader::new(&d)).is_ok() {
                    (t, d)
                } else {
                    (Rtype::new(65400), d)
                }
            }),
    ]
}

fn class() -> impl Strategy<Value = Class> {
    prop_oneof![
        6 => Just(Class::IN),
        1 => Just(Class::CH),
        1 => any::<u16>().prop_map(Class::new),
    ]
}

#[derive(Clone, Debug)]
struct Rr {
    section: Section,
    name: NameBuf,
    class: Class,
    ttl: u32,
    rtype: Rtype,
    rdata: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Msg {
    id: u16,
    flags: u16,
    questions: Vec<(NameBuf, Rtype, Class)>,
    records: Vec<Rr>,
}

fn record() -> impl Strategy<Value = Rr> {
    (
        prop::sample::select(vec![
            Section::Answer,
            Section::Authority,
            Section::Additional,
        ]),
        name(),
        class(),
        any::<u32>(),
        rdata(),
    )
        .prop_map(|(section, name, class, ttl, (rtype, rdata))| Rr {
            section,
            name,
            class,
            ttl,
            rtype,
            rdata,
        })
}

fn message() -> impl Strategy<Value = Msg> {
    (
        any::<u16>(),
        any::<u16>(),
        prop::collection::vec((name(), any::<u16>().prop_map(Rtype::new), class()), 0..3),
        prop::collection::vec(record(), 0..24),
    )
        .prop_map(|(id, flags, questions, mut records)| {
            records.sort_by_key(|r| r.section);
            Msg {
                id,
                flags,
                questions,
                records,
            }
        })
}

/// Builds `m` into `buf`, returning the message length.
fn build(m: &Msg, buf: &mut [u8], compress: bool) -> usize {
    let mut b = MessageBuilder::new(buf).unwrap();
    b.set_id(m.id);
    b.set_flags(Flags::from_bits(m.flags));
    b.set_compression(compress);
    for (n, t, c) in &m.questions {
        b.push_question(n, *t, *c).unwrap();
    }
    for r in &m.records {
        let data = RData::parse(r.rtype, r.class, WireReader::new(&r.rdata)).unwrap();
        b.push_record(r.section, &r.name, r.class, r.ttl, &data)
            .unwrap();
    }
    b.finish().len()
}

/// Checks that `wire` parses back to exactly `m`.
fn assert_matches(m: &Msg, wire: &[u8]) {
    let msg = Message::parse_validated(wire).unwrap();
    assert_eq!(msg.id(), m.id);
    assert_eq!(msg.flags().bits(), m.flags);
    let qs: Vec<_> = msg.questions().map(Result::unwrap).collect();
    assert_eq!(qs.len(), m.questions.len());
    for (q, (n, t, c)) in qs.iter().zip(&m.questions) {
        assert!(q.name().eq_exact(&n.as_name()));
        assert_eq!((q.qtype(), q.qclass()), (*t, *c));
    }
    let rrs: Vec<_> = msg.records().map(Result::unwrap).collect();
    assert_eq!(rrs.len(), m.records.len());
    for ((s, rr), want) in rrs.iter().zip(&m.records) {
        assert_eq!(*s, want.section);
        assert!(rr.name().eq_exact(&want.name.as_name()));
        assert_eq!(
            (rr.rtype(), rr.class(), rr.ttl()),
            (want.rtype, want.class, want.ttl)
        );
        let expected = RData::parse(want.rtype, want.class, WireReader::new(&want.rdata)).unwrap();
        let got = rr.data().unwrap();
        assert_eq!(got, expected);
        // Display preserves case, so this also checks RDATA name case.
        assert_eq!(got.to_string(), expected.to_string());
    }
}

/// Re-encodes a parsed message with the builder.
fn rebuild(wire: &[u8], buf: &mut [u8], compress: bool) -> usize {
    let msg = Message::parse_validated(wire).unwrap();
    let mut b = MessageBuilder::new(buf).unwrap();
    b.set_id(msg.id());
    b.set_flags(msg.flags());
    b.set_compression(compress);
    for q in msg.questions() {
        b.copy_question(&q.unwrap()).unwrap();
    }
    for rr in msg.records() {
        let (s, rr) = rr.unwrap();
        b.copy_record(s, &rr).unwrap();
    }
    b.finish().len()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// build → parse: what was pushed is what parses back, compressed or
    /// not, and compression never makes a message longer.
    #[test]
    fn build_parse_identity(m in message()) {
        let mut c = vec![0u8; 65535];
        let mut u = vec![0u8; 65535];
        let cl = build(&m, &mut c, true);
        let ul = build(&m, &mut u, false);
        assert_matches(&m, &c[..cl]);
        assert_matches(&m, &u[..ul]);
        prop_assert!(cl <= ul);
    }

    /// parse → build → parse: re-encoding a parsed message reproduces the
    /// builder's own encoding byte for byte (the builder's output depends
    /// only on the content), in both directions between compressed and
    /// uncompressed forms.
    #[test]
    fn parse_build_parse_identity(m in message()) {
        let mut c = vec![0u8; 65535];
        let mut u = vec![0u8; 65535];
        let cl = build(&m, &mut c, true);
        let ul = build(&m, &mut u, false);
        let mut out = vec![0u8; 65535];
        let n = rebuild(&u[..ul], &mut out, true);
        prop_assert_eq!(&out[..n], &c[..cl]);
        let n = rebuild(&c[..cl], &mut out, false);
        prop_assert_eq!(&out[..n], &u[..ul]);
        let n = rebuild(&c[..cl], &mut out, true);
        prop_assert_eq!(&out[..n], &c[..cl]);
        assert_matches(&m, &out[..n]);
    }

    /// The shared fuzz checks hold for generated messages and for random
    /// corruptions of them.
    #[test]
    fn fuzz_checks_on_generated(
        m in message(),
        flips in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 0..4),
    ) {
        let mut buf = vec![0u8; 65535];
        let len = build(&m, &mut buf, true);
        let mut wire = buf[..len].to_vec();
        checks::message(&wire);
        for (i, v) in flips {
            let i = i.index(wire.len());
            wire[i] = v;
        }
        checks::message(&wire);
    }
}
