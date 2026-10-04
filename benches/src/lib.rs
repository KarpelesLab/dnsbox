//! Benchmark fixtures and the per-library code under test.
//!
//! Each fixture is described once, library-neutrally ([`Fixture`]); every
//! library then builds its own native representation outside the timed
//! region. The timed operations are:
//!
//! - **parse**: decode the whole message and visit every entry: walk the
//!   labels of every owner name and decode every record's typed RDATA
//!   (names inside RDATA included). hickory-proto decodes eagerly into
//!   owned values; dnsbox and domain decode lazily, so the walk forces the
//!   same work out of them.
//! - **build**: encode the message with name compression from
//!   pre-constructed records.
//!
//! The tests at the bottom check that all three libraries agree on every
//! fixture, so the benchmarks compare like with like.

use std::hint::black_box;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Record data used by the fixtures (the common RFC 1035 types).
#[derive(Clone, Debug)]
pub enum Rd {
    /// IPv4 address.
    A(Ipv4Addr),
    /// IPv6 address.
    Aaaa(Ipv6Addr),
    /// Name server.
    Ns(&'static str),
    /// Canonical name.
    Cname(&'static str),
    /// Mail exchange.
    Mx(u16, &'static str),
    /// A single character-string.
    Txt(&'static str),
    /// Start of authority.
    Soa(&'static str, &'static str, [u32; 5]),
}

/// One resource record.
#[derive(Clone, Debug)]
pub struct Rr {
    /// Owner name.
    pub name: String,
    /// TTL.
    pub ttl: u32,
    /// Data.
    pub data: Rd,
}

/// A message, library-neutrally.
#[derive(Clone, Debug)]
pub struct Fixture {
    /// Short identifier used in benchmark names.
    pub id: &'static str,
    /// Whether this is a response (QR) or a query.
    pub response: bool,
    /// The question.
    pub qname: String,
    /// QTYPE (1 = A).
    pub qtype: u16,
    /// Answer section.
    pub answer: Vec<Rr>,
    /// Authority section.
    pub authority: Vec<Rr>,
    /// Additional section (before the OPT record).
    pub additional: Vec<Rr>,
    /// EDNS(0) UDP payload size, if an OPT record is present.
    pub edns: Option<u16>,
}

fn rr(name: &str, ttl: u32, data: Rd) -> Rr {
    Rr {
        name: name.to_string(),
        ttl,
        data,
    }
}

/// A typical recursive query: one question plus an EDNS(0) OPT record.
pub fn typical_query() -> Fixture {
    Fixture {
        id: "query",
        response: false,
        qname: "www.example.com".into(),
        qtype: 1,
        answer: vec![],
        authority: vec![],
        additional: vec![],
        edns: Some(1232),
    }
}

/// A large response: 66 records over all three sections, every name
/// sharing suffixes with earlier ones (so almost every name compresses).
pub fn large_response() -> Fixture {
    let mut answer = Vec::new();
    for i in 0..20u8 {
        answer.push(rr(
            "www.example.com",
            300,
            Rd::A(Ipv4Addr::new(192, 0, 2, i)),
        ));
    }
    for i in 0..10u16 {
        answer.push(rr(
            "www.example.com",
            300,
            Rd::Aaaa(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i)),
        ));
    }
    const MX: [&str; 5] = [
        "mx1.mail.example.com",
        "mx2.mail.example.com",
        "mx3.mail.example.com",
        "mx4.mail.example.com",
        "mx5.mail.example.com",
    ];
    for (i, mx) in MX.iter().enumerate() {
        answer.push(rr("example.com", 3600, Rd::Mx(10 * i as u16, mx)));
    }
    for txt in [
        "v=spf1 include:_spf.example.com ~all",
        "google-site-verification=abcdefghijklmnopqrstuvwxyz0123456789",
        "MS=ms12345678",
    ] {
        answer.push(rr("example.com", 3600, Rd::Txt(txt)));
    }
    answer.push(rr("cdn.example.com", 60, Rd::Cname("www.example.com")));
    const NS: [&str; 4] = [
        "ns1.example.net",
        "ns2.example.net",
        "ns3.example.net",
        "ns4.example.net",
    ];
    let mut authority: Vec<Rr> = NS
        .iter()
        .map(|ns| rr("example.com", 86400, Rd::Ns(ns)))
        .collect();
    authority.push(rr(
        "example.com",
        3600,
        Rd::Soa(
            "ns1.example.net",
            "hostmaster.example.com",
            [2026100401, 7200, 3600, 1209600, 300],
        ),
    ));
    let mut additional = Vec::new();
    for (i, ns) in NS.iter().enumerate() {
        additional.push(rr(ns, 86400, Rd::A(Ipv4Addr::new(198, 51, 100, i as u8))));
        additional.push(rr(
            ns,
            86400,
            Rd::Aaaa(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, i as u16)),
        ));
    }
    for (i, mx) in MX.iter().enumerate() {
        additional.push(rr(mx, 3600, Rd::A(Ipv4Addr::new(203, 0, 113, i as u8))));
    }
    Fixture {
        id: "large",
        response: true,
        qname: "www.example.com".into(),
        qtype: 1,
        answer,
        authority,
        additional,
        edns: Some(1232),
    }
}

/// Number of chained labels in the deepest names of [`compression_heavy`].
pub const CHAIN_DEPTH: usize = 120;

/// A pathological, compression-heavy response: 240 A records whose owner
/// names are `x.x.….x.a.example`, each one label longer than the previous,
/// so on the wire every owner name is one label plus a pointer to the
/// previous owner. Decoding name *n* follows *n* pointers (up to 120), which
/// is the worst case a decoder with a sane hop limit has to accept.
pub fn compression_heavy() -> Fixture {
    let mut answer = Vec::new();
    for _round in 0..2 {
        let mut name = String::from("a.example");
        for i in 0..CHAIN_DEPTH {
            name.insert_str(0, "x.");
            answer.push(rr(
                &name,
                60,
                Rd::A(Ipv4Addr::new(10, 0, (i >> 8) as u8, i as u8)),
            ));
        }
    }
    Fixture {
        id: "pathological",
        response: true,
        qname: "a.example".into(),
        qtype: 1,
        answer,
        authority: vec![],
        additional: vec![],
        edns: None,
    }
}

/// Every fixture.
pub fn fixtures() -> Vec<Fixture> {
    vec![typical_query(), large_response(), compression_heavy()]
}

// ---------------------------------------------------------------------------
// dnsbox
// ---------------------------------------------------------------------------

/// dnsbox: owned inputs for building.
pub mod dnsbox_impl {
    use super::*;
    use dnsbox::rdata::{A, Aaaa, Cname, Mx, Ns, Soa, TxtParts, UnknownRdata};
    use dnsbox::{
        Class, ComposeRdata, Flags, Message, MessageBuilder, NameBuf, OutBuf, RData, Rtype, Section,
    };

    /// Pre-parsed names for one record.
    pub struct Prepared {
        section: Section,
        owner: NameBuf,
        ttl: u32,
        data: PData,
    }

    // Inline NameBufs on purpose: no indirection in the timed loop.
    #[allow(clippy::large_enum_variant)]
    enum PData {
        A(A),
        Aaaa(Aaaa),
        Ns(NameBuf),
        Cname(NameBuf),
        Mx(u16, NameBuf),
        Txt(&'static str),
        Soa(NameBuf, NameBuf, [u32; 5]),
    }

    /// A fixture with every name pre-parsed.
    pub struct Built {
        response: bool,
        qname: NameBuf,
        qtype: Rtype,
        records: Vec<Prepared>,
        edns: Option<u16>,
    }

    fn name(s: &str) -> NameBuf {
        s.parse().expect("valid fixture name")
    }

    /// Prepares a fixture (outside the timed region).
    pub fn prepare(f: &Fixture) -> Built {
        let mut records = Vec::new();
        for (section, rrs) in [
            (Section::Answer, &f.answer),
            (Section::Authority, &f.authority),
            (Section::Additional, &f.additional),
        ] {
            for r in rrs {
                let data = match &r.data {
                    Rd::A(a) => PData::A(A::new(*a)),
                    Rd::Aaaa(a) => PData::Aaaa(Aaaa::new(*a)),
                    Rd::Ns(n) => PData::Ns(name(n)),
                    Rd::Cname(n) => PData::Cname(name(n)),
                    Rd::Mx(p, n) => PData::Mx(*p, name(n)),
                    Rd::Txt(t) => PData::Txt(t),
                    Rd::Soa(m, r, nums) => PData::Soa(name(m), name(r), *nums),
                };
                records.push(Prepared {
                    section,
                    owner: name(&r.name),
                    ttl: r.ttl,
                    data,
                });
            }
        }
        Built {
            response: f.response,
            qname: name(&f.qname),
            qtype: Rtype::new(f.qtype),
            records,
            edns: f.edns,
        }
    }

    fn push<D: ComposeRdata, B: OutBuf>(b: &mut MessageBuilder<B>, p: &Prepared, d: &D) {
        b.push_record(p.section, &p.owner, Class::IN, p.ttl, d)
            .expect("fits");
    }

    /// Builds the message into `buf` (no allocation), returning its length.
    pub fn build(m: &Built, buf: &mut [u8]) -> usize {
        fill(m, MessageBuilder::new(buf).expect("buffer")).len()
    }

    /// Builds the message into a new `Vec` (like the other libraries do).
    pub fn build_vec(m: &Built) -> Vec<u8> {
        fill(m, MessageBuilder::new_vec())
    }

    fn fill<B: OutBuf>(m: &Built, mut b: MessageBuilder<B>) -> B::Output {
        b.set_id(0x2a2a);
        b.set_flags(Flags::default().with_qr(m.response).with_rd(true));
        b.push_question(&m.qname, m.qtype, Class::IN).expect("fits");
        for p in &m.records {
            match &p.data {
                PData::A(a) => push(&mut b, p, a),
                PData::Aaaa(a) => push(&mut b, p, a),
                PData::Ns(n) => push(&mut b, p, &Ns::new(n.as_name())),
                PData::Cname(n) => push(&mut b, p, &Cname::new(n.as_name())),
                PData::Mx(pref, n) => push(
                    &mut b,
                    p,
                    &Mx {
                        preference: *pref,
                        exchange: n.as_name(),
                    },
                ),
                PData::Txt(t) => push(&mut b, p, &TxtParts(&[t.as_bytes()])),
                PData::Soa(mn, rn, v) => push(
                    &mut b,
                    p,
                    &Soa {
                        mname: mn.as_name(),
                        rname: rn.as_name(),
                        serial: v[0],
                        refresh: v[1],
                        retry: v[2],
                        expire: v[3],
                        minimum: v[4],
                    },
                ),
            }
        }
        if let Some(size) = m.edns {
            b.push_additional(
                dnsbox::Name::ROOT,
                Class::new(size),
                0,
                &UnknownRdata::new(Rtype::OPT, &[]),
            )
            .expect("fits");
        }
        b.finish()
    }

    fn walk(name: dnsbox::Name<'_>) -> usize {
        name.labels().map(|l| l.len()).sum()
    }

    /// Parses and visits everything; returns a checksum.
    pub fn parse(wire: &[u8]) -> usize {
        let msg = Message::parse(wire).expect("valid");
        let mut sum = 0;
        for q in msg.questions() {
            sum += walk(q.expect("valid").name());
        }
        for rr in msg.records() {
            let (_, rr) = rr.expect("valid");
            sum += walk(rr.name());
            match rr.data().expect("valid") {
                RData::A(a) => sum += a.addr.octets()[3] as usize,
                RData::Aaaa(a) => sum += a.addr.octets()[15] as usize,
                RData::Ns(n) => sum += walk(n.nsdname),
                RData::Cname(n) => sum += walk(n.cname),
                RData::Mx(mx) => sum += walk(mx.exchange) + mx.preference as usize,
                RData::Txt(t) => sum += t.strings().map(|s| s.len()).sum::<usize>(),
                RData::Soa(s) => sum += walk(s.mname) + walk(s.rname) + s.serial as usize,
                other => {
                    black_box(&other);
                }
            }
        }
        sum
    }

    /// Validates the whole message (dnsbox's fail-fast entry point).
    pub fn validate(wire: &[u8]) -> bool {
        Message::parse_validated(wire).is_ok()
    }

    /// Counts (questions, records) for the agreement tests.
    pub fn counts(wire: &[u8]) -> (usize, usize) {
        let msg = Message::parse_validated(wire).expect("valid");
        (msg.questions().count(), msg.records().count())
    }
}

// ---------------------------------------------------------------------------
// hickory-proto
// ---------------------------------------------------------------------------

/// hickory-proto 0.26.
pub mod hickory_impl {
    use super::*;
    use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::{A, AAAA, CNAME, MX, NS, SOA, TXT};
    use hickory_proto::rr::{Name, RData, Record, RecordType};

    fn name(s: &str) -> Name {
        Name::from_ascii(format!("{s}.")).expect("valid fixture name")
    }

    fn record(r: &Rr) -> Record {
        let data = match &r.data {
            Rd::A(a) => RData::A(A(*a)),
            Rd::Aaaa(a) => RData::AAAA(AAAA(*a)),
            Rd::Ns(n) => RData::NS(NS(name(n))),
            Rd::Cname(n) => RData::CNAME(CNAME(name(n))),
            Rd::Mx(p, n) => RData::MX(MX::new(*p, name(n))),
            Rd::Txt(t) => RData::TXT(TXT::new(vec![t.to_string()])),
            Rd::Soa(m, rn, v) => RData::SOA(SOA::new(
                name(m),
                name(rn),
                v[0],
                v[1] as i32,
                v[2] as i32,
                v[3] as i32,
                v[4],
            )),
        };
        Record::from_rdata(name(&r.name), r.ttl, data)
    }

    /// Builds the owned `Message` (outside the timed region).
    pub fn prepare(f: &Fixture) -> Message {
        let mut m = Message::new(
            0x2a2a,
            if f.response {
                MessageType::Response
            } else {
                MessageType::Query
            },
            OpCode::Query,
        );
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(name(&f.qname), RecordType::from(f.qtype)));
        for r in &f.answer {
            m.add_answer(record(r));
        }
        for r in &f.authority {
            m.add_authority(record(r));
        }
        for r in &f.additional {
            m.add_additional(record(r));
        }
        if let Some(size) = f.edns {
            let mut e = Edns::new();
            e.set_max_payload(size);
            m.set_edns(e);
        }
        m
    }

    /// Encodes the message.
    pub fn build(m: &Message) -> Vec<u8> {
        m.to_vec().expect("encodes")
    }

    fn walk(name: &Name) -> usize {
        name.iter().map(<[u8]>::len).sum()
    }

    /// Parses (eagerly) and visits everything; returns a checksum.
    pub fn parse(wire: &[u8]) -> usize {
        let msg = Message::from_vec(wire).expect("valid");
        let mut sum = 0;
        for q in &msg.queries {
            sum += walk(q.name());
        }
        for rr in msg
            .answers
            .iter()
            .chain(&msg.authorities)
            .chain(&msg.additionals)
        {
            sum += walk(&rr.name);
            match &rr.data {
                RData::A(a) => sum += a.0.octets()[3] as usize,
                RData::AAAA(a) => sum += a.0.octets()[15] as usize,
                RData::NS(n) => sum += walk(&n.0),
                RData::CNAME(n) => sum += walk(&n.0),
                RData::MX(mx) => sum += walk(&mx.exchange) + mx.preference as usize,
                RData::TXT(t) => sum += t.txt_data.iter().map(|s| s.len()).sum::<usize>(),
                RData::SOA(s) => sum += walk(&s.mname) + walk(&s.rname) + s.serial as usize,
                other => {
                    black_box(other);
                }
            }
        }
        sum
    }

    /// Counts (questions, records incl. OPT) for the agreement tests.
    pub fn counts(wire: &[u8]) -> (usize, usize) {
        let msg = Message::from_vec(wire).expect("valid");
        let opt = usize::from(msg.edns.is_some());
        (
            msg.queries.len(),
            msg.answers.len() + msg.authorities.len() + msg.additionals.len() + opt,
        )
    }
}

// ---------------------------------------------------------------------------
// domain
// ---------------------------------------------------------------------------

/// NLnet Labs domain 0.12.
pub mod domain_impl {
    use super::*;
    use domain::base::iana::{Class, Rtype};
    use domain::base::message_builder::StaticCompressor;
    use domain::base::name::ParsedName;
    use domain::base::{Message, MessageBuilder, Name, Record, Serial, Ttl};
    use domain::rdata::{A, Aaaa, AllRecordData, Cname, Mx, Ns, Soa, Txt};

    type OwnedName = Name<Vec<u8>>;
    type Data = AllRecordData<Vec<u8>, OwnedName>;

    fn name(s: &str) -> OwnedName {
        OwnedName::from_str(s).expect("valid fixture name")
    }

    fn record(r: &Rr) -> Record<OwnedName, Data> {
        let data = match &r.data {
            Rd::A(a) => Data::A(A::new(*a)),
            Rd::Aaaa(a) => Data::Aaaa(Aaaa::new(*a)),
            Rd::Ns(n) => Data::Ns(Ns::new(name(n))),
            Rd::Cname(n) => Data::Cname(Cname::new(name(n))),
            Rd::Mx(p, n) => Data::Mx(Mx::new(*p, name(n))),
            Rd::Txt(t) => Data::Txt(Txt::build_from_slice(t.as_bytes()).expect("short")),
            Rd::Soa(m, rn, v) => Data::Soa(Soa::new(
                name(m),
                name(rn),
                Serial(v[0]),
                Ttl::from_secs(v[1]),
                Ttl::from_secs(v[2]),
                Ttl::from_secs(v[3]),
                Ttl::from_secs(v[4]),
            )),
        };
        Record::new(name(&r.name), Class::IN, Ttl::from_secs(r.ttl), data)
    }

    /// Pre-built records.
    pub struct Built {
        response: bool,
        qname: OwnedName,
        qtype: Rtype,
        answer: Vec<Record<OwnedName, Data>>,
        authority: Vec<Record<OwnedName, Data>>,
        additional: Vec<Record<OwnedName, Data>>,
        edns: Option<u16>,
    }

    /// Prepares a fixture (outside the timed region).
    pub fn prepare(f: &Fixture) -> Built {
        Built {
            response: f.response,
            qname: name(&f.qname),
            qtype: Rtype::from_int(f.qtype),
            answer: f.answer.iter().map(record).collect(),
            authority: f.authority.iter().map(record).collect(),
            additional: f.additional.iter().map(record).collect(),
            edns: f.edns,
        }
    }

    /// Encodes the message with domain's allocation-free compressor.
    pub fn build(m: &Built) -> Vec<u8> {
        let target = StaticCompressor::new(Vec::with_capacity(4096));
        let mut b = MessageBuilder::from_target(target).expect("header");
        b.header_mut().set_id(0x2a2a);
        b.header_mut().set_qr(m.response);
        b.header_mut().set_rd(true);
        let mut q = b.question();
        q.push((&m.qname, m.qtype)).expect("fits");
        let mut a = q.answer();
        for r in &m.answer {
            a.push(r).expect("fits");
        }
        let mut au = a.authority();
        for r in &m.authority {
            au.push(r).expect("fits");
        }
        let mut ad = au.additional();
        for r in &m.additional {
            ad.push(r).expect("fits");
        }
        if let Some(size) = m.edns {
            ad.opt(|o| {
                o.set_udp_payload_size(size);
                Ok(())
            })
            .expect("fits");
        }
        ad.finish().into_target()
    }

    fn walk<O: AsRef<[u8]>>(name: &ParsedName<O>) -> usize {
        name.iter().map(|l| l.len()).sum()
    }

    /// Parses (lazily) and visits everything; returns a checksum.
    pub fn parse(wire: &[u8]) -> usize {
        let msg = Message::from_octets(wire).expect("valid");
        let mut sum = 0;
        for q in msg.question() {
            sum += walk(q.expect("valid").qname());
        }
        let mut section = msg.answer().expect("valid");
        loop {
            for rr in section.into_records::<AllRecordData<_, ParsedName<_>>>() {
                let rr = rr.expect("valid");
                sum += walk(rr.owner());
                match rr.data() {
                    AllRecordData::A(a) => sum += a.addr().octets()[3] as usize,
                    AllRecordData::Aaaa(a) => sum += a.addr().octets()[15] as usize,
                    AllRecordData::Ns(n) => sum += walk(n.nsdname()),
                    AllRecordData::Cname(n) => sum += walk(n.cname()),
                    AllRecordData::Mx(mx) => sum += walk(mx.exchange()) + mx.preference() as usize,
                    AllRecordData::Txt(t) => sum += t.iter().map(|s| s.len()).sum::<usize>(),
                    AllRecordData::Soa(s) => {
                        sum += walk(s.mname()) + walk(s.rname()) + s.serial().0 as usize
                    }
                    other => {
                        black_box(other);
                    }
                }
            }
            match section.next_section().expect("valid") {
                Some(next) => section = next,
                None => break,
            }
        }
        sum
    }

    /// Counts (questions, records) for the agreement tests.
    pub fn counts(wire: &[u8]) -> (usize, usize) {
        let msg = Message::from_octets(wire).expect("valid");
        let h = msg.header_counts();
        (
            h.qdcount() as usize,
            h.ancount() as usize + h.nscount() as usize + h.arcount() as usize,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected(f: &Fixture) -> (usize, usize) {
        (
            1,
            f.answer.len() + f.authority.len() + f.additional.len() + usize::from(f.edns.is_some()),
        )
    }

    /// All three libraries build the same message content, and each one
    /// parses what every library built, computing the same checksum.
    #[test]
    fn libraries_agree() {
        for f in fixtures() {
            let mut buf = vec![0u8; 65535];
            let n = dnsbox_impl::build(&dnsbox_impl::prepare(&f), &mut buf);
            let ours = buf[..n].to_vec();
            assert_eq!(dnsbox_impl::build_vec(&dnsbox_impl::prepare(&f)), ours);
            let hickory = hickory_impl::build(&hickory_impl::prepare(&f));
            let domain = domain_impl::build(&domain_impl::prepare(&f));
            let reference = dnsbox_impl::parse(&ours);
            for (who, wire) in [
                ("dnsbox", &ours),
                ("hickory", &hickory),
                ("domain", &domain),
            ] {
                assert_eq!(dnsbox_impl::counts(wire), expected(&f), "{} {who}", f.id);
                assert_eq!(hickory_impl::counts(wire), expected(&f), "{} {who}", f.id);
                assert_eq!(domain_impl::counts(wire), expected(&f), "{} {who}", f.id);
                assert_eq!(dnsbox_impl::parse(wire), reference, "{} {who}", f.id);
                assert_eq!(hickory_impl::parse(wire), reference, "{} {who}", f.id);
                assert_eq!(domain_impl::parse(wire), reference, "{} {who}", f.id);
                assert!(dnsbox_impl::validate(wire));
            }
            println!(
                "{}: dnsbox {} bytes, hickory {} bytes, domain {} bytes",
                f.id,
                ours.len(),
                hickory.len(),
                domain.len()
            );
        }
    }

    /// The pathological fixture really is one label plus a pointer per
    /// owner name when built by dnsbox.
    #[test]
    fn pathological_shape() {
        let f = compression_heavy();
        let mut buf = vec![0u8; 65535];
        let n = dnsbox_impl::build(&dnsbox_impl::prepare(&f), &mut buf);
        // header + question (a.example) + 240 × (x + pointer + fixed + A),
        // where the first owner of each round may point into the question.
        assert!(n <= 12 + 15 + 240 * (2 + 2 + 10 + 4), "{n}");
    }
}
