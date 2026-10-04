//! Zone-transfer stream tests, including the RFC 1995 §7 examples.

use super::*;
use crate::rdata::{A, Ns};
use crate::{Flags, NameBuf};
use std::string::String;
use std::vec::Vec;

fn n(s: &str) -> NameBuf {
    s.parse().unwrap()
}

/// A record line of a test response.
enum Rr {
    Soa(&'static str, u32),
    A(&'static str, [u8; 4]),
    Ns(&'static str, &'static str),
}

fn soa_data<'a>(m: &'a NameBuf, r: &'a NameBuf, serial: u32) -> Soa<'a> {
    Soa {
        mname: m.as_name(),
        rname: r.as_name(),
        serial,
        refresh: 600,
        retry: 600,
        expire: 3600000,
        minimum: 604800,
    }
}

/// Builds one response message with the given answer records.
fn message(zone: &str, qtype: Option<Rtype>, id: u16, rcode: Rcode, rrs: &[Rr]) -> Vec<u8> {
    let mut buf = std::vec![0u8; 4096];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.set_id(id);
    b.set_flags(
        Flags::default()
            .with_qr(true)
            .with_aa(true)
            .with_rcode(rcode),
    );
    if let Some(t) = qtype {
        b.push_question(n(zone), t, Class::IN).unwrap();
    }
    let (m, r) = (n("NS.JAIN.AD.JP"), n("mohta.jain.ad.jp"));
    for rr in rrs {
        match *rr {
            Rr::Soa(owner, serial) => b
                .push_answer(n(owner), Class::IN, 0, &soa_data(&m, &r, serial))
                .unwrap(),
            Rr::A(owner, addr) => b
                .push_answer(n(owner), Class::IN, 0, &A::new(addr.into()))
                .unwrap(),
            Rr::Ns(owner, target) => {
                let t = n(target);
                b.push_answer(n(owner), Class::IN, 0, &Ns::new(t.as_name()))
                    .unwrap()
            }
        }
    }
    b.finish().to_vec()
}

/// Feeds the messages and renders the events, one per line.
fn run(proc: &mut XfrProcessor, messages: &[Vec<u8>]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for wire in messages {
        let msg = Message::parse_validated(wire)?;
        for ev in proc.process(&msg)? {
            out.push(match ev? {
                XfrEvent::Start { soa, .. } => std::format!("start {}", soa.serial),
                XfrEvent::UpToDate { soa, .. } => std::format!("up-to-date {}", soa.serial),
                XfrEvent::Record(rr) => std::format!("record {}", rr.name()),
                XfrEvent::DeleteStart { soa, .. } => std::format!("delete-from {}", soa.serial),
                XfrEvent::Delete(rr) => std::format!("delete {} {}", rr.name(), rr.data()?),
                XfrEvent::AddStart { soa, .. } => std::format!("add-to {}", soa.serial),
                XfrEvent::Add(rr) => std::format!("add {} {}", rr.name(), rr.data()?),
                XfrEvent::End { soa, .. } => std::format!("end {}", soa.serial),
            });
        }
    }
    Ok(out)
}

const Z: &str = "JAIN.AD.JP";

#[test]
fn rfc1995_incremental_example() {
    // RFC 1995 §7: serial 1 -> 2 (NEZU removed, JAIN-BB gains two
    // addresses) -> 3 (one JAIN-BB address renumbered).
    let msg = message(
        Z,
        Some(Rtype::IXFR),
        1,
        Rcode::NOERROR,
        &[
            Rr::Soa(Z, 3),
            Rr::Soa(Z, 1),
            Rr::A("NEZU.JAIN.AD.JP", [133, 69, 136, 5]),
            Rr::Soa(Z, 2),
            Rr::A("JAIN-BB.JAIN.AD.JP", [133, 69, 136, 4]),
            Rr::A("JAIN-BB.JAIN.AD.JP", [192, 41, 197, 2]),
            Rr::Soa(Z, 2),
            Rr::A("JAIN-BB.JAIN.AD.JP", [133, 69, 136, 4]),
            Rr::Soa(Z, 3),
            Rr::A("JAIN-BB.JAIN.AD.JP", [133, 69, 136, 3]),
            Rr::Soa(Z, 3),
        ],
    );
    let mut p = XfrProcessor::ixfr(n(Z), 1).with_id(1);
    let events = run(&mut p, &[msg]).unwrap();
    assert_eq!(
        events,
        [
            "start 3",
            "delete-from 1",
            "delete NEZU.JAIN.AD.JP. 133.69.136.5",
            "add-to 2",
            "add JAIN-BB.JAIN.AD.JP. 133.69.136.4",
            "add JAIN-BB.JAIN.AD.JP. 192.41.197.2",
            "delete-from 2",
            "delete JAIN-BB.JAIN.AD.JP. 133.69.136.4",
            "add-to 3",
            "add JAIN-BB.JAIN.AD.JP. 133.69.136.3",
            "end 3",
        ]
    );
    assert!(p.is_done());
    assert_eq!(p.style(), Some(XfrStyle::Incremental));
    assert_eq!((p.messages(), p.records()), (1, 11));
}

#[test]
fn rfc1995_condensed_example() {
    // RFC 1995 §7, condensed: one sequence straight from 1 to 3.
    let msg = message(
        Z,
        Some(Rtype::IXFR),
        1,
        Rcode::NOERROR,
        &[
            Rr::Soa(Z, 3),
            Rr::Soa(Z, 1),
            Rr::A("NEZU.JAIN.AD.JP", [133, 69, 136, 5]),
            Rr::Soa(Z, 3),
            Rr::A("JAIN-BB.JAIN.AD.JP", [133, 69, 136, 3]),
            Rr::A("JAIN-BB.JAIN.AD.JP", [192, 41, 197, 2]),
            Rr::Soa(Z, 3),
        ],
    );
    let mut p = XfrProcessor::ixfr(n(Z), 1);
    let events = run(&mut p, &[msg]).unwrap();
    assert_eq!(events.len(), 7);
    assert_eq!(events[3], "add-to 3");
    assert_eq!(events[6], "end 3");
    assert!(p.is_done());
}

#[test]
fn axfr_across_messages() {
    let msgs = [
        message(
            Z,
            Some(Rtype::AXFR),
            7,
            Rcode::NOERROR,
            &[Rr::Soa(Z, 9), Rr::Ns(Z, "NS.JAIN.AD.JP")],
        ),
        message(Z, None, 7, Rcode::NOERROR, &[]),
        message(
            Z,
            None,
            7,
            Rcode::NOERROR,
            &[Rr::A("NS.JAIN.AD.JP", [133, 69, 136, 1])],
        ),
        message(Z, Some(Rtype::AXFR), 7, Rcode::NOERROR, &[Rr::Soa(Z, 9)]),
    ];
    let mut p = XfrProcessor::axfr(n(Z)).with_id(7);
    assert_eq!(p.serial(), None);
    let events = run(&mut p, &msgs[..2]).unwrap();
    assert_eq!(events, ["start 9", "record JAIN.AD.JP."]);
    assert!(!p.is_done());
    assert_eq!(p.serial(), Some(9));
    let events = run(&mut p, &msgs[2..]).unwrap();
    assert_eq!(events, ["record NS.JAIN.AD.JP.", "end 9"]);
    assert!(p.is_done());
    assert_eq!(p.style(), Some(XfrStyle::Full));
    // Nothing may follow the end.
    assert_eq!(run(&mut p, &msgs[3..]).err(), Some(Error::MalformedXfr));
}

#[test]
fn soa_only_zone_and_axfr_style_ixfr() {
    let msg = message(
        Z,
        Some(Rtype::AXFR),
        0,
        Rcode::NOERROR,
        &[Rr::Soa(Z, 4), Rr::Soa(Z, 4)],
    );
    let mut p = XfrProcessor::axfr(n(Z));
    assert_eq!(run(&mut p, &[msg]).unwrap(), ["start 4", "end 4"]);
    assert!(p.is_done());

    // IXFR answered with the full zone (RFC 1995 §4).
    let msg = message(
        Z,
        Some(Rtype::IXFR),
        0,
        Rcode::NOERROR,
        &[
            Rr::Soa(Z, 4),
            Rr::Ns(Z, "NS.JAIN.AD.JP"),
            Rr::A("NS.JAIN.AD.JP", [1, 2, 3, 4]),
            Rr::Soa(Z, 4),
        ],
    );
    let mut p = XfrProcessor::ixfr(n(Z), 1);
    let ev = run(&mut p, &[msg]).unwrap();
    assert_eq!(
        ev,
        [
            "start 4",
            "record JAIN.AD.JP.",
            "record NS.JAIN.AD.JP.",
            "end 4"
        ]
    );
    assert_eq!(p.style(), Some(XfrStyle::Full));
}

#[test]
fn up_to_date_and_udp_fallback() {
    // Server serial 3; the client has 3, something newer (4), or a
    // serial exactly 2^31 away (undefined in RFC 1982; not "newer").
    for client in [3, 4, 0x8000_0003] {
        let msg = message(Z, Some(Rtype::IXFR), 0, Rcode::NOERROR, &[Rr::Soa(Z, 3)]);
        let mut p = XfrProcessor::ixfr(n(Z), client);
        let ev = run(&mut p, &[msg]).unwrap();
        assert_eq!(ev, ["up-to-date 3"], "client {client}");
        assert!(p.is_done());
        assert_eq!(p.style(), Some(XfrStyle::UpToDate));
    }
    // A single newer SOA over UDP: "retry over TCP"; not done.
    let msg = message(Z, Some(Rtype::IXFR), 0, Rcode::NOERROR, &[Rr::Soa(Z, 3)]);
    let mut p = XfrProcessor::ixfr(n(Z), 2);
    assert_eq!(run(&mut p, &[msg]).unwrap(), ["start 3"]);
    assert!(!p.is_done());
    assert_eq!(p.style(), None);
    // AXFR never reports up to date.
    let msg = message(Z, Some(Rtype::AXFR), 0, Rcode::NOERROR, &[Rr::Soa(Z, 3)]);
    let mut p = XfrProcessor::axfr(n(Z));
    assert_eq!(run(&mut p, &[msg]).unwrap(), ["start 3"]);
}

#[test]
fn serial_arithmetic() {
    assert!(serial_newer(2, 1));
    assert!(!serial_newer(1, 1));
    assert!(!serial_newer(1, 2));
    assert!(serial_newer(0, u32::MAX));
    assert!(serial_newer(0x7fff_ffff, 0));
    assert!(!serial_newer(0x8000_0000, 0));
}

#[test]
fn malformed_streams() {
    let bad = |qtype: Rtype, client: Option<u32>, rrs: &[Rr]| {
        let msg = message(Z, Some(qtype), 0, Rcode::NOERROR, rrs);
        let mut p = match client {
            Some(c) => XfrProcessor::ixfr(n(Z), c),
            None => XfrProcessor::axfr(n(Z)),
        };
        let res = run(&mut p, core::slice::from_ref(&msg));
        // Once failed, the processor stays failed.
        assert_eq!(run(&mut p, &[msg]).err(), Some(Error::MalformedXfr));
        res.err()
    };
    let e = Some(Error::MalformedXfr);
    // First record is not the SOA.
    assert_eq!(bad(Rtype::AXFR, None, &[Rr::Ns(Z, "a")]), e);
    // SOA of another zone.
    assert_eq!(bad(Rtype::AXFR, None, &[Rr::Soa("other", 1)]), e);
    // AXFR ending with a different serial.
    assert_eq!(
        bad(
            Rtype::AXFR,
            None,
            &[Rr::Soa(Z, 1), Rr::Ns(Z, "a"), Rr::Soa(Z, 2)]
        ),
        e
    );
    // AXFR with a second SOA right away (looks incremental).
    assert_eq!(bad(Rtype::AXFR, None, &[Rr::Soa(Z, 1), Rr::Soa(Z, 2)]), e);
    // Records after the end in the same message.
    assert_eq!(
        bad(
            Rtype::AXFR,
            None,
            &[Rr::Soa(Z, 1), Rr::Soa(Z, 1), Rr::Ns(Z, "a")]
        ),
        e
    );
    // IXFR sequences that do not chain (1->2, then 5->...).
    assert_eq!(
        bad(
            Rtype::IXFR,
            Some(1),
            &[Rr::Soa(Z, 3), Rr::Soa(Z, 1), Rr::Soa(Z, 2), Rr::Soa(Z, 5)]
        ),
        e
    );

    // Header checks.
    let ok_rrs = [Rr::Soa(Z, 1), Rr::Soa(Z, 1)];
    let mut p = XfrProcessor::axfr(n(Z));
    let refused = message(Z, Some(Rtype::AXFR), 0, Rcode::REFUSED, &ok_rrs);
    assert_eq!(
        p.process(&Message::parse(&refused).unwrap()).err(),
        Some(Error::ErrorResponse)
    );
    let mut p = XfrProcessor::axfr(n(Z)).with_id(5);
    let wrong_id = message(Z, Some(Rtype::AXFR), 6, Rcode::NOERROR, &ok_rrs);
    assert_eq!(
        p.process(&Message::parse(&wrong_id).unwrap()).err(),
        Some(Error::MalformedXfr)
    );
    let mut p = XfrProcessor::axfr(n(Z));
    let wrong_q = message("other", Some(Rtype::AXFR), 0, Rcode::NOERROR, &ok_rrs);
    assert_eq!(
        p.process(&Message::parse(&wrong_q).unwrap()).err(),
        Some(Error::MalformedXfr)
    );
    let mut p = XfrProcessor::axfr(n(Z));
    let wrong_t = message(Z, Some(Rtype::IXFR), 0, Rcode::NOERROR, &ok_rrs);
    assert_eq!(
        p.process(&Message::parse(&wrong_t).unwrap()).err(),
        Some(Error::MalformedXfr)
    );
    // Not a response.
    let mut q = message(Z, Some(Rtype::AXFR), 0, Rcode::NOERROR, &ok_rrs);
    q[2] &= 0x7f;
    let mut p = XfrProcessor::axfr(n(Z));
    assert_eq!(
        p.process(&Message::parse(&q).unwrap()).err(),
        Some(Error::MalformedXfr)
    );
}

#[test]
fn queries() {
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.set_id(0x2e00);
    let zone = n("example.com");
    let (m, r) = (n("ns1.example.com"), n("hostmaster.example.com"));
    let soa = Soa {
        mname: m.as_name(),
        rname: r.as_name(),
        serial: 1,
        refresh: 7200,
        retry: 3600,
        expire: 1_209_600,
        minimum: 300,
    };
    build_ixfr_query(&mut b, &zone, Class::IN, &soa).unwrap();
    let wire = b.finish().to_vec();
    // `dig example.com IXFR=1` from BIND 9.18 (without its TSIG; see
    // tests/data/named/ixfr1.query.bin): BIND writes the SOA names
    // uncompressed with "." for both, so only compare the question.
    let msg = Message::parse_validated(&wire).unwrap();
    let q = msg.questions().next().unwrap().unwrap();
    assert_eq!(q.qtype(), Rtype::IXFR);
    let auth = msg.authority().next().unwrap().unwrap();
    assert_eq!(auth.data_as::<Soa>().unwrap().serial, 1);
    assert_eq!(auth.name(), zone.as_name());

    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    build_axfr_query(&mut b, &zone, Class::IN).unwrap();
    assert_eq!(
        build_axfr_query(&mut b, &zone, Class::IN),
        Err(Error::SectionOrder)
    );
    assert_eq!(
        build_ixfr_query(&mut b, &zone, Class::IN, &soa),
        Err(Error::SectionOrder)
    );
    let wire = b.finish().to_vec();
    assert_eq!(&wire[12..], b"\x07example\x03com\x00\x00\xfc\x00\x01");

    // Atomic on overflow.
    let mut small = [0u8; 40];
    let mut b = MessageBuilder::new(&mut small).unwrap();
    assert_eq!(
        build_ixfr_query(&mut b, &zone, Class::IN, &soa),
        Err(Error::BufferTooSmall)
    );
    assert!(b.is_empty());
}

#[test]
fn truncated_messages_never_panic() {
    let msg = message(
        Z,
        Some(Rtype::IXFR),
        1,
        Rcode::NOERROR,
        &[
            Rr::Soa(Z, 3),
            Rr::Soa(Z, 1),
            Rr::A("NEZU.JAIN.AD.JP", [133, 69, 136, 5]),
            Rr::Soa(Z, 3),
            Rr::Soa(Z, 3),
        ],
    );
    for end in 0..msg.len() {
        if let Ok(m) = Message::parse(&msg[..end]) {
            let mut p = XfrProcessor::ixfr(n(Z), 1);
            if let Ok(events) = p.process(&m) {
                for ev in events {
                    let _ = ev;
                }
            }
            assert!(!p.is_done() || end == msg.len());
        }
    }
}
