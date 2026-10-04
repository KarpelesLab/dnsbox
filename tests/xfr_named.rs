//! AXFR / IXFR streams from BIND 9.18 (`tests/data/named/axfr*` and
//! `ixfr*`, captured October 2026 over TCP; every message is TSIG-signed).

use dnsbox::xfr::{XfrEvent, XfrProcessor, XfrStyle};
use dnsbox::{Message, NameBuf, Rtype};

fn data(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/data/named/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn zone() -> NameBuf {
    "example.com".parse().unwrap()
}

#[test]
fn axfr_three_messages() {
    let query = data("axfr.query.bin");
    let q = Message::parse(&query).unwrap();
    let mut p = XfrProcessor::axfr(zone()).with_id(q.id());
    let (mut start, mut records, mut end, mut txt) = (None, 0, None, 0);
    for f in [
        "axfr.response.bin",
        "axfr.response2.bin",
        "axfr.response3.bin",
    ] {
        assert!(!p.is_done());
        let wire = data(f);
        let msg = Message::parse_validated(&wire).unwrap();
        for ev in p.process(&msg).unwrap() {
            match ev.unwrap() {
                XfrEvent::Start { soa, .. } => start = Some(soa.serial),
                XfrEvent::Record(rr) => {
                    records += 1;
                    if rr.rtype() == Rtype::TXT {
                        txt += 1;
                    }
                }
                XfrEvent::End { soa, .. } => end = Some(soa.serial),
                ev => panic!("{ev:?}"),
            }
        }
    }
    assert!(p.is_done());
    assert_eq!(p.style(), Some(XfrStyle::Full));
    assert_eq!((start, end), (Some(1), Some(1)));
    // NS, ns1 A, www A + AAAA, MX, mail A, old A, and 450 TXT.
    assert_eq!((records, txt), (457, 450));
    assert_eq!(p.message_count(), 3);
    assert_eq!(p.record_count(), 459);
}

#[test]
fn ixfr_incremental() {
    let wire = data("ixfr1.response.bin");
    let msg = Message::parse_validated(&wire).unwrap();
    let mut p = XfrProcessor::ixfr(zone(), 1);
    let mut log = Vec::new();
    for ev in p.process(&msg).unwrap() {
        log.push(match ev.unwrap() {
            XfrEvent::Start { soa, .. } => format!("start {}", soa.serial),
            XfrEvent::DeleteStart { soa, .. } => format!("from {}", soa.serial),
            XfrEvent::Delete(rr) => format!("- {} {}", rr.name(), rr.rtype()),
            XfrEvent::AddStart { soa, .. } => format!("to {}", soa.serial),
            XfrEvent::Add(rr) => format!("+ {}", rr),
            XfrEvent::End { soa, .. } => format!("end {}", soa.serial),
            ev => panic!("{ev:?}"),
        });
    }
    assert_eq!(
        log,
        [
            "start 3",
            "from 1",
            "- old.example.com. A",
            "- t000.example.com. TXT",
            "- t001.example.com. TXT",
            "to 2",
            "+ new.example.com. 300 IN A 192.0.2.1",
            "from 2",
            "to 3",
            "+ www.example.com. 3600 IN TXT \"hello\"",
            "+ new2.example.com. 300 IN AAAA 2001:db8::2",
            "end 3",
        ]
    );
    assert!(p.is_done());
    assert_eq!(p.style(), Some(XfrStyle::Incremental));
}

#[test]
fn ixfr_up_to_date() {
    let wire = data("ixfr-uptodate.response.bin");
    let msg = Message::parse_validated(&wire).unwrap();
    let mut p = XfrProcessor::ixfr(zone(), 3);
    let events: Vec<_> = p.process(&msg).unwrap().collect();
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], Ok(XfrEvent::UpToDate { soa, .. }) if soa.serial == 3));
    assert!(p.is_done());

    // The same response to a client at serial 1 means "use TCP".
    let mut p = XfrProcessor::ixfr(zone(), 1);
    for ev in p.process(&msg).unwrap() {
        assert!(matches!(ev.unwrap(), XfrEvent::Start { .. }));
    }
    assert!(!p.is_done());
}

#[cfg(feature = "tsig")]
#[test]
fn axfr_with_tsig() {
    use dnsbox::tsig::{self, HmacKey, TsigAlgorithm, TsigVerifier};
    let secret: Vec<u8> = (0u8..32).collect();
    let name: NameBuf = "tsig-key".parse().unwrap();
    let key = HmacKey::new(&name, TsigAlgorithm::HmacSha256, &secret);
    let query = data("axfr.query.bin");
    let q = Message::parse(&query).unwrap();
    let t = tsig::find(&q).unwrap().unwrap();
    let mut v = TsigVerifier::new(&key, t.mac()).unwrap();
    let mut p = XfrProcessor::axfr(zone()).with_id(q.id());
    for f in [
        "axfr.response.bin",
        "axfr.response2.bin",
        "axfr.response3.bin",
    ] {
        let wire = data(f);
        let msg = Message::parse(&wire).unwrap();
        v.verify(&msg, t.data.time_signed).unwrap().unwrap();
        for ev in p.process(&msg).unwrap() {
            ev.unwrap();
        }
    }
    v.finish().unwrap();
    assert!(p.is_done());
}

#[test]
fn mutated_streams_never_panic() {
    let parts: Vec<Vec<u8>> = ["axfr.response.bin", "ixfr1.response.bin"]
        .iter()
        .map(|f| data(f))
        .collect();
    for wire in &parts {
        for i in (0..wire.len()).step_by(13) {
            let mut m = wire.clone();
            m[i] ^= 0x5a;
            if let Ok(msg) = Message::parse(&m) {
                let mut p = XfrProcessor::ixfr(zone(), 1);
                if let Ok(events) = p.process(&msg) {
                    events.for_each(drop);
                }
            }
        }
    }
}
