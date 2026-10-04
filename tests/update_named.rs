//! Dynamic UPDATE (RFC 2136) against BIND 9.18 `nsupdate` captures
//! (`tests/data/named/update*.bin`, October 2026).

use dnsbox::rdata::{A, Aaaa, RData};
use dnsbox::update::{Prerequisite, UpdateBuilder, UpdateMessage, UpdateOp};
use dnsbox::{Class, Message, MessageBuilder, NameBuf, Opcode, Rcode, Rtype};

fn data(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/data/named/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn n(s: &str) -> NameBuf {
    s.parse().unwrap()
}

#[test]
fn parse_nsupdate_request() {
    // prereq nxdomain new / yxdomain www / yxrrset www A / yxrrset www A
    // 192.0.2.80 / nxrrset www TXT; update add new 300 A 192.0.2.1 /
    // delete old A 192.0.2.99 / delete t000 TXT / delete t001.
    let wire = data("update1.query.bin");
    let msg = Message::parse_validated(&wire).unwrap();
    let up = UpdateMessage::new(msg).unwrap();
    up.validate().unwrap();
    assert_eq!(up.zone_name().to_string(), "example.com.");
    assert_eq!(up.zone_class(), Class::IN);

    let pre: Vec<_> = up.prerequisites().map(Result::unwrap).collect();
    assert_eq!(pre.len(), 5);
    assert!(matches!(pre[0], Prerequisite::NameAbsent(n) if n.to_string() == "new.example.com."));
    assert!(matches!(pre[1], Prerequisite::NameInUse(n) if n.to_string() == "www.example.com."));
    assert!(matches!(
        pre[2],
        Prerequisite::RrsetExists {
            rtype: Rtype::A,
            ..
        }
    ));
    match pre[3] {
        Prerequisite::RrExists(rr) => {
            assert_eq!(rr.to_string(), "www.example.com. 0 IN A 192.0.2.80")
        }
        p => panic!("{p:?}"),
    }
    assert!(matches!(
        pre[4],
        Prerequisite::RrsetAbsent {
            rtype: Rtype::TXT,
            ..
        }
    ));
    for p in &pre {
        assert!(up.in_zone(&p.name()));
    }

    let ops: Vec<_> = up.updates().map(Result::unwrap).collect();
    assert_eq!(ops.len(), 4);
    match ops[0] {
        UpdateOp::Add(rr) => assert_eq!(rr.to_string(), "new.example.com. 300 IN A 192.0.2.1"),
        o => panic!("{o:?}"),
    }
    match ops[1] {
        UpdateOp::DeleteRr(rr) => {
            assert_eq!(rr.to_string(), "old.example.com. 0 NONE A 192.0.2.99")
        }
        o => panic!("{o:?}"),
    }
    assert!(
        matches!(ops[2], UpdateOp::DeleteRrset { rtype: Rtype::TXT, name } if name.to_string() == "t000.example.com.")
    );
    assert!(
        matches!(ops[3], UpdateOp::DeleteName(name) if name.to_string() == "t001.example.com.")
    );
    // The TSIG is the additional data.
    assert_eq!(up.additional().count(), 1);

    let ok = data("update1.response.bin");
    let ok = Message::parse_validated(&ok).unwrap();
    assert_eq!(ok.flags().opcode(), Opcode::UPDATE);
    assert_eq!(ok.flags().rcode(), Rcode::NOERROR);
    let fail = data("update-fail.response.bin");
    let fail = Message::parse_validated(&fail).unwrap();
    assert_eq!(fail.flags().rcode(), Rcode::YXDOMAIN);
}

/// Rebuilds update1 with the builder: same bytes as nsupdate, including
/// name compression and (with the `tsig` feature) the TSIG.
#[test]
fn rebuild_nsupdate_request() {
    let wire = data("update1.query.bin");
    let msg = Message::parse(&wire).unwrap();
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.set_id(msg.id());
    let mut u = UpdateBuilder::new(b, n("example.com"), Class::IN).unwrap();
    u.require_name_absent(n("new.example.com")).unwrap();
    u.require_name_in_use(n("www.example.com")).unwrap();
    u.require_rrset_exists(n("www.example.com"), Rtype::A)
        .unwrap();
    u.require_rr(n("www.example.com"), &A::new([192, 0, 2, 80].into()))
        .unwrap();
    u.require_rrset_absent(n("www.example.com"), Rtype::TXT)
        .unwrap();
    u.add(n("new.example.com"), 300, &A::new([192, 0, 2, 1].into()))
        .unwrap();
    u.delete_rr(n("old.example.com"), &A::new([192, 0, 2, 99].into()))
        .unwrap();
    u.delete_rrset(n("t000.example.com"), Rtype::TXT).unwrap();
    u.delete_name(n("t001.example.com")).unwrap();
    let b = u.builder();
    let tsig_start = dnsbox::tsig::find(&msg).unwrap().unwrap().start;
    assert_eq!(&b.as_bytes()[12..], &wire[12..tsig_start]);

    #[cfg(feature = "tsig")]
    {
        use dnsbox::tsig::{HmacKey, TsigAlgorithm, TsigSigner};
        let secret: Vec<u8> = (0u8..32).collect();
        let key = HmacKey::new(n("tsig-key"), TsigAlgorithm::HmacSha256, &secret);
        let t = dnsbox::tsig::find(&msg).unwrap().unwrap();
        TsigSigner::request(&key)
            .sign(b, t.data.time_signed)
            .unwrap();
        assert_eq!(u.finish(), &wire[..]);
    }
}

#[test]
fn second_update() {
    let wire = data("update2.query.bin");
    let up = UpdateMessage::new(Message::parse_validated(&wire).unwrap()).unwrap();
    assert_eq!(up.prerequisites().count(), 0);
    let ops: Vec<_> = up.updates().map(Result::unwrap).collect();
    let rendered: Vec<String> = ops
        .iter()
        .map(|op| match op {
            UpdateOp::Add(rr) => match rr.data().unwrap() {
                RData::Aaaa(Aaaa { addr }) => format!("AAAA {addr}"),
                RData::Txt(t) => format!("TXT {t}"),
                d => format!("{d}"),
            },
            o => format!("{o:?}"),
        })
        .collect();
    assert_eq!(rendered, ["AAAA 2001:db8::2", "TXT \"hello\""]);
}

#[test]
fn mutations_never_panic() {
    for f in [
        "update1.query.bin",
        "update2.query.bin",
        "update-fail.query.bin",
    ] {
        let wire = data(f);
        for i in 0..wire.len() {
            for delta in [1u8, 0x80, 0xff] {
                let mut m = wire.clone();
                m[i] = m[i].wrapping_add(delta);
                let Ok(msg) = Message::parse(&m) else {
                    continue;
                };
                if let Ok(up) = UpdateMessage::new(msg) {
                    let _ = up.validate();
                    for p in up.prerequisites().flatten() {
                        let _ = up.in_zone(&p.name());
                    }
                    for op in up.updates().flatten() {
                        let _ = op.name();
                    }
                }
            }
        }
        for end in 0..wire.len() {
            if let Ok(msg) = Message::parse(&wire[..end])
                && let Ok(up) = UpdateMessage::new(msg)
            {
                let _ = up.validate();
            }
        }
    }
}
