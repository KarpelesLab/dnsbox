//! The record types defined only by Internet-Drafts: IPN and CLA
//! (draft-johnson-dns-ipn-cla-07) and UNECE and ISO
//! (draft-woodcock-faltstrom-external-registry-rrtypes-01), in a master
//! file (RFC 1035 §5) with the examples of their drafts: every record
//! reads, displays as expected, reads back from its display, and survives
//! a message round trip (build, parse, re-encode with compression).

use dnsbox::rdata::{Cla, Ipn, Iso, Precision, RData, RegistryValue, Unece};
use dnsbox::zone::ZoneReader;
use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};

/// The examples, in the forms zone files use.
const ZONE: &str = r#"
$TTL 3600
$ORIGIN example.
; draft-johnson-dns-ipn-cla-07 §3.1: one 64-bit number, or two 32-bit
; halves, most significant first
node            IPN     977000
                IPN     1.2
; ... and the RFC 3597 form of the first
                TYPE264 \# 8 00000000000ee868
; §3.2: one adapter per string, quoted or not
node            CLA     "TCP-V4-V6" "TCP-V6-V7"
                CLA     TCP-v4-v7 TCP-v6-v7 LTP-v6-v7
                TYPE263 \# 10 095443502d76362d7637
; draft-woodcock-faltstrom-external-registry-rrtypes-01 §3.4
asset           UNECE   16 - JPTYO "place of inspection"
                UNECE   20 -18 CEL "cold-chain storage temperature"
                UNECE   20 ? P1 "moisture content, assay pending"
                UNECE   24 - 219
; §4.4 (a precision's parentheses must be escaped or quoted: unescaped,
; they group lines, RFC 1035 §5.1)
                ISO     3166-2 - US-CA "state of incorporation"
                ISO     4217 2400000\(50000\) EUR "insured value, hull and machinery"
                ISO     4217 "780000(?)" CHF "salvage award, assessment ongoing"
                TYPE70  \# 9 033633390002617278
"#;

/// What each record of [`ZONE`] displays as.
const EXPECTED: &[&str] = &[
    "node.example. 3600 IN IPN 977000",
    "node.example. 3600 IN IPN 4294967298",
    "node.example. 3600 IN IPN 977000",
    "node.example. 3600 IN CLA TCP-V4-V6 TCP-V6-V7",
    "node.example. 3600 IN CLA TCP-v4-v7 TCP-v6-v7 LTP-v6-v7",
    "node.example. 3600 IN CLA TCP-v6-v7",
    "asset.example. 3600 IN UNECE 16 - JPTYO \"place of inspection\"",
    "asset.example. 3600 IN UNECE 20 -18 CEL \"cold-chain storage temperature\"",
    "asset.example. 3600 IN UNECE 20 ? P1 \"moisture content, assay pending\"",
    "asset.example. 3600 IN UNECE 24 - 219",
    "asset.example. 3600 IN ISO 3166-2 - US-CA \"state of incorporation\"",
    "asset.example. 3600 IN ISO 4217 2400000\\(50000\\) EUR \"insured value, hull and machinery\"",
    "asset.example. 3600 IN ISO 4217 780000\\(?\\) CHF \"salvage award, assessment ongoing\"",
    "asset.example. 3600 IN ISO 639 - ar \"x\"",
];

/// Reads `text`, returning each record's display form and wire RDATA.
fn read(text: &str) -> Vec<(String, NameBuf, Rtype, Vec<u8>)> {
    let mut r = ZoneReader::new(text);
    let mut buf = [0u8; 65535];
    let mut out = Vec::new();
    while let Some(rr) = r.next_record(&mut buf).unwrap_or_else(|e| panic!("{e}")) {
        // Every record is typed.
        assert!(!matches!(rr.data().unwrap(), RData::Unknown(_)), "{rr}");
        out.push((rr.to_string(), rr.name.clone(), rr.rtype, rr.rdata.to_vec()));
    }
    out
}

#[test]
fn draft_types_are_typed() {
    for t in [Rtype::IPN, Rtype::CLA, Rtype::UNECE, Rtype::ISO] {
        assert!(RData::is_known(t), "{t}");
    }
    // Reserved without a format: still opaque.
    for t in [Rtype::UINFO, Rtype::UID, Rtype::GID, Rtype::UNSPEC] {
        assert!(!RData::is_known(t), "{t}");
    }
}

#[test]
fn zone_with_the_examples() {
    let records = read(ZONE);
    let shown: Vec<&str> = records.iter().map(|(s, ..)| s.as_str()).collect();
    assert_eq!(shown, EXPECTED);
    // The displayed zone reads back to the same records.
    assert_eq!(read(&EXPECTED.join("\n")), records);
    // The presentation and generic forms agree.
    assert_eq!(records[0].3, records[2].3);
}

#[test]
fn message_round_trip() {
    let records = read(ZONE);
    let mut buf = [0u8; 4096];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.set_id(264);
    for (_, name, rtype, rdata) in &records {
        let data = RData::parse(*rtype, Class::IN, dnsbox::WireReader::new(rdata)).unwrap();
        b.push_answer(name, Class::IN, 3600, &data).unwrap();
    }
    let wire = b.finish();
    let msg = Message::parse_validated(wire).unwrap();
    // Re-encoding with compression keeps every RDATA as it was (no names
    // in these RDATA, RFC 3597 §4).
    let mut abuf = [0u8; 4096];
    let mut again = MessageBuilder::new(&mut abuf).unwrap();
    assert_eq!(
        again.copy_message(&msg).unwrap(),
        dnsbox::builder::Outcome::Added
    );
    let again = again.finish();
    let reparsed = Message::parse_validated(again).unwrap();
    let rdatas: Vec<&[u8]> = reparsed.answers().map(|rr| rr.unwrap().rdata()).collect();
    let expected: Vec<&[u8]> = records.iter().map(|(.., r)| r.as_slice()).collect();
    assert_eq!(rdatas, expected);

    // Typed access.
    let of = |t: Rtype| {
        msg.answers()
            .map(|rr| rr.unwrap())
            .filter(move |rr| rr.rtype() == t)
    };
    let ipn: Ipn = of(Rtype::IPN).nth(1).unwrap().data_as().unwrap();
    assert_eq!(ipn.parts(), (1, 2));
    let cla: Cla<'_> = of(Rtype::CLA).nth(1).unwrap().data_as().unwrap();
    let adapters: Vec<&[u8]> = cla.strings().map(|s| s.as_bytes()).collect();
    assert_eq!(adapters, [&b"TCP-v4-v7"[..], b"TCP-v6-v7", b"LTP-v6-v7"]);
    let unece: Unece<'_> = of(Rtype::UNECE).nth(1).unwrap().data_as().unwrap();
    assert_eq!(
        (unece.recommendation, unece.code),
        (&b"20"[..], &b"CEL"[..])
    );
    assert_eq!(
        unece.value_kind(),
        RegistryValue::Quantity {
            number: "-18",
            precision: None
        }
    );
    let iso: Iso<'_> = of(Rtype::ISO).nth(1).unwrap().data_as().unwrap();
    assert_eq!(
        iso.value_kind(),
        RegistryValue::Quantity {
            number: "2400000",
            precision: Some(Precision::Known("50000"))
        }
    );
    assert_eq!(iso.descriptor, b"insured value, hull and machinery");
}
