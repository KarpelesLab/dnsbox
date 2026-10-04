//! Milestone 4 record types, batch A (SRV, NAPTR, CAA, SSHFP, TLSA, SMIMEA,
//! OPENPGPKEY, DNAME, URI, CERT, DHCID): build → parse round trips through
//! whole messages, the no-compression rule for RDATA names (RFC 3597 §4),
//! and hostile-input robustness.

use dnsbox::rdata::{
    Caa, Cert, CertType, Dhcid, Dname, Naptr, Openpgpkey, Smimea, Srv, Sshfp, SshfpAlgorithm,
    SshfpFpType, Tlsa, TlsaCertUsage, TlsaMatchingType, TlsaSelector, Uri,
};
use dnsbox::{CharStr, Class, ComposeRdata, Message, MessageBuilder, NameBuf, RData, Rtype};

fn name(s: &str) -> NameBuf {
    s.parse().unwrap()
}

/// Builds a response holding one record of every batch-A type, all owned by
/// (or pointing at) `example.com`, with compression enabled.
fn build(buf: &mut [u8]) -> &mut [u8] {
    let owner = name("example.com");
    let target = name("host.example.com");
    let digest = [0xab; 32];
    let dhcid = [&[0x00, 0x02, 0x01][..], &digest].concat();

    let naptr = Naptr {
        order: 100,
        preference: 10,
        flags: CharStr::new(b"S").unwrap(),
        services: CharStr::new(b"SIP+D2U").unwrap(),
        regexp: CharStr::new(b"").unwrap(),
        replacement: target.as_name(),
    };
    let records: [RData<'_>; 11] = [
        RData::Srv(Srv::new(1, 2, 443, target.as_name())),
        RData::Naptr(naptr),
        RData::Caa(Caa::new(0, b"issue", b"ca.example.net").unwrap()),
        RData::Sshfp(Sshfp::new(
            SshfpAlgorithm::ED25519,
            SshfpFpType::SHA256,
            &digest,
        )),
        RData::Tlsa(Tlsa::new(
            TlsaCertUsage::DANE_EE,
            TlsaSelector::SPKI,
            TlsaMatchingType::SHA2_256,
            &digest,
        )),
        RData::Smimea(Smimea::new(
            TlsaCertUsage::DANE_EE,
            TlsaSelector::CERT,
            TlsaMatchingType::FULL,
            b"\x30\x00",
        )),
        RData::Openpgpkey(Openpgpkey::new(b"\x98\x33\x04")),
        RData::Dname(Dname::new(target.as_name())),
        RData::Uri(Uri::new(10, 1, b"https://example.com/").unwrap()),
        RData::Cert(Cert::new(
            CertType::PKIX,
            0,
            dnsbox::dnssec::Algorithm::new(0),
            b"\x30\x00",
        )),
        RData::Dhcid(Dhcid::from_wire(&dhcid).unwrap()),
    ];

    let mut b = MessageBuilder::new(buf).unwrap();
    b.set_id(0xbeef);
    b.push_question(&owner, Rtype::ANY, Class::IN).unwrap();
    for data in records {
        b.push_answer(&owner, Class::IN, 300, &data).unwrap();
    }
    b.finish()
}

#[test]
fn build_parse_round_trip() {
    let mut buf = [0u8; 2048];
    let wire = build(&mut buf);
    let msg = Message::parse_validated(wire).unwrap();
    let texts: Vec<String> = msg
        .answers()
        .map(|rr| rr.unwrap().data().unwrap().to_string())
        .collect();
    let digest = "AB".repeat(32);
    assert_eq!(
        texts,
        [
            "1 2 443 host.example.com.".to_string(),
            r#"100 10 "S" "SIP+D2U" "" host.example.com."#.to_string(),
            r#"0 issue "ca.example.net""#.to_string(),
            format!("4 2 {digest}"),
            format!("3 1 1 {digest}"),
            "3 0 0 3000".to_string(),
            "mDME".to_string(),
            "host.example.com.".to_string(),
            r#"10 1 "https://example.com/""#.to_string(),
            "PKIX 0 0 MAA=".to_string(),
            format!("AAIB{}", "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s="),
        ]
    );

    // Every record is typed, and re-encoding it through a fresh builder
    // reproduces the message byte for byte.
    let mut out = [0u8; 2048];
    let mut b = MessageBuilder::new(&mut out).unwrap();
    b.set_id(0xbeef);
    for q in msg.questions() {
        b.copy_question(&q.unwrap()).unwrap();
    }
    for rr in msg.answers() {
        let rr = rr.unwrap();
        assert!(!matches!(rr.data().unwrap(), RData::Unknown(_)), "{rr}");
        b.copy_record(dnsbox::Section::Answer, &rr).unwrap();
    }
    assert_eq!(b.finish(), &*wire);
}

#[test]
fn rdata_names_are_never_compressed() {
    let mut buf = [0u8; 2048];
    let wire = build(&mut buf);
    let msg = Message::parse_validated(wire).unwrap();
    let full = b"\x04host\x07example\x03com\x00";
    for rr in msg.answers() {
        let rr = rr.unwrap();
        // The owner names are compressed against the question...
        assert_eq!(&wire[rr.start()..rr.start() + 2], b"\xc0\x0c");
        // ...but the names inside SRV, NAPTR and DNAME RDATA are written in
        // full, even though `example.com` is available as a target.
        if matches!(rr.rtype(), Rtype::SRV | Rtype::NAPTR | Rtype::DNAME) {
            assert!(rr.rdata().ends_with(full), "{rr}");
        }
    }
}

#[test]
fn hostile_rdata_never_panics() {
    let mut buf = [0u8; 2048];
    let wire = build(&mut buf).to_vec();
    // Truncation at every offset.
    for end in 0..wire.len() {
        if let Ok(msg) = Message::parse(&wire[..end]) {
            for (_, rr) in msg.records().flatten() {
                let _ = rr.data().map(|d| d.to_string());
            }
        }
    }
    // Deterministic pseudo-random byte mutations (xorshift).
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..20_000 {
        let mut m = wire.clone();
        for _ in 0..1 + next() % 4 {
            let i = (next() as usize) % m.len();
            m[i] = next() as u8;
        }
        if let Ok(msg) = Message::parse(&m) {
            let _ = msg.validate();
            for (_, rr) in msg.records().flatten() {
                if let Ok(d) = rr.data() {
                    let s = d.to_string();
                    // Whatever parsed must re-compose.
                    let mut out = [0u8; 4096];
                    let mut w = dnsbox::WireWriter::new(&mut out);
                    d.compose_rdata(&mut w).unwrap();
                    assert!(!s.is_empty());
                }
            }
        }
    }
}

#[test]
fn update_forms_stay_opaque() {
    // RFC 2136 §2.5.2: "delete an RRset" uses class ANY with empty RDATA,
    // which is not valid typed data for these types.
    for t in [
        Rtype::SRV,
        Rtype::CAA,
        Rtype::URI,
        Rtype::DHCID,
        Rtype::TLSA,
    ] {
        let mut r = dnsbox::WireReader::new(b"");
        let d = RData::parse(t, Class::ANY, r.sub_reader(0).unwrap()).unwrap();
        assert!(matches!(d, RData::Unknown(_)));
        assert_eq!(d.rtype(), t);
    }
}
