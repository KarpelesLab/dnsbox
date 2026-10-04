use super::*;
use crate::rdata::{Mx, RData};
use crate::testutil::hex;
use std::string::{String, ToString};
use std::vec::Vec;

/// `dig @1.1.1.1 gmail.com MX` (captured 2026-10): five MX records whose
/// exchanges are compressed against each other.
const GMAIL_MX: &str = "beef8180000100050000000005676d61696c03636f6d00000f0001c00c000f00\
    0100000bbc0020001e04616c74330d676d61696c2d736d74702d696e016c06676f6f676c65c0\
    12c00c000f000100000bbc0009000a04616c7431c02ec00c000f000100000bbc0009001404616c\
    7432c02ec00c000f000100000bbc0009002804616c7434c02ec00c000f000100000bbc00040005c02e";

/// `dig @1.1.1.1 nonexistent-dnsbox-test.example.com A +edns` (NODATA with
/// SOA in authority and an OPT record in additional).
const NODATA_SOA: &str = "beef81800001000000010001176e6f6e6578697374656e742d646e73626f782d74657374\
    076578616d706c6503636f6d0000010001c0240006000100000708003207656c6c696f74\
    74026e730a636c6f7564666c617265c02c03646e73c04c9006f398000027100000096000\
    093a800000070800002904d0000000000000";

#[test]
fn gmail_mx() {
    let wire = hex(GMAIL_MX);
    let msg = Message::parse_validated(&wire).unwrap();
    assert_eq!(msg.id(), 0xbeef);
    assert!(msg.flags().qr() && msg.flags().rd() && msg.flags().ra());
    let q = msg.questions().next().unwrap().unwrap();
    assert_eq!(q.to_string(), "gmail.com. IN MX");
    assert_eq!(q.range(), 12..27);

    let mut exchanges = Vec::new();
    for rr in msg.answers() {
        let rr = rr.unwrap();
        assert_eq!(rr.name().to_string(), "gmail.com.");
        assert_eq!(
            (rr.rtype(), rr.class(), rr.ttl()),
            (Rtype::MX, Class::IN, 3004)
        );
        let RData::Mx(mx) = rr.data().unwrap() else {
            panic!("not MX")
        };
        exchanges.push((mx.preference, mx.exchange.to_string()));
    }
    assert_eq!(
        exchanges,
        [
            (30, "alt3.gmail-smtp-in.l.google.com.".to_string()),
            (10, "alt1.gmail-smtp-in.l.google.com.".to_string()),
            (20, "alt2.gmail-smtp-in.l.google.com.".to_string()),
            (40, "alt4.gmail-smtp-in.l.google.com.".to_string()),
            (5, "gmail-smtp-in.l.google.com.".to_string()),
        ]
    );
    let first = msg.answers().next().unwrap().unwrap();
    assert_eq!(
        first.to_string(),
        "gmail.com. 3004 IN MX 30 alt3.gmail-smtp-in.l.google.com."
    );
    assert_eq!(first.start(), 27);
    assert_eq!(first.rdata_range(), 39..71);
    assert_eq!(first.rdata().len(), 32);
    assert_eq!(first.message().len(), wire.len());
    let mx: Mx<'_> = first.data_as().unwrap();
    assert_eq!(mx.preference, 30);
    assert_eq!(msg.authority().count(), 0);
    assert_eq!(msg.additional().count(), 0);
    assert_eq!(msg.section(Section::Question).count(), 0);
    assert_eq!(msg.section_offset(Section::Answer), Ok(27));
    assert_eq!(msg.section_offset(Section::Additional), Ok(wire.len()));
}

#[test]
fn sections_and_all_records() {
    let wire = hex(NODATA_SOA);
    let msg = Message::parse_validated(&wire).unwrap();
    assert_eq!(msg.answers().count(), 0);
    let soa = msg.authority().next().unwrap().unwrap();
    assert_eq!(
        soa.to_string(),
        "example.com. 1800 IN SOA elliott.ns.cloudflare.com. dns.cloudflare.com. \
         2416374680 10000 2400 604800 1800"
    );
    let opt = msg.additional().next().unwrap().unwrap();
    assert_eq!(opt.rtype(), Rtype::OPT);
    assert_eq!(opt.class().get(), 1232);
    assert!(opt.name().is_root());
    let all: Vec<(Section, Rtype)> = msg
        .records()
        .map(|r| r.map(|(s, rr)| (s, rr.rtype())).unwrap())
        .collect();
    assert_eq!(
        all,
        [
            (Section::Authority, Rtype::SOA),
            (Section::Additional, Rtype::OPT)
        ]
    );
    assert_eq!(msg.authority().section(), Section::Authority);
}

#[test]
fn count_mismatch_and_trailing_data() {
    let mut wire = hex(GMAIL_MX);
    // Claim one more answer than present.
    wire[7] = 6;
    let msg = Message::parse(&wire).unwrap();
    let results: Vec<_> = msg.answers().collect();
    assert_eq!(results.len(), 6);
    assert_eq!(results[5].as_ref().unwrap_err(), &Error::UnexpectedEof);
    assert_eq!(msg.validate(), Err(Error::UnexpectedEof));
    assert!(msg.additional().next().is_none(), "arcount is 0");
    // With a non-zero arcount, the additional section cannot be located.
    wire[11] = 1;
    let msg = Message::parse(&wire).unwrap();
    let mut add = msg.additional();
    assert_eq!(add.next().unwrap().unwrap_err(), Error::UnexpectedEof);
    assert!(add.next().is_none(), "fused after error");

    // Trailing garbage is only reported by `validate`.
    let mut wire = hex(GMAIL_MX);
    wire.push(0);
    let msg = Message::parse(&wire).unwrap();
    assert_eq!(msg.answers().filter(|r| r.is_ok()).count(), 5);
    assert_eq!(msg.validate(), Err(Error::TrailingData));
}

#[test]
fn malformed_rdata_is_reported_by_validate() {
    let mut wire = hex(GMAIL_MX);
    // Corrupt the last MX record's exchange pointer into a forward pointer.
    let n = wire.len();
    wire[n - 1] = 0xff;
    let msg = Message::parse(&wire).unwrap();
    assert_eq!(msg.answers().count(), 5, "structure is still fine");
    assert_eq!(msg.validate(), Err(Error::BadPointer));
    let last = msg.answers().last().unwrap().unwrap();
    assert_eq!(last.data(), Err(Error::BadPointer));
    // Display falls back to the generic form.
    assert!(last.to_string().ends_with("MX \\# 4 0005C0FF"));
}

#[test]
fn header_only() {
    assert_eq!(Message::parse(&[0; 11]).unwrap_err(), Error::UnexpectedEof);
    let msg = Message::parse(&[0; 12]).unwrap();
    assert_eq!(msg.questions().count(), 0);
    assert_eq!(msg.records().count(), 0);
    assert_eq!(msg.validate(), Ok(()));
    assert_eq!(msg.as_bytes().len(), 12);
    assert_eq!(msg.header(), Header::default());
}

#[test]
fn every_truncation_fails_cleanly() {
    for capture in [GMAIL_MX, NODATA_SOA] {
        let wire = hex(capture);
        for end in 0..wire.len() {
            let res = Message::parse(&wire[..end]).and_then(|m| m.validate());
            assert!(res.is_err(), "prefix {end} validated");
            if let Ok(msg) = Message::parse(&wire[..end]) {
                exercise(&msg);
            }
        }
    }
}

/// Touches every accessor of every entry; must never panic.
pub(crate) fn exercise(msg: &Message<'_>) -> String {
    let mut out = String::new();
    for q in msg.questions().flatten() {
        out += &q.to_string();
    }
    for (_, rr) in msg.records().flatten() {
        out += &rr.to_string();
        let _ = rr.data();
        let _ = rr.name().to_buf();
    }
    for s in Section::ALL {
        let _ = msg.section(s).count();
        let _ = msg.section_offset(s);
    }
    out
}

#[test]
fn section_helpers() {
    let h = Header {
        qdcount: 1,
        ancount: 2,
        nscount: 3,
        arcount: 4,
        ..Header::default()
    };
    let counts: Vec<u16> = Section::ALL.iter().map(|s| s.count(&h)).collect();
    assert_eq!(counts, [1, 2, 3, 4]);
    assert_eq!(Section::Additional.index(), 3);
    assert!(Section::Question < Section::Answer);
}
