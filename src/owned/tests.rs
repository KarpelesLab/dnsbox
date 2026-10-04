use super::*;
use crate::edns::{ExtendedError, InfoCode, Nsid, OptData};
use crate::rdata::{Mx, TxtParts, UnknownRdata};
use crate::testutil::hex;
use crate::wire::{Canonical, WireWriter};
use std::string::ToString;
use std::vec;

/// `dig @1.1.1.1 gmail.com MX` (captured 2026-10): five MX records whose
/// exchanges are compressed against each other (same capture as
/// `message::tests::GMAIL_MX`).
const GMAIL_MX: &str = "beef8180000100050000000005676d61696c03636f6d00000f0001c00c000f00\
    0100000bbc0020001e04616c74330d676d61696c2d736d74702d696e016c06676f6f676c65c0\
    12c00c000f000100000bbc0009000a04616c7431c02ec00c000f000100000bbc0009001404616c\
    7432c02ec00c000f000100000bbc0009002804616c7434c02ec00c000f000100000bbc00040005c02e";

fn name(s: &str) -> NameBuf {
    s.parse().unwrap()
}

#[test]
fn from_view_decompresses_and_rebuild_recompresses() {
    let wire = hex(GMAIL_MX);
    let msg = Message::parse_validated(&wire).unwrap();
    let owned = OwnedMessage::from_message(&msg).unwrap();
    assert_eq!((owned.id, owned.flags), (0xbeef, msg.flags()));
    assert_eq!(owned.questions.len(), 1);
    assert_eq!(owned.answers.len(), 5);
    assert!(owned.authority.is_empty() && owned.additional.is_empty());
    assert_eq!(owned.questions[0].to_string(), "gmail.com. IN MX");
    let first = &owned.answers[0];
    assert_eq!(
        first.to_string(),
        "gmail.com. 3004 IN MX 30 alt3.gmail-smtp-in.l.google.com."
    );
    // The stored RDATA is self-contained: no pointer, full exchange name.
    assert_eq!(
        first.rdata.as_bytes(),
        b"\x00\x1e\x04alt3\x0dgmail-smtp-in\x01l\x06google\x03com\x00"
    );
    assert_eq!(first.rdata.len(), 35);
    let RData::Mx(mx) = first.data().unwrap() else {
        panic!("not MX")
    };
    assert_eq!(mx.preference, 30);

    // Re-encoding compresses again; this server compresses exactly like
    // the builder, so the bytes are identical.
    assert_eq!(owned.to_vec().unwrap(), wire);
    assert_eq!(OwnedMessage::from_wire(&wire).unwrap(), owned);
    assert_eq!(msg.to_owned_message().unwrap(), owned);
    assert_eq!(OwnedMessage::try_from(msg).unwrap(), owned);
    assert_eq!(OwnedMessage::try_from(&msg).unwrap(), owned);

    // Without compression: same content, longer.
    let mut b = MessageBuilder::new_vec();
    b.set_compression(false);
    owned.write_to(&mut b).unwrap();
    let plain = b.finish();
    assert!(plain.len() > wire.len());
    assert_eq!(OwnedMessage::from_wire(&plain).unwrap(), owned);

    // The dig form is the same for the view and the owned message.
    assert_eq!(owned.to_string(), msg.to_string());
}

#[test]
fn view_conversions() {
    let wire = hex(GMAIL_MX);
    let msg = Message::parse(&wire).unwrap();
    let q = msg.questions().next().unwrap().unwrap();
    assert_eq!(q.to_owned_question(), OwnedQuestion::from(q));
    assert_eq!(OwnedQuestion::from(&q).name, name("gmail.com"));
    let rr = msg.answers().next().unwrap().unwrap();
    let o = rr.to_owned_record().unwrap();
    assert_eq!(OwnedRecord::try_from(rr).unwrap(), o);
    assert_eq!(OwnedRecord::try_from(&rr).unwrap(), o);
    assert_eq!((o.rtype(), o.class, o.ttl), (Rtype::MX, Class::IN, 3004));
    assert_eq!(o.to_string(), rr.to_string());
    let d = rr.data().unwrap();
    assert_eq!(OwnedRData::try_from(&d).unwrap(), o.rdata);
    assert_eq!(OwnedRData::try_from(d).unwrap(), o.rdata);
}

#[test]
fn invalid_views_are_rejected() {
    let mut wire = hex(GMAIL_MX);
    // Corrupt the last exchange pointer into a forward pointer.
    let n = wire.len();
    wire[n - 1] = 0xff;
    let msg = Message::parse(&wire).unwrap();
    assert_eq!(OwnedMessage::from_message(&msg), Err(Error::BadPointer));
    assert_eq!(OwnedMessage::from_wire(&wire), Err(Error::BadPointer));
    let last = msg.answers().last().unwrap().unwrap();
    assert_eq!(OwnedRecord::from_record(&last), Err(Error::BadPointer));
    // Truncations: errors, never panics.
    let wire = hex(GMAIL_MX);
    for len in 0..wire.len() {
        assert!(OwnedMessage::from_wire(&wire[..len]).is_err(), "{len}");
        if let Ok(m) = Message::parse(&wire[..len]) {
            assert!(OwnedMessage::from_message(&m).is_err(), "{len}");
        }
    }
    // Trailing data is only rejected by `from_wire`.
    let mut wire = hex(GMAIL_MX);
    wire.push(0);
    assert_eq!(OwnedMessage::from_wire(&wire), Err(Error::TrailingData));
    assert!(OwnedMessage::from_message(&Message::parse(&wire).unwrap()).is_ok());
}

#[test]
fn rdata_class_semantics() {
    // A is class-specific (RFC 3597 §4): typed in IN, opaque in CH.
    let a = OwnedRData::from_wire(Rtype::A, Class::IN, &[192, 0, 2, 1]).unwrap();
    assert!(matches!(a.as_rdata(), RData::A(_)));
    assert!(matches!(a.parse(Class::IN), Ok(RData::A(_))));
    assert!(matches!(a.parse(Class::CH), Ok(RData::Unknown(_))));
    let ch = OwnedRData::from_wire(Rtype::A, Class::CH, &[1, 2]).unwrap();
    assert_eq!(ch.as_bytes(), [1, 2]);
    assert!(matches!(ch.as_rdata(), RData::Unknown(_)));
    assert_eq!(ch.to_string(), "\\# 2 0102");
    let rr = OwnedRecord::new(name("ch.example"), Class::CH, 0, ch.clone());
    assert_eq!(rr.to_string(), "ch.example. 0 CH A \\# 2 0102");
    assert_eq!(
        OwnedRData::from_wire(Rtype::A, Class::IN, &[1, 2]),
        Err(Error::UnexpectedEof)
    );
    assert_eq!(
        OwnedRData::from_wire(Rtype::A, Class::IN, &[1, 2, 3, 4, 5]),
        Err(Error::TrailingData)
    );

    // Empty RDATA in class NONE / ANY (RFC 2136 §2.5) is opaque.
    let del = OwnedRData::from_wire(Rtype::MX, Class::ANY, &[]).unwrap();
    assert!(del.is_empty());
    assert_eq!(del.rtype(), Rtype::MX);
    assert!(matches!(del.parse(Class::ANY), Ok(RData::Unknown(_))));
    assert!(matches!(del.as_rdata(), RData::Unknown(_)));
    assert_eq!(del.parse(Class::IN), Err(Error::UnexpectedEof));

    // Bytes that do not decode (built from opaque data) fall back to
    // the generic form everywhere, and are copied verbatim.
    let bad = OwnedRData::new(&UnknownRdata::new(Rtype::MX, &[0, 1, 0xc0])).unwrap();
    assert_eq!(bad.parse(Class::IN), Err(Error::UnexpectedEof));
    assert!(matches!(bad.as_rdata(), RData::Unknown(_)));
    assert_eq!(bad.to_string(), "\\# 3 0001C0");
    let rr = OwnedRecord::new(name("x"), Class::IN, 1, bad.clone());
    assert_eq!(rr.to_string(), "x. 1 IN MX \\# 3 0001C0");
    let mut buf = [0u8; 8];
    let mut w = WireWriter::new(&mut buf);
    bad.compose_rdata(&mut w).unwrap();
    assert_eq!(w.written(), [0, 1, 0xc0]);
    assert!(std::format!("{bad:?}").contains("data: \\# 3 0001C0"));
}

#[test]
fn rdata_size_limit() {
    let big = vec![0u8; MAX_RDATA_LEN + 1];
    assert_eq!(
        OwnedRData::new(&UnknownRdata::new(Rtype::NULL, &big)),
        Err(Error::BufferTooSmall)
    );
    let ok = OwnedRData::new(&UnknownRdata::new(Rtype::NULL, &big[1..])).unwrap();
    assert_eq!(ok.len(), MAX_RDATA_LEN);
}

#[test]
fn compose_only_data() {
    let txt = OwnedRData::new(&TxtParts(&[b"v=spf1", b"-all"])).unwrap();
    assert_eq!(txt.rtype(), Rtype::TXT);
    assert_eq!(txt.to_string(), "\"v=spf1\" \"-all\"");
    let rr = OwnedRecord::new(name("example.com"), Class::IN, 300, txt);
    assert_eq!(
        rr.to_string(),
        "example.com. 300 IN TXT \"v=spf1\" \"-all\""
    );
}

#[test]
fn builder_compresses_and_canonicalizes() {
    let owner = name("Example.COM");
    let exchange = name("Mail.Example.COM");
    let mx = OwnedRData::new(&Mx {
        preference: 10,
        exchange: exchange.as_name(),
    })
    .unwrap();
    assert_eq!(mx.as_bytes(), b"\x00\x0a\x04Mail\x07Example\x03COM\x00");
    let rr = OwnedRecord::new(&owner, Class::IN, 300, mx.clone());

    // The builder compresses the exchange against the owner (RFC 1035 MX).
    let mut b = MessageBuilder::new_vec();
    rr.push_to(&mut b, Section::Answer).unwrap();
    let wire = b.finish();
    assert!(
        wire.ends_with(b"\x00\x09\x00\x0a\x04Mail\xc0\x0c"),
        "{wire:02x?}"
    );
    let back = OwnedMessage::from_wire(&wire).unwrap();
    assert_eq!(back.answers, core::slice::from_ref(&rr));
    // Case is preserved exactly.
    assert_eq!(back.answers[0].rdata.as_bytes(), mx.as_bytes());

    // Canonical form (RFC 4034 §6.2) lowercases the MX exchange.
    let mut out = Vec::new();
    mx.compose_rdata(&mut Canonical::new(&mut out)).unwrap();
    assert_eq!(out, b"\x00\x0a\x04mail\x07example\x03com\x00");

    // Pushing into a buffer that is too small fails cleanly.
    let mut buf = [0u8; 20];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    assert_eq!(
        rr.push_to(&mut b, Section::Answer),
        Err(Error::BufferTooSmall)
    );
    assert_eq!(b.header().ancount, 0);
    let mut m = OwnedMessage::new(1, Flags::default());
    m.answers.push(rr);
    let mut buf = [0u8; 20];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    assert_eq!(m.write_to(&mut b), Err(Error::BufferTooSmall));
}

#[test]
fn edns_and_rcode() {
    let mut m = OwnedMessage::new(7, Flags::default().with_qr(true).with_rcode(Rcode::BADVERS));
    assert_eq!(m.opt(), None);
    assert_eq!(m.opt_header(), None);
    assert_eq!(m.effective_rcode(), Rcode::NOERROR);
    let header = OptHeader::new(1232)
        .with_dnssec_ok(true)
        .with_rcode(Rcode::BADVERS);
    let opts = OptData(&(
        Nsid::new(b"ns1"),
        ExtendedError::new(InfoCode::NOT_SUPPORTED, b""),
    ));
    let opt = OwnedRData::new(&opts).unwrap();
    m.additional.push(OwnedRecord::new(
        Name::ROOT,
        header.class(),
        header.ttl(),
        opt,
    ));
    assert_eq!(m.opt_header(), Some(header));
    assert_eq!(m.effective_rcode(), Rcode::BADVERS);
    let text = m.to_string();
    assert!(
        text.starts_with(
            ";; ->>HEADER<<- opcode: QUERY, status: BADVERS, id: 7\n\
         ;; flags: qr; QUERY: 0, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n\
         ;; OPT PSEUDOSECTION:\n\
         ; EDNS: version: 0, flags: do; udp: 1232\n\
         ; NSID: 6e 73 31 (\"ns1\")\n\
         ; EDE: 21 (Not Supported)\n"
        ),
        "{text}"
    );
    let wire = m.to_vec().unwrap();
    let msg = Message::parse_validated(&wire).unwrap();
    assert_eq!(msg.effective_rcode(), Ok(Rcode::BADVERS));
    assert_eq!(msg.to_string(), text);
    assert_eq!(OwnedMessage::from_wire(&wire).unwrap(), m);
}

#[test]
fn header_and_sections() {
    let mut m = OwnedMessage::default();
    assert_eq!(m.header(), Ok(Header::default()));
    let rr = OwnedRecord::new(
        name("a.example"),
        Class::IN,
        60,
        OwnedRData::from_wire(Rtype::A, Class::IN, &[192, 0, 2, 7]).unwrap(),
    );
    m.questions
        .push(OwnedQuestion::new(name("a.example"), Rtype::A, Class::IN));
    for s in [Section::Answer, Section::Authority, Section::Additional] {
        m.section_mut(s).unwrap().push(rr.clone());
        assert_eq!(m.section(s), core::slice::from_ref(&rr));
    }
    assert!(m.section_mut(Section::Question).is_none());
    assert!(m.section(Section::Question).is_empty());
    let h = m.header().unwrap();
    assert_eq!((h.qdcount, h.ancount, h.nscount, h.arcount), (1, 1, 1, 1));
    let sections: Vec<Section> = m.records().map(|(s, _)| s).collect();
    assert_eq!(
        sections,
        [Section::Answer, Section::Authority, Section::Additional]
    );
    let wire = m.to_vec().unwrap();
    assert_eq!(Message::parse_validated(&wire).unwrap().header(), h);

    // More than 65535 entries cannot be encoded.
    m.answers = vec![rr; 65536];
    assert_eq!(m.header(), Err(Error::CountOverflow));
    assert!(m.to_vec().is_err());
    // The dig header saturates rather than failing.
    let text = m.to_string();
    assert!(text.contains("ANSWER: 65535,"), "{}", &text[..200]);
}

#[test]
fn update_messages_display_with_update_names() {
    use crate::Opcode;
    let mut m = OwnedMessage::new(9, Flags::default().with_opcode(Opcode::UPDATE));
    m.questions.push(OwnedQuestion::new(
        name("example.com"),
        Rtype::SOA,
        Class::IN,
    ));
    // Delete all MX RRsets at mail.example.com (RFC 2136 §2.5.2).
    m.authority.push(OwnedRecord::new(
        name("mail.example.com"),
        Class::ANY,
        0,
        OwnedRData::from_wire(Rtype::MX, Class::ANY, &[]).unwrap(),
    ));
    assert_eq!(
        m.to_string(),
        ";; ->>HEADER<<- opcode: UPDATE, status: NOERROR, id: 9\n\
         ;; flags:; ZONE: 1, PREREQ: 0, UPDATE: 1, ADDITIONAL: 0\n\n\
         ;; ZONE SECTION:\n\
         ;example.com.\t\t\tIN\tSOA\n\n\
         ;; UPDATE SECTION:\n\
         mail.example.com.\t0\tANY\tMX\t\\# 0\n\n"
    );
    let wire = m.to_vec().unwrap();
    assert_eq!(OwnedMessage::from_wire(&wire).unwrap(), m);
}

#[test]
fn rdata_from_text() {
    // Presentation format (RFC 1035 §5.1), relative names completed with
    // the root.
    let mx = OwnedRData::from_text(Rtype::MX, Class::IN, "10 mail.example.com").unwrap();
    assert_eq!(mx.as_bytes(), b"\x00\x0a\x04mail\x07example\x03com\x00");
    assert_eq!(mx.to_string(), "10 mail.example.com.");
    // The RFC 3597 §5 generic form, for known and unknown types; hex may
    // be split and in either case.
    let generic = OwnedRData::from_text(
        Rtype::MX,
        Class::IN,
        r"\# 20 000a046d61696c 076578616D706C6503636F6D00",
    );
    assert_eq!(generic.unwrap(), mx);
    let unknown = OwnedRData::from_text(Rtype::new(65280), Class::IN, r"\# 3 0 a 0 b 0 c").unwrap();
    assert_eq!(unknown.as_bytes(), [10, 11, 12]);
    assert_eq!(
        OwnedRData::from_text(Rtype::NULL, Class::IN, r"  \#  0  ")
            .unwrap()
            .as_bytes(),
        b""
    );
    let mut big = std::string::String::from(r"\# 65535 ");
    big.push_str(&"ab".repeat(65535));
    assert_eq!(
        OwnedRData::from_text(Rtype::NULL, Class::IN, &big)
            .unwrap()
            .as_bytes()
            .len(),
        65535
    );
    // Class-specific data of another class is kept opaque (RFC 3597 §4).
    assert!(OwnedRData::from_text(Rtype::A, Class::CH, r"\# 3 C00002").is_ok());
    for bad in [
        "",
        r"\#",
        r"# 1 00",
        r"\# 1",
        r"\# 1 0",
        r"\# 1 0000",
        r"\# 2 00",
        r"\# +1 00",
        r"\# -1 00",
        r"\# x 00",
        r"\# 1 0g",
        r"\# 65536 00",
        r"\# 99999999999999999999999 00",
        r"\#1 00",
    ] {
        assert!(
            OwnedRData::from_text(Rtype::new(65280), Class::IN, bad).is_err(),
            "{bad:?}"
        );
    }
    // Typed formats are checked; leftover tokens are refused.
    assert_eq!(
        OwnedRData::from_text(Rtype::A, Class::IN, "192.0.2.256"),
        Err(Error::InvalidText)
    );
    assert_eq!(
        OwnedRData::from_text(Rtype::A, Class::IN, r"\# 3 C00002"),
        Err(Error::UnexpectedEof)
    );
    assert_eq!(
        OwnedRData::from_text(Rtype::A, Class::IN, "192.0.2.1 x"),
        Err(Error::InvalidText)
    );
    assert_eq!(
        OwnedRData::from_text(Rtype::NULL, Class::IN, "01"),
        Err(Error::NoTextFormat)
    );
}

#[test]
fn record_from_zone_text() {
    let zone = "$ORIGIN example.\n$TTL 300\n@ IN SOA ns hostmaster 1 7200 3600 1209600 300\n\
                www A 192.0.2.1\nmail 60 MX 10 mx1\n";
    let records = crate::zone::parse(zone).unwrap();
    let owned: Vec<OwnedRecord> = records.iter().cloned().map(OwnedRecord::from).collect();
    assert_eq!(owned.len(), 3);
    assert_eq!(owned[1].to_string(), "www.example. 300 IN A 192.0.2.1");
    assert_eq!(
        owned[2].to_string(),
        "mail.example. 60 IN MX 10 mx1.example."
    );
    // The borrowed reader's records convert the same way.
    let mut reader = crate::zone::ZoneReader::new(zone);
    let mut buf = [0u8; 512];
    for want in &owned {
        let rr = reader.next_record(&mut buf).unwrap().unwrap();
        assert_eq!(&OwnedRecord::from(&rr), want);
        assert_eq!(&OwnedRecord::from(rr), want);
    }
    // The owned record goes into a message like any other.
    let mut msg = OwnedMessage::new(7, Flags::default());
    msg.answers.clone_from(&owned);
    let wire = msg.to_vec().unwrap();
    let back = OwnedMessage::from_wire(&wire).unwrap();
    assert_eq!(back.answers, owned);
}

#[test]
fn record_from_str() {
    let rr: OwnedRecord = "mail.example.com. 3600 IN MX 10 mx1.example.com."
        .parse()
        .unwrap();
    assert_eq!((rr.rtype(), rr.ttl, rr.class), (Rtype::MX, 3600, Class::IN));
    assert_eq!(
        rr.to_string(),
        "mail.example.com. 3600 IN MX 10 mx1.example.com."
    );
    // Display output parses back to the same record, multi-line entries
    // and comments are fine, the class defaults to IN.
    assert_eq!(rr.to_string().parse::<OwnedRecord>().unwrap(), rr);
    let multi: OwnedRecord = "mail.example.com. 3600 MX ( 10 ; preference\n mx1.example.com. )"
        .parse()
        .unwrap();
    assert_eq!(multi, rr);
    // `$TTL` applies; the SOA MINIMUM stands in for a missing TTL.
    let soa: OwnedRecord = ". SOA a. b. 1 2 3 4 5".parse().unwrap();
    assert_eq!(soa.ttl, 5);
    let a: OwnedRecord = "$TTL 60\nwww. A 192.0.2.1".parse().unwrap();
    assert_eq!(a.ttl, 60);
    for (text, err) in [
        ("", Error::UnexpectedEof),
        ("; only a comment\n", Error::UnexpectedEof),
        ("www. A 192.0.2.1", Error::MissingTtl),
        ("www. 60 A 192.0.2.256", Error::InvalidText),
        (
            "www. 60 A 192.0.2.1\nwww. 60 A 192.0.2.2",
            Error::InvalidText,
        ),
        ("$INCLUDE other.zone", Error::InvalidText),
        ("$GENERATE 1-2 h$ 60 A 192.0.2.$", Error::InvalidText),
    ] {
        assert_eq!(text.parse::<OwnedRecord>(), Err(err), "{text:?}");
    }
}
