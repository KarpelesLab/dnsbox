//! AMTRELAY (RFC 8777), DSYNC (RFC 9859), HHIT/BRID (RFC 9886) and DOA
//! records in a master file (RFC 1035 §5), with the examples of their
//! specifications: every record reads, displays as expected, reads back
//! from its display, and survives a message round trip (build, parse,
//! re-encode with compression). TKEY (RFC 2930), a meta type, is checked
//! in a key exchange.

use dnsbox::rdata::{
    Amtrelay, AmtrelayRelay, Dsync, DsyncScheme, ParseRdataText, RData, Tkey, TkeyMode, TsigRcode,
};
use dnsbox::zone::ZoneReader;
use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype, Section, tkey};

/// The examples, in the forms zone files use.
const ZONE: &str = r#"
$TTL 3600
; RFC 8777 §4.3.2
$ORIGIN 100.51.198.in-addr.arpa.
12              AMTRELAY 10 0 1 203.0.113.15
12              AMTRELAY 10 0 2 2001:db8::15
12              AMTRELAY 128 1 3 amtrelays.example.com.
; ... and their RFC 3597 form (the RFC's second record has ::f for ::15,
; its third one lacks the root label)
10              TYPE260 \# ( 6  ; length
                        0a ; precedence=10
                        01 ; D=0, relay type=1, an IPv4 address
                        cb00710f ) ; 203.0.113.15
10              TYPE260 \# ( 18 ; length
                        0a ; precedence=10
                        02 ; D=0, relay type=2, an IPv6 address
                        20010db800000000000000000000000f ) ; 2001:db8::15
10              TYPE260 \# ( 25 ; length
                        80 ; precedence=128
                        83 ; D=1, relay type=3, a wire-encoded domain name
                        09616d7472656c617973076578616d706c6503636f6d00 )
; no relay, and a relay type RFC 8777 does not define
13              AMTRELAY 0 0 0 .
14              AMTRELAY \# 4 00840102
; RFC 9859 §2.3, §3.1, §3.2
$ORIGIN example.
*._dsync        DSYNC   CDS   NOTIFY 5359 cds-scanner.example.net.
                DSYNC   CSYNC NOTIFY 5360 csync-scanner.example.net.
child._dsync    DSYNC   CDS NOTIFY 5300 rr-endpoint
                DSYNC   TYPE1000 200 53 @
; RFC 9886 Appendix A.1.1 (the start of the HHIT) and a short BRID
drip            HHIT    ( gwppM2ZmOCAwMDAwWQFGMIIBQjCB9aAD
                          AgECAgE1MAUGAytlcDArMSkwJwYDVQQD )
                BRID    owAAAYIEUQ==
; draft-durand-doa-over-dns §3.3
doa             DOA     0 1 2 "" aHR0cHM6Ly93d3cuaXNjLm9yZy8=
                DOA     1234567890 100 1 "text/plain" -
"#;

/// What each record of [`ZONE`] displays as.
const EXPECTED: &[&str] = &[
    "12.100.51.198.in-addr.arpa. 3600 IN AMTRELAY 10 0 1 203.0.113.15",
    "12.100.51.198.in-addr.arpa. 3600 IN AMTRELAY 10 0 2 2001:db8::15",
    "12.100.51.198.in-addr.arpa. 3600 IN AMTRELAY 128 1 3 amtrelays.example.com.",
    "10.100.51.198.in-addr.arpa. 3600 IN AMTRELAY 10 0 1 203.0.113.15",
    "10.100.51.198.in-addr.arpa. 3600 IN AMTRELAY 10 0 2 2001:db8::f",
    "10.100.51.198.in-addr.arpa. 3600 IN AMTRELAY 128 1 3 amtrelays.example.com.",
    "13.100.51.198.in-addr.arpa. 3600 IN AMTRELAY 0 0 0 .",
    "14.100.51.198.in-addr.arpa. 3600 IN AMTRELAY \\# 4 00840102",
    "*._dsync.example. 3600 IN DSYNC CDS NOTIFY 5359 cds-scanner.example.net.",
    "*._dsync.example. 3600 IN DSYNC CSYNC NOTIFY 5360 csync-scanner.example.net.",
    "child._dsync.example. 3600 IN DSYNC CDS NOTIFY 5300 rr-endpoint.example.",
    "child._dsync.example. 3600 IN DSYNC TYPE1000 200 53 example.",
    "drip.example. 3600 IN HHIT gwppM2ZmOCAwMDAwWQFGMIIBQjCB9aADAgECAgE1MAUGAytlcDArMSkwJwYDVQQD",
    "drip.example. 3600 IN BRID owAAAYIEUQ==",
    "doa.example. 3600 IN DOA 0 1 2 \"\" aHR0cHM6Ly93d3cuaXNjLm9yZy8=",
    "doa.example. 3600 IN DOA 1234567890 100 1 \"text/plain\" -",
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
fn zone_with_the_examples() {
    let records = read(ZONE);
    let shown: Vec<&str> = records.iter().map(|(s, ..)| s.as_str()).collect();
    assert_eq!(shown, EXPECTED);
    // The displayed zone reads back to the same records.
    assert_eq!(read(&EXPECTED.join("\n")), records);
    // The presentation and generic forms of RFC 8777 agree.
    assert_eq!(records[0].3, records[3].3);
    assert_eq!(records[2].3, records[5].3);
}

#[test]
fn message_round_trip() {
    let records = read(ZONE);
    let mut buf = [0u8; 4096];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.set_id(8777);
    for (_, name, rtype, rdata) in &records {
        let data = RData::parse(*rtype, Class::IN, dnsbox::WireReader::new(rdata)).unwrap();
        b.push_answer(name, Class::IN, 3600, &data).unwrap();
    }
    let wire = b.finish();
    let msg = Message::parse_validated(wire).unwrap();
    // Re-encoding with compression keeps every RDATA as it was (none of
    // these types allows compression inside RDATA, RFC 3597 §4).
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
    let first = msg.answers().next().unwrap().unwrap();
    let relay: Amtrelay<'_> = first.data_as().unwrap();
    assert_eq!(relay.relay, AmtrelayRelay::Ipv4([203, 0, 113, 15].into()));
    let dsync = msg
        .answers()
        .map(|rr| rr.unwrap())
        .find(|rr| rr.rtype() == Rtype::DSYNC)
        .unwrap();
    let dsync: Dsync<'_> = dsync.data_as().unwrap();
    assert_eq!(
        (dsync.rrtype, dsync.scheme, dsync.port),
        (Rtype::CDS, DsyncScheme::NOTIFY, 5359)
    );
}

#[test]
fn tkey_exchange() {
    // A resolver asks for a server-assigned key; the server answers with
    // the name it assigned (RFC 2930 §4.4, §2.1's naming example).
    let key_name: NameBuf = "789.resolver.example.net".parse().unwrap();
    let mut buf = [0u8; 64];
    let request = Tkey::from_text(
        "hmac-sha256. 20261004000000 20261005000000 1 NOERROR 4 AAECAw== 0",
        &mut buf,
    )
    .unwrap();
    assert_eq!(request.mode, TkeyMode::SERVER_ASSIGNMENT);
    let mut qbuf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut qbuf).unwrap();
    b.set_id(2930);
    tkey::build_query(&mut b, &key_name, &request).unwrap();
    let query = b.finish();
    let query = Message::parse_validated(query).unwrap();
    assert_eq!(
        query.additional().next().unwrap().unwrap().to_string(),
        "789.resolver.example.net. 0 ANY TKEY hmac-sha256. 1791072000 1791158400 1 NOERROR 4 AAECAw== 0"
    );
    assert!(
        query
            .to_string()
            .contains("\tTKEY\thmac-sha256. 1791072000 1791158400 1 NOERROR 4 AAECAw== 0\n")
    );

    let found = tkey::find(&query).unwrap().unwrap();
    assert_eq!(found.section, Section::Additional);
    assert!(found.data.is_valid_at(1_791_100_000));
    let assigned: NameBuf = "789.resolver.example.net.server1.example.com"
        .parse()
        .unwrap();
    let keying = [0x5a; 32]; // encrypted under the resolver's KEY
    let reply = Tkey {
        key: &keying,
        ..found.data
    };
    let mut rbuf = [0u8; 512];
    let mut r = MessageBuilder::new(&mut rbuf).unwrap();
    tkey::build_response(&mut r, &query, &assigned, &reply).unwrap();
    let response = r.finish();
    let response = Message::parse_validated(response).unwrap();
    assert_eq!(response.id(), 2930);
    let answer = tkey::find(&response).unwrap().unwrap();
    assert_eq!(answer.key_name, assigned.as_name());
    assert_eq!(answer.data.key, keying);
    assert_eq!(answer.data.error, TsigRcode::NOERROR);

    // Truncated responses never panic.
    for end in 0..response.as_bytes().len() {
        if let Ok(m) = Message::parse(&response.as_bytes()[..end]) {
            let _ = tkey::find(&m);
        }
    }
}
