//! Presentation-format parsing of the Milestone 4 batch-A types and the
//! RFC 1183 types (SRV, NAPTR, CAA, SSHFP, TLSA, SMIMEA, OPENPGPKEY, DNAME,
//! URI, CERT, DHCID, RP, AFSDB, X25, ISDN, RT, KX) in a master file: each
//! record is read with the RFC examples' text, displayed, re-read from its
//! display, pushed into a message (with compression enabled) and parsed
//! back; malformed entries are reported with their line and skipped.

use dnsbox::zone::{Scanner, ZoneReader};
use dnsbox::{Error, Message, MessageBuilder, NameBuf, RData, Rtype, WireWriter};

/// RFC presentation examples (origin `example.`), one per entry; the
/// expected display of each record follows in [`EXPECTED`].
const ZONE: &str = r#"$ORIGIN example.
$TTL 1h
_ldap._tcp SRV 0 1 389 old-slow-box     ; RFC 2782
  SRV 0 0 0 .
naptr NAPTR 100 10 "u" "E2U+sip" "!^.*$!sip:information@foo.se!i" .  ; RFC 3403 §6.2
  NAPTR 100 50 a z3950+N2L+N2C "" cidserver.example.com.
caa CAA 0 issue "ca1.example.net; account=230123"   ; RFC 8659 §4.2
  CAA 128 tbs Unknown
host SSHFP 4 2 ( a87f1b687ac0e57d2a081a2f2826723    ; RFC 7479 §3
                 34d90ed316d2b818ca9580ea384d924
                 01 )
_443._tcp.www TLSA (                                ; RFC 6698 §2.3
      0 0 1 d2abde240d7cd3ee6b4b28c54df034b9
            7983a1d16e8a410e4561cb106618e971 )
smime SMIMEA 3 1 1 D2ABDE240D7CD3EE6B4B28C54DF034B97983A1D16E8A410E4561CB106618E971
pgp OPENPGPKEY ( mDME V/fnvBY= )
frobozz DNAME frobozz-division.acme             ; RFC 6672 §2.3
_ftp._tcp URI 10 1 "ftp://ftp1.example.com/public"  ; RFC 7553 §4
cert CERT PGP 0 RSASHA256 mDMEV/fnvBY=          ; RFC 4398 §2.2
chi DHCID ( AAEBOSD+XR3Os/0LozeXVqcNc7FwCfQdW      ; RFC 4701 §3.6
            L3b/NaiUDlW2No= )
rp RP louie.trantor.umd.edu. LAM1.people.umd.edu.   ; RFC 1183 §2.2
toaster AFSDB 1 jack.toaster.com.               ; RFC 1183 §1
relay X25 311061700956                          ; RFC 1183 §3.1
sh ISDN 150862028003217 004                     ; RFC 1183 §3.2
  RT 2 Relay.Prime.COM.                         ; RFC 1183 §3.3
kx KX 10 kx1                                    ; RFC 2230 §3
bad1 SSHFP 2 1
bad2 TLSA 3 1 1 abc
bad3 URI 10 1 ""
bad4 CAA 0 is-sue x
bad5 CERT X509 0 0 AQ==
bad6 X25 123
last SRV 1 2 3 last
"#;

/// `owner type rdata` of every good record, in order.
const EXPECTED: &[&str] = &[
    "_ldap._tcp.example. SRV 0 1 389 old-slow-box.example.",
    "_ldap._tcp.example. SRV 0 0 0 .",
    r#"naptr.example. NAPTR 100 10 "u" "E2U+sip" "!^.*$!sip:information@foo.se!i" ."#,
    r#"naptr.example. NAPTR 100 50 "a" "z3950+N2L+N2C" "" cidserver.example.com."#,
    r#"caa.example. CAA 0 issue "ca1.example.net; account=230123""#,
    r#"caa.example. CAA 128 tbs "Unknown""#,
    "host.example. SSHFP 4 2 A87F1B687AC0E57D2A081A2F282672334D90ED316D2B818CA9580EA384D92401",
    "_443._tcp.www.example. TLSA 0 0 1 \
     D2ABDE240D7CD3EE6B4B28C54DF034B97983A1D16E8A410E4561CB106618E971",
    "smime.example. SMIMEA 3 1 1 \
     D2ABDE240D7CD3EE6B4B28C54DF034B97983A1D16E8A410E4561CB106618E971",
    "pgp.example. OPENPGPKEY mDMEV/fnvBY=",
    "frobozz.example. DNAME frobozz-division.acme.example.",
    r#"_ftp._tcp.example. URI 10 1 "ftp://ftp1.example.com/public""#,
    "cert.example. CERT PGP 0 RSASHA256 mDMEV/fnvBY=",
    "chi.example. DHCID AAEBOSD+XR3Os/0LozeXVqcNc7FwCfQdWL3b/NaiUDlW2No=",
    "rp.example. RP louie.trantor.umd.edu. LAM1.people.umd.edu.",
    "toaster.example. AFSDB 1 jack.toaster.com.",
    r#"relay.example. X25 "311061700956""#,
    r#"sh.example. ISDN "150862028003217" "004""#,
    "sh.example. RT 2 Relay.Prime.COM.",
    "kx.example. KX 10 kx1.example.",
    "last.example. SRV 1 2 3 last.example.",
];

/// The rejected entries: (line, error).
const ERRORS: &[(u32, Error)] = &[
    (28, Error::UnexpectedEof),
    (29, Error::InvalidText),
    (30, Error::InvalidRdata),
    (31, Error::InvalidRdata),
    (32, Error::InvalidText),
    (33, Error::InvalidRdata),
];

#[test]
fn rfc_examples_in_a_zone() {
    let origin: NameBuf = "example.".parse().unwrap();
    let mut zone = ZoneReader::new(ZONE).with_origin(&origin);
    let mut buf = [0u8; 1024];
    let mut msg_buf = [0u8; 8192];
    let mut b = MessageBuilder::new(&mut msg_buf).unwrap();
    let mut shown = Vec::new();
    let mut errors = Vec::new();
    loop {
        match zone.next_record(&mut buf) {
            Ok(Some(rr)) => {
                assert_eq!(rr.ttl, 3600);
                let data = rr.data().unwrap();
                let text = data.to_string();
                shown.push(format!("{} {} {}", rr.name, rr.rtype, text));
                // The display reads back as the same wire form.
                let mut s = Scanner::new(&text);
                let mut again = [0u8; 1024];
                let mut w = WireWriter::new(&mut again);
                RData::parse_text(rr.rtype, rr.class, &mut s, &mut w).unwrap();
                assert_eq!(w.as_bytes(), rr.rdata, "{rr}");
                b.push_answer(&rr.name, rr.class, rr.ttl, &data).unwrap();
            }
            Ok(None) => break,
            Err(e) => errors.push((e.line(), e.error())),
        }
    }
    assert_eq!(shown, EXPECTED);
    assert_eq!(errors, ERRORS);

    // Through a compressed message and back: the same records.
    let msg = Message::parse_validated(b.finish()).unwrap();
    let back: Vec<String> = msg
        .answers()
        .map(|rr| {
            let rr = rr.unwrap();
            format!("{} {} {}", rr.name(), rr.rtype(), rr.data().unwrap())
        })
        .collect();
    assert_eq!(back, EXPECTED);
    assert_eq!(
        msg.answers()
            .filter(|rr| rr.as_ref().unwrap().rtype() == Rtype::SRV)
            .count(),
        3
    );
}

#[test]
fn hostile_text_terminates() {
    // Every prefix of the zone and of each line parses without panicking
    // and yields at most as many records as the whole zone.
    let origin: NameBuf = "example.".parse().unwrap();
    let mut buf = [0u8; 1024];
    for (i, _) in ZONE.char_indices() {
        let mut zone = ZoneReader::new(&ZONE[..i]).with_origin(&origin);
        let mut n = 0;
        while let Some(res) = zone.next_record(&mut buf).transpose() {
            n += usize::from(res.is_ok());
            assert!(n <= EXPECTED.len());
        }
    }
}
