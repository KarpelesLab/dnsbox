//! The `serde` feature: protocol numbers as mnemonics in human-readable
//! formats and integers otherwise, names as presentation strings, and
//! lossless round trips of the owned message types over the whole interop
//! corpus (JSON through `serde_json`; both forms token by token through
//! `serde_test`).

#![cfg(feature = "serde")]

use dnsbox::dnssec::{Algorithm, DigestType, Nsec3HashAlgorithm};
use dnsbox::dso::DsoType;
use dnsbox::edns::{InfoCode, OptionCode, ZoneVersionType};
use dnsbox::rdata::{
    CertType, DsyncScheme, IpseckeyAlgorithm, SshfpAlgorithm, SshfpFpType, SvcParamKey, TkeyMode,
    TlsaCertUsage, TlsaMatchingType, TlsaSelector, TsigRcode, ZonemdHashAlg, ZonemdScheme,
};
use dnsbox::{Class, Flags, NameBuf, Opcode, Rcode, Rtype};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_test::{Configure, Token, assert_de_tokens, assert_de_tokens_error, assert_tokens};

/// JSON text of a value.
fn json<T: Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap()
}

/// Parses JSON text.
fn from_json<T: DeserializeOwned>(s: &str) -> serde_json::Result<T> {
    serde_json::from_str(s)
}

#[test]
fn protocol_numbers_in_json() {
    assert_eq!(json(&Rtype::MX), "\"MX\"");
    assert_eq!(json(&Rtype::new(65534)), "\"TYPE65534\"");
    assert_eq!(json(&Class::IN), "\"IN\"");
    assert_eq!(json(&Class::new(42)), "\"CLASS42\"");
    assert_eq!(json(&OptionCode::ECS), "\"ECS\"");
    assert_eq!(json(&OptionCode::new(65001)), "\"OPT65001\"");
    assert_eq!(json(&Algorithm::ECDSAP256SHA256), "\"ECDSAP256SHA256\"");
    assert_eq!(json(&Algorithm::new(200)), "\"200\"");
    assert_eq!(json(&SvcParamKey::new(65535)), "\"key65535\"");
    assert_eq!(json(&InfoCode::new(9)), "\"DNSKEY Missing\"");
    assert_eq!(json(&Opcode::UPDATE), "\"UPDATE\"");
    assert_eq!(json(&Opcode::new(3)), "\"OPCODE3\"");
    assert_eq!(json(&Rcode::NXDOMAIN), "\"NXDOMAIN\"");
    assert_eq!(json(&Rcode::new(4000)), "\"RCODE4000\"");

    // Mnemonics (any case), aliases, generic forms and plain numbers are
    // all accepted.
    assert_eq!(from_json::<Rtype>("\"mx\"").unwrap(), Rtype::MX);
    assert_eq!(from_json::<Rtype>("\"*\"").unwrap(), Rtype::ANY);
    assert_eq!(from_json::<Rtype>("\"TYPE15\"").unwrap(), Rtype::MX);
    assert_eq!(from_json::<Rtype>("15").unwrap(), Rtype::MX);
    assert_eq!(from_json::<Class>("\"class3\"").unwrap(), Class::CH);
    assert_eq!(
        from_json::<OptionCode>("\"CLIENT-SUBNET\"").unwrap(),
        OptionCode::ECS
    );
    assert_eq!(
        from_json::<Algorithm>("\"13\"").unwrap(),
        Algorithm::new(13)
    );
    assert_eq!(from_json::<Opcode>("\"notify\"").unwrap(), Opcode::NOTIFY);
    assert_eq!(from_json::<Opcode>("5").unwrap(), Opcode::UPDATE);
    assert_eq!(from_json::<Rcode>("\"BADCOOKIE\"").unwrap(), Rcode::new(23));
    assert_eq!(
        from_json::<Rcode>("\"rcode4095\"").unwrap(),
        Rcode::new(4095)
    );

    // Out of range or unknown.
    for bad in [
        "\"BOGUS\"",
        "65536",
        "-1",
        "1.5",
        "\"TYPE65536\"",
        "null",
        "[]",
    ] {
        assert!(from_json::<Rtype>(bad).is_err(), "{bad}");
    }
    assert!(from_json::<Algorithm>("256").is_err());
    assert!(from_json::<Opcode>("16").is_err());
    assert!(from_json::<Opcode>("\"OPCODE16\"").is_err());
    assert!(from_json::<Rcode>("4096").is_err());
    assert!(from_json::<Rcode>("\"RCODE4096\"").is_err());
    let e = from_json::<Rtype>("\"BOGUS\"").unwrap_err().to_string();
    assert!(e.contains("Rtype mnemonic or number"), "{e}");
}

/// Every value of a registry survives both forms.
macro_rules! every_value {
    ($($ty:ty: $int:ty),* $(,)?) => {$(
        for v in <$int>::MIN..=<$int>::MAX {
            let x = <$ty>::new(v);
            let text = json(&x);
            assert_eq!(text, format!("\"{x}\""));
            assert_eq!(from_json::<$ty>(&text).unwrap(), x, "{}", text);
            assert_eq!(from_json::<$ty>(&v.to_string()).unwrap(), x);
        }
    )*};
}

#[test]
fn every_registry_value_round_trips() {
    every_value!(
        Rtype: u16,
        Class: u16,
        OptionCode: u16,
        SvcParamKey: u16,
        InfoCode: u16,
        CertType: u16,
        TsigRcode: u16,
        DsoType: u16,
        Algorithm: u8,
        DigestType: u8,
        Nsec3HashAlgorithm: u8,
        TlsaCertUsage: u8,
        TlsaSelector: u8,
        TlsaMatchingType: u8,
        ZoneVersionType: u8,
        ZonemdScheme: u8,
        ZonemdHashAlg: u8,
        IpseckeyAlgorithm: u8,
        SshfpAlgorithm: u8,
        SshfpFpType: u8,
        DsyncScheme: u8,
        TkeyMode: u16,
    );
    for v in 0..16 {
        let op = Opcode::new(v);
        assert_eq!(from_json::<Opcode>(&json(&op)).unwrap(), op);
    }
    for v in 0..4096 {
        let rc = Rcode::new(v);
        assert_eq!(from_json::<Rcode>(&json(&rc)).unwrap(), rc);
    }
}

#[test]
fn readable_and_compact_tokens() {
    assert_tokens(&Rtype::MX.readable(), &[Token::Str("MX")]);
    assert_tokens(&Rtype::MX.compact(), &[Token::U16(15)]);
    assert_tokens(&Algorithm::ED25519.readable(), &[Token::Str("ED25519")]);
    assert_tokens(&Algorithm::ED25519.compact(), &[Token::U8(15)]);
    assert_tokens(&Opcode::NOTIFY.compact(), &[Token::U8(4)]);
    assert_tokens(&Rcode::BADVERS.compact(), &[Token::U16(16)]);
    // Numbers are also accepted in human-readable formats.
    assert_de_tokens(&Rtype::MX.readable(), &[Token::U64(15)]);
    assert_de_tokens(&Rtype::MX.readable(), &[Token::I32(15)]);
    assert_de_tokens_error::<serde_test::Readable<Rtype>>(
        &[Token::I32(-15)],
        "invalid value: integer `-15`, expected a Rtype mnemonic or number",
    );
    assert_de_tokens_error::<serde_test::Readable<Opcode>>(
        &[Token::U8(16)],
        "invalid value: integer `16`, expected an opcode mnemonic or number below 16",
    );
    assert_de_tokens_error::<serde_test::Compact<Opcode>>(
        &[Token::U8(16)],
        "invalid value: integer `16`, expected an opcode mnemonic or number below 16",
    );
}

#[test]
fn names() {
    let name: NameBuf = "www.Example.com".parse().unwrap();
    assert_eq!(json(&name), "\"www.Example.com.\"");
    assert_eq!(json(&name.as_name()), "\"www.Example.com.\"");
    assert_eq!(json(&NameBuf::root()), "\".\"");
    // Escapes are kept (RFC 1035 §5.1).
    let odd = NameBuf::from_labels([&b"a.b"[..], b"c\x00d", b"e f"]).unwrap();
    assert_eq!(json(&odd), r#""a\\.b.c\\000d.e\\032f.""#);
    assert_eq!(from_json::<NameBuf>(&json(&odd)).unwrap(), odd);
    // The trailing dot is optional; case is preserved exactly.
    let back: NameBuf = from_json("\"www.Example.com\"").unwrap();
    assert!(back.as_name().eq_exact(&name.as_name()));
    // Both forms use the string.
    assert_tokens(&name.clone().compact(), &[Token::Str("www.Example.com.")]);
    for bad in ["\"a..b\"", "\"\"", "12", &format!("\"{}\"", "a".repeat(64))] {
        assert!(from_json::<NameBuf>(bad).is_err(), "{bad}");
    }
    let e = from_json::<NameBuf>("\"a..b\"").unwrap_err().to_string();
    assert!(e.contains("invalid domain name \"a..b\""), "{e}");
}

#[test]
fn header_flags() {
    let flags = Flags::default()
        .with_qr(true)
        .with_opcode(Opcode::UPDATE)
        .with_rd(true)
        .with_cd(true)
        .with_rcode(Rcode::REFUSED);
    let text = json(&flags);
    assert_eq!(
        text,
        r#"{"qr":true,"opcode":"UPDATE","aa":false,"tc":false,"rd":true,"ra":false,"z":false,"ad":false,"cd":true,"rcode":"REFUSED"}"#
    );
    assert_eq!(from_json::<Flags>(&text).unwrap(), flags);
    assert_tokens(&flags.compact(), &[Token::U16(flags.bits())]);
    // Missing fields default to clear / QUERY / NOERROR.
    assert_eq!(from_json::<Flags>("{}").unwrap(), Flags::default());
    assert_eq!(
        from_json::<Flags>(r#"{"rd":true}"#).unwrap(),
        Flags::default().with_rd(true)
    );
    // Every bit pattern survives.
    for bits in 0..=u16::MAX {
        let f = Flags::from_bits(bits);
        assert_eq!(from_json::<Flags>(&json(&f)).unwrap(), f);
    }
    // The header RCODE has four bits; extended values live in OPT.
    assert!(from_json::<Flags>(r#"{"rcode":"BADVERS"}"#).is_err());
    assert!(from_json::<Flags>(r#"{"opcode":16}"#).is_err());
}

#[cfg(feature = "alloc")]
mod owned {
    use super::*;
    use dnsbox::{Message, OwnedMessage, OwnedQuestion, OwnedRData, OwnedRecord};
    use std::fs;
    use std::path::Path;

    /// Every corpus and BIND capture in the repository.
    fn captures() -> Vec<(String, Vec<u8>)> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
        let mut out = Vec::new();
        for entry in fs::read_dir(root.join("corpus")).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "hex") {
                let text = fs::read_to_string(&path).unwrap();
                let digits: Vec<u8> = text
                    .lines()
                    .filter(|l| !l.starts_with('#'))
                    .flat_map(str::bytes)
                    .filter(|b| !b.is_ascii_whitespace())
                    .map(|b| (b as char).to_digit(16).unwrap() as u8)
                    .collect();
                let wire = digits.chunks(2).map(|p| (p[0] << 4) | p[1]).collect();
                out.push((path.display().to_string(), wire));
            }
        }
        for entry in fs::read_dir(root.join("data/named")).unwrap() {
            let path = entry.unwrap().path();
            out.push((path.display().to_string(), fs::read(&path).unwrap()));
        }
        out.sort();
        out
    }

    #[test]
    fn whole_corpus_round_trips_through_json() {
        let all = captures();
        assert!(all.len() > 80, "{}", all.len());
        for (name, wire) in all {
            let msg = OwnedMessage::from_wire(&wire).unwrap_or_else(|e| panic!("{name}: {e}"));
            let text = serde_json::to_string(&msg).unwrap();
            let back: OwnedMessage = serde_json::from_str(&text).unwrap();
            assert_eq!(back, msg, "{name}");
            // The re-encoded message displays like the original.
            let again = back.to_vec().unwrap();
            assert_eq!(
                Message::parse(&again).unwrap().to_string(),
                msg.to_string(),
                "{name}"
            );
            // Pretty-printed JSON parses too.
            let pretty = serde_json::to_string_pretty(&msg).unwrap();
            assert_eq!(serde_json::from_str::<OwnedMessage>(&pretty).unwrap(), msg);
        }
    }

    fn name(s: &str) -> NameBuf {
        s.parse().unwrap()
    }

    fn sample() -> OwnedMessage {
        let mut m = OwnedMessage::new(0x1234, Flags::default().with_qr(true).with_rd(true));
        m.questions.push(OwnedQuestion::new(
            name("example.com"),
            Rtype::MX,
            Class::IN,
        ));
        let mx = OwnedRData::from_wire(
            Rtype::MX,
            Class::IN,
            b"\x00\x0a\x04mail\x07example\x03com\x00",
        )
        .unwrap();
        m.answers
            .push(OwnedRecord::new(name("example.com"), Class::IN, 300, mx));
        m
    }

    #[test]
    fn json_layout() {
        let m = sample();
        assert_eq!(
            serde_json::to_value(&m).unwrap(),
            serde_json::json!({
                "id": 4660,
                "flags": {
                    "qr": true, "opcode": "QUERY", "aa": false, "tc": false,
                    "rd": true, "ra": false, "z": false, "ad": false,
                    "cd": false, "rcode": "NOERROR"
                },
                "questions": [{"name": "example.com.", "type": "MX", "class": "IN"}],
                "answers": [{
                    "name": "example.com.", "type": "MX", "class": "IN", "ttl": 300,
                    "rdata": "\\# 20 000A046D61696C076578616D706C6503636F6D00"
                }],
                "authority": [],
                "additional": []
            })
        );
        // Sections may be omitted; RDATA hex may be split and in any case.
        let m2: OwnedMessage = serde_json::from_str(
            r#"{"id": 4660, "flags": {"qr": true, "rd": true},
                "questions": [{"name": "example.com", "type": "mx", "class": "in"}],
                "answers": [{"name": "example.com.", "type": 15, "class": 1, "ttl": 300,
                             "rdata": "\\# 20 000a046d61696c 076578616d706c6503636f6d00"}]}"#,
        )
        .unwrap();
        assert_eq!(m2, m);
        // OwnedRData on its own.
        let rdata = &m.answers[0].rdata;
        assert_eq!(
            serde_json::to_string(rdata).unwrap(),
            r#"{"type":"MX","rdata":"\\# 20 000A046D61696C076578616D706C6503636F6D00"}"#
        );
        let back: OwnedRData = from_json(&serde_json::to_string(rdata).unwrap()).unwrap();
        assert_eq!(&back, rdata);
    }

    #[test]
    fn compact_tokens() {
        let m = sample();
        let rdata: &'static [u8] = b"\x00\x0a\x04mail\x07example\x03com\x00";
        assert_tokens(
            &m.compact(),
            &[
                Token::Struct {
                    name: "OwnedMessage",
                    len: 6,
                },
                Token::Str("id"),
                Token::U16(0x1234),
                Token::Str("flags"),
                Token::U16(0x8100),
                Token::Str("questions"),
                Token::Seq { len: Some(1) },
                Token::Struct {
                    name: "OwnedQuestion",
                    len: 3,
                },
                Token::Str("name"),
                Token::Str("example.com."),
                Token::Str("type"),
                Token::U16(15),
                Token::Str("class"),
                Token::U16(1),
                Token::StructEnd,
                Token::SeqEnd,
                Token::Str("answers"),
                Token::Seq { len: Some(1) },
                Token::Struct {
                    name: "OwnedRecord",
                    len: 5,
                },
                Token::Str("name"),
                Token::Str("example.com."),
                Token::Str("type"),
                Token::U16(15),
                Token::Str("class"),
                Token::U16(1),
                Token::Str("ttl"),
                Token::U32(300),
                Token::Str("rdata"),
                Token::Bytes(rdata),
                Token::StructEnd,
                Token::SeqEnd,
                Token::Str("authority"),
                Token::Seq { len: Some(0) },
                Token::SeqEnd,
                Token::Str("additional"),
                Token::Seq { len: Some(0) },
                Token::SeqEnd,
                Token::StructEnd,
            ],
        );
        // A byte sequence is accepted as RDATA too.
        let mut tokens = vec![
            Token::Struct {
                name: "OwnedRData",
                len: 2,
            },
            Token::Str("type"),
            Token::U16(1),
            Token::Str("rdata"),
            Token::Seq { len: Some(4) },
        ];
        tokens.extend([192, 0, 2, 1].map(Token::U8));
        tokens.extend([Token::SeqEnd, Token::StructEnd]);
        let a = OwnedRData::from_wire(Rtype::A, Class::IN, &[192, 0, 2, 1]).unwrap();
        assert_de_tokens(&a.compact(), &tokens);
    }

    #[test]
    fn presentation_rdata_is_accepted() {
        // Human-readable input may use the type's presentation format
        // (RFC 1035 §5.1); output stays in the lossless generic form.
        let rr: OwnedRecord = from_json(
            r#"{"name": "example.com.", "type": "MX", "class": "IN", "ttl": 300,
                "rdata": "10 mail.example.com"}"#,
        )
        .unwrap();
        assert_eq!(
            rr.to_string(),
            "example.com. 300 IN MX 10 mail.example.com."
        );
        assert_eq!(
            serde_json::to_value(&rr).unwrap()["rdata"],
            "\\# 20 000A046D61696C076578616D706C6503636F6D00"
        );
        let txt: OwnedRData =
            from_json(r#"{"type": "TXT", "rdata": "\"v=spf1 -all\" second"}"#).unwrap();
        assert_eq!(txt.to_string(), "\"v=spf1 -all\" \"second\"");
        let svcb: OwnedRData =
            from_json(r#"{"type": "HTTPS", "rdata": "1 . alpn=h2,h3 port=443"}"#).unwrap();
        assert_eq!(svcb.to_string(), "1 . alpn=\"h2,h3\" port=443");
        // Errors name the type and the parser's error.
        let e = from_json::<OwnedRData>(r#"{"type": "A", "rdata": "192.0.2.256"}"#)
            .unwrap_err()
            .to_string();
        assert!(e.contains("invalid A RDATA"), "{e}");
        // The reserved SvcParamKey 65535 is refused (RFC 9460 §14.3.2),
        // in text and in the generic form alike.
        assert!(from_json::<OwnedRData>(r#"{"type": "SVCB", "rdata": "1 . key65535"}"#).is_err());
        assert!(
            from_json::<OwnedRData>(r#"{"type": "SVCB", "rdata": "\\# 7 0001 00 ffff0000"}"#)
                .is_err()
        );
    }

    #[test]
    fn invalid_records_are_rejected() {
        let rr = |rtype: &str, class: &str, rdata: &str| {
            from_json::<OwnedRecord>(&format!(
                r#"{{"name": "x.", "type": "{rtype}", "class": "{class}", "ttl": 0, "rdata": "{rdata}"}}"#
            ))
        };
        assert!(rr("A", "IN", r"\\# 4 C0000201").is_ok());
        // Typed RDATA must decode (RFC 1035 A: four octets).
        let e = rr("A", "IN", r"\\# 3 C00002").unwrap_err().to_string();
        assert!(e.contains("invalid A RDATA"), "{e}");
        // ... unless it is class-specific data of another class, or an
        // UPDATE deletion (RFC 3597 §4, RFC 2136 §2.5).
        assert!(rr("A", "CH", r"\\# 3 C00002").is_ok());
        assert!(rr("A", "ANY", r"\\# 0").is_ok());
        assert!(
            rr("MX", "IN", r"\\# 3 000A01")
                .unwrap_err()
                .to_string()
                .contains("MX")
        );
        // A compression pointer is not valid in stored RDATA.
        assert!(rr("MX", "IN", r"\\# 4 000AC00C").is_err());
        // Malformed generic form.
        for bad in [
            "",
            "1",
            r"\\#",
            r"\\# 2 00",
            r"\\# 1 0",
            r"\\# 1 0g",
            r"\\# x 00",
            r"\\# 65536",
        ] {
            assert!(rr("NULL", "IN", bad).is_err(), "{bad}");
        }
        assert!(rr("TYPE65280", "IN", r"\\# 2 ABCD").is_ok());
        // Unknown fields are ignored; missing ones are errors.
        assert!(
            from_json::<OwnedRecord>(r#"{"name": "x.", "type": "A", "class": "IN", "ttl": 0}"#)
                .is_err()
        );
        assert!(
            from_json::<OwnedQuestion>(r#"{"name": "x.", "type": "A", "class": "IN", "extra": 1}"#)
                .is_ok()
        );
        // More than 65535 octets of RDATA cannot exist.
        let big = vec![0u8; 65536];
        let mut tokens = vec![
            Token::Struct {
                name: "OwnedRData",
                len: 2,
            },
            Token::Str("type"),
            Token::U16(10),
            Token::Str("rdata"),
        ];
        let big: &'static [u8] = big.leak();
        tokens.push(Token::Bytes(big));
        tokens.push(Token::StructEnd);
        assert_de_tokens_error::<serde_test::Compact<OwnedRData>>(
            &tokens,
            "invalid length 65536, expected at most 65535 octets",
        );
    }

    #[test]
    fn sections_are_bounded() {
        // A section holds at most 65535 entries (16-bit header counts):
        // longer input is refused while it is read.
        let question = r#"{"name":".","type":"A","class":"IN"}"#;
        let message = |n: usize| {
            let list = vec![question; n].join(",");
            format!(r#"{{"id":1,"flags":{{}},"questions":[{list}]}}"#)
        };
        let msg: OwnedMessage = from_json(&message(65535)).unwrap();
        assert_eq!(msg.questions.len(), 65535);
        assert_eq!(msg.header().unwrap().qdcount, 65535);
        let err = from_json::<OwnedMessage>(&message(65536)).unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid length 65536, expected a sequence of at most 65535 entries"),
            "{err}"
        );
    }
}
