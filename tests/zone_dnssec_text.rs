//! DNSSEC and transaction record types in master files (RFC 1035 §5),
//! written in their presentation formats: DNSKEY, RRSIG, NSEC, DS
//! (RFC 4034 §2.2, §3.2, §4.2, §5.3), NSEC3 and NSEC3PARAM (RFC 5155 §3.3,
//! §4.3), CDS and CDNSKEY (RFC 7344, RFC 8078), KEY, SIG and NXT
//! (RFC 2535), TSIG (RFC 8945, BIND's layout) and the TXT-like and
//! experimental types. The examples are the RFCs' own.

#![cfg(feature = "alloc")]

use dnsbox::rdata::RData;
use dnsbox::zone::{ZoneReader, parse};
use dnsbox::{Error, Rtype};

const ZONE: &str = r#"$ORIGIN example.com.
$TTL 86400
@ SOA ns hostmaster 1 2h 15m 2w 1h
; RFC 4034 §2.3
  DNSKEY 256 3 5 ( AQPSKmynfzW4kyBv015MUG2DeIQ3
                   Cbl+BBZH4b/0PY1kxkmvHjcZc8no
                   kfzj31GajIQKY+5CptLr3buXA10h
                   WqTkF7H6RfoRqXQeogmMHfpftf6z
                   Mv1LyBUgia7za6ZEzOJBOztyvhjL
                   742iU/TpPSEDhm2SNKLijfUppn1U
                   aNvv4w==  )
; RFC 8078 §4
  CDNSKEY 0 3 0 AA==
  CDS 0 0 0 00
; RFC 5155 Appendix A
  NSEC3PARAM 1 0 12 aabbccdd
; RFC 4034 §3.3
host A 192.0.2.1
     RRSIG A 5 3 86400 20030322173103 (
                  20030220173103 2642 example.com.
                  oJB1W6WNGv+ldvQ3WDG0MQkg5IEhjRip8WTr
                  PYGv07h108dUKGMeDPKijVCHX3DDKdfb+v6o
                  B9wfuh3DTJXUAfI/M0zmO/zz8bW0Rznl8O3t
                  GNazPwQKkRN20XPXV6nwwfoXmJQbsLNrLfkG
                  J5D6fwFm8nN+6pBzeDQfsS3Ap3o= )
; RFC 4034 §4.3
alfa NSEC host.example.com. (
                A MX RRSIG NSEC TYPE1234 )
; RFC 4034 §5.4
dskey DS 60485 5 1 ( 2BB183AF5F22588179A53B0A
                     98631FAD1A292118 )
; RFC 5155 Appendix A
0p9mhaveqvm6t7vbl5lop2u3t2rp3tom NSEC3 1 1 12 aabbccdd (
      2t7b4g4vsa5smi47k61mv5bv1a22bojr MX DNSKEY NS
      SOA NSEC3PARAM RRSIG )
; RFC 2535 §5.4
big NXT medium.foo.tld. A MX SIG NXT
    KEY 49664 DNSSEC RSASHA1
    SIG TYPE0 ED25519 0 0 20261004090347 20261004085347 43160 sig0 AAAA
spf SPF "v=spf1 -all"
ri RESINFO qnamemin exterr=15,16,17
ta TALINK . next
rk RKEY 0 1 7 AQID
tsig.key ANY TSIG hmac-sha256. 1791104299 300 4 AAAAAA== 1 NOERROR 0
"#;

#[test]
fn signed_zone_in_presentation_format() {
    let zone = parse(ZONE).unwrap_or_else(|e| panic!("{e}"));
    let shown: Vec<String> = zone.iter().map(|r| r.to_string()).collect();
    assert_eq!(
        shown,
        [
            "example.com. 86400 IN SOA ns.example.com. hostmaster.example.com. 1 7200 900 1209600 3600",
            "example.com. 86400 IN DNSKEY 256 3 5 AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8nokfzj31GajIQKY+5CptLr3buXA10hWqTkF7H6RfoRqXQeogmMHfpftf6zMv1LyBUgia7za6ZEzOJBOztyvhjL742iU/TpPSEDhm2SNKLijfUppn1UaNvv4w==",
            "example.com. 86400 IN CDNSKEY 0 3 0 AA==",
            "example.com. 86400 IN CDS 0 0 0 00",
            "example.com. 86400 IN NSEC3PARAM 1 0 12 AABBCCDD",
            "host.example.com. 86400 IN A 192.0.2.1",
            "host.example.com. 86400 IN RRSIG A 5 3 86400 20030322173103 20030220173103 2642 example.com. oJB1W6WNGv+ldvQ3WDG0MQkg5IEhjRip8WTrPYGv07h108dUKGMeDPKijVCHX3DDKdfb+v6oB9wfuh3DTJXUAfI/M0zmO/zz8bW0Rznl8O3tGNazPwQKkRN20XPXV6nwwfoXmJQbsLNrLfkGJ5D6fwFm8nN+6pBzeDQfsS3Ap3o=",
            "alfa.example.com. 86400 IN NSEC host.example.com. A MX RRSIG NSEC TYPE1234",
            "dskey.example.com. 86400 IN DS 60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118",
            "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.com. 86400 IN NSEC3 1 1 12 AABBCCDD 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR NS SOA MX RRSIG DNSKEY NSEC3PARAM",
            "big.example.com. 86400 IN NXT medium.foo.tld. A MX SIG NXT",
            "big.example.com. 86400 IN KEY 49664 3 5",
            "big.example.com. 86400 IN SIG TYPE0 15 0 0 20261004090347 20261004085347 43160 sig0.example.com. AAAA",
            "spf.example.com. 86400 IN SPF \"v=spf1 -all\"",
            "ri.example.com. 86400 IN RESINFO \"qnamemin\" \"exterr=15,16,17\"",
            "ta.example.com. 86400 IN TALINK . next.example.com.",
            "rk.example.com. 86400 IN RKEY 0 1 7 AQID",
            "tsig.key.example.com. 86400 ANY TSIG hmac-sha256. 1791104299 300 4 AAAAAA== 1 NOERROR 0",
        ]
    );
    for rr in &zone {
        let data = rr.data().unwrap();
        assert!(!matches!(data, RData::Unknown(_)), "{rr}");
        match data {
            RData::Dnskey(k) => assert_eq!(k.key_tag(), 2642),
            RData::Rrsig(s) => assert_eq!((s.key_tag, s.expiration), (2642, 1_048_354_263)),
            RData::Cdnskey(k) => assert!(k.is_delete()),
            RData::Cds(d) => assert!(d.is_delete()),
            RData::Nsec3(n) => assert!(n.is_opt_out() && n.types.contains(Rtype::NSEC3PARAM)),
            _ => {}
        }
    }
    // What the reader displays reads back the same (one line per record).
    let mut again = parse(&shown.join("\n")).unwrap();
    for (i, (a, z)) in again.iter_mut().zip(&zone).enumerate() {
        assert_eq!(a.line as usize, i + 1);
        a.line = z.line;
    }
    assert_eq!(again, zone);
}

#[test]
fn errors_are_positioned_and_recovered() {
    let zone = "$ORIGIN example.\n\
                a 1 DNSKEY 256 3 5 AQ*=\n\
                b 1 DS 1 5 1 ABC\n\
                c 1 RRSIG A 5 3 1 20031322173103 1 1 . AA==\n\
                d 1 NSEC3 1 0 0 - WW\n\
                e 1 NSEC3PARAM 1 0 0 aa bb\n\
                f 1 NXT . CAA\n\
                g 1 NSEC . NOSUCHTYPE\n\
                h 1 TSIG . 1 1 1 AA== 1 NOERROR\n\
                i 1 DNSKEY 256 3 5 AQM=\n";
    let mut r = ZoneReader::new(zone);
    let mut buf = [0u8; 512];
    let mut errors = Vec::new();
    let mut ok = Vec::new();
    loop {
        match r.next_record(&mut buf) {
            Ok(Some(rr)) => ok.push(rr.to_string()),
            Ok(None) => break,
            Err(e) => errors.push((e.error(), e.line())),
        }
    }
    assert_eq!(ok, ["i.example. 1 IN DNSKEY 256 3 5 AQM="]);
    assert_eq!(
        errors,
        [
            (Error::InvalidText, 2),
            (Error::InvalidText, 3),
            (Error::InvalidText, 4),
            (Error::InvalidText, 5),
            (Error::InvalidText, 6),
            (Error::InvalidRdata, 7),
            (Error::UnknownMnemonic, 8),
            (Error::UnexpectedEof, 9),
        ]
    );
}
