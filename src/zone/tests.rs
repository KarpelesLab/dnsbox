//! Master-file tests: the RFC 1035 §5.3 example, a signed zone, the
//! directives, defaults, errors with positions and recovery, and hostile
//! input.

use super::*;
use crate::rdata::{ParseRdataText, RData, Txt};
use crate::{Class, Composer, Error, NameBuf, Rtype, WireWriter};
use std::format;
use std::string::{String, ToString};
use std::vec::Vec;

/// Reads every entry of `text` (with origin `origin`), returning each
/// record's display form or the error's `(error, line, column)`.
fn read_all(text: &str, origin: &str) -> Vec<core::result::Result<String, (Error, u32, u32)>> {
    let origin: NameBuf = origin.parse().unwrap();
    let mut r = ZoneReader::new(text).with_origin(&origin);
    let mut buf = [0u8; 65535];
    let mut out = Vec::new();
    for _ in 0..10_000 {
        match r.next_record(&mut buf) {
            Ok(Some(rr)) => {
                check_record(&rr);
                out.push(Ok(rr.to_string()));
            }
            Ok(None) => return out,
            Err(e) => out.push(Err((e.error(), e.line(), e.column()))),
        }
    }
    panic!("reader does not terminate");
}

/// Reads `text`, which must be error-free.
fn records(text: &str, origin: &str) -> Vec<String> {
    read_all(text, origin)
        .into_iter()
        .map(|r| r.unwrap_or_else(|e| panic!("{e:?}")))
        .collect()
}

/// The text → wire → Display → text → wire round trip of one record:
/// the displayed RDATA parses back to the same wire form, or, for types
/// whose text format is not implemented yet, is refused with
/// `NoTextFormat`.
fn check_record(rr: &ZoneRecord<'_>) {
    let data = rr.data().unwrap();
    let shown = data.to_string();
    let mut s = Scanner::new(&shown).with_origin(crate::Name::ROOT);
    let mut buf = std::vec![0u8; 65535];
    let mut again = WireWriter::new(&mut buf);
    match RData::parse_text(rr.rtype, rr.class, &mut s, &mut again) {
        Ok(()) => assert_eq!(again.as_bytes(), rr.rdata, "{rr}"),
        Err(Error::NoTextFormat) => {}
        Err(e) => panic!("{rr}: display does not parse back: {e}"),
    }
}

/// The RFC 1035 §5.3 example master file (ISI.EDU), with the mailbox file
/// it includes.
const RFC1035_ZONE: &str = "\
@   IN  SOA     VENERA      Action\\.domains (
                                 20     ; SERIAL
                                 7200   ; REFRESH
                                 600    ; RETRY
                                 3600000; EXPIRE
                                 60)    ; MINIMUM

        NS      A.ISI.EDU.
        NS      VENERA
        NS      VAXA
        MX      10      VENERA
        MX      20      VAXA

A       A       26.3.0.103

VENERA  A       10.1.0.52
        A       128.9.0.32

VAXA    A       10.2.0.27
        A       128.9.0.33


$INCLUDE <SUBSYS>ISI-MAILBOXES.TXT
";

const RFC1035_MAILBOXES: &str = "\
MOE     MB      A.ISI.EDU.
LARRY   MB      A.ISI.EDU.
CURLEY  MB      A.ISI.EDU.
STOOGES MG      MOE
        MG      LARRY
        MG      CURLEY
";

const RFC1035_RECORDS: [&str; 11] = [
    // No TTL anywhere: the SOA MINIMUM applies, as in BIND.
    "ISI.EDU. 60 IN SOA VENERA.ISI.EDU. Action\\.domains.ISI.EDU. 20 7200 600 3600000 60",
    "ISI.EDU. 60 IN NS A.ISI.EDU.",
    "ISI.EDU. 60 IN NS VENERA.ISI.EDU.",
    "ISI.EDU. 60 IN NS VAXA.ISI.EDU.",
    "ISI.EDU. 60 IN MX 10 VENERA.ISI.EDU.",
    "ISI.EDU. 60 IN MX 20 VAXA.ISI.EDU.",
    "A.ISI.EDU. 60 IN A 26.3.0.103",
    "VENERA.ISI.EDU. 60 IN A 10.1.0.52",
    "VENERA.ISI.EDU. 60 IN A 128.9.0.32",
    "VAXA.ISI.EDU. 60 IN A 10.2.0.27",
    "VAXA.ISI.EDU. 60 IN A 128.9.0.33",
];

const RFC1035_MAILBOX_RECORDS: [&str; 6] = [
    "MOE.ISI.EDU. 60 IN MB A.ISI.EDU.",
    "LARRY.ISI.EDU. 60 IN MB A.ISI.EDU.",
    "CURLEY.ISI.EDU. 60 IN MB A.ISI.EDU.",
    "STOOGES.ISI.EDU. 60 IN MG MOE.ISI.EDU.",
    "STOOGES.ISI.EDU. 60 IN MG LARRY.ISI.EDU.",
    "STOOGES.ISI.EDU. 60 IN MG CURLEY.ISI.EDU.",
];

#[test]
fn rfc1035_example_zone() {
    let origin: NameBuf = "ISI.EDU".parse().unwrap();
    let mut r = ZoneReader::new(RFC1035_ZONE).with_origin(&origin);
    let mut buf = [0u8; 512];
    let mut shown = Vec::new();
    let include = loop {
        match r.next_entry(&mut buf).unwrap() {
            Some(Entry::Record(rr)) => {
                check_record(&rr);
                shown.push(rr.to_string());
            }
            Some(Entry::Include(inc)) => break inc,
            None => panic!("no $INCLUDE"),
        }
    };
    assert_eq!(shown, RFC1035_RECORDS);
    assert_eq!(include.path.as_bytes(), b"<SUBSYS>ISI-MAILBOXES.TXT");
    assert_eq!(include.origin, origin);
    assert_eq!((include.line, include.column), (23, 1));
    assert_eq!(r.next_entry(&mut buf), Ok(None));

    // The included file, read with the include's origin.
    let mut inc = ZoneReader::new(RFC1035_MAILBOXES)
        .with_origin(&include.origin)
        .with_default_ttl(60);
    let mut shown = Vec::new();
    while let Some(rr) = inc.next_record(&mut buf).unwrap() {
        shown.push(rr.to_string());
    }
    assert_eq!(shown, RFC1035_MAILBOX_RECORDS);

    // next_record refuses the $INCLUDE, at its position.
    let mut r = ZoneReader::new(RFC1035_ZONE).with_origin(&origin);
    let mut n = 0;
    let err = loop {
        match r.next_record(&mut buf) {
            Ok(Some(_)) => n += 1,
            Ok(None) => panic!("no error"),
            Err(e) => break e,
        }
    };
    assert_eq!(n, 11);
    assert_eq!(
        (err.error(), err.line(), err.column()),
        (Error::BadInclude, 23, 1)
    );
}

#[cfg(feature = "alloc")]
#[test]
fn rfc1035_example_zone_with_include() {
    let origin: NameBuf = "ISI.EDU".parse().unwrap();
    let all: Vec<String> = ZoneReader::new(RFC1035_ZONE)
        .with_origin(&origin)
        .records()
        .with_includes(|path: &str| {
            assert_eq!(path, "<SUBSYS>ISI-MAILBOXES.TXT");
            Ok(RFC1035_MAILBOXES.to_string())
        })
        .map(|r| r.unwrap().to_string())
        .collect();
    let want: Vec<&str> = RFC1035_RECORDS
        .iter()
        .chain(RFC1035_MAILBOX_RECORDS.iter())
        .copied()
        .collect();
    assert_eq!(all, want);
    // Without a resolver, the include is an error (after the records).
    let res: Vec<_> = ZoneReader::new(RFC1035_ZONE)
        .with_origin(&origin)
        .records()
        .collect();
    assert_eq!(res.len(), 12);
    let err = res[11].as_ref().unwrap_err();
    assert_eq!(
        (err.error(), err.line(), err.file()),
        (Error::BadInclude, 23, None)
    );
}

/// `\# <length> <hex>` for `wire`.
fn generic(wire: &[u8]) -> String {
    let mut s = String::new();
    crate::text::fmt_generic_rdata(&mut s, wire).unwrap();
    s
}

/// Wire-format NSEC RDATA: `next` and the type bitmap of `types`.
fn nsec(next: &str, types: &str) -> Vec<u8> {
    let mut buf = [0u8; 1024];
    let mut w = WireWriter::new(&mut buf);
    let next = NameBuf::from_text(next.as_bytes()).unwrap();
    w.put_bytes(next.as_wire()).unwrap();
    Scanner::new(types).type_bitmap_into(&mut w).unwrap();
    w.as_bytes().to_vec()
}

/// Wire-format RRSIG RDATA with a dummy signature.
fn rrsig(covered: Rtype, labels: u8, signer: &str) -> Vec<u8> {
    let mut w = Vec::new();
    w.extend_from_slice(&covered.get().to_be_bytes());
    w.push(8); // RSASHA256
    w.push(labels);
    w.extend_from_slice(&3600u32.to_be_bytes());
    w.extend_from_slice(&1_893_456_000u32.to_be_bytes()); // 2030-01-01
    w.extend_from_slice(&1_704_067_200u32.to_be_bytes()); // 2024-01-01
    w.extend_from_slice(&2642u16.to_be_bytes());
    w.extend_from_slice(NameBuf::from_text(signer.as_bytes()).unwrap().as_wire());
    w.extend_from_slice(&[0xa5; 64]);
    w
}

/// A small signed zone in the style of RFC 4035 Appendix A. The DNSSEC
/// records are in the RFC 3597 generic form, which every reader accepts
/// whatever types it knows; they come out as typed data.
#[test]
fn signed_zone() {
    let dnskey = crate::testutil::hex(crate::dnssec::testvec::RFC4034_KEY);
    let zone = format!(
        "$ORIGIN example.\n\
         $TTL 3600\n\
         @ IN SOA ns1 bugs.x.w ( 1081539377 3600 300 3600000 3600 )\n\
         \x20 RRSIG {soa_sig}\n\
         \x20 NS ns1\n\
         \x20 RRSIG {ns_sig}\n\
         \x20 MX 1 xx\n\
         \x20 DNSKEY {dnskey}\n\
         \x20 NSEC {apex_nsec}\n\
         ns1 A 192.0.2.1\n\
         \x20   RRSIG {a_sig}\n\
         \x20   NSEC {ns1_nsec}\n\
         xx  A 192.0.2.10\n\
         \x20   AAAA 2001:db8::f00:baaa\n\
         \x20   HINFO \"KLH-10\" \"ITS\"\n\
         \x20   NSEC {xx_nsec}\n",
        soa_sig = generic(&rrsig(Rtype::SOA, 1, "example.")),
        ns_sig = generic(&rrsig(Rtype::NS, 1, "example.")),
        dnskey = generic(&dnskey),
        apex_nsec = generic(&nsec("ns1.example.", "SOA NS MX RRSIG NSEC DNSKEY")),
        a_sig = generic(&rrsig(Rtype::A, 2, "example.")),
        ns1_nsec = generic(&nsec("xx.example.", "A RRSIG NSEC")),
        xx_nsec = generic(&nsec("example.", "A AAAA HINFO NSEC")),
    );
    let mut r = ZoneReader::new(&zone);
    let mut buf = [0u8; 1024];
    let mut types = Vec::new();
    while let Some(rr) = r.next_record(&mut buf).unwrap() {
        check_record(&rr);
        assert_eq!((rr.class, rr.ttl), (Class::IN, 3600));
        let data = rr.data().unwrap();
        assert!(!matches!(data, RData::Unknown(_)), "{rr}");
        match data {
            RData::Rrsig(sig) => {
                assert_eq!(sig.signer_name.to_string(), "example.");
                assert_eq!(sig.key_tag, 2642);
            }
            RData::Dnskey(key) => assert_eq!(key.key_tag(), 2642),
            RData::Nsec(n) if rr.name.to_string() == "xx.example." => {
                assert_eq!(n.next_domain_name.to_string(), "example.");
                assert_eq!(n.types.to_string(), "A HINFO AAAA NSEC");
            }
            _ => {}
        }
        types.push(rr.rtype);
    }
    use Rtype as T;
    assert_eq!(
        types,
        [
            T::SOA,
            T::RRSIG,
            T::NS,
            T::RRSIG,
            T::MX,
            T::DNSKEY,
            T::NSEC,
            T::A,
            T::RRSIG,
            T::NSEC,
            T::A,
            T::AAAA,
            T::HINFO,
            T::NSEC
        ]
    );
    // Generic RDATA of a known type must have its wire format (RFC 3597
    // §5): a truncated RRSIG is refused.
    let bad = format!("@ 1 RRSIG {}\n", generic(&rrsig(Rtype::A, 1, ".")[..17]));
    assert_eq!(
        read_all(&bad, "example."),
        [Err((Error::UnexpectedEof, 1, 17))]
    );
}

#[test]
fn defaults_and_directives() {
    let zone = "\
$ORIGIN example.com.
$TTL 1h30m
@ SOA ns hostmaster 1 2 3 4 5
  NS ns.example.net.
www 300 A 192.0.2.1 ; explicit TTL
    A 192.0.2.2         ; $TTL again, not the last explicit TTL
$ORIGIN sub
x CH 60 TXT a          ; class then TTL
  TXT b                ; inherits owner and class
y IN TXT \"c\"
$TTL 2d
@ AAAA ::1
$origin .
z.example. 1w IN TYPE65280 \\# 2 abcd
z.example. CLASS1 A \\# 4 C0000201
z.example. CLASS32 TYPE1 1.2.3.4
";
    // $TTL and the class carry over; z's last record has class 32, in
    // which A has no text format (only the generic form).
    let res = read_all(zone, ".");
    let ok: Vec<&str> = res.iter().filter_map(|r| r.as_deref().ok()).collect();
    assert_eq!(
        ok,
        [
            "example.com. 5400 IN SOA ns.example.com. hostmaster.example.com. 1 2 3 4 5",
            "example.com. 5400 IN NS ns.example.net.",
            "www.example.com. 300 IN A 192.0.2.1",
            "www.example.com. 5400 IN A 192.0.2.2",
            "x.sub.example.com. 60 CH TXT \"a\"",
            "x.sub.example.com. 5400 CH TXT \"b\"",
            "y.sub.example.com. 5400 IN TXT \"c\"",
            "sub.example.com. 172800 IN AAAA ::1",
            "z.example. 604800 IN TYPE65280 \\# 2 ABCD",
            "z.example. 172800 IN A 192.0.2.1",
        ]
    );
    assert_eq!(res.last(), Some(&Err((Error::NoTextFormat, 16, 20))));
    assert_eq!(res.len(), 11);
}

#[test]
fn ttl_without_ttl_directive() {
    // RFC 1035: the last explicit TTL is the default.
    assert_eq!(
        records(
            "a 10 A 192.0.2.1\nb A 192.0.2.2\nc 20 A 192.0.2.3\nd A 192.0.2.4\n",
            "x."
        ),
        [
            "a.x. 10 IN A 192.0.2.1",
            "b.x. 10 IN A 192.0.2.2",
            "c.x. 20 IN A 192.0.2.3",
            "d.x. 20 IN A 192.0.2.4"
        ]
    );
    // No TTL at all.
    assert_eq!(
        read_all("a A 192.0.2.1\n", "x."),
        [Err((Error::MissingTtl, 1, 1))]
    );
    // An SOA without a TTL supplies its MINIMUM.
    assert_eq!(
        records("@ SOA a. b. 1 2 3 4 300\nb A 192.0.2.2\n", "x."),
        ["x. 300 IN SOA a. b. 1 2 3 4 300", "b.x. 300 IN A 192.0.2.2"]
    );
    // An explicit default overrides it.
    let mut buf = [0u8; 64];
    let mut r = ZoneReader::new("a A 192.0.2.1").with_default_ttl(7);
    assert_eq!(r.default_ttl(), Some(7));
    assert_eq!(r.next_record(&mut buf).unwrap().unwrap().ttl, 7);
}

#[test]
fn lexical_details() {
    // CRLF line ends, tabs, comments, empty and comment-only lines,
    // parentheses over several lines, escapes in owners, `@`, and a final
    // line without a newline.
    let zone = "; header comment\r\n\
                \r\n\
                $TTL 60\r\n\
                a\\.b\tIN\tTXT\t( \"one\"\r\n\
                \t\t; inner comment\r\n\
                \t\t\"two\" )\r\n\
                \x20\x20\x20\x20; indented comment\n\
                @ MX ( 10\n\
                \x20 @ )\n\
                \\@\\$ TXT \"x\\\"y\"\n\
                *.w A 192.0.2.9";
    assert_eq!(
        records(zone, "example."),
        [
            "a\\.b.example. 60 IN TXT \"one\" \"two\"",
            "example. 60 IN MX 10 example.",
            "\\@\\$.example. 60 IN TXT \"x\\\"y\"",
            "*.w.example. 60 IN A 192.0.2.9",
        ]
    );
    assert!(records("", ".").is_empty());
    assert!(records("\n\n ; x\n\t\n( )\n", ".").is_empty());
}

#[test]
fn errors_have_positions_and_recover() {
    let zone = "\
$TTL 60
a A 192.0.2.1
b IN BOGUS x
c IN A 192.0.2
d MX ( 10
       mail.
       extra )
f A 192.0.2.6
  A 192.0.2.7 )
g A ( 192.0.2.8
  192.0.2.9 )
$BOGUS 1
$TTL 1x
h é 192.0.2.10
  TXT ok
e TXT \"unterminated
i A 192.0.2.11
";
    assert_eq!(
        read_all(zone, "example."),
        [
            Ok("a.example. 60 IN A 192.0.2.1".to_string()),
            Err((Error::UnknownMnemonic, 3, 6)),
            Err((Error::InvalidText, 4, 8)),
            Err((Error::InvalidText, 7, 8)),
            Ok("f.example. 60 IN A 192.0.2.6".to_string()),
            Err((Error::InvalidText, 9, 15)),
            Err((Error::InvalidText, 11, 3)),
            Err((Error::UnknownMnemonic, 12, 1)),
            Err((Error::InvalidText, 13, 6)),
            Err((Error::UnknownMnemonic, 14, 3)),
            // The owner of a bad entry still applies to the next line.
            Ok("h.example. 60 IN TXT \"ok\"".to_string()),
            Err((Error::InvalidText, 16, 7)),
            Ok("i.example. 60 IN A 192.0.2.11".to_string()),
        ]
    );
    // A quoted owner.
    assert_eq!(
        read_all("\"q\" 1 A 192.0.2.1\n", "x."),
        [Err((Error::InvalidText, 1, 1))]
    );
    // No previous owner.
    assert_eq!(
        read_all("  A 192.0.2.1\n", "x."),
        [Err((Error::InvalidText, 1, 1))]
    );
    // A missing type.
    assert_eq!(
        read_all("a 60 IN\nb 60 A 192.0.2.1\n", "x."),
        [
            Err((Error::UnexpectedEof, 1, 6)),
            Ok("b.x. 60 IN A 192.0.2.1".to_string())
        ]
    );
    // Errors display with their position.
    let e = ZoneError::new(Error::MissingTtl, 3, 7);
    assert_eq!(
        e.to_string(),
        "line 3, column 7: no TTL given and no default TTL"
    );
    assert_eq!(Error::from(e), Error::MissingTtl);
}

#[test]
fn rdata_buffer_limits() {
    let mut small = [0u8; 3];
    let mut r = ZoneReader::new("a 1 A 192.0.2.1\nb 1 A 192.0.2.2\n");
    let e = r.next_record(&mut small).unwrap_err();
    assert_eq!((e.error(), e.line()), (Error::BufferTooSmall, 1));
    let mut buf = [0u8; 4];
    assert_eq!(
        r.next_record(&mut buf).unwrap().unwrap().to_string(),
        "b. 1 IN A 192.0.2.2"
    );
    // SVCB reserves room in place: it works in a tight buffer too.
    let mut buf = [0u8; 16];
    let mut r = ZoneReader::new("s 1 SVCB 1 . port=53\n");
    let rr = r.next_record(&mut buf).unwrap().unwrap();
    assert_eq!(rr.rdata, b"\x00\x01\x00\x00\x03\x00\x02\x00\x35");
    assert_eq!(rr.to_string(), "s. 1 IN SVCB 1 . port=53");
}

#[test]
fn generate() {
    let zone = "\
$ORIGIN 2.0.192.in-addr.arpa.
$TTL 300
$GENERATE 1-3 $ PTR host-$.example.
$GENERATE 10-30/10 ${0,3,d} 60 IN CNAME ${-9,2,x}.sub
$GENERATE 0-1 h$ TXT \"v=$ \\$x\"
after A 192.0.2.99
";
    assert_eq!(
        records(zone, "."),
        [
            "1.2.0.192.in-addr.arpa. 300 IN PTR host-1.example.",
            "2.2.0.192.in-addr.arpa. 300 IN PTR host-2.example.",
            "3.2.0.192.in-addr.arpa. 300 IN PTR host-3.example.",
            "010.2.0.192.in-addr.arpa. 60 IN CNAME 01.sub.2.0.192.in-addr.arpa.",
            "020.2.0.192.in-addr.arpa. 60 IN CNAME 0b.sub.2.0.192.in-addr.arpa.",
            "030.2.0.192.in-addr.arpa. 60 IN CNAME 15.sub.2.0.192.in-addr.arpa.",
            "h0.2.0.192.in-addr.arpa. 300 IN TXT \"v=0 $x\"",
            "h1.2.0.192.in-addr.arpa. 300 IN TXT \"v=1 $x\"",
            "after.2.0.192.in-addr.arpa. 300 IN A 192.0.2.99",
        ]
    );
    // ip6.arpa nibbles.
    assert_eq!(
        records("$GENERATE 254-255 ${0,3,n} 1 PTR h$\n", "ip6.arpa."),
        [
            "e.f.ip6.arpa. 1 IN PTR h254.ip6.arpa.",
            "f.f.ip6.arpa. 1 IN PTR h255.ip6.arpa."
        ]
    );
    // Errors: bad range, bad template, an iteration failing (which ends
    // the directive), missing TTL.
    assert_eq!(
        read_all(
            "$GENERATE 1-2 $ A 192.0.2.$\n\
             $GENERATE 5-1 $ 1 A 192.0.2.$\n\
             $GENERATE 1-2 ${x} 1 A 192.0.2.$\n\
             $GENERATE 255-257 $ 1 A 192.0.2.$\n\
             ok 1 A 192.0.2.1\n",
            "x."
        ),
        [
            Err((Error::MissingTtl, 1, 1)),
            Err((Error::InvalidText, 2, 11)),
            Err((Error::InvalidText, 3, 1)),
            Ok("255.x. 1 IN A 192.0.2.255".to_string()),
            Err((Error::InvalidText, 4, 1)),
            Ok("ok.x. 1 IN A 192.0.2.1".to_string()),
        ]
    );
    // The iteration count is bounded.
    assert_eq!(
        read_all("$GENERATE 0-4294967295 $ 1 A 192.0.2.1\n", "x."),
        [Err((Error::LimitExceeded, 1, 11))]
    );
    let mut r = ZoneReader::new("$GENERATE 0-65535 $ 1 TXT x\n");
    let mut buf = [0u8; 8];
    let mut n = 0u32;
    while r.next_record(&mut buf).unwrap().is_some() {
        n += 1;
    }
    assert_eq!(n, MAX_GENERATE);
}

#[cfg(feature = "alloc")]
#[test]
fn includes() {
    use std::collections::BTreeMap;
    let files: BTreeMap<&str, &str> = [
        (
            "a.inc",
            "$ORIGIN inner.\nx A 192.0.2.1\n  TXT \"same owner\"\n$INCLUDE b.inc deeper\n",
        ),
        ("b.inc", "@ A 192.0.2.2\n"),
        ("loop.inc", "$INCLUDE loop.inc\n"),
        ("bad.inc", "ok 1 A 192.0.2.3\nbad 1 A 300.0.0.1\n"),
    ]
    .into_iter()
    .collect();
    let resolver = |path: &str| {
        files
            .get(path)
            .map(|t| t.to_string())
            .ok_or(Error::BadInclude)
    };
    let zone = "\
$ORIGIN example.
$TTL 60
top A 192.0.2.100
$INCLUDE a.inc sub
  TXT \"owner and origin restored\"
after A 192.0.2.101
$INCLUDE \"missing.inc\"
$INCLUDE bad.inc
$INCLUDE loop.inc
end A 192.0.2.102
";
    let res: Vec<_> = ZoneReader::new(zone)
        .records()
        .with_includes(resolver)
        .map(|r| {
            r.map(|rr| rr.to_string())
                .map_err(|e| (e.error(), e.line(), e.file().map(String::from)))
        })
        .collect();
    let ok = |s: &str| Ok(s.to_string());
    assert_eq!(
        res,
        [
            ok("top.example. 60 IN A 192.0.2.100"),
            ok("x.inner. 60 IN A 192.0.2.1"),
            ok("x.inner. 60 IN TXT \"same owner\""),
            ok("deeper.inner. 60 IN A 192.0.2.2"),
            ok("top.example. 60 IN TXT \"owner and origin restored\""),
            ok("after.example. 60 IN A 192.0.2.101"),
            Err((Error::BadInclude, 7, None)),
            ok("ok.example. 1 IN A 192.0.2.3"),
            Err((Error::InvalidText, 2, Some("bad.inc".to_string()))),
            // loop.inc includes itself until the depth limit.
            Err((Error::LimitExceeded, 1, Some("loop.inc".to_string()))),
            ok("end.example. 60 IN A 192.0.2.102"),
        ]
    );
    // The total number of includes is bounded too.
    let res: Vec<_> = ZoneReader::new("$INCLUDE b.inc\n$INCLUDE b.inc\n")
        .with_default_ttl(1)
        .records()
        .with_includes(resolver)
        .max_includes(1)
        .map(|r| r.map(|rr| rr.to_string()).map_err(|e| e.error()))
        .collect();
    assert_eq!(
        res,
        [
            Ok(". 1 IN A 192.0.2.2".to_string()),
            Err(Error::LimitExceeded)
        ]
    );
    // Depth 0 forbids includes.
    let res: Vec<_> = ZoneReader::new("$INCLUDE b.inc\n")
        .with_default_ttl(1)
        .records()
        .with_includes(resolver)
        .max_include_depth(0)
        .collect();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].as_ref().unwrap_err().error(), Error::LimitExceeded);
    // Errors in included files name the file.
    let e = ZoneError::new(Error::InvalidText, 2, 5).in_file("x.inc");
    assert_eq!(
        e.to_string(),
        "x.inc: line 2, column 5: malformed presentation-format text"
    );
}

#[cfg(feature = "alloc")]
#[test]
fn owned_records() {
    let zone = parse("$ORIGIN example.\n$TTL 1d\n@ NS ns1\nns1 A 192.0.2.53\n").unwrap();
    assert_eq!(zone.len(), 2);
    let ns = &zone[0];
    assert_eq!(ns.as_record().to_string(), ns.to_string());
    assert!(matches!(ns.data().unwrap(), RData::Ns(_)));
    assert_eq!(ns.line, 3);
    assert_eq!(
        parse("a A 192.0.2.1\n").unwrap_err().error(),
        Error::MissingTtl
    );
    let wire = RData::text_to_wire(Rtype::MX, Class::IN, "1 a.").unwrap();
    assert_eq!(wire, b"\x00\x01\x01a\x00");
}

#[test]
fn rdata_from_text() {
    let mut buf = [0u8; 64];
    let txt = Txt::from_text("\"a\" b", &mut buf).unwrap();
    assert_eq!(txt.as_wire(), b"\x01a\x01b");
    let mut buf = [0u8; 64];
    assert_eq!(Txt::from_text("a )", &mut buf), Err(Error::InvalidText));
    assert_eq!(
        crate::rdata::Mx::from_text("1 a. b.", &mut buf),
        Err(Error::InvalidText)
    );
    // The generic form, validated by the wire parser.
    let mut buf = [0u8; 64];
    let a = crate::rdata::A::from_text("\\# 4 7f000001", &mut buf).unwrap();
    assert_eq!(a.addr, core::net::Ipv4Addr::LOCALHOST);
    assert_eq!(
        crate::rdata::A::from_text("\\# 3 7f0000", &mut [0u8; 8]),
        Err(Error::UnexpectedEof)
    );
    // Types without a text format accept only the generic form.
    assert_eq!(
        crate::rdata::Null::from_text("x", &mut [0u8; 8]),
        Err(Error::NoTextFormat)
    );
    let mut buf = [0u8; 64];
    let d = RData::from_text(Rtype::new(65280), Class::IN, "\\# 1 ff", &mut buf).unwrap();
    assert_eq!(d.to_string(), "\\# 1 FF");
    assert_eq!(
        RData::from_text(Rtype::new(65280), Class::IN, "ff", &mut [0u8; 8]),
        Err(Error::NoTextFormat)
    );
    // Class-specific types in another class.
    assert_eq!(
        RData::from_text(Rtype::A, Class::CH, "1.2.3.4", &mut [0u8; 8]),
        Err(Error::NoTextFormat)
    );
    assert_eq!(
        RData::from_text(Rtype::A, Class::CH, "\\# 2 0102", &mut [0u8; 8])
            .unwrap()
            .to_string(),
        "\\# 2 0102"
    );
    // The buffer must hold the result.
    assert_eq!(
        RData::from_text(Rtype::A, Class::IN, "1.2.3.4", &mut [0u8; 3]),
        Err(Error::BufferTooSmall)
    );
}

#[test]
fn hostile_input() {
    // Deeply nested or unbalanced parentheses, endless quotes and long
    // lines are rejected or consumed in linear time.
    let deep = format!("a 1 TXT {}x{}\n", "(".repeat(100), ")".repeat(100));
    assert_eq!(read_all(&deep, "x.").len(), 1);
    let open = format!("a 1 A ( 192.0.2.1\n{}", "\n".repeat(50_000));
    assert_eq!(
        read_all(&open, "x."),
        [Err((Error::InvalidText, 50_002, 1))]
    );
    let quotes = format!("a 1 TXT \"{}", "z ".repeat(100_000));
    assert_eq!(read_all(&quotes, "x.").len(), 1);
    let many = "a 1 TXT x ; c\n".repeat(20_000);
    let mut r = ZoneReader::new(&many);
    let mut buf = [0u8; 16];
    let mut n = 0;
    while r.next_record(&mut buf).unwrap().is_some() {
        n += 1;
    }
    assert_eq!(n, 20_000);
    assert_eq!(r.line(), 20_001);
    // Arbitrary bytes never panic and always terminate.
    let junk: Vec<u8> = (0..20_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let mut r = ZoneReader::from_bytes(&junk);
    let mut buf = [0u8; 65535];
    for _ in 0..junk.len() + 1 {
        if let Ok(None) = r.next_record(&mut buf) {
            break;
        }
    }
    assert_eq!(r.next_record(&mut buf), Ok(None));
}

/// Reads every entry of `text` under `limits`, as [`read_all`] does.
fn read_limited(
    text: &str,
    limits: ZoneLimits,
) -> Vec<core::result::Result<String, (Error, u32, u32)>> {
    let mut r = ZoneReader::new(text).with_limits(limits);
    let mut buf = [0u8; 65535];
    let mut out = Vec::new();
    for _ in 0..10_000 {
        match r.next_record(&mut buf) {
            Ok(Some(rr)) => out.push(Ok(rr.to_string())),
            Ok(None) => return out,
            Err(e) => out.push(Err((e.error(), e.line(), e.column()))),
        }
    }
    panic!("reader does not terminate");
}

#[test]
fn record_limit() {
    let ok = |s: &str| Ok(s.to_string());
    let text = "$TTL 1\na A 192.0.2.1\nb A 192.0.2.2\nc A 192.0.2.3\nd A 192.0.2.4\n";
    let limits = ZoneLimits::DEFAULT.with_max_records(2);
    // The third record stops the reader.
    assert_eq!(
        read_limited(text, limits),
        [
            ok("a. 1 IN A 192.0.2.1"),
            ok("b. 1 IN A 192.0.2.2"),
            Err((Error::LimitExceeded, 4, 1)),
        ]
    );
    assert_eq!(read_limited(text, limits.with_max_records(4)).len(), 4);
    assert_eq!(
        read_limited(text, limits.with_max_records(0)),
        [Err((Error::LimitExceeded, 2, 1))]
    );
    // Failed entries do not count; generated records do.
    let text = "$TTL 1\nbad A x\n$GENERATE 1-3 g$ A 192.0.2.$\nz A 192.0.2.9\n";
    assert_eq!(
        read_limited(text, limits),
        [
            Err((Error::InvalidText, 2, 7)),
            ok("g1. 1 IN A 192.0.2.1"),
            ok("g2. 1 IN A 192.0.2.2"),
            Err((Error::LimitExceeded, 3, 1)),
        ]
    );
    let mut r = ZoneReader::new(text).with_limits(limits.with_max_records(3));
    let mut buf = [0u8; 64];
    let mut n = 0;
    while let Ok(Some(_)) | Err(_) = r.next_record(&mut buf) {
        n += 1;
    }
    assert_eq!((n, r.record_count()), (5, 3));
    // A hostile file: each line yields MAX_GENERATE records.
    let line = "$GENERATE 0-65535 h$ TXT x\n";
    let text = format!("$TTL 1\n{}", line.repeat(64));
    let mut r = ZoneReader::new(&text).with_limits(limits.with_max_records(70_000));
    let mut seen = 0u64;
    let err = loop {
        match r.next_record(&mut buf) {
            Ok(Some(_)) => seen += 1,
            Ok(None) => panic!("not stopped"),
            Err(e) => break e,
        }
    };
    assert_eq!(seen, 70_000);
    assert_eq!((err.error(), err.line()), (Error::LimitExceeded, 3));
    assert_eq!(r.next_record(&mut buf), Ok(None));
}

#[test]
fn generate_limit() {
    let ok = |s: &str| Ok(s.to_string());
    let text = "$TTL 1\n$GENERATE 1-3 g$ A 192.0.2.$\n$GENERATE 1-2 h$ A 192.0.2.$\n";
    let limits = ZoneLimits::DEFAULT.with_max_generate(2);
    // The directive over the limit is skipped; reading goes on.
    assert_eq!(
        read_limited(text, limits),
        [
            Err((Error::LimitExceeded, 2, 11)),
            ok("h1. 1 IN A 192.0.2.1"),
            ok("h2. 1 IN A 192.0.2.2"),
        ]
    );
    assert_eq!(read_limited(text, limits.with_max_generate(3)).len(), 5);
    assert_eq!(
        read_limited(text, limits.with_max_generate(0)),
        [
            Err((Error::LimitExceeded, 2, 11)),
            Err((Error::LimitExceeded, 3, 11)),
        ]
    );
    // Steps count iterations, not the span.
    let stepped = "$TTL 1\n$GENERATE 0-1000/500 g$ A 192.0.2.1\n";
    assert_eq!(read_limited(stepped, limits.with_max_generate(3)).len(), 3);
    // Raised above MAX_GENERATE.
    let mut r = ZoneReader::new("$GENERATE 1-65537 $ 1 TXT x\n").with_limits(ZoneLimits::UNLIMITED);
    let mut buf = [0u8; 8];
    let mut n = 0u32;
    while r.next_record(&mut buf).unwrap().is_some() {
        n += 1;
    }
    assert_eq!(n, MAX_GENERATE + 1);
}

#[test]
fn input_limit() {
    let text = "a 1 A 192.0.2.1\n";
    let limits = ZoneLimits::DEFAULT.with_max_input_len(text.len());
    assert_eq!(read_limited(text, limits).len(), 1);
    assert_eq!(
        read_limited(text, limits.with_max_input_len(text.len() - 1)),
        [Err((Error::LimitExceeded, 1, 1))]
    );
}

#[test]
fn line_and_token_limits() {
    let ok = |s: &str| Ok(s.to_string());
    let limits = ZoneLimits::DEFAULT.with_max_line_len(20);
    // 21 characters on line 2: reported at the 21st, the entry skipped.
    let text = "a 1 A 192.0.2.1\nb 1 TXT \"01234567890\"\nc 1 A 192.0.2.3\n";
    assert_eq!(
        read_limited(text, limits),
        [
            ok("a. 1 IN A 192.0.2.1"),
            Err((Error::LimitExceeded, 2, 21)),
            ok("c. 1 IN A 192.0.2.3"),
        ]
    );
    assert_eq!(read_limited(text, limits.with_max_line_len(21)).len(), 3);
    // Lines inside parentheses, comments, quoted strings, escaped
    // newlines and the last line are measured too.
    for text in [
        "a 1 TXT ( x\n                       y )\nc 1 A 192.0.2.3\n",
        "a 1 TXT x ; a long comment here\nc 1 A 192.0.2.3\n",
        "a 1 TXT \"x\n123456789012345678901234\"\nc 1 A 192.0.2.3\n",
        "a 1 TXT x\\\n123456789012345678901234\nc 1 A 192.0.2.3\n",
    ] {
        let res = read_limited(text, limits);
        assert!(
            matches!(res[0], Err((Error::LimitExceeded, _, 21))),
            "{text:?}: {res:?}"
        );
        assert_eq!(res.last(), Some(&ok("c. 1 IN A 192.0.2.3")), "{text:?}");
    }
    assert_eq!(
        read_limited("c 1 A 192.0.2.3\n; 1234567890123456789012", limits),
        [
            ok("c. 1 IN A 192.0.2.3"),
            Err((Error::LimitExceeded, 2, 21))
        ]
    );
    // Tokens: reported at their start.
    let limits = ZoneLimits::DEFAULT.with_max_token_len(5);
    assert_eq!(
        read_limited("a 1 TXT abcde \"abc\"\nb 1 TXT abcdef\n", limits),
        [
            ok("a. 1 IN TXT \"abcde\" \"abc\""),
            Err((Error::LimitExceeded, 2, 9))
        ]
    );
    assert_eq!(
        read_limited("b 1 TXT \"abcd\"\n", limits),
        [Err((Error::LimitExceeded, 1, 9))]
    );
    // The default token limit fits the largest RDATA in hex.
    let hex = format!("a 1 TYPE65280 \\# 65535 {}\n", "ab".repeat(65535));
    let res = read_all(&hex, "x.");
    assert_eq!(res.len(), 1);
    assert!(res[0].is_ok());
}

#[cfg(feature = "alloc")]
#[test]
fn limits_across_includes() {
    let resolver = |path: &str| match path {
        "two.inc" => Ok("x A 192.0.2.1\ny A 192.0.2.2\n".to_string()),
        "big.inc" => Ok(format!("z TXT \"{}\"\n", "a".repeat(100))),
        _ => Err(Error::BadInclude),
    };
    type Item = core::result::Result<String, (Error, u32, Option<String>)>;
    let collect = |text: &str, limits: ZoneLimits| -> Vec<Item> {
        ZoneReader::new(text)
            .with_default_ttl(1)
            .records()
            .with_includes(resolver)
            .with_limits(limits)
            .map(|r| {
                r.map(|rr| rr.name.to_string())
                    .map_err(|e| (e.error(), e.line(), e.file().map(String::from)))
            })
            .collect()
    };
    // The record limit counts every file and ends the iteration.
    let text = "a A 192.0.2.10\n$INCLUDE two.inc\nb A 192.0.2.11\n$INCLUDE two.inc\n";
    let limits = ZoneLimits::DEFAULT.with_max_records(2);
    assert_eq!(
        collect(text, limits),
        [
            Ok("a.".to_string()),
            Ok("x.".to_string()),
            Err((Error::LimitExceeded, 2, Some("two.inc".to_string()))),
        ]
    );
    assert_eq!(collect(text, limits.with_max_records(6)).len(), 6);
    // The input limit counts the included text; a file over what is left
    // fails its directive.
    let text = "$INCLUDE big.inc\n$INCLUDE two.inc\n";
    let limits = ZoneLimits::DEFAULT.with_max_input_len(text.len() + 50);
    assert_eq!(
        collect(text, limits),
        [
            Err((Error::LimitExceeded, 1, None)),
            Ok("x.".to_string()),
            Ok("y.".to_string()),
        ]
    );
    // The default `load_limited` checks resolvers that do not.
    let mut r = resolver;
    assert_eq!(r.load_limited("two.inc", 10), Err(Error::LimitExceeded));
    assert!(r.load_limited("two.inc", 28).is_ok());
    // Line limits apply in included files.
    let limits = ZoneLimits::DEFAULT.with_max_line_len(20);
    assert_eq!(
        collect("$INCLUDE big.inc\n", limits),
        [Err((Error::LimitExceeded, 1, Some("big.inc".to_string())))]
    );
    // parse_with_limits.
    let one = ZoneLimits::DEFAULT.with_max_records(1);
    let err = parse_with_limits("$TTL 1\na A 192.0.2.1\nb A 192.0.2.2\n", one).unwrap_err();
    assert_eq!((err.error(), err.line()), (Error::LimitExceeded, 3));
}

#[cfg(feature = "std")]
#[test]
fn fs_includes() {
    use std::fs;
    use std::path::PathBuf;

    // A fresh directory: zone/ (served) next to secret (not served).
    let root: PathBuf = std::env::temp_dir().join(format!(
        "dnsbox-fs-includes-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = fs::remove_dir_all(&root);
    let zone = root.join("zone");
    fs::create_dir_all(zone.join("sub")).unwrap();
    fs::write(root.join("secret"), "s A 192.0.2.66\n").unwrap();
    fs::write(zone.join("a.inc"), "a A 192.0.2.1\n").unwrap();
    fs::write(zone.join("sub").join("b.inc"), "b A 192.0.2.2\n").unwrap();
    fs::write(zone.join("big.inc"), "x".repeat(1000)).unwrap();
    fs::write(zone.join("bad.inc"), [0xff, 0xfe]).unwrap();

    let mut inc = FsIncludes::new(&zone);
    assert!(inc.is_confined());
    assert_eq!(inc.base(), zone.as_path());
    assert_eq!(inc.load("a.inc").unwrap(), "a A 192.0.2.1\n");
    assert_eq!(inc.load("./sub/b.inc").unwrap(), "b A 192.0.2.2\n");
    let secret = root.join("secret");
    for path in [
        "../secret",
        "sub/../../secret",
        "sub/../a.inc",
        secret.to_str().unwrap(),
        "",
        ".",
        "sub",
        "missing.inc",
        "bad.inc",
    ] {
        assert_eq!(inc.load(path), Err(Error::BadInclude), "{path:?}");
    }
    assert_eq!(inc.load_limited("big.inc", 999), Err(Error::LimitExceeded));
    assert_eq!(inc.load_limited("big.inc", 1000).unwrap().len(), 1000);
    #[cfg(unix)]
    {
        // Symbolic links may not lead out of the directory.
        use std::os::unix::fs::symlink;
        symlink(&secret, zone.join("escape.inc")).unwrap();
        symlink(&root, zone.join("up")).unwrap();
        symlink(zone.join("a.inc"), zone.join("sub").join("link.inc")).unwrap();
        assert_eq!(inc.load("escape.inc"), Err(Error::BadInclude));
        assert_eq!(inc.load("up/secret"), Err(Error::BadInclude));
        assert_eq!(inc.load("sub/link.inc").unwrap(), "a A 192.0.2.1\n");
        // Devices are not read, even unconfined.
        let mut any = FsIncludes::unconfined(&zone);
        assert_eq!(any.load("/dev/zero"), Err(Error::BadInclude));
    }
    // Unconfined: any path, as BIND does.
    let mut any = FsIncludes::unconfined(&zone);
    assert!(!any.is_confined());
    assert_eq!(any.load("../secret").unwrap(), "s A 192.0.2.66\n");
    assert_eq!(
        any.load(secret.to_str().unwrap()).unwrap(),
        "s A 192.0.2.66\n"
    );

    // Through Records: errors at the directives, the rest is read.
    let text = "$TTL 1\n$INCLUDE a.inc\n$INCLUDE ../secret\n$INCLUDE big.inc\nend A 192.0.2.9\n";
    let res: Vec<_> = ZoneReader::new(text)
        .records()
        .with_includes(FsIncludes::new(&zone))
        .with_limits(ZoneLimits::DEFAULT.with_max_input_len(text.len() + 100))
        .map(|r| {
            r.map(|rr| rr.name.to_string())
                .map_err(|e| (e.error(), e.line()))
        })
        .collect();
    assert_eq!(
        res,
        [
            Ok("a.".to_string()),
            Err((Error::BadInclude, 3)),
            Err((Error::LimitExceeded, 4)),
            Ok("end.".to_string()),
        ]
    );
    fs::remove_dir_all(&root).unwrap();
}
