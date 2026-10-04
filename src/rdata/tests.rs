//! Shared RDATA test helpers (`parse`, `compose`, `round_trip`) — reuse them
//! from the tests of new record-type modules via `crate::rdata::tests::*`.

use super::*;
use crate::name::NameBuf;
use crate::wire::{Canonical, WireWriter};
use crate::zone::Scanner;
use crate::{Error, Record};
use std::string::{String, ToString};
use std::vec::Vec;

/// Parses `rdata` as a standalone RDATA of `rtype`/`class`.
pub(crate) fn parse(rtype: Rtype, class: Class, rdata: &[u8]) -> Result<RData<'_>> {
    RData::parse(rtype, class, WireReader::new(rdata))
}

/// Composes `data` with a plain (non-compressing) writer.
pub(crate) fn compose<D: ComposeRdata + ?Sized>(data: &D) -> Vec<u8> {
    let mut buf = [0u8; 1024];
    let mut w = WireWriter::new(&mut buf);
    data.compose_rdata(&mut w).unwrap();
    w.as_bytes().to_vec()
}

/// Parses `rdata` (class IN) as a typed `rtype`, checks its presentation
/// format and that composing gives the same bytes back, and that every
/// truncation of it fails without panicking. Returns the display string.
pub(crate) fn round_trip(rtype: Rtype, rdata: &[u8], display: &str) -> String {
    let data = parse(rtype, Class::IN, rdata).unwrap();
    assert!(
        !matches!(data, RData::Unknown(_)),
        "{rtype} parsed as unknown"
    );
    assert_eq!(data.rtype(), rtype);
    assert_eq!(data.to_string(), display, "{rtype}");
    assert_eq!(compose(&data), rdata, "{rtype}");
    // Truncated RDATA must fail, not panic.
    for end in 0..rdata.len() {
        let _ = parse(rtype, Class::IN, &rdata[..end]);
    }
    data.to_string()
}

#[test]
fn rfc1035_types() {
    round_trip(Rtype::A, &[192, 0, 2, 1], "192.0.2.1");
    round_trip(
        Rtype::AAAA,
        &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        "2001:db8::1",
    );
    round_trip(Rtype::NS, b"\x02ns\x07example\x00", "ns.example.");
    round_trip(Rtype::CNAME, b"\x01a\x00", "a.");
    round_trip(Rtype::PTR, b"\x03one\x03one\x00", "one.one.");
    for t in [Rtype::MD, Rtype::MF, Rtype::MB, Rtype::MG, Rtype::MR] {
        round_trip(t, b"\x01m\x00", "m.");
    }
    round_trip(Rtype::MX, b"\x00\x0a\x04mail\x00", "10 mail.");
    round_trip(Rtype::MINFO, b"\x01a\x00\x01b\x00", "a. b.");
    round_trip(
        Rtype::SOA,
        b"\x02ns\x00\x04host\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00\x05",
        "ns. host. 1 2 3 4 5",
    );
    round_trip(Rtype::TXT, b"\x05hello\x00\x02\"\\", r#""hello" "" "\"\\""#);
    round_trip(Rtype::HINFO, b"\x03x86\x05Linux", r#""x86" "Linux""#);
    round_trip(Rtype::NULL, b"\x01\x02", "\\# 2 0102");
    round_trip(Rtype::NULL, b"", "\\# 0");
    round_trip(
        Rtype::WKS,
        &[10, 0, 0, 1, 6, 0x00, 0x00, 0x00, 0x40, 0x04],
        "10.0.0.1 6 25 37",
    );
}

#[test]
fn malformed_rdata() {
    // Wrong fixed lengths.
    assert_eq!(
        parse(Rtype::A, Class::IN, &[1, 2, 3]),
        Err(Error::UnexpectedEof)
    );
    assert_eq!(
        parse(Rtype::A, Class::IN, &[1, 2, 3, 4, 5]),
        Err(Error::TrailingData)
    );
    assert_eq!(
        parse(Rtype::NS, Class::IN, b"\x01a\x00\x00"),
        Err(Error::TrailingData)
    );
    // TXT needs at least one string, and complete ones.
    assert_eq!(parse(Rtype::TXT, Class::IN, b""), Err(Error::InvalidRdata));
    assert_eq!(
        parse(Rtype::TXT, Class::IN, b"\x05abc"),
        Err(Error::UnexpectedEof)
    );
    assert_eq!(Txt::from_wire(b""), Err(Error::InvalidRdata));
    assert_eq!(
        parse(Rtype::HINFO, Class::IN, b"\x01a"),
        Err(Error::UnexpectedEof)
    );
    // Standalone RDATA cannot contain pointers to anything.
    assert_eq!(
        parse(Rtype::NS, Class::IN, b"\xc0\x00"),
        Err(Error::BadPointer)
    );
}

#[test]
fn class_handling() {
    // A is class-specific: in CH it stays opaque (RFC 3597 §4).
    let d = parse(Rtype::A, Class::CH, b"\x01a\x00\x00\x01").unwrap();
    assert_eq!(
        d,
        RData::Unknown(UnknownRdata::new(Rtype::A, b"\x01a\x00\x00\x01"))
    );
    assert_eq!(d.to_string(), "\\# 5 0161000001");
    // NS is class-independent.
    assert!(matches!(
        parse(Rtype::NS, Class::CH, b"\x00").unwrap(),
        RData::Ns(_)
    ));
    // Update forms: empty RDATA in NONE / ANY.
    for class in [Class::NONE, Class::ANY] {
        let d = parse(Rtype::MX, class, b"").unwrap();
        assert_eq!(d, RData::Unknown(UnknownRdata::new(Rtype::MX, b"")));
        assert_eq!(d.rtype(), Rtype::MX);
        // ...but zone-class RDATA in NONE is typed (RFC 2136 §2.5.4).
        assert!(matches!(
            parse(Rtype::A, class, &[1, 2, 3, 4]).unwrap(),
            RData::A(_)
        ));
    }
    // Empty RDATA in class IN is an error for typed types.
    assert_eq!(parse(Rtype::MX, Class::IN, b""), Err(Error::UnexpectedEof));
}

#[test]
fn unknown_types() {
    let t = Rtype::new(65280);
    assert!(!RData::is_known(t));
    assert!(RData::is_known(Rtype::SOA));
    let d = parse(t, Class::IN, &[0xde, 0xad]).unwrap();
    assert_eq!(d.to_string(), "\\# 2 DEAD");
    assert_eq!(d.rtype(), t);
    assert_eq!(compose(&d), [0xde, 0xad]);
    let RData::Unknown(u) = d else { panic!() };
    assert_eq!((u.rtype(), u.data()), (t, &[0xde, 0xad][..]));
}

#[test]
fn compressed_names_in_rdata() {
    // A message where the MX exchange is "mail" + pointer to the qname.
    let msg = b"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\
                \x07example\x03com\x00\x00\x0f\x00\x01\
                \xc0\x0c\x00\x0f\x00\x01\x00\x00\x0e\x10\x00\x09\x00\x0a\x04mail\xc0\x0c";
    let mut r = WireReader::new(msg);
    r.skip(29).unwrap();
    let rr = Record::parse(&mut r).unwrap();
    let mx: Mx<'_> = rr.data_as().unwrap();
    assert_eq!(mx.preference, 10);
    assert_eq!(mx.exchange.to_string(), "mail.example.com.");
    assert_eq!(rr.data_as::<Ns<'_>>(), Err(Error::WrongType));
    // Re-composed without a compressing writer, the name is expanded.
    assert_eq!(compose(&mx), b"\x00\x0a\x04mail\x07example\x03com\x00");
}

#[test]
fn canonical_form() {
    let n: NameBuf = "NS.Example.".parse().unwrap();
    let soa = Soa {
        mname: n.as_name(),
        rname: n.as_name(),
        serial: 1,
        refresh: 2,
        retry: 3,
        expire: 4,
        minimum: 5,
    };
    let mut buf = [0u8; 128];
    let mut w = WireWriter::new(&mut buf);
    soa.compose_rdata(&mut Canonical::new(&mut w)).unwrap();
    assert!(
        w.as_bytes()
            .starts_with(b"\x02ns\x07example\x00\x02ns\x07example\x00")
    );
}

#[test]
fn txt_parts() {
    assert_eq!(compose(&TxtParts(&[b"a", b""])), b"\x01a\x00");
    let mut buf = [0u8; 600];
    let mut w = WireWriter::new(&mut buf);
    assert_eq!(
        TxtParts(&[&[0u8; 256]]).compose_rdata(&mut w),
        Err(Error::CharStringTooLong)
    );
    assert_eq!(
        TxtParts(&[]).compose_rdata(&mut w),
        Err(Error::InvalidRdata)
    );
    assert_eq!(TxtParts(&[]).rtype(), Rtype::TXT);
    let txt = Txt::from_wire(b"\x01a\x01b").unwrap();
    let strings: Vec<_> = txt.strings().map(|s| s.as_bytes()).collect();
    assert_eq!(strings, [b"a", b"b"]);
    assert_eq!(txt.as_wire(), b"\x01a\x01b");
}

#[test]
fn type_bitmaps() {
    // RFC 4034 §4.3 example: A MX RRSIG NSEC TYPE1234.
    let mut wire = b"\x00\x06\x40\x01\x00\x00\x00\x03\x04\x1b".to_vec();
    wire.extend_from_slice(&[0; 26]);
    wire.push(0x20);
    let wire = &wire[..];
    let bm = TypeBitmap::new(wire).unwrap();
    let types: Vec<Rtype> = bm.iter().collect();
    assert_eq!(
        types,
        [
            Rtype::A,
            Rtype::MX,
            Rtype::RRSIG,
            Rtype::NSEC,
            Rtype::new(1234)
        ]
    );
    assert_eq!(bm.to_string(), "A MX RRSIG NSEC TYPE1234");
    assert!(bm.contains(Rtype::new(1234)) && !bm.contains(Rtype::new(1235)));
    assert!(!bm.contains(Rtype::new(0xff00)));
    let mut buf = [0u8; 128];
    let mut w = WireWriter::new(&mut buf);
    TypeBitmap::compose(&types, &mut w).unwrap();
    assert_eq!(w.as_bytes(), wire);
    assert_eq!(std::format!("{bm:?}"), "[A, MX, RRSIG, NSEC, TYPE1234]");

    let empty = TypeBitmap::new(b"").unwrap();
    assert!(empty.is_empty() && empty.to_string().is_empty());
    let mut r = WireReader::new(wire);
    assert_eq!(TypeBitmap::parse(&mut r).unwrap(), bm);
    assert!(r.is_empty());

    for bad in [
        &b"\x00"[..],                // truncated header
        b"\x00\x00",                 // zero length
        b"\x00\x21",                 // length > 32
        b"\x00\x02\x40",             // truncated bitmap
        b"\x01\x01\x40\x00\x01\x40", // windows out of order
        b"\x01\x01\x40\x01\x01\x40", // duplicate window
    ] {
        assert_eq!(TypeBitmap::new(bad), Err(Error::InvalidRdata), "{bad:?}");
    }
}

#[test]
fn wks_ports() {
    let w = Wks {
        address: [1, 2, 3, 4].into(),
        protocol: 17,
        bitmap: &[0x80, 0, 0x01],
    };
    let ports: Vec<u16> = w.ports().collect();
    assert_eq!(ports, [0, 23]);
}

/// The single-name macro can be reused from another module, as a new
/// record-type file would (e.g. DNAME, with an uncompressed name).
mod reuse {
    crate::rdata::single_name::single_name_rdata! {
        /// Test-only DNAME-like type.
        Dn, DNAME, target, Lowercase, read_name_uncompressed
    }
}

#[test]
fn single_name_macro_is_reusable() {
    let mut r = WireReader::new(b"\x01X\x00");
    let d = reuse::Dn::parse_rdata(&mut r).unwrap();
    assert_eq!(d.to_string(), "X.");
    assert_eq!(d.rtype(), Rtype::DNAME);
    assert_eq!(d, reuse::Dn::new(d.target));
    let mut buf = [0u8; 16];
    let mut w = WireWriter::new(&mut buf);
    d.compose_rdata(&mut Canonical::new(&mut w)).unwrap();
    assert_eq!(w.as_bytes(), b"\x01x\x00");
    let mut r = WireReader::new(b"\xc0\x00");
    assert_eq!(
        reuse::Dn::parse_rdata(&mut r),
        Err(Error::UnexpectedPointer)
    );
}

// ---------------------------------------------------------------------------
// Presentation-format parsing helpers (`ParseRdataText`).
// ---------------------------------------------------------------------------

/// The origin relative names are completed with by [`text_parse`].
pub(crate) const TEXT_ORIGIN: &str = "example.";

/// Parses presentation-format `text` as `rtype` RDATA (class IN, relative
/// names completed with [`TEXT_ORIGIN`]) and returns the wire form. Checks
/// that a failed parse leaves the output buffer untouched.
pub(crate) fn text_parse(rtype: Rtype, text: &str) -> Result<Vec<u8>> {
    let origin: NameBuf = TEXT_ORIGIN.parse().unwrap();
    let mut s = Scanner::new(text).with_origin(origin.as_name());
    let mut buf = std::vec![0u8; 6 + 65536];
    let mut out = WireWriter::new(&mut buf);
    out.put_bytes(b"prefix").unwrap();
    let res = RData::parse_text(rtype, Class::IN, &mut s, &mut out);
    let out = out.as_bytes();
    match res {
        Ok(()) => {
            assert!(out.starts_with(b"prefix"), "{rtype} {text:?}");
            Ok(out[6..].to_vec())
        }
        Err(e) => {
            assert_eq!(out, b"prefix", "{rtype} {text:?}: output not rolled back");
            Err(e)
        }
    }
}

/// Checks the presentation-format round trip of one RDATA: `text` parses
/// to `wire`; `wire` passes [`round_trip`] (displays as `display`,
/// re-composes, survives truncation); `display` and the RFC 3597 generic
/// form parse back to `wire`; and no prefix of `text` makes the parser
/// panic.
pub(crate) fn text_round_trip(rtype: Rtype, text: &str, wire: &[u8], display: &str) {
    assert_eq!(
        text_parse(rtype, text).as_deref(),
        Ok(wire),
        "{rtype} {text:?}"
    );
    round_trip(rtype, wire, display);
    assert_eq!(
        text_parse(rtype, display).as_deref(),
        Ok(wire),
        "{rtype}: display {display:?} does not parse back"
    );
    let mut generic = String::new();
    crate::text::fmt_generic_rdata(&mut generic, wire).unwrap();
    assert_eq!(
        text_parse(rtype, &generic).as_deref(),
        Ok(wire),
        "{generic}"
    );
    for (i, _) in text.char_indices() {
        let _ = text_parse(rtype, &text[..i]);
    }
}

/// Asserts that `text` is rejected as `rtype` RDATA and returns the error.
pub(crate) fn text_error(rtype: Rtype, text: &str) -> Error {
    match text_parse(rtype, text) {
        Ok(wire) => panic!("{rtype} {text:?} parsed as {wire:02x?}"),
        Err(e) => e,
    }
}
