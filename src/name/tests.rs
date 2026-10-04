use super::*;
use crate::WireReader;
use std::string::ToString;
use std::vec::Vec;

/// The RFC 1035 §4.1.4 example: F.ISI.ARPA at 20, FOO.F.ISI.ARPA at 40
/// (pointer to 20), ARPA at 64 (pointer to 26), root at 92.
fn rfc1035_example() -> Vec<u8> {
    let mut m = std::vec![0u8; 20];
    m.extend_from_slice(b"\x01F\x03ISI\x04ARPA\x00"); // 20..32
    m.resize(40, 0);
    m.extend_from_slice(b"\x03FOO\xc0\x14"); // 40..46
    m.resize(64, 0);
    m.extend_from_slice(b"\xc0\x1a"); // 64..66
    m.resize(92, 0);
    m.push(0); // 92
    m
}

fn read_at(msg: &[u8], pos: usize) -> Result<(Name<'_>, usize)> {
    Name::parse_bounded(msg, pos, msg.len(), true)
}

#[test]
fn rfc1035_compression_example() {
    let m = rfc1035_example();
    let (a, end) = read_at(&m, 20).unwrap();
    assert_eq!((a.to_string().as_str(), end), ("F.ISI.ARPA.", 32));
    assert!(a.as_contiguous().is_some());

    let (b, end) = read_at(&m, 40).unwrap();
    assert_eq!((b.to_string().as_str(), end), ("FOO.F.ISI.ARPA.", 46));
    assert_eq!((b.wire_len(), b.label_count()), (16, 4));
    assert!(b.as_contiguous().is_none());

    let (c, end) = read_at(&m, 64).unwrap();
    assert_eq!((c.to_string().as_str(), end), ("ARPA.", 66));
    // A leading pointer is resolved, so the view itself is contiguous.
    assert_eq!(c.as_contiguous(), Some(&b"\x04ARPA\x00"[..]));

    let (d, end) = read_at(&m, 92).unwrap();
    assert!(d.is_root());
    assert_eq!((d.to_string().as_str(), end), (".", 93));

    // Parents walk across the pointer.
    let p = b.parent().unwrap();
    assert_eq!(p.to_string(), "F.ISI.ARPA.");
    assert!(p.as_contiguous().is_some());
    assert_eq!(b.strip_labels(3).unwrap(), c);
    assert!(b.strip_labels(5).is_none());
    assert!(Name::ROOT.parent().is_none());

    assert!(b.is_subdomain_of(&a));
    assert!(b.is_subdomain_of(&b));
    assert!(b.is_subdomain_of(&Name::ROOT));
    assert!(!a.is_subdomain_of(&b));
    let isi: NameBuf = "isi.arpa".parse().unwrap();
    assert!(b.is_subdomain_of(&isi.as_name()));
    let other: NameBuf = "x.arpa".parse().unwrap();
    assert!(!b.is_subdomain_of(&other.as_name()));

    let mut flat = [0u8; MAX_NAME_LEN];
    let n = b.flatten(&mut flat);
    assert_eq!(&flat[..n], b"\x03FOO\x01F\x03ISI\x04ARPA\x00");
    assert_eq!(b.to_buf().as_wire(), &flat[..n]);
}

#[test]
fn pointer_hardening() {
    // Self pointer.
    let m = b"\xc0\x00";
    assert_eq!(read_at(m, 0).unwrap_err(), Error::BadPointer);
    // Forward pointer.
    let m = b"\xc0\x02\x00";
    assert_eq!(read_at(m, 0).unwrap_err(), Error::BadPointer);
    // Pointer back into the name's own labels (a loop).
    let m = b"\x01a\xc0\x00";
    assert_eq!(read_at(m, 0).unwrap_err(), Error::BadPointer);
    // Two-step loop: 4 -> 0 -> 2 (2 is not before the run starting at 0).
    let m = b"\x01a\xc0\x00\xc0\x00";
    assert_eq!(read_at(m, 4).unwrap_err(), Error::BadPointer);
    // Truncated pointer.
    assert_eq!(read_at(b"\x01a\xc0", 0).unwrap_err(), Error::UnexpectedEof);
    // Pointer outside the message.
    let m = b"\x00\xc0\x00";
    assert!(read_at(m, 1).is_ok());
    // Long chain of pointer -> pointer -> ... -> root.
    let mut m = std::vec![0u8];
    for i in 0..200usize {
        let target = if i == 0 { 0 } else { 1 + 2 * (i - 1) };
        m.extend_from_slice(&[0xc0 | (target >> 8) as u8, target as u8]);
    }
    let last = m.len() - 2;
    assert_eq!(read_at(&m, last).unwrap_err(), Error::TooManyPointers);
    let ok_at = 1 + 2 * (MAX_POINTERS - 1);
    assert!(read_at(&m, ok_at).unwrap().0.is_root());
    // Pointers are rejected where compression is forbidden.
    let m = rfc1035_example();
    let mut r = WireReader::with_range(&m, 40, 46).unwrap();
    assert_eq!(r.read_name_uncompressed(), Err(Error::UnexpectedPointer));
    assert_eq!(r.position(), 40);
    assert_eq!(r.read_name().unwrap().label_count(), 4);
    assert!(r.is_empty());
}

#[test]
fn label_and_length_limits() {
    // Extended (0b01) and reserved (0b10) label types.
    assert_eq!(read_at(b"\x41\x00", 0).unwrap_err(), Error::BadLabelType);
    assert_eq!(read_at(b"\x80\x00", 0).unwrap_err(), Error::BadLabelType);
    // A 63-octet label is fine.
    let mut m = std::vec![63u8];
    m.extend_from_slice(&[b'a'; 63]);
    m.push(0);
    assert_eq!(Name::from_wire(&m).unwrap().wire_len(), 65);
    // 255 octets is the maximum: 4 * 63-octet labels = 256 > 255.
    let mut m = Vec::new();
    for _ in 0..3 {
        m.push(63);
        m.extend_from_slice(&[b'a'; 63]);
    }
    m.push(61);
    m.extend_from_slice(&[b'a'; 61]);
    m.push(0);
    assert_eq!(m.len(), 255);
    assert_eq!(Name::from_wire(&m).unwrap().wire_len(), 255);
    let mut m2 = m.clone();
    m2.truncate(192);
    m2.push(62);
    m2.extend_from_slice(&[b'a'; 62]);
    m2.push(0);
    assert_eq!(m2.len(), 256);
    assert_eq!(Name::from_wire(&m2).unwrap_err(), Error::NameTooLong);
    // The limit applies to the decompressed length too.
    let mut m = std::vec![];
    m.push(63);
    m.extend_from_slice(&[b'b'; 63]);
    m.push(63);
    m.extend_from_slice(&[b'b'; 63]);
    m.push(0); // 0..129: 129-octet name
    m.push(63);
    m.extend_from_slice(&[b'c'; 63]);
    m.push(63);
    m.extend_from_slice(&[b'c'; 63]);
    m.extend_from_slice(&[0xc0, 0]); // 128 + 129 = 257 > 255
    assert_eq!(read_at(&m, 129).unwrap_err(), Error::NameTooLong);
    // Trailing data after an uncompressed name.
    assert_eq!(
        Name::from_wire(b"\x00\x00").unwrap_err(),
        Error::TrailingData
    );
    assert_eq!(Name::from_wire(b"").unwrap_err(), Error::UnexpectedEof);
}

#[test]
fn truncation_never_panics() {
    let m = rfc1035_example();
    for end in 0..m.len() {
        for start in 0..end {
            let _ = Name::parse_bounded(&m[..end], start, end, true);
        }
    }
    let wire = b"\x03www\x07example\x03com\x00";
    for end in 0..wire.len() {
        assert!(Name::from_wire(&wire[..end]).is_err());
    }
}

#[test]
fn presentation_round_trip() {
    for (text, wire, display) in [
        (".", &b"\x00"[..], "."),
        ("com", b"\x03com\x00", "com."),
        ("com.", b"\x03com\x00", "com."),
        ("a\\.b.c", b"\x03a.b\x01c\x00", "a\\.b.c."),
        ("\\065\\000z", b"\x03A\x00z\x00", "A\\000z."),
        ("sp\\ ace", b"\x06sp ace\x00", "sp\\032ace."),
        ("q\\\"\\\\", b"\x03q\"\\\x00", "q\\\"\\\\."),
        ("*.wild", b"\x01*\x04wild\x00", "*.wild."),
    ] {
        let n: NameBuf = text.parse().unwrap();
        assert_eq!(n.as_wire(), wire, "{text}");
        assert_eq!(n.to_string(), display, "{text}");
        let back: NameBuf = display.parse().unwrap();
        assert!(back.as_name().eq_exact(&n.as_name()), "{text}");
    }
    assert!("*.wild".parse::<NameBuf>().unwrap().as_name().is_wildcard());
}

#[test]
fn presentation_errors() {
    for (text, err) in [
        ("", Error::InvalidText),
        ("..", Error::EmptyLabel),
        (".com", Error::EmptyLabel),
        ("a..b", Error::EmptyLabel),
        ("a\\", Error::InvalidText),
        ("a\\25", Error::InvalidText),
        ("a\\2x5", Error::InvalidText),
        ("a\\256", Error::InvalidText),
    ] {
        assert_eq!(text.parse::<NameBuf>().unwrap_err(), err, "{text:?}");
    }
    let long_label = "a".repeat(64);
    assert_eq!(
        long_label.parse::<NameBuf>().unwrap_err(),
        Error::LabelTooLong
    );
    assert!("a".repeat(63).parse::<NameBuf>().is_ok());
    // 127 one-character labels = 254 octets + root = 255: the maximum.
    let max = "a.".repeat(127);
    assert_eq!(max.parse::<NameBuf>().unwrap().wire_len(), 255);
    assert_eq!(
        max[..max.len() - 1].parse::<NameBuf>().unwrap().wire_len(),
        255
    );
    let too_long = std::format!("{max}a");
    assert_eq!(too_long.parse::<NameBuf>().unwrap_err(), Error::NameTooLong);
    let too_long = std::format!("{max}a.");
    assert_eq!(too_long.parse::<NameBuf>().unwrap_err(), Error::NameTooLong);
    let too_long = std::format!("{}{}", "a".repeat(63), ".bcd".repeat(48));
    assert_eq!(too_long.parse::<NameBuf>().unwrap_err(), Error::NameTooLong);
}

#[test]
fn case_insensitive_eq_and_hash() {
    use std::hash::{BuildHasher, RandomState};
    let m = rfc1035_example();
    let (compressed, _) = read_at(&m, 40).unwrap();
    let flat: NameBuf = "foo.f.isi.arpa.".parse().unwrap();
    assert_eq!(compressed, flat.as_name());
    assert_eq!(flat, compressed);
    assert!(!compressed.eq_exact(&flat.as_name()));
    assert!(compressed.eq_exact(&"FOO.F.ISI.ARPA".parse::<NameBuf>().unwrap().as_name()));
    let s = RandomState::new();
    assert_eq!(s.hash_one(compressed), s.hash_one(flat.as_name()));
    assert_eq!(s.hash_one(&flat), s.hash_one(flat.as_name()));
    let other: NameBuf = "foo.f.isi.arpb.".parse().unwrap();
    assert_ne!(compressed, other.as_name());
    assert_ne!(flat, NameBuf::root());
}

#[test]
fn canonical_ordering_rfc4034() {
    // RFC 4034 §6.1 example, already in canonical order.
    let names = [
        "example",
        "a.example",
        "yljkjljk.a.example",
        "Z.a.example",
        "zABC.a.EXAMPLE",
        "z.example",
        "\\001.z.example",
        "*.z.example",
        "\\200.z.example",
    ];
    let bufs: Vec<NameBuf> = names.iter().map(|n| n.parse().unwrap()).collect();
    for (i, a) in bufs.iter().enumerate() {
        for (j, b) in bufs.iter().enumerate() {
            assert_eq!(a.cmp(b), i.cmp(&j), "{a} vs {b}");
            assert_eq!(a.as_name().cmp(&b.as_name()), i.cmp(&j));
        }
    }
    let mut shuffled = bufs.clone();
    shuffled.reverse();
    shuffled.sort();
    assert_eq!(shuffled, bufs);
    assert!(NameBuf::root() < bufs[0]);
}

#[test]
fn name_buf_editing() {
    let mut n: NameBuf = "Example.COM".parse().unwrap();
    n.make_ascii_lowercase();
    assert_eq!(n.as_wire(), b"\x07example\x03com\x00");
    n.prepend_label(b"*").unwrap();
    assert_eq!(n.to_string(), "*.example.com.");
    assert_eq!(n.label_count(), 3);
    assert_eq!(n.prepend_label(b""), Err(Error::EmptyLabel));
    assert_eq!(n.prepend_label(&[b'x'; 64]), Err(Error::LabelTooLong));
    let mut big: NameBuf = "a.".repeat(126).parse().unwrap();
    assert_eq!(big.wire_len(), 253);
    assert_eq!(big.prepend_label(b"bb"), Err(Error::NameTooLong));
    big.prepend_label(b"b").unwrap();
    assert_eq!(big.wire_len(), 255);

    assert_eq!(NameBuf::from_labels([&b""[..]]), Err(Error::EmptyLabel));
    assert_eq!(
        NameBuf::from_labels([&[0u8; 64][..]]),
        Err(Error::LabelTooLong)
    );
    assert_eq!(
        NameBuf::from_labels(core::iter::repeat_n(&b"ab"[..], 85)),
        Err(Error::NameTooLong)
    );
    assert!(NameBuf::from_labels(core::iter::empty()).unwrap().is_root());
    assert!(NameBuf::default().is_root());
    assert_eq!(NameBuf::from_wire(b"\x01a\x00").unwrap().to_string(), "a.");
    assert_eq!(std::format!("{:?}", NameBuf::root()), "NameBuf(.)");
    assert_eq!(std::format!("{:?}", Name::ROOT), "Name(.)");
    let labels: Vec<_> = n.as_name().labels().map(|l| l.to_string()).collect();
    assert_eq!(labels, ["*", "example", "com"]);
    assert_eq!(n.as_name().labels().len(), 3);
}
