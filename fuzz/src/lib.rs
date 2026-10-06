//! Property checks shared by the fuzz targets and by the regression tests
//! in `tests/fuzz_regressions.rs` (which include this file with `#[path]`).
//!
//! Every check takes arbitrary bytes and must never panic except through
//! one of its own `assert!`s, which state a property of the crate:
//!
//! - [`message`]: whole-message parsing, lazy iteration, validation and
//!   parse → build → parse identity (RFC 1035 §4.1);
//! - [`name`]: name decompression and the `Name` / `NameBuf` invariants
//!   (RFC 1035 §4.1.4, RFC 4034 §6.1, RFC 4343);
//! - [`rdata`]: every record type through the generic `RData` dispatch,
//!   including types registered after this file was written;
//! - [`roundtrip`]: build → parse identity of builder-generated messages, plus
//!   atomic pushes and checkpoint rollback;
//! - [`text`]: presentation-format parsing (names, types, classes,
//!   SVCB/HTTPS RDATA, RFC 9460 Appendix A, and whole master files,
//!   RFC 1035 §5);
//! - [`edns`]: OPT RDATA framing and every typed EDNS(0) option
//!   (RFC 6891 §6.1.2), including options registered after this file was
//!   written.
//!
//! [`message`] also runs the protocol views over each parsed message:
//! EDNS, TSIG and SIG(0) placement, UPDATE classification, NOTIFY,
//! AXFR/IXFR processing and DSO.
//!
//! The trust decisions (denial proofs, chain of trust, TSIG and SIG(0),
//! zone files with includes and ZONEMD) are checked in [`security`].
//!
//! Only the `&mut [u8]` builder is used, so the checks also run against a
//! crate built without the `alloc` feature; the owned-type checks
//! ([`check_owned`]) are compiled only with `alloc`.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::string::{String, ToString};
use std::sync::OnceLock;
use std::vec::Vec;

#[path = "security.rs"]
pub mod security;

use dnsbox::edns::{ComposeOption, EdnsOption, Opt};
use dnsbox::rdata::{Https, Svcb};
use dnsbox::wire::Canonical;
use dnsbox::{
    Class, ComposeRdata, Error, Flags, Header, Message, MessageBuilder, Name, NameBuf, RData,
    Rtype, Section, WireReader, WireWriter,
};

/// Largest DNS message (RFC 1035 §4.2.2: 16-bit TCP length).
const MAX_MESSAGE: usize = 65535;

// ---------------------------------------------------------------------------
// Byte source for structured inputs.
// ---------------------------------------------------------------------------

/// Consumes fuzzer bytes as structured choices; returns zeros when empty so
/// every input decodes to *something*.
struct Bytes<'a>(&'a [u8]);

impl<'a> Bytes<'a> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn u8(&mut self) -> u8 {
        match self.0.split_first() {
            Some((&b, rest)) => {
                self.0 = rest;
                b
            }
            None => 0,
        }
    }

    fn u16(&mut self) -> u16 {
        u16::from_be_bytes([self.u8(), self.u8()])
    }

    fn u32(&mut self) -> u32 {
        u32::from_be_bytes([self.u8(), self.u8(), self.u8(), self.u8()])
    }

    fn bool(&mut self) -> bool {
        self.u8() & 1 == 1
    }

    fn take(&mut self, n: usize) -> &'a [u8] {
        let n = n.min(self.0.len());
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        head
    }
}

/// Every record type with a typed implementation, found through the
/// registry itself so newly registered types are fuzzed automatically.
fn known_types() -> &'static [Rtype] {
    static KNOWN: OnceLock<Vec<Rtype>> = OnceLock::new();
    KNOWN.get_or_init(|| {
        Rtype::all()
            .map(|(t, _)| t)
            .filter(|&t| RData::is_known(t))
            .collect()
    })
}

/// Picks a record type: mostly a registered one, sometimes any value.
fn pick_rtype(b: &mut Bytes<'_>, known: &[Rtype]) -> Rtype {
    let mode = b.u8();
    let v = b.u16();
    if mode & 1 == 0 && !known.is_empty() {
        known[v as usize % known.len()]
    } else {
        Rtype::new(v)
    }
}

/// Picks a class, favouring the ones with special dispatch rules.
fn pick_class(b: &mut Bytes<'_>) -> Class {
    match b.u8() % 6 {
        0 | 1 => Class::IN,
        2 => Class::NONE,
        3 => Class::ANY,
        4 => Class::CH,
        _ => Class::new(b.u16()),
    }
}

// ---------------------------------------------------------------------------
// Names.
// ---------------------------------------------------------------------------

fn hash_of<T: Hash + ?Sized>(v: &T) -> u64 {
    let mut h = DefaultHasher::new();
    v.hash(&mut h);
    h.finish()
}

/// Checks every invariant of a valid name view.
pub fn check_name(n: Name<'_>) {
    let len = n.wire_len();
    assert!((1..=255).contains(&len), "wire_len {len}");
    assert!(n.label_count() <= 127);
    assert_eq!(n.is_root(), n.label_count() == 0);

    // Labels add up to the wire length.
    let mut sum = 1;
    let mut count = 0;
    for l in n.labels() {
        assert!((1..=63).contains(&l.len()));
        sum += 1 + l.len();
        count += 1;
    }
    assert_eq!(sum, len);
    assert_eq!(count, n.label_count());
    assert_eq!(n.labels().len(), n.label_count());
    assert_eq!(n.first_label().is_none(), n.is_root());

    // Flattening gives a valid uncompressed name equal to this one.
    let mut flat = [0u8; 255];
    let flen = n.flatten(&mut flat);
    assert_eq!(flen, len);
    let flat = &flat[..flen];
    let back = Name::from_wire(flat).expect("flattened name must parse");
    assert!(back.eq_exact(&n) && n.eq_exact(&back));
    assert_eq!(back.label_count(), n.label_count());
    if let Some(c) = n.as_contiguous() {
        assert_eq!(c, flat);
    }
    let buf = n.to_buf();
    assert_eq!(buf.as_wire(), flat);
    assert!(buf.as_name().eq_exact(&n));

    // Equality, ordering and hashing agree, case-insensitively (RFC 4343).
    let copy = n;
    assert_eq!(n, copy);
    assert_eq!(n.cmp(&n), core::cmp::Ordering::Equal);
    let mut lower = buf.clone();
    lower.make_ascii_lowercase();
    assert_eq!(lower.as_name(), n);
    assert_eq!(lower.as_name().cmp(&n), core::cmp::Ordering::Equal);
    assert_eq!(hash_of(&lower.as_name()), hash_of(&n));
    assert_eq!(hash_of(&buf), hash_of(&n));

    // Presentation format round-trips exactly (RFC 1035 §5.1 escapes).
    let text = n.to_string();
    let parsed: NameBuf = text
        .parse()
        .unwrap_or_else(|e| panic!("display {text:?} does not parse: {e}"));
    assert!(parsed.as_name().eq_exact(&n), "{text:?}");

    // Walking up the tree ends at the root after label_count steps.
    let mut cur = n;
    let mut steps = 0;
    while let Some(p) = cur.parent() {
        assert_eq!(p.label_count() + 1, cur.label_count());
        let first = cur.first_label().expect("non-root has a first label");
        assert_eq!(p.wire_len() + 1 + first.len(), cur.wire_len());
        assert!(cur.is_subdomain_of(&p));
        assert!(n.is_subdomain_of(&p));
        assert!(p.cmp(&n) != core::cmp::Ordering::Greater || n.is_root());
        let mut pf = [0u8; 255];
        let pl = p.flatten(&mut pf);
        assert_eq!(&pf[..pl], &flat[flat.len() - pl..]);
        cur = p;
        steps += 1;
        assert!(steps <= 127);
    }
    assert!(cur.is_root());
    assert_eq!(steps, n.label_count());
    assert!(n.strip_labels(n.label_count()).is_some_and(|r| r.is_root()));
    assert!(n.strip_labels(n.label_count() + 1).is_none());
    assert!(n.is_subdomain_of(&Name::ROOT));
}

/// Checks that two names compare consistently.
pub fn check_name_pair(a: Name<'_>, b: Name<'_>) {
    use core::cmp::Ordering;
    let ab = a.cmp(&b);
    assert_eq!(ab, b.cmp(&a).reverse());
    assert_eq!(ab == Ordering::Equal, a == b);
    assert_eq!(a == b, a.to_buf() == b.to_buf());
    if a == b {
        assert_eq!(hash_of(&a), hash_of(&b));
    }
    if a.eq_exact(&b) {
        assert!(a == b);
    }
    // Canonical order puts a domain before its descendants (RFC 4034 §6.1).
    if a.is_subdomain_of(&b) && a != b {
        assert_eq!(ab, Ordering::Greater);
    }
}

/// Reference name decoder (differential oracle), written from the rules in
/// `ARCHITECTURE.md` rather than from the crate's code: labels of 1–63
/// octets, label types `0b01`/`0b10` rejected, at most 255 octets in all,
/// every pointer strictly before the start of the run of labels it ends, at
/// most 128 pointers. Returns the flattened name and the offset after its
/// in-place encoding.
fn reference_name(msg: &[u8], start: usize, allow_pointers: bool) -> Option<(Vec<u8>, usize)> {
    let mut out = Vec::new();
    let mut pos = start;
    let mut run_start = start;
    let mut after: Option<usize> = None;
    let mut hops = 0;
    loop {
        let len = *msg.get(pos)? as usize;
        match len {
            0 => {
                out.push(0);
                return Some((out, after.unwrap_or(pos + 1)));
            }
            1..=63 => {
                let label = msg.get(pos + 1..pos + 1 + len)?;
                if out.len() + 1 + len >= 255 {
                    return None;
                }
                out.push(len as u8);
                out.extend_from_slice(label);
                pos += 1 + len;
            }
            0xc0..=0xff if allow_pointers => {
                let target = ((len & 0x3f) << 8) | *msg.get(pos + 1)? as usize;
                after.get_or_insert(pos + 2);
                hops += 1;
                if target >= run_start || hops > 128 {
                    return None;
                }
                pos = target;
                run_start = target;
            }
            _ => return None,
        }
    }
}

/// Reference presentation-format name parser (differential oracle) for
/// the documented syntax: `.` is the root, otherwise dot-separated
/// non-empty labels with an optional trailing dot, `\DDD` (three digits,
/// at most 255) and `\X` escapes; labels ≤ 63 and names ≤ 255 octets.
fn reference_text_name(text: &[u8]) -> Option<Vec<u8>> {
    if text == b"." {
        return Some(std::vec![0]);
    }
    if text.is_empty() {
        return None;
    }
    let mut labels: Vec<Vec<u8>> = std::vec![Vec::new()];
    let mut i = 0;
    while let Some(&c) = text.get(i) {
        i += 1;
        let byte = match c {
            b'.' => {
                if labels.last()?.is_empty() {
                    return None;
                }
                labels.push(Vec::new());
                continue;
            }
            b'\\' => match text.get(i) {
                None => return None,
                Some(d) if d.is_ascii_digit() => {
                    let digits = text.get(i..i + 3)?;
                    if !digits.iter().all(u8::is_ascii_digit) {
                        return None;
                    }
                    let v = digits
                        .iter()
                        .fold(0u32, |a, d| a * 10 + u32::from(d - b'0'));
                    i += 3;
                    u8::try_from(v).ok()?
                }
                Some(&x) => {
                    i += 1;
                    x
                }
            },
            c => c,
        };
        labels.last_mut()?.push(byte);
    }
    if labels.last()?.is_empty() {
        labels.pop();
    }
    let mut out = Vec::new();
    for l in &labels {
        if l.len() > 63 {
            return None;
        }
        out.push(l.len() as u8);
        out.extend_from_slice(l);
    }
    out.push(0);
    (out.len() <= 255).then_some(out)
}

/// Name decompression: `[offset: u16][flags: u8][message...]`. Reads a
/// name at `offset` of the message (pointers may target anything before
/// it), and a second one right after it, then checks both.
pub fn name(data: &[u8]) {
    let mut b = Bytes(data);
    let off = b.u16() as usize;
    let flags = b.u8();
    let msg = b.0;
    let off = if msg.is_empty() { 0 } else { off % msg.len() };

    // Standalone uncompressed forms.
    if let Ok(n) = Name::from_wire(msg) {
        check_name(n);
        assert_eq!(n.wire_len(), msg.len());
        let buf = NameBuf::from_wire(msg).expect("from_wire agrees");
        assert!(buf.as_name().eq_exact(&n));
    }

    let Ok(mut r) = WireReader::with_range(msg, off, msg.len()) else {
        return;
    };
    let read = if flags & 1 == 0 {
        r.read_name()
    } else {
        r.read_name_uncompressed()
    };
    // The decoder agrees with the reference on acceptance, content and
    // extent.
    let reference = reference_name(msg, off, flags & 1 == 0);
    match (&read, &reference) {
        (Ok(n), Some((flat, end))) => {
            let mut buf = [0u8; 255];
            let len = n.flatten(&mut buf);
            assert_eq!(&buf[..len], &flat[..], "decoded name differs");
            assert_eq!(r.position(), *end, "name extent differs");
        }
        (Err(_), None) => {}
        (Ok(n), None) => panic!("accepted {n}, which the reference rejects"),
        (Err(e), Some(_)) => panic!("rejected ({e}) a name the reference accepts"),
    }
    match read {
        Ok(n) => {
            check_name(n);
            assert!(r.position() > off && r.position() <= msg.len());
            if flags & 1 == 1 {
                // Uncompressed names are stored in place.
                assert_eq!(r.position() - off, n.wire_len());
                assert_eq!(n.as_contiguous(), msg.get(off..r.position()));
            }
            let second = r.read_name();
            if let Ok(m) = second {
                check_name(m);
                check_name_pair(n, m);
                check_name_pair(m, n);
            }
        }
        Err(e) => {
            // A failed read never moves the cursor.
            assert_eq!(r.position(), off, "{e}");
            assert!(!matches!(e, Error::BufferTooSmall));
        }
    }
}

// ---------------------------------------------------------------------------
// Record data.
// ---------------------------------------------------------------------------

/// Composes `d` with a plain (non-compressing) writer, or canonically.
/// Names may expand when decompressed, so a large buffer is the fallback.
fn compose_plain<D: ComposeRdata + ?Sized>(
    d: &D,
    canonical: bool,
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    for size in [4096, 4 * MAX_MESSAGE] {
        let mut buf = std::vec![0u8; size];
        let mut w = WireWriter::new(&mut buf);
        let res = if canonical {
            d.compose_rdata(&mut Canonical::new(&mut w))
        } else {
            d.compose_rdata(&mut w)
        };
        match res {
            Err(Error::BufferTooSmall) if size < 4 * MAX_MESSAGE => continue,
            Err(e) => return Err(e),
            Ok(()) => {
                out.clear();
                out.extend_from_slice(w.as_bytes());
                return Ok(());
            }
        }
    }
    Err(Error::BufferTooSmall)
}

/// Checks a successfully parsed RDATA: presentation format, re-composing,
/// re-parsing the composed form, canonical form, and embedding in a
/// message built by the builder.
pub fn check_rdata(rtype: Rtype, class: Class, d: &RData<'_>) {
    assert_eq!(d.rtype(), rtype);
    let text = d.to_string();
    check_text_round_trip(rtype, class, &text);

    // Plain composition is valid standalone RDATA equal to the original.
    let mut wire = Vec::new();
    compose_plain(d, false, &mut wire).unwrap_or_else(|e| panic!("{rtype}: compose failed: {e}"));
    let again = RData::parse(rtype, class, WireReader::new(&wire))
        .unwrap_or_else(|e| panic!("{rtype} {text}: re-parse of composed form failed: {e}"));
    assert_eq!(&again, d, "{rtype}");
    assert_eq!(again.to_string(), text, "{rtype}");
    let mut wire2 = Vec::new();
    compose_plain(&again, false, &mut wire2).expect("second compose");
    assert_eq!(wire, wire2, "{rtype}: composing is not deterministic");

    // Canonical form (RFC 4034 §6.2) is valid RDATA of the same type that
    // is its own canonical form.
    let mut canon = Vec::new();
    compose_plain(d, true, &mut canon)
        .unwrap_or_else(|e| panic!("{rtype}: canonical compose failed: {e}"));
    assert_eq!(
        canon.len(),
        wire.len(),
        "{rtype}: canonical form changes length"
    );
    let c = RData::parse(rtype, class, WireReader::new(&canon))
        .unwrap_or_else(|e| panic!("{rtype}: canonical form does not parse: {e}"));
    assert_eq!(&c, d, "{rtype}: canonical form differs beyond case");
    let mut canon2 = Vec::new();
    compose_plain(&c, true, &mut canon2).expect("canonical compose");
    assert_eq!(canon2, canon, "{rtype}: canonical form not idempotent");

    // Inside a message, with compression, it comes back identical. The
    // compressed form is never longer than the plain one.
    let size = wire.len() + 512;
    if size > MAX_MESSAGE {
        return;
    }
    let mut mbuf = std::vec![0u8; size];
    let Ok(mut b) = MessageBuilder::new(&mut mbuf) else {
        unreachable!()
    };
    let owner: NameBuf = "owner.example".parse().expect("static name");
    let _ = b.push_question(&owner, rtype, class);
    match b.push_answer(&owner, class, 3600, d) {
        Ok(()) => {}
        // RDATA longer than 65535 bytes once names are expanded cannot be
        // encoded; anything else is a bug.
        Err(Error::BufferTooSmall) => return,
        Err(e) => panic!("{rtype}: push failed: {e}"),
    }
    let out = b.finish();
    let msg = Message::parse_validated(out)
        .unwrap_or_else(|e| panic!("{rtype} {text}: built message invalid: {e}"));
    let rr = msg
        .answers()
        .next()
        .expect("one answer")
        .expect("valid answer");
    let back = rr.data().expect("validated");
    assert_eq!(&back, d, "{rtype}");
    assert_eq!(back.to_string(), text, "{rtype}");
}

/// One wire form per value: RDATA without compression pointers (no octet
/// of 0xc0 or above, so certainly none) re-encodes to exactly the octets it
/// was parsed from. DNSSEC signs the re-encoded form of parsed records
/// (`RecordRdata`), so two encodings of one value would let a signature
/// over one authenticate the other.
fn check_wire_identity(d: &RData<'_>, raw: &[u8]) {
    if raw.iter().any(|&b| b >= 0xc0) {
        return;
    }
    let mut wire = Vec::new();
    compose_plain(d, false, &mut wire).expect("composed before");
    assert_eq!(wire, raw, "{}: parsing is not injective", d.rtype());
}

/// Every record type through the generic dispatch:
/// `[type choice: 3][class choice: 1-3][prefix: u8][message...]`. The
/// RDATA is the message after `prefix` bytes, so compression pointers in it
/// can target the prefix.
pub fn rdata(data: &[u8]) {
    let known = known_types();
    let mut b = Bytes(data);
    let rtype = pick_rtype(&mut b, known);
    let class = pick_class(&mut b);
    let prefix = b.u8() as usize;
    let msg = b.0;
    let prefix = prefix.min(msg.len());
    let r = WireReader::with_range(msg, prefix, msg.len()).expect("in range");
    match RData::parse(rtype, class, r) {
        Ok(d) => {
            if RData::is_known(rtype) && !matches!(d, RData::Unknown(_)) {
                // Typed data must also come out of the typed entry point.
                assert_eq!(d.rtype(), rtype);
            }
            check_rdata(rtype, class, &d);
            check_wire_identity(&d, msg.get(prefix..).unwrap_or(&[]));
        }
        Err(e) => {
            // Unknown types never fail: their RDATA is opaque (RFC 3597).
            assert!(RData::is_known(rtype), "{rtype}: {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// Messages.
// ---------------------------------------------------------------------------

/// Re-encodes a parsed message through the builder (`copy_question` /
/// `copy_record`). Returns the output length, or `None` if it does not fit.
fn rebuild(msg: &Message<'_>, buf: &mut [u8], compress: bool) -> Option<usize> {
    let mut b = MessageBuilder::new(buf).expect("buffer holds a header");
    b.set_id(msg.id());
    b.set_flags(msg.flags());
    b.set_compression(compress);
    for q in msg.questions() {
        match b.copy_question(&q.expect("validated")) {
            Ok(()) => {}
            Err(Error::BufferTooSmall) => return None,
            Err(e) => panic!("copy_question: {e}"),
        }
    }
    for rr in msg.records() {
        let (s, rr) = rr.expect("validated");
        match b.copy_record(s, &rr) {
            Ok(()) => {}
            // Decompressed names can make a message outgrow 65535 bytes.
            Err(Error::BufferTooSmall) => return None,
            Err(e) => panic!("copy_record: {e}"),
        }
    }
    Some(b.finish().len())
}

/// Asserts that two valid messages carry the same content: header, and
/// every question and record, with names compared case-sensitively.
pub fn assert_same_message(a: &Message<'_>, b: &Message<'_>) {
    assert_eq!(a.header(), b.header());
    let qa: Vec<_> = a.questions().map(|q| q.expect("valid")).collect();
    let qb: Vec<_> = b.questions().map(|q| q.expect("valid")).collect();
    assert_eq!(qa.len(), qb.len());
    for (x, y) in qa.iter().zip(&qb) {
        assert!(x.name().eq_exact(&y.name()), "{} vs {}", x.name(), y.name());
        assert_eq!((x.qtype(), x.qclass()), (y.qtype(), y.qclass()));
    }
    let ra: Vec<_> = a.records().map(|r| r.expect("valid")).collect();
    let rb: Vec<_> = b.records().map(|r| r.expect("valid")).collect();
    assert_eq!(ra.len(), rb.len());
    for ((sx, x), (sy, y)) in ra.iter().zip(&rb) {
        assert_eq!(sx, sy);
        assert!(x.name().eq_exact(&y.name()), "{} vs {}", x.name(), y.name());
        assert_eq!(
            (x.rtype(), x.class(), x.ttl()),
            (y.rtype(), y.class(), y.ttl())
        );
        let (dx, dy) = (x.data().expect("valid"), y.data().expect("valid"));
        assert_eq!(dx, dy);
        assert_eq!(dx.to_string(), dy.to_string());
        assert_eq!(x.to_string(), y.to_string());
    }
}

/// The owned copy of a validated message (feature `alloc`): it displays
/// like the view (`shown`), re-encodes to a valid message that copies back
/// to the same value, and its record data re-encodes to itself.
#[cfg(feature = "alloc")]
pub fn check_owned(msg: &Message<'_>, shown: &str) {
    let owned = dnsbox::OwnedMessage::from_message(msg)
        .unwrap_or_else(|e| panic!("validated message does not copy: {e}"));
    assert_eq!(owned.header(), Ok(msg.header()));
    assert_eq!(owned.to_string(), shown);
    for (_, rr) in owned.records() {
        let _ = rr.to_string();
        assert_eq!(
            dnsbox::OwnedRData::new(&rr.rdata).as_ref(),
            Ok(&rr.rdata),
            "{rr}"
        );
    }
    match owned.to_vec() {
        Ok(wire) => {
            let again = dnsbox::OwnedMessage::from_wire(&wire)
                .unwrap_or_else(|e| panic!("re-encoded owned message invalid: {e}"));
            assert_eq!(again, owned);
        }
        // Recompression may need more room than the original used.
        Err(e) => assert_eq!(e, Error::BufferTooSmall),
    }
}

/// Parse → build → parse identity for a validated message, with and
/// without compression; re-building the rebuilt message is a fixed point.
pub fn check_reencode(msg: &Message<'_>) {
    for compress in [true, false] {
        let mut buf = std::vec![0u8; MAX_MESSAGE];
        let Some(len) = rebuild(msg, &mut buf, compress) else {
            continue;
        };
        let out = &buf[..len];
        let m2 = Message::parse_validated(out)
            .unwrap_or_else(|e| panic!("rebuilt message invalid: {e}"));
        assert_same_message(msg, &m2);
        let mut buf2 = std::vec![0u8; MAX_MESSAGE];
        let len2 = rebuild(&m2, &mut buf2, compress).expect("fits again");
        assert_eq!(out, &buf2[..len2], "rebuild is not a fixed point");
    }
}

/// Whole-message parsing: header, every lazy iterator, typed RDATA of
/// every record, validation, then parse → build → parse identity.
pub fn message(data: &[u8]) {
    let msg = match Message::parse(data) {
        Ok(m) => m,
        Err(e) => {
            assert!(data.len() < Header::LEN, "{e}");
            return;
        }
    };
    let h = msg.header();
    assert_eq!(msg.as_bytes(), data);
    check_protocol_views(&msg, data);

    // Questions: at most QDCOUNT items, an error ends the iteration.
    let mut q_ok = 0usize;
    let mut q_err = false;
    let mut it = msg.questions();
    for q in it.by_ref() {
        match q {
            Ok(q) => {
                assert!(!q_err);
                q_ok += 1;
                let r = q.range();
                assert!(r.start >= Header::LEN && r.start < r.end && r.end <= data.len());
                check_name(q.name());
                let _ = q.to_string();
            }
            Err(_) => q_err = true,
        }
    }
    assert!(it.next().is_none(), "questions iterator is not fused");
    assert!(q_ok <= h.qdcount as usize);
    assert!(q_err || q_ok == h.qdcount as usize);

    // All records in one pass.
    let mut all = Vec::new();
    let mut all_err = false;
    let mut it = msg.records();
    for r in it.by_ref() {
        match r {
            Ok(x) => {
                assert!(!all_err);
                all.push(x);
            }
            Err(_) => all_err = true,
        }
    }
    assert!(it.next().is_none(), "records iterator is not fused");
    assert!(all.len() <= h.ancount as usize + h.nscount as usize + h.arcount as usize);
    let mut prev_section = Section::Answer;
    let mut prev_end = 0;
    let mut typed_ok = true;
    for (s, rr) in &all {
        assert!(*s >= prev_section && *s != Section::Question);
        prev_section = *s;
        assert!(rr.start() >= Header::LEN && rr.start() >= prev_end);
        assert!(rr.rdata_range().start > rr.start() && rr.end() <= data.len());
        assert_eq!(rr.rdata(), &data[rr.rdata_range()]);
        assert_eq!(rr.rdata_reader().remaining(), rr.rdata().len());
        prev_end = rr.end();
        check_name(rr.name());
        // The iterators decode owner names through a cache of suffixes
        // already seen; a fresh decode at the same offset agrees exactly.
        let mut fresh = WireReader::with_range(data, rr.start(), data.len()).expect("in range");
        let plain = dnsbox::Record::parse(&mut fresh).expect("decodes without the cache too");
        assert!(
            plain.name().eq_exact(&rr.name()),
            "cached owner name differs"
        );
        assert_eq!(plain.name().as_contiguous(), rr.name().as_contiguous());
        assert_eq!((plain.end(), fresh.position()), (rr.end(), rr.end()));
        let _ = rr.to_string();
        match rr.data() {
            Ok(d) => {
                assert_eq!(d.rtype(), rr.rtype());
                let _ = d.to_string();
                check_rdata(rr.rtype(), rr.class(), &d);
            }
            Err(_) => typed_ok = false,
        }
    }

    // Per-section iterators see the same records as `records()`.
    let mut per_section = Vec::new();
    for s in [Section::Answer, Section::Authority, Section::Additional] {
        let mut it = msg.section(s);
        assert_eq!(it.section(), s);
        for r in it.by_ref() {
            match r {
                Ok(rr) => per_section.push((s, rr)),
                Err(_) => break,
            }
        }
        assert!(it.next().is_none());
    }
    for ((s1, a), (s2, b)) in all.iter().zip(&per_section) {
        if s1 != s2 {
            // The per-section walk stopped early; the rest is unrelated.
            break;
        }
        assert_eq!((a.start(), a.end()), (b.start(), b.end()));
        assert_eq!(
            (a.rtype(), a.class(), a.ttl()),
            (b.rtype(), b.class(), b.ttl())
        );
    }
    if !all_err {
        assert_eq!(all.len(), per_section.len());
    }
    assert_eq!(msg.questions().count(), q_ok + usize::from(q_err));
    assert_eq!(msg.section(Section::Question).count(), 0);

    // The `dig` form reports every iteration error, and only errors.
    let shown = msg.to_string();
    if q_err || all_err {
        assert!(shown.contains(";; ERROR: "), "{shown}");
    }

    // Validation agrees with what the iterators saw.
    match msg.validate() {
        Ok(()) => {
            assert!(!shown.contains(";; ERROR: "), "{shown}");
            #[cfg(feature = "alloc")]
            check_owned(&msg, &shown);
            assert!(!q_err && !all_err && typed_ok);
            assert_eq!(q_ok, h.qdcount as usize);
            let total = h.ancount as usize + h.nscount as usize + h.arcount as usize;
            assert_eq!(all.len(), total);
            let end = all
                .last()
                .map(|(_, r)| r.end())
                .or_else(|| msg.questions().last().map(|q| q.expect("ok").range().end))
                .unwrap_or(Header::LEN);
            assert_eq!(end, data.len());
            assert!(Message::parse_validated(data).is_ok());
            for s in Section::ALL {
                assert!(msg.section_offset(s).is_ok());
            }
            check_reencode(&msg);
        }
        Err(e) => {
            assert!(Message::parse_validated(data).is_err());
            assert!(
                q_err || all_err || !typed_ok || e == Error::TrailingData,
                "validate failed with {e} but every entry parsed"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// EDNS(0) and the protocol views.
// ---------------------------------------------------------------------------

/// Composes an option TLV with a plain writer.
fn tlv_bytes<O: ComposeOption + ?Sized>(o: &O) -> Vec<u8> {
    let mut buf = std::vec![0u8; 4 + MAX_MESSAGE];
    let mut w = WireWriter::new(&mut buf);
    o.compose_tlv(&mut w)
        .expect("an option fits its own length");
    w.as_bytes().to_vec()
}

/// OPT RDATA whose framing was accepted: the raw options re-compose to the
/// same bytes, and every option that decodes re-composes to its own TLV
/// and decodes again to the same value (RFC 6891 §6.1.2).
pub fn check_opt(opt: Opt<'_>) {
    let mut all = Vec::new();
    for raw in opt.raw_options() {
        let tlv = tlv_bytes(&raw);
        all.extend_from_slice(&tlv);
        let _ = raw.to_string();
        let Ok(o) = raw.parse() else { continue };
        assert_eq!(o.code(), raw.code, "{o}");
        let text = o.to_string();
        let again = tlv_bytes(&o);
        assert_eq!(again, tlv, "{text}: option does not re-compose");
        let back = EdnsOption::parse(raw.code, WireReader::new(&again[4..])).expect("re-parse");
        assert_eq!(back, o, "{text}");
        assert_eq!(back.to_string(), text);
    }
    assert_eq!(all, opt.as_wire(), "options do not cover the OPT RDATA");
    assert_eq!(opt.options().count(), opt.raw_options().count());
    if opt.validate().is_ok() {
        assert!(opt.options().all(|o| o.is_ok()));
    }
    let _ = opt.to_string();
}

/// OPT RDATA (RFC 6891 §6.1.2): framing, then [`check_opt`].
pub fn edns(data: &[u8]) {
    match Opt::new(data) {
        Ok(opt) => {
            assert_eq!(opt.as_wire(), data);
            check_opt(opt);
        }
        Err(e) => assert!(
            matches!(e, Error::UnexpectedEof | Error::InvalidOption),
            "{e}"
        ),
    }
}

/// TKEY (RFC 2930): the request/answer/deletion readers agree with each
/// other, KEY iteration ends, and RFC 2539 Diffie-Hellman keys re-encode
/// to their octets when written in the shortest form.
fn check_tkey(msg: &Message<'_>) {
    use dnsbox::tkey;
    if let Ok(r) = tkey::find_request(msg) {
        assert!(!msg.flags().qr());
        assert!(matches!(r.section, Section::Answer | Section::Additional));
        assert_eq!(tkey::find(msg), Ok(Some(r)));
    }
    if let Ok(a) = tkey::find_answer(msg) {
        assert!(msg.flags().qr() && a.section == Section::Answer);
    }
    if let Ok(Some(d)) = tkey::find_deletion(msg) {
        assert_eq!(d.data.mode, dnsbox::rdata::TkeyMode::KEY_DELETION);
    }
    for section in [Section::Answer, Section::Authority, Section::Additional] {
        for key in tkey::keys(msg, section) {
            let Ok((_, key)) = key else { break };
            if let Ok(dh) = tkey::DhKey::parse(key.public_key) {
                let mut buf = std::vec![0u8; key.public_key.len()];
                let mut w = WireWriter::new(&mut buf);
                dh.compose(&mut w).expect("a parsed DH key composes");
                let out = w.as_bytes();
                assert_eq!(out.len(), dh.wire_len());
                if out.len() == key.public_key.len() {
                    assert_eq!(out, key.public_key);
                }
                let _ = (dh.group(), dh.same_group(&dh));
            }
        }
    }
}

/// The higher-level views over a parsed message must never panic, and
/// their accessors must agree with the message.
fn check_protocol_views(msg: &Message<'_>, data: &[u8]) {
    match msg.edns() {
        Ok(Some(e)) => {
            let _ = e.header().to_string();
            assert_eq!(e.version(), e.header().version);
            let rcode = msg.effective_rcode().expect("EDNS parsed");
            assert_eq!(rcode.header_bits(), msg.flags().rcode().header_bits());
            check_opt(e.opt());
        }
        Ok(None) => assert_eq!(msg.effective_rcode(), Ok(msg.flags().rcode())),
        Err(_) => assert!(msg.effective_rcode().is_err()),
    }
    if let Ok(Some(t)) = dnsbox::tsig::find(msg) {
        assert!(t.start >= Header::LEN && t.start < data.len());
    }
    if let Ok(Some(s)) = dnsbox::sig0::find(msg) {
        assert!(s.start >= Header::LEN && s.start < data.len());
        assert_eq!(s.data.type_covered.get(), 0);
    }
    if let Ok(u) = dnsbox::update::UpdateMessage::new(*msg) {
        for p in u.prerequisites() {
            if p.map(|p| std::format!("{p:?}")).is_err() {
                break;
            }
        }
        for op in u.updates() {
            if op.map(|op| std::format!("{op:?}")).is_err() {
                break;
            }
        }
    }
    if let Ok(n) = dnsbox::notify::NotifyMessage::new(*msg) {
        let _ = (n.soa(), n.serial());
    }
    check_tkey(msg);
    if let Some(Ok(q)) = msg.questions().next() {
        for mut p in [
            dnsbox::xfr::XfrProcessor::axfr(q.name()),
            dnsbox::xfr::XfrProcessor::ixfr(q.name(), msg.id().into()),
        ] {
            if let Ok(events) = p.process(msg) {
                for e in events.take(usize::from(u16::MAX) + 1) {
                    if e.map(|e| std::format!("{e:?}")).is_err() {
                        break;
                    }
                }
            }
            // A finished or failed processor refuses further messages.
            if p.is_done() {
                assert!(p.process(msg).is_err());
            }
        }
    }
    if let Ok(d) = dnsbox::dso::DsoMessage::parse(data) {
        let ok = d.validate().is_ok();
        let mut tlvs_ok = true;
        for t in d.tlvs() {
            match t {
                Ok(t) => {
                    let _ = std::format!("{t:?}");
                }
                Err(_) => {
                    tlvs_ok = false;
                    break;
                }
            }
        }
        if ok {
            assert!(tlvs_ok);
            assert!(d.primary().is_ok());
        }
    }
}

// ---------------------------------------------------------------------------
// Building.
// ---------------------------------------------------------------------------

/// A pushed entry, as the model expects to read it back.
enum Entry {
    Question(NameBuf, Rtype, Class),
    Record(Section, NameBuf, Class, u32, Rtype, Vec<u8>),
}

/// Labels that make names share suffixes (so compression has work to do),
/// in several cases (compression is case-sensitive).
const LABELS: &[&[u8]] = &[
    b"example",
    b"EXAMPLE",
    b"Example",
    b"com",
    b"net",
    b"www",
    b"mail",
    b"a",
    b"b",
    b"*",
    b"_tcp",
    b"ns1",
    b"xn--bcher-kva",
    b"\x00",
    b".",
    b"\\",
    b"\xff\xc0",
];

/// Generates a name: pool labels and fuzzer-chosen bytes, or a previously
/// used name with labels added in front.
fn gen_name(b: &mut Bytes<'_>, pool: &[NameBuf]) -> NameBuf {
    let mode = b.u8();
    let mut name = if mode & 0x80 != 0 && !pool.is_empty() {
        pool[b.u8() as usize % pool.len()].clone()
    } else {
        NameBuf::root()
    };
    let count = (mode & 0x07) as usize;
    let mut labels: Vec<Vec<u8>> = Vec::new();
    for _ in 0..count {
        let sel = b.u8();
        if sel < 0xe0 {
            labels.push(LABELS[sel as usize % LABELS.len()].to_vec());
        } else {
            let len = 1 + (b.u8() as usize % 63);
            let bytes = b.take(len);
            if bytes.is_empty() {
                break;
            }
            labels.push(bytes.to_vec());
        }
    }
    for l in labels.iter().rev() {
        if name.prepend_label(l).is_err() {
            break;
        }
    }
    name
}

/// Generates RDATA bytes as a run of segments: raw bytes, big-endian
/// numbers, and uncompressed names from the pool (so name-bearing types
/// parse often and their names compress against the rest of the message).
fn gen_rdata(b: &mut Bytes<'_>, pool: &[NameBuf]) -> Vec<u8> {
    let segments = b.u8() % 6;
    let mut out = Vec::new();
    for _ in 0..segments {
        match b.u8() % 4 {
            0 => {
                let n = b.u8() as usize;
                out.extend_from_slice(b.take(n));
            }
            1 => out.extend_from_slice(&b.u16().to_be_bytes()),
            2 => out.extend_from_slice(&b.u32().to_be_bytes()),
            _ => out.extend_from_slice(gen_name(b, pool).as_wire()),
        }
    }
    out
}

/// Build → parse identity. The input drives a sequence of builder
/// operations (questions, records with any registered type, compression
/// toggles, size limits, checkpoints and rollbacks); the model of what was
/// pushed must match what parses back, failed pushes must leave the
/// message untouched, and rollbacks must restore it byte for byte.
pub fn roundtrip(data: &[u8]) {
    let known = known_types();
    let mut b = Bytes(data);
    let size = match b.u8() % 4 {
        0 => 512,
        1 => 12 + b.u8() as usize,
        2 => 4096,
        _ => MAX_MESSAGE,
    };
    let mut buf = std::vec![0u8; size];
    let mut builder = MessageBuilder::new(&mut buf).expect("size >= 12");
    let id = b.u16();
    let flags = Flags::from_bits(b.u16());
    builder.set_id(id);
    builder.set_flags(flags);

    let mut model: Vec<Entry> = Vec::new();
    let mut pool: Vec<NameBuf> = Vec::new();
    let mut checkpoints = Vec::new();
    // The section the model says the builder is in (RFC 1035 §4.1 order).
    let mut section_now = Section::Question;
    let mut ops = 0;
    while !b.is_empty() && ops < 256 {
        ops += 1;
        let before = builder.as_bytes().to_vec();
        let header_before = builder.header();
        let op = b.u8();
        let mut pushed = None;
        let res = match op % 8 {
            0 => {
                let name = gen_name(&mut b, &pool);
                let qtype = pick_rtype(&mut b, known);
                let qclass = pick_class(&mut b);
                let r = builder.push_question(&name, qtype, qclass);
                pushed = Some(Section::Question);
                if r.is_ok() {
                    model.push(Entry::Question(name.clone(), qtype, qclass));
                }
                pool.push(name);
                r
            }
            1..=3 => {
                let section = match op % 8 {
                    1 => Section::Answer,
                    2 => Section::Authority,
                    _ => Section::Additional,
                };
                let name = gen_name(&mut b, &pool);
                let rtype = pick_rtype(&mut b, known);
                let class = pick_class(&mut b);
                let ttl = b.u32();
                let wire = gen_rdata(&mut b, &pool);
                pool.push(name.clone());
                let Ok(d) = RData::parse(rtype, class, WireReader::new(&wire)) else {
                    continue;
                };
                let r = builder.push_record(section, &name, class, ttl, &d);
                pushed = Some(section);
                if r.is_ok() {
                    model.push(Entry::Record(section, name, class, ttl, rtype, wire));
                }
                r
            }
            4 => {
                if checkpoints.len() < 8 {
                    checkpoints.push((
                        builder.checkpoint(),
                        before.clone(),
                        model.len(),
                        section_now,
                    ));
                }
                Ok(())
            }
            5 => {
                if let Some((cp, bytes, len, section)) = checkpoints.pop() {
                    builder.rollback(cp);
                    model.truncate(len);
                    section_now = section;
                    // Headers may differ only in ID and flags set since.
                    assert_eq!(&builder.as_bytes()[4..], &bytes[4..], "rollback");
                }
                Ok(())
            }
            6 => {
                builder.set_compression(b.bool());
                Ok(())
            }
            _ => {
                builder.set_limit(b.u16() as usize);
                assert!(builder.limit() <= size);
                Ok(())
            }
        };
        match (res, pushed) {
            (Err(e), Some(section)) => {
                // Every push is atomic.
                assert_eq!(builder.as_bytes(), &before[..], "failed push ({e}) wrote");
                assert_eq!(builder.header(), header_before);
                // Section order errors exactly when going backwards.
                assert_eq!(e == Error::SectionOrder, section < section_now, "{e}");
            }
            (Ok(()), Some(section)) => {
                assert!(
                    section >= section_now,
                    "pushed {section:?} after {section_now:?}"
                );
                section_now = section;
                // A successful push respects the size limit.
                assert!(builder.len() <= builder.limit(), "push exceeded the limit");
                assert!(builder.len() > before.len());
            }
            (Err(e), None) => panic!("non-push operation failed: {e}"),
            (Ok(()), None) => {}
        }
        assert_eq!(builder.section(), section_now);
        assert!(builder.len() <= size);
        let cur = Message::parse_validated(builder.as_bytes())
            .unwrap_or_else(|e| panic!("intermediate message invalid: {e}"));
        assert_eq!(cur.header(), builder.header());
    }

    let out = builder.finish();
    let msg =
        Message::parse_validated(out).unwrap_or_else(|e| panic!("built message invalid: {e}"));
    assert_eq!((msg.id(), msg.flags()), (id, flags));

    let mut questions = msg.questions();
    let mut records = msg.records();
    for entry in &model {
        match entry {
            Entry::Question(name, qtype, qclass) => {
                let q = questions.next().expect("question").expect("valid");
                assert!(q.name().eq_exact(&name.as_name()), "{} vs {name}", q.name());
                assert_eq!((q.qtype(), q.qclass()), (*qtype, *qclass));
            }
            Entry::Record(section, name, class, ttl, rtype, wire) => {
                let (s, rr) = records.next().expect("record").expect("valid");
                assert_eq!(s, *section);
                assert!(
                    rr.name().eq_exact(&name.as_name()),
                    "{} vs {name}",
                    rr.name()
                );
                assert_eq!((rr.rtype(), rr.class(), rr.ttl()), (*rtype, *class, *ttl));
                let want = RData::parse(*rtype, *class, WireReader::new(wire)).expect("parsed");
                let got = rr.data().expect("validated");
                assert_eq!(got, want);
                assert_eq!(got.to_string(), want.to_string());
            }
        }
    }
    assert!(questions.next().is_none());
    assert!(records.next().is_none());
    check_reencode(&msg);
}

// ---------------------------------------------------------------------------
// Presentation format.
// ---------------------------------------------------------------------------

/// Presentation-format parsing (RFC 1035 §5.1): names (escapes included),
/// record types and classes (mnemonics and RFC 3597 generic forms).
pub fn text(data: &[u8]) {
    let parsed = NameBuf::from_text(data);
    assert_eq!(
        parsed.as_ref().ok().map(|n| n.as_wire().to_vec()),
        reference_text_name(data),
        "{:?}",
        String::from_utf8_lossy(data)
    );
    if let Ok(n) = parsed {
        check_name(n.as_name());
        let shown = n.to_string();
        let again: NameBuf = shown.parse().expect("display re-parses");
        assert_eq!(again.as_wire(), n.as_wire());
    }
    let Ok(s) = core::str::from_utf8(data) else {
        return;
    };
    if let Ok(n) = s.parse::<NameBuf>() {
        assert_eq!(
            NameBuf::from_text(data).map(|m| m.as_wire().to_vec()),
            Ok(n.as_wire().to_vec())
        );
    }
    if let Ok(t) = s.parse::<Rtype>() {
        let shown = t.to_string();
        assert_eq!(shown.parse::<Rtype>(), Ok(t), "{shown}");
        assert_eq!(std::format!("TYPE{}", t.get()).parse::<Rtype>(), Ok(t));
    }
    if let Ok(c) = s.parse::<Class>() {
        let shown = c.to_string();
        assert_eq!(shown.parse::<Class>(), Ok(c), "{shown}");
        assert_eq!(std::format!("CLASS{}", c.get()).parse::<Class>(), Ok(c));
    }
    check_svcb_text(s);
    check_zone(data);
    let _: String = s.to_string();
}

/// Master-file parsing (RFC 1035 §5): the reader terminates, and every
/// record it yields is valid RDATA that passes [`check_rdata`] (which
/// includes the presentation-format round trip).
fn check_zone(data: &[u8]) {
    let origin: NameBuf = "example.".parse().expect("static name");
    let mut zone = dnsbox::zone::ZoneReader::from_bytes(data).with_origin(&origin);
    let mut buf = std::vec![0u8; MAX_MESSAGE];
    // One `$GENERATE` may yield many records: cap the work per input.
    for _ in 0..4096 {
        match zone.next_record(&mut buf) {
            Ok(Some(rr)) => {
                let d = rr
                    .data()
                    .unwrap_or_else(|e| panic!("{}: zone RDATA invalid: {e}", rr.name));
                check_rdata(rr.rtype, rr.class, &d);
                #[cfg(feature = "alloc")]
                check_owned_zone_record(&rr);
            }
            Ok(None) => return,
            Err(_) => {}
        }
    }
}

/// A record read from a master file copies into an [`OwnedRecord`]
/// (feature `alloc`) with the same RDATA, which re-encodes to itself and
/// whose display parses back (as one master-file entry) to the same record.
///
/// [`OwnedRecord`]: dnsbox::OwnedRecord
#[cfg(feature = "alloc")]
fn check_owned_zone_record(rr: &dnsbox::zone::ZoneRecord<'_>) {
    let owned = dnsbox::OwnedRecord::from(rr);
    assert_eq!(owned.rdata.as_wire(), rr.rdata);
    assert_eq!(dnsbox::OwnedRecord::from(rr.clone()), owned);
    assert_eq!(
        dnsbox::OwnedRData::new(&owned.rdata).as_ref(),
        Ok(&owned.rdata),
        "{owned}"
    );
    let shown = owned.to_string();
    assert_eq!(shown, rr.to_string());
    let again: dnsbox::OwnedRecord = shown
        .parse()
        .unwrap_or_else(|e| panic!("{shown:?}: owned record display does not parse back: {e}"));
    assert_eq!(again, owned, "{shown}");
    assert!(
        again.name.as_name().eq_exact(&owned.name.as_name()),
        "{shown}"
    );
}

/// Presentation format parses back (RFC 1035 §5.1, RFC 3597 §5): the
/// displayed RDATA reads back as RDATA displaying the same, unless the
/// type has no text format (yet).
fn check_text_round_trip(rtype: Rtype, class: Class, text: &str) {
    let mut buf = std::vec![0u8; MAX_MESSAGE];
    let mut w = WireWriter::new(&mut buf);
    let mut s = dnsbox::zone::Scanner::new(text);
    match RData::parse_text(rtype, class, &mut s, &mut w) {
        Ok(()) => {
            let again = RData::parse(rtype, class, WireReader::new(w.as_bytes()))
                .unwrap_or_else(|e| panic!("{rtype} {text:?}: parse_text output invalid: {e}"));
            assert_eq!(again.to_string(), text, "{rtype}: text does not round-trip");
        }
        // Every registered type has a text format except NULL (generic
        // form only, which its display uses) and the OPT pseudo-RR.
        Err(Error::NoTextFormat) if rtype == Rtype::OPT => {}
        Err(e) => panic!("{rtype} {text:?}: display does not parse back: {e}"),
    }
}

/// SVCB / HTTPS presentation format (RFC 9460 §2.1, Appendix A): anything
/// accepted displays as text that parses back to the same RDATA.
fn check_svcb_text(s: &str) {
    let mut buf = std::vec![0u8; s.len() * 4 + 512];
    let Ok(svcb) = Svcb::from_text(s, &mut buf) else {
        return;
    };
    let shown = svcb.to_string();
    let mut buf2 = std::vec![0u8; shown.len() * 4 + 512];
    let again = Svcb::from_text(&shown, &mut buf2)
        .unwrap_or_else(|e| panic!("{shown:?}: display does not re-parse: {e}"));
    assert_eq!(again, svcb, "{shown}");
    let rdata = RData::Svcb(svcb);
    check_rdata(Rtype::SVCB, Class::IN, &rdata);
    let https = Https::from(svcb);
    assert_eq!(https.to_string(), shown);
}
