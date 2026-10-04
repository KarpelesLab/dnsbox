//! TSIG protocol tests with a non-cryptographic stand-in MAC, so they run
//! without the `tsig` feature. Interop with real HMACs and BIND captures is
//! in `tests/tsig_named.rs`.

use super::*;
use crate::message::Section;
use crate::name::{Name, NameBuf};
use crate::rdata::{A, UnknownRdata};
use crate::wire::WireWriter;
use crate::{Class, Flags, Message, MessageBuilder, Rtype};
use std::vec::Vec;

/// A deterministic, NON-cryptographic checksum standing in for a MAC
/// (two FNV-1a lanes, widened to 32 bytes). Only for protocol tests.
#[derive(Clone)]
struct TestMac {
    lanes: [u64; 4],
}

impl TsigMac for TestMac {
    fn update(&mut self, data: &[u8]) {
        for &b in data {
            for (i, lane) in self.lanes.iter_mut().enumerate() {
                *lane ^= u64::from(b) + i as u64;
                *lane = lane.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
    }

    fn finalize(self, out: &mut [u8; MAX_MAC_LEN]) -> usize {
        for (i, lane) in self.lanes.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&lane.to_be_bytes());
        }
        32
    }

    fn verify(self, expected: &[u8]) -> bool {
        let mut out = [0u8; MAX_MAC_LEN];
        let n = self.finalize(&mut out);
        expected.len() <= n && out[..expected.len()] == *expected
    }
}

struct TestKey {
    name: NameBuf,
    algorithm: NameBuf,
    secret: u64,
    mac_len: usize,
}

impl TestKey {
    fn new(name: &str, secret: u64) -> Self {
        TestKey {
            name: name.parse().unwrap(),
            algorithm: "hmac-test".parse().unwrap(),
            secret,
            mac_len: 32,
        }
    }
}

impl TsigKey for TestKey {
    type Mac = TestMac;

    fn name(&self) -> Name<'_> {
        self.name.as_name()
    }

    fn algorithm(&self) -> Name<'_> {
        self.algorithm.as_name()
    }

    fn digest_len(&self) -> usize {
        32
    }

    fn mac_len(&self) -> usize {
        self.mac_len
    }

    fn new_mac(&self) -> TestMac {
        let mut m = TestMac {
            lanes: [0xcbf2_9ce4_8422_2325; 4],
        };
        m.update(&self.secret.to_be_bytes());
        m
    }
}

/// Collects the bytes fed to a MAC.
struct Collect(Vec<u8>);

impl TsigMac for Collect {
    fn update(&mut self, data: &[u8]) {
        self.0.extend_from_slice(data);
    }
    fn finalize(self, _: &mut [u8; MAX_MAC_LEN]) -> usize {
        0
    }
    fn verify(self, _: &[u8]) -> bool {
        false
    }
}

const NOW: u64 = 1_700_000_000;

fn query(id: u16) -> Vec<u8> {
    let name: NameBuf = "example.com".parse().unwrap();
    let mut b = MessageBuilder::new_vec_or_buf();
    b.set_id(id);
    b.push_question(&name, Rtype::SOA, Class::IN).unwrap();
    b.finish_vec()
}

/// Builder helpers that work with and without `alloc`.
trait TestBuilder {
    fn new_vec_or_buf() -> Self;
    fn finish_vec(self) -> Vec<u8>;
}

impl TestBuilder for MessageBuilder<WireWriter<'static>> {
    fn new_vec_or_buf() -> Self {
        let buf: &'static mut [u8] = std::vec![0u8; 4096].leak();
        MessageBuilder::new(buf).unwrap()
    }
    fn finish_vec(self) -> Vec<u8> {
        self.finish().to_vec()
    }
}

fn sign_query(key: &TestKey, id: u16) -> (Vec<u8>, MacBuf) {
    let name: NameBuf = "example.com".parse().unwrap();
    let mut b = MessageBuilder::new_vec_or_buf();
    b.set_id(id);
    b.push_question(&name, Rtype::SOA, Class::IN).unwrap();
    let mac = TsigSigner::request(key).sign(&mut b, NOW).unwrap();
    (b.finish_vec(), mac)
}

fn response(id: u16, n: u8) -> MessageBuilder<WireWriter<'static>> {
    let name: NameBuf = "example.com".parse().unwrap();
    let mut b = MessageBuilder::new_vec_or_buf();
    b.set_id(id);
    b.set_flags(Flags::default().with_qr(true));
    b.push_answer(&name, Class::IN, 60, &A::new([192, 0, 2, n].into()))
        .unwrap();
    b
}

#[test]
fn mac_input_layout() {
    // RFC 8945 §4.3: request MAC input = message (no TSIG, original ID)
    // + key name, class ANY, TTL 0, algorithm, time, fudge, error, other.
    let key = TestKey::new("Key.Example", 1);
    let (wire, mac) = sign_query(&key, 0x1234);
    let msg = Message::parse_validated(&wire).unwrap();
    let rec = find(&msg).unwrap().unwrap();
    assert_eq!(rec.mac(), mac.as_slice());
    assert_eq!(rec.data.original_id, 0x1234);
    assert_eq!(rec.data.fudge, DEFAULT_FUDGE);
    assert_eq!(rec.data.time_signed, NOW);

    let mut c = Collect(Vec::new());
    rec.feed_mac_input(&wire, None, false, &mut |d| c.update(d))
        .unwrap();
    let mut expected = query(0x1234);
    expected.extend_from_slice(b"\x03key\x07example\x00"); // lowercased
    expected.extend_from_slice(&[0x00, 0xff, 0, 0, 0, 0]); // ANY, TTL 0
    expected.extend_from_slice(b"\x09hmac-test\x00");
    expected.extend_from_slice(&NOW.to_be_bytes()[2..]);
    expected.extend_from_slice(&[0x01, 0x2c, 0, 0, 0, 0]); // fudge, error, other len
    assert_eq!(c.0, expected);

    // A response: prior MAC with its length first.
    let mut c = Collect(Vec::new());
    rec.feed_mac_input(&wire, Some(&[9, 9]), true, &mut |d| c.update(d))
        .unwrap();
    let mut expected = std::vec![0, 2, 9, 9];
    expected.extend_from_slice(&query(0x1234));
    expected.extend_from_slice(&NOW.to_be_bytes()[2..]);
    expected.extend_from_slice(&[0x01, 0x2c]);
    assert_eq!(c.0, expected);

    // The header ID is replaced by the original ID (forwarding).
    let mut forwarded = wire.clone();
    forwarded[0] = 0x55;
    let msg = Message::parse(&forwarded).unwrap();
    assert!(verify_request(&msg, &key, NOW).verified().is_some());
}

#[test]
fn request_response_round_trip() {
    let key = TestKey::new("k", 7);
    let (wire, req_mac) = sign_query(&key, 1);
    let msg = Message::parse_validated(&wire).unwrap();
    let v = verify_request(&msg, &key, NOW + 300).verified().unwrap();
    assert_eq!(v.request_mac(), req_mac.as_slice());
    assert_eq!(v.key.name(), key.name());

    let mut b = response(1, 1);
    let resp_mac = v.signer().sign(&mut b, NOW + 1).unwrap();
    let resp = b.finish_vec();
    let mut cv = TsigVerifier::new(&key, req_mac.as_slice()).unwrap();
    let rec = cv
        .verify(&Message::parse_validated(&resp).unwrap(), NOW)
        .unwrap()
        .unwrap();
    assert_eq!(rec.mac(), resp_mac.as_slice());
    assert_eq!(cv.last_mac(), resp_mac.as_slice());
    cv.finish().unwrap();

    // A response verified against the wrong request MAC fails.
    let mut cv = TsigVerifier::new(&key, &[0; 32]).unwrap();
    assert_eq!(
        cv.verify(&Message::parse(&resp).unwrap(), NOW),
        Err(Error::BadSignature)
    );
    // Unsigned response.
    let mut cv = TsigVerifier::new(&key, req_mac.as_slice()).unwrap();
    let plain = response(1, 1).finish_vec();
    assert_eq!(
        cv.verify(&Message::parse(&plain).unwrap(), NOW),
        Err(Error::Unsigned)
    );
    assert_eq!(cv.finish(), Err(Error::Unsigned));
    // Response signed by another key.
    let other = TestKey::new("other", 7);
    let mut cv = TsigVerifier::new(&other, req_mac.as_slice()).unwrap();
    assert_eq!(
        cv.verify(&Message::parse(&resp).unwrap(), NOW),
        Err(Error::BadKey)
    );
}

#[test]
fn server_rejections() {
    let key = TestKey::new("k", 7);
    let (wire, _) = sign_query(&key, 1);
    let msg = Message::parse(&wire).unwrap();
    // Unsigned request.
    let plain = query(1);
    assert!(matches!(
        verify_request(&Message::parse(&plain).unwrap(), &key, NOW),
        RequestStatus::Unsigned
    ));
    // Unknown key.
    let other = TestKey::new("other", 7);
    let st = verify_request(&msg, &other, NOW);
    assert_eq!(st.error(), Some(Error::BadKey));
    let rej = st.rejected().unwrap();
    assert!(rej.key.is_none());
    assert_eq!(rej.rcode(), crate::Rcode::NOTAUTH);
    // Wrong secret.
    let wrong = TestKey::new("k", 8);
    assert_eq!(
        verify_request(&msg, &wrong, NOW).error(),
        Some(Error::BadSignature)
    );
    // Out of the time window, either way.
    assert_eq!(
        verify_request(&msg, &key, NOW + 301).error(),
        Some(Error::BadTime)
    );
    assert_eq!(
        verify_request(&msg, &key, NOW - 301).error(),
        Some(Error::BadTime)
    );
    // Key stores.
    let keys = [TestKey::new("a", 1), TestKey::new("K", 7)];
    assert!(verify_request(&msg, &keys, NOW).verified().is_some());
    assert!(verify_request(&msg, &keys[..1], NOW).rejected().is_some());
}

#[test]
fn error_responses() {
    let key = TestKey::new("k", 7);
    let (wire, req_mac) = sign_query(&key, 1);
    let msg = Message::parse(&wire).unwrap();

    // BADKEY / BADSIG: unsigned TSIG echoing the request.
    let wrong = TestKey::new("k", 8);
    let rej = verify_request(&msg, &wrong, NOW).rejected().unwrap();
    let mut b = response(1, 1);
    rej.sign_response(&mut b, NOW).unwrap();
    let out = b.finish_vec();
    let m = Message::parse_validated(&out).unwrap();
    let t = find(&m).unwrap().unwrap();
    assert!(t.mac().is_empty());
    assert_eq!(t.data.error, TsigRcode::BADSIG);
    assert_eq!(t.data.time_signed, NOW);
    let mut cv = TsigVerifier::new(&key, req_mac.as_slice()).unwrap();
    assert_eq!(cv.verify(&m, NOW), Err(Error::TsigErrorResponse));

    // BADTIME: signed, request time, server time in other data.
    let rej = verify_request(&msg, &key, NOW + 1000).rejected().unwrap();
    assert_eq!(rej.tsig_error(), TsigRcode::BADTIME);
    let mut b = response(1, 1);
    rej.sign_response(&mut b, NOW + 1000).unwrap();
    let out = b.finish_vec();
    let m = Message::parse_validated(&out).unwrap();
    let t = find(&m).unwrap().unwrap();
    assert_eq!(t.data.time_signed, NOW);
    assert_eq!(t.data.other, &(NOW + 1000).to_be_bytes()[2..]);
    let mut cv = TsigVerifier::new(&key, req_mac.as_slice()).unwrap();
    assert_eq!(cv.verify(&m, NOW), Err(Error::BadTime));

    // BADTRUNC: the key demands longer MACs than the request has.
    let short = TestKey {
        mac_len: 16,
        ..TestKey::new("k", 7)
    };
    let (wire16, mac16) = sign_query(&short, 2);
    assert_eq!(mac16.len(), 16);
    let msg16 = Message::parse(&wire16).unwrap();
    assert!(verify_request(&msg16, &short, NOW).verified().is_some());
    let rej = verify_request(&msg16, &key, NOW).rejected().unwrap();
    assert_eq!(rej.error, Error::BadTrunc);
    let mut b = response(2, 1);
    rej.sign_response(&mut b, NOW).unwrap();
    let out = b.finish_vec();
    let mut cv = TsigVerifier::new(&key, mac16.as_slice()).unwrap();
    assert_eq!(
        cv.verify(&Message::parse(&out).unwrap(), NOW),
        Err(Error::BadTrunc)
    );

    // FORMERR (misplaced TSIG): no TSIG in the response.
    let rej = Rejected::<TestKey> {
        error: Error::MisplacedSignature,
        record: None,
        key: None,
    };
    assert_eq!(rej.rcode(), crate::Rcode::FORMERR);
    let mut b = response(1, 1);
    let before = b.len();
    rej.sign_response(&mut b, NOW).unwrap();
    assert_eq!(b.len(), before);
}

#[test]
fn response_codes_table() {
    use crate::Rcode;
    assert_eq!(
        response_codes(Error::BadKey),
        (Rcode::NOTAUTH, TsigRcode::BADKEY)
    );
    assert_eq!(
        response_codes(Error::BadSignature),
        (Rcode::NOTAUTH, TsigRcode::BADSIG)
    );
    assert_eq!(
        response_codes(Error::BadTime),
        (Rcode::NOTAUTH, TsigRcode::BADTIME)
    );
    assert_eq!(
        response_codes(Error::BadTrunc),
        (Rcode::NOTAUTH, TsigRcode::BADTRUNC)
    );
    for e in [
        Error::MisplacedSignature,
        Error::BadMacSize,
        Error::UnexpectedEof,
    ] {
        assert_eq!(response_codes(e), (Rcode::FORMERR, TsigRcode::NOERROR));
    }
}

#[test]
fn mac_size_rules() {
    // RFC 8945 §5.2.2.1: at most the digest, at least max(10, digest/2).
    for (digest, ok_min) in [(16, 10), (20, 10), (28, 14), (32, 16), (48, 24), (64, 32)] {
        assert_eq!(check_mac_size(digest, digest), Ok(()));
        assert_eq!(check_mac_size(ok_min, digest), Ok(()));
        assert_eq!(check_mac_size(ok_min - 1, digest), Err(Error::BadMacSize));
        assert_eq!(check_mac_size(digest + 1, digest), Err(Error::BadMacSize));
    }
    assert_eq!(check_mac_size(0, 32), Err(Error::BadMacSize));
    assert_eq!(check_mac_size(65, 80), Err(Error::BadMacSize));

    // The signer refuses to generate a MAC below the floor ...
    let key = TestKey::new("k", 7);
    let mut weak = TestKey::new("k", 7);
    weak.mac_len = 15;
    let mut b = response(1, 1);
    assert_eq!(
        TsigSigner::request(&weak).sign(&mut b, NOW),
        Err(Error::BadMacSize)
    );
    // ... and a received one is FORMERR.
    let (wire, _) = sign_query(&key, 1);
    let msg = Message::parse(&wire).unwrap();
    let rec = find(&msg).unwrap().unwrap();
    let short = Tsig {
        mac: &rec.data.mac[..15],
        ..rec.data
    };
    let name: NameBuf = "example.com".parse().unwrap();
    let mut b = MessageBuilder::new_vec_or_buf();
    b.set_id(1);
    b.push_question(&name, Rtype::SOA, Class::IN).unwrap();
    b.push_additional(rec.key_name, Class::ANY, 0, &short)
        .unwrap();
    let wire = b.finish_vec();
    let msg = Message::parse(&wire).unwrap();
    let st = verify_request(&msg, &key, NOW);
    assert_eq!(st.error(), Some(Error::BadMacSize));
    assert_eq!(st.rejected().unwrap().rcode(), crate::Rcode::FORMERR);
    let mut v = TsigVerifier::new(&key, &[]).unwrap();
    assert_eq!(v.verify(&msg, NOW), Err(Error::BadMacSize));
}

#[test]
fn stream_with_unsigned_messages() {
    let key = TestKey::new("k", 7);
    let (_, req_mac) = sign_query(&key, 9);
    let mut signer = TsigSigner::response(&key, req_mac.as_slice()).unwrap();

    // Unsigned before the first signed message is not allowed.
    let first = response(9, 0);
    assert_eq!(signer.skip(first.as_bytes()), Err(Error::Unsigned));

    // Messages: signed, unsigned, unsigned, signed, unsigned, signed.
    let plan = [true, false, false, true, false, true];
    let mut stream = Vec::new();
    for (i, &signed) in plan.iter().enumerate() {
        let mut b = response(9, i as u8);
        if signed {
            signer.sign(&mut b, NOW + i as u64).unwrap();
        } else {
            signer.skip(b.as_bytes()).unwrap();
        }
        stream.push(b.finish_vec());
    }

    let mut v = TsigVerifier::new(&key, req_mac.as_slice()).unwrap();
    for (i, msg) in stream.iter().enumerate() {
        let got = v.verify(&Message::parse(msg).unwrap(), NOW).unwrap();
        assert_eq!(got.is_some(), plan[i], "message {i}");
    }
    v.finish().unwrap();

    // Dropping an unsigned message breaks the chain.
    let mut v = TsigVerifier::new(&key, req_mac.as_slice()).unwrap();
    for i in [0, 1, 3] {
        let res = v.verify(&Message::parse(&stream[i]).unwrap(), NOW);
        if i == 3 {
            assert_eq!(res, Err(Error::BadSignature));
        } else {
            res.unwrap();
        }
    }

    // A stream ending unsigned is incomplete.
    let mut v = TsigVerifier::new(&key, req_mac.as_slice()).unwrap();
    for msg in &stream[..3] {
        v.verify(&Message::parse(msg).unwrap(), NOW).unwrap();
    }
    assert_eq!(v.finish(), Err(Error::Unsigned));

    // The first response message must be signed.
    let mut v = TsigVerifier::new(&key, req_mac.as_slice()).unwrap();
    assert_eq!(
        v.verify(&Message::parse(&stream[1]).unwrap(), NOW),
        Err(Error::Unsigned)
    );
}

#[test]
fn at_most_99_unsigned() {
    let key = TestKey::new("k", 7);
    let (_, req_mac) = sign_query(&key, 9);
    let mut signer = TsigSigner::response(&key, req_mac.as_slice()).unwrap();
    let mut v = TsigVerifier::new(&key, req_mac.as_slice()).unwrap();
    let mut b = response(9, 0);
    signer.sign(&mut b, NOW).unwrap();
    v.verify(&Message::parse(b.as_bytes()).unwrap(), NOW)
        .unwrap();
    let plain = response(9, 1).finish_vec();
    for _ in 0..MAX_UNSIGNED {
        signer.skip(&plain).unwrap();
        assert_eq!(v.verify(&Message::parse(&plain).unwrap(), NOW), Ok(None));
    }
    assert_eq!(signer.skip(&plain), Err(Error::Unsigned));
    assert_eq!(
        v.verify(&Message::parse(&plain).unwrap(), NOW),
        Err(Error::Unsigned)
    );
    // Signing resets the count.
    let mut b = response(9, 2);
    signer.sign(&mut b, NOW).unwrap();
    assert!(
        v.verify(&Message::parse(b.as_bytes()).unwrap(), NOW)
            .unwrap()
            .is_some()
    );
    v.finish().unwrap();
    signer.skip(&plain).unwrap();
}

#[test]
fn signing_is_atomic() {
    let key = TestKey::new("k", 7);
    let name: NameBuf = "example.com".parse().unwrap();
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.push_question(&name, Rtype::SOA, Class::IN).unwrap();
    let need = record_len(key.name(), key.algorithm(), 32, 0);
    b.set_limit(b.len() + need - 1);
    let before = b.as_bytes().to_vec();
    let mut signer = TsigSigner::request(&key);
    assert_eq!(signer.sign(&mut b, NOW), Err(Error::BufferTooSmall));
    assert_eq!(b.as_bytes(), &before[..]);
    assert_eq!(signer.last_mac(), None);
    b.set_limit(b.len() + need);
    signer.sign(&mut b, NOW).unwrap();
    assert_eq!(b.len(), before.len() + need);
    // Bad parameters.
    let mut b2 = response(1, 1);
    assert_eq!(
        TsigSigner::request(&key).sign(&mut b2, crate::rdata::MAX_TIME_SIGNED + 1),
        Err(Error::InvalidRdata)
    );
    let mut long = TestKey::new("k", 7);
    long.mac_len = 33;
    assert_eq!(
        TsigSigner::request(&long).sign(&mut b2, NOW),
        Err(Error::BadMacSize)
    );
    assert_eq!(
        TsigSigner::response(&key, &[0; 65]).err(),
        Some(Error::BadMacSize)
    );
}

#[test]
fn sign_raw_buffer() {
    // A message preceded by a TCP length prefix, signed in place.
    let key = TestKey::new("k", 7);
    let q = query(3);
    let mut storage = [0u8; 256];
    let mut w = WireWriter::new(&mut storage);
    crate::wire::OutBuf::append(&mut w, &[0, 0]).unwrap();
    crate::wire::OutBuf::append(&mut w, &q).unwrap();
    let mac = TsigSigner::request(&key).sign_buf(&mut w, 2, NOW).unwrap();
    let out = w.into_written();
    let msg = Message::parse_validated(&out[2..]).unwrap();
    assert_eq!(msg.header().arcount, 1);
    let v = verify_request(&msg, &key, NOW).verified().unwrap();
    assert_eq!(v.request_mac(), mac.as_slice());
    // Matches signing through the builder.
    let (built, _) = sign_query(&key, 3);
    assert_eq!(&out[2..], &built[..]);

    // Too small: untouched.
    let mut small = [0u8; 40];
    let mut w = WireWriter::new(&mut small);
    crate::wire::OutBuf::append(&mut w, &q).unwrap();
    assert_eq!(
        TsigSigner::request(&key).sign_buf(&mut w, 0, NOW),
        Err(Error::BufferTooSmall)
    );
    assert_eq!(w.written(), &q[..]);
    // Not a message.
    let mut tiny = [0u8; 300];
    let mut w = WireWriter::new(&mut tiny);
    crate::wire::OutBuf::append(&mut w, &[1, 2, 3]).unwrap();
    assert_eq!(
        TsigSigner::request(&key).sign_buf(&mut w, 0, NOW),
        Err(Error::UnexpectedEof)
    );
    assert_eq!(
        TsigSigner::request(&key).sign_buf(&mut w, 9, NOW),
        Err(Error::UnexpectedEof)
    );
}

/// Builds a message with a TSIG-typed record placed by hand.
fn with_tsig_at(section: Section, extra_after: bool, class: Class, ttl: u32) -> Vec<u8> {
    let name: NameBuf = "example.com".parse().unwrap();
    let alg: NameBuf = "hmac-test".parse().unwrap();
    let tsig = Tsig {
        algorithm: alg.as_name(),
        time_signed: NOW,
        fudge: 300,
        mac: &[1; 32],
        original_id: 0,
        error: TsigRcode::NOERROR,
        other: &[],
    };
    let mut b = MessageBuilder::new_vec_or_buf();
    b.push_question(&name, Rtype::SOA, Class::IN).unwrap();
    b.push_record(section, &name, class, ttl, &tsig).unwrap();
    if extra_after {
        b.push_additional(
            &name,
            Class::IN,
            0,
            &UnknownRdata::new(Rtype::new(65280), &[]),
        )
        .unwrap();
    }
    b.finish_vec()
}

#[test]
fn placement() {
    let ok = with_tsig_at(Section::Additional, false, Class::ANY, 0);
    assert!(find(&Message::parse(&ok).unwrap()).unwrap().is_some());
    for (section, after) in [
        (Section::Answer, false),
        (Section::Authority, false),
        (Section::Additional, true),
    ] {
        let wire = with_tsig_at(section, after, Class::ANY, 0);
        let msg = Message::parse(&wire).unwrap();
        assert_eq!(find(&msg), Err(Error::MisplacedSignature), "{section:?}");
        let key = TestKey::new("example.com", 1);
        let rej = verify_request(&msg, &key, NOW).rejected().unwrap();
        assert_eq!(rej.error, Error::MisplacedSignature);
        assert_eq!(rej.rcode(), crate::Rcode::FORMERR);
    }
    // Two TSIGs: the first is not last.
    let name: NameBuf = "example.com".parse().unwrap();
    let msg = Message::parse(&ok).unwrap();
    let rec = find(&msg).unwrap().unwrap();
    let mut b = MessageBuilder::new_vec_or_buf();
    b.push_question(&name, Rtype::SOA, Class::IN).unwrap();
    b.push_additional(&name, Class::ANY, 0, &rec.data).unwrap();
    b.push_additional(&name, Class::ANY, 0, &rec.data).unwrap();
    let two = b.finish_vec();
    assert_eq!(
        find(&Message::parse(&two).unwrap()),
        Err(Error::MisplacedSignature)
    );
    // Class must be ANY and TTL 0 (RFC 8945 §4.2).
    for (class, ttl) in [(Class::IN, 0), (Class::ANY, 1)] {
        let wire = with_tsig_at(Section::Additional, false, class, ttl);
        assert_eq!(
            find(&Message::parse(&wire).unwrap()),
            Err(Error::InvalidRdata)
        );
    }
}

#[test]
fn malformed_messages_never_panic() {
    let key = TestKey::new("k", 7);
    let (wire, mac) = sign_query(&key, 1);
    let mut b = response(1, 1);
    TsigSigner::response(&key, mac.as_slice())
        .unwrap()
        .sign(&mut b, NOW)
        .unwrap();
    let resp = b.finish_vec();
    for msg in [&wire, &resp] {
        for end in 0..msg.len() {
            let cut = &msg[..end];
            if let Ok(m) = Message::parse(cut) {
                let _ = find(&m);
                assert!(verify_request(&m, &key, NOW).verified().is_none());
                let mut v = TsigVerifier::new(&key, mac.as_slice()).unwrap();
                assert!(!matches!(v.verify(&m, NOW), Ok(Some(_))));
            }
        }
        for i in 0..msg.len() {
            let mut m = msg.to_vec();
            m[i] = m[i].wrapping_add(0x41);
            if let Ok(m) = Message::parse(&m) {
                let _ = verify_request(&m, &key, NOW);
                let mut v = TsigVerifier::new(&key, mac.as_slice()).unwrap();
                let _ = v.verify(&m, NOW);
            }
        }
    }
}

#[test]
fn variables_feed() {
    let name: NameBuf = "A.b".parse().unwrap();
    let vars = TsigVariables {
        key_name: name.as_name(),
        algorithm: name.as_name(),
        time_signed: 0x0102_0304_0506,
        fudge: 0x0708,
        error: TsigRcode::BADTIME,
        other: &[0xaa],
    };
    let mut out = Vec::new();
    vars.feed(&mut |d: &[u8]| out.extend_from_slice(d));
    assert_eq!(
        out,
        b"\x01a\x01b\x00\x00\xff\x00\x00\x00\x00\x01a\x01b\x00\x01\x02\x03\x04\x05\x06\x07\x08\x00\x12\x00\x01\xaa"
    );
    let mut out = Vec::new();
    vars.feed_timers(&mut |d: &[u8]| out.extend_from_slice(d));
    assert_eq!(out, [1, 2, 3, 4, 5, 6, 7, 8]);
    let mut out = Vec::new();
    feed_prior_mac(&[1, 2, 3], &mut |d: &[u8]| out.extend_from_slice(d));
    assert_eq!(out, [0, 3, 1, 2, 3]);
    let mut out = Vec::new();
    assert_eq!(
        feed_message(&[0; 11], None, 0, &mut |d: &[u8]| out.extend_from_slice(d)),
        Err(Error::UnexpectedEof)
    );
    // ARCOUNT 0 cannot hold a TSIG.
    assert_eq!(
        feed_message(&[0; 12], Some(12), 0, &mut |d: &[u8]| out
            .extend_from_slice(d)),
        Err(Error::UnexpectedEof)
    );
    assert_eq!(
        feed_message(
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            Some(13),
            0,
            &mut |d: &[u8]| out.extend_from_slice(d)
        ),
        Err(Error::UnexpectedEof)
    );
}

#[test]
fn mac_buf() {
    let m = MacBuf::new(&[1, 2, 3]).unwrap();
    assert_eq!(m.as_slice(), &[1, 2, 3]);
    assert_eq!(m.len(), 3);
    assert!(!m.is_empty());
    assert_eq!(m.as_ref(), &[1, 2, 3]);
    assert_eq!(std::format!("{m:?}"), "MacBuf(010203)");
    assert!(MacBuf::new(&[0; 64]).is_ok());
    assert_eq!(MacBuf::new(&[0; 65]), Err(Error::BadMacSize));
}
