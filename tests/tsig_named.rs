//! TSIG interoperability with BIND 9.18.
//!
//! The messages under `tests/data/named/` were captured (October 2026)
//! between `dig`/`nsupdate` and a local `named`, all using the shared
//! secret `00 01 02 .. 1f` (base64 `AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=`)
//! under different key names and algorithms. HMAC is deterministic, so
//! besides verifying BIND's MACs we also re-sign BIND's messages and
//! rebuild its error responses byte for byte.

#![cfg(feature = "tsig")]

use dnsbox::tsig::{self, HmacKey, TsigAlgorithm, TsigKey, TsigRcode, TsigSigner, TsigVerifier};
use dnsbox::{Error, Flags, Message, MessageBuilder, NameBuf, Rcode};

const SECRET: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

fn data(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/data/named/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn key(name: &str, alg: TsigAlgorithm) -> HmacKey<'static> {
    let n: NameBuf = name.parse().unwrap();
    HmacKey::new(&n, alg, &SECRET)
}

/// (capture prefix, key name, algorithm)
const ALGORITHMS: &[(&str, &str, TsigAlgorithm)] = &[
    ("query-md5", "md5-key", TsigAlgorithm::HmacMd5),
    ("query-sha1", "sha1-key", TsigAlgorithm::HmacSha1),
    ("query-sha224", "sha224-key", TsigAlgorithm::HmacSha224),
    ("query-sha256", "tsig-key", TsigAlgorithm::HmacSha256),
    ("query-sha384", "sha384-key", TsigAlgorithm::HmacSha384),
    ("query-sha512", "sha512-key", TsigAlgorithm::HmacSha512),
];

#[test]
fn every_algorithm_request_and_response() {
    for &(prefix, name, alg) in ALGORITHMS {
        let key = key(name, alg);
        let query = data(&format!("{prefix}.query.bin"));
        let response = data(&format!("{prefix}.response.bin"));
        let q = Message::parse_validated(&query).unwrap();
        let rec = tsig::find(&q).unwrap().expect("signed");
        let now = rec.data.time_signed;

        // Server side.
        let verified = tsig::verify_request(&q, &key, now)
            .verified()
            .unwrap_or_else(|| panic!("{prefix}"));
        assert_eq!(verified.request_mac().len(), alg.digest_len());

        // Client side.
        let mut v = TsigVerifier::new(&key, verified.request_mac()).unwrap();
        let r = Message::parse_validated(&response).unwrap();
        assert!(v.verify(&r, now).unwrap().is_some(), "{prefix}");
        v.finish().unwrap();

        // Re-sign the query ourselves: identical bytes.
        let mut buf = [0u8; 512];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.set_id(q.id());
        b.set_flags(q.flags());
        b.copy_question(&q.questions().next().unwrap().unwrap())
            .unwrap();
        let mac = TsigSigner::request(&key)
            .with_fudge(rec.data.fudge)
            .sign(&mut b, now)
            .unwrap();
        assert_eq!(mac.as_slice(), rec.data.mac, "{prefix}");
        assert_eq!(b.finish(), &query[..], "{prefix}");

        // Re-sign the response: identical bytes too.
        let r_rec = tsig::find(&r).unwrap().unwrap();
        let mut buf = [0u8; 512];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.set_id(r.id());
        b.set_flags(r.flags());
        b.copy_question(&r.questions().next().unwrap().unwrap())
            .unwrap();
        for rr in r.answers() {
            b.copy_record(dnsbox::Section::Answer, &rr.unwrap())
                .unwrap();
        }
        verified
            .signer()
            .with_fudge(r_rec.data.fudge)
            .sign(&mut b, r_rec.data.time_signed)
            .unwrap();
        assert_eq!(b.finish(), &response[..], "{prefix} response");

        // Wrong time: BADTIME both ways.
        let late = now + u64::from(rec.data.fudge) + 1;
        let rej = tsig::verify_request(&q, &key, late).rejected().unwrap();
        assert_eq!(rej.error, Error::BadTime);
        let mut v = TsigVerifier::new(&key, verified.request_mac()).unwrap();
        assert_eq!(v.verify(&r, late), Err(Error::BadTime));
        // Within the fudge on the other side is fine.
        assert!(
            tsig::verify_request(&q, &key, now - 300)
                .verified()
                .is_some()
        );
    }
}

#[test]
fn wrong_key_or_algorithm() {
    let query = data("query-sha256.query.bin");
    let q = Message::parse(&query).unwrap();
    let now = tsig::find(&q).unwrap().unwrap().data.time_signed;
    // Same name, other algorithm: BADKEY.
    let other_alg = key("tsig-key", TsigAlgorithm::HmacSha512);
    let rej = tsig::verify_request(&q, &other_alg, now)
        .rejected()
        .unwrap();
    assert_eq!(rej.error, Error::BadKey);
    assert_eq!(rej.rcode(), Rcode::NOTAUTH);
    assert_eq!(rej.tsig_error(), TsigRcode::BADKEY);
    // A key store with several keys finds the right one.
    let keys = [
        key("md5-key", TsigAlgorithm::HmacMd5),
        key("TSIG-KEY", TsigAlgorithm::HmacSha256),
    ];
    let ok = tsig::verify_request(&q, &keys[..], now).verified().unwrap();
    assert_eq!(ok.key.name(), keys[1].name());
    // Right name and algorithm, wrong secret: BADSIG.
    let bad = HmacKey::new(keys[1].name(), TsigAlgorithm::HmacSha256, b"wrong");
    let rej = tsig::verify_request(&q, &bad, now).rejected().unwrap();
    assert_eq!(rej.error, Error::BadSignature);
}

#[test]
fn truncated_mac() {
    // BIND key "trunc-key" is `hmac-sha256-128`: the algorithm name on the
    // wire is hmac-sha256 and the MAC is truncated to 16 bytes.
    let query = data("query-sha256-trunc.query.bin");
    let response = data("query-sha256-trunc.response.bin");
    let q = Message::parse(&query).unwrap();
    let rec = tsig::find(&q).unwrap().unwrap();
    assert_eq!(rec.data.mac.len(), 16);
    let now = rec.data.time_signed;

    let trunc = key("trunc-key", TsigAlgorithm::HmacSha256)
        .with_mac_len(16)
        .unwrap();
    let verified = tsig::verify_request(&q, &trunc, now).verified().unwrap();
    let mut v = TsigVerifier::new(&trunc, verified.request_mac()).unwrap();
    let r = Message::parse(&response).unwrap();
    assert_eq!(tsig::find(&r).unwrap().unwrap().data.mac.len(), 16);
    assert!(v.verify(&r, now).unwrap().is_some());

    // A key that requires full-length MACs: the MAC verifies but is below
    // policy, so BADTRUNC (RFC 8945 §5.2.4).
    let full = key("trunc-key", TsigAlgorithm::HmacSha256);
    let rej = tsig::verify_request(&q, &full, now).rejected().unwrap();
    assert_eq!(rej.error, Error::BadTrunc);
    assert_eq!(rej.tsig_error(), TsigRcode::BADTRUNC);
    let mut v = TsigVerifier::new(&full, verified.request_mac()).unwrap();
    assert_eq!(v.verify(&r, now), Err(Error::BadTrunc));

    // Re-signing with the truncating key reproduces BIND's bytes.
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.set_id(q.id());
    b.set_flags(q.flags());
    b.copy_question(&q.questions().next().unwrap().unwrap())
        .unwrap();
    TsigSigner::request(&trunc).sign(&mut b, now).unwrap();
    assert_eq!(b.finish(), &query[..]);

    // The `hmac-sha256-128` algorithm name is a distinct algorithm (RFC
    // 8945 §6) and does not match BIND's `hmac-sha256` record.
    let named_128 = key("trunc-key", TsigAlgorithm::HmacSha256_128);
    assert_eq!(named_128.mac_len(), 16);
    assert_eq!(
        tsig::verify_request(&q, &named_128, now)
            .rejected()
            .unwrap()
            .error,
        Error::BadKey
    );
}

/// Rebuilds a BIND error response from the rejected request.
fn rebuild_error(query: &[u8], response: &[u8], store: &[HmacKey<'_>], now: u64) -> Vec<u8> {
    let q = Message::parse(query).unwrap();
    let r = Message::parse(response).unwrap();
    let rej = tsig::verify_request(&q, store, now).rejected().unwrap();
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.set_id(q.id());
    b.set_flags(
        Flags::default()
            .with_qr(true)
            .with_rd(true)
            .with_rcode(rej.rcode()),
    );
    assert_eq!(b.header().flags, r.flags());
    b.copy_question(&q.questions().next().unwrap().unwrap())
        .unwrap();
    rej.sign_response(&mut b, now).unwrap();
    b.finish().to_vec()
}

#[test]
fn bind_error_responses() {
    let store = [key("tsig-key", TsigAlgorithm::HmacSha256)];

    // BADKEY: unknown key "nokey"; unsigned TSIG echoing the request.
    let query = data("badkey.query.bin");
    let response = data("badkey.response.bin");
    let now = 1_791_104_299;
    assert_eq!(rebuild_error(&query, &response, &store, now), response);
    let r = Message::parse(&response).unwrap();
    let t = tsig::find(&r).unwrap().unwrap();
    assert_eq!(t.data.error, TsigRcode::BADKEY);
    let nokey = key("nokey", TsigAlgorithm::HmacSha256);
    let mut v = TsigVerifier::new(&nokey, &[0; 32]).unwrap();
    assert_eq!(v.verify(&r, now), Err(Error::TsigErrorResponse));

    // BADSIG: wrong secret on the client.
    let query = data("badsig.query.bin");
    let response = data("badsig.response.bin");
    let now = 1_791_104_316;
    assert_eq!(rebuild_error(&query, &response, &store, now), response);
    let mut v = TsigVerifier::new(&store[0], &[0; 32]).unwrap();
    assert_eq!(
        v.verify(&Message::parse(&response).unwrap(), now),
        Err(Error::TsigErrorResponse)
    );

    // BADTIME: the client clock was 1000 s behind. The response is signed
    // with the request MAC, keeps the request's Time Signed and carries
    // the server time in Other Data.
    let query = data("badtime.query.bin");
    let response = data("badtime.response.bin");
    let server_now = 0x6ac2_15dd;
    assert_eq!(
        rebuild_error(&query, &response, &store, server_now),
        response
    );
    let q = Message::parse(&query).unwrap();
    let mac = tsig::find(&q).unwrap().unwrap().data.mac;
    let r = Message::parse(&response).unwrap();
    let mut v = TsigVerifier::new(&store[0], mac).unwrap();
    assert_eq!(v.verify(&r, server_now - 1000), Err(Error::BadTime));
    let t = tsig::find(&r).unwrap().unwrap();
    assert_eq!(t.data.error, TsigRcode::BADTIME);
    assert_eq!(t.data.other, &[0, 0, 0x6a, 0xc2, 0x15, 0xdd]);
}

#[test]
fn update_and_notify() {
    let key = key("tsig-key", TsigAlgorithm::HmacSha256);
    for (q, r) in [
        ("update1.query.bin", "update1.response.bin"),
        ("update2.query.bin", "update2.response.bin"),
        ("update-fail.query.bin", "update-fail.response.bin"),
        ("update1.notify.bin", ""),
        ("update2.notify.bin", ""),
    ] {
        let query = data(q);
        let msg = Message::parse_validated(&query).unwrap();
        let now = tsig::find(&msg).unwrap().unwrap().data.time_signed;
        let verified = tsig::verify_request(&msg, &key, now)
            .verified()
            .unwrap_or_else(|| panic!("{q}"));
        if r.is_empty() {
            continue;
        }
        let response = data(r);
        let mut v = TsigVerifier::new(&key, verified.request_mac()).unwrap();
        assert!(
            v.verify(&Message::parse(&response).unwrap(), now)
                .unwrap()
                .is_some()
        );
        v.finish().unwrap();
    }
}

#[test]
fn axfr_stream() {
    // A signed AXFR over TCP: three messages, each signed; the second and
    // third MACs cover the prior MAC and the timers only (RFC 8945 §5.3.1).
    let key = key("tsig-key", TsigAlgorithm::HmacSha256);
    let query = data("axfr.query.bin");
    let q = Message::parse(&query).unwrap();
    let now = tsig::find(&q).unwrap().unwrap().data.time_signed;
    let verified = tsig::verify_request(&q, &key, now).verified().unwrap();
    let parts: Vec<Vec<u8>> = [
        "axfr.response.bin",
        "axfr.response2.bin",
        "axfr.response3.bin",
    ]
    .iter()
    .map(|n| data(n))
    .collect();
    let mut v = TsigVerifier::new(&key, verified.request_mac()).unwrap();
    for p in &parts {
        let m = Message::parse_validated(p).unwrap();
        assert!(v.verify(&m, now).unwrap().is_some());
    }
    v.finish().unwrap();

    // Out of order: the chain breaks.
    let mut v = TsigVerifier::new(&key, verified.request_mac()).unwrap();
    v.verify(&Message::parse(&parts[0]).unwrap(), now).unwrap();
    assert_eq!(
        v.verify(&Message::parse(&parts[2]).unwrap(), now),
        Err(Error::BadSignature)
    );

    // Re-sign the whole stream: identical bytes, message after message.
    let mut signer = verified.signer();
    for p in &parts {
        let m = Message::parse(p).unwrap();
        let t = tsig::find(&m).unwrap().unwrap();
        let mut out = p[..t.start].to_vec();
        // ARCOUNT back to its value before the TSIG was added.
        let ar = u16::from_be_bytes([out[10], out[11]]) - 1;
        out[10..12].copy_from_slice(&ar.to_be_bytes());
        let mut storage = vec![0u8; p.len()];
        let mut w = dnsbox::WireWriter::new(&mut storage);
        dnsbox::OutBuf::append(&mut w, &out).unwrap();
        signer.sign_buf(&mut w, 0, t.data.time_signed).unwrap();
        assert_eq!(w.written(), &p[..]);
    }
}

#[test]
fn ixfr_responses() {
    let key = key("tsig-key", TsigAlgorithm::HmacSha256);
    for (q, r) in [
        ("ixfr1.query.bin", "ixfr1.response.bin"),
        ("ixfr-uptodate.query.bin", "ixfr-uptodate.response.bin"),
    ] {
        let query = data(q);
        let m = Message::parse(&query).unwrap();
        let now = tsig::find(&m).unwrap().unwrap().data.time_signed;
        let verified = tsig::verify_request(&m, &key, now).verified().unwrap();
        let mut v = TsigVerifier::new(&key, verified.request_mac()).unwrap();
        assert!(
            v.verify(&Message::parse(&data(r)).unwrap(), now)
                .unwrap()
                .is_some()
        );
        v.finish().unwrap();
    }
}

#[test]
fn tampering_never_verifies() {
    let key = key("tsig-key", TsigAlgorithm::HmacSha256);
    let query = data("query-sha256.query.bin");
    let now = 1_791_104_299;
    let start = tsig::find(&Message::parse(&query).unwrap())
        .unwrap()
        .unwrap()
        .start;
    for i in 0..query.len() {
        for bit in [0x01u8, 0x20, 0x80] {
            let mut m = query.clone();
            m[i] ^= bit;
            let Ok(msg) = Message::parse(&m) else {
                continue;
            };
            let res = tsig::verify_request(&msg, &key, now);
            // The header ID (replaced by the original ID) and the case of
            // the TSIG key/algorithm names (canonicalised) are not covered.
            let uncovered = i < 2 || (i >= start && bit == 0x20 && m[i].is_ascii_alphabetic());
            if !uncovered {
                assert!(
                    res.verified().is_none(),
                    "flip {bit:#x} at {i} still verifies"
                );
            }
        }
    }
    // Every truncation fails cleanly.
    for end in 0..query.len() {
        if let Ok(msg) = Message::parse(&query[..end]) {
            assert!(tsig::verify_request(&msg, &key, now).verified().is_none());
        }
    }
}
