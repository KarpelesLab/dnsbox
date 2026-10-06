use super::*;
use crate::WireWriter;
use crate::rdata::{TkeyMode, TsigRcode, UnknownRdata};
use crate::{Error, NameBuf, Rcode};
use std::vec::Vec;

fn names() -> (NameBuf, NameBuf) {
    (
        "key.example".parse().unwrap(),
        "hmac-sha256".parse().unwrap(),
    )
}

/// The message `f` writes into a fresh growable builder.
fn build(f: impl FnOnce(&mut MessageBuilder<WireWriter<'_>>)) -> Vec<u8> {
    let mut buf = std::vec![0u8; 65535];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    f(&mut b);
    b.finish().to_vec()
}

#[test]
fn query_and_response() {
    let (key, alg) = names();
    let data = Tkey::new(alg.as_name(), 1, 2, TkeyMode::DIFFIE_HELLMAN, &[9; 16]);
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.set_id(77);
    // Leftover flags are replaced.
    b.set_flags(Flags::default().with_rd(true).with_qr(true));
    build_query(&mut b, &key, &data).unwrap();
    let query = b.finish().to_vec();
    let q = Message::parse_validated(&query).unwrap();
    assert_eq!(q.id(), 77);
    assert!(!q.flags().rd() && !q.flags().qr());
    assert_eq!(q.flags().opcode(), Opcode::QUERY);
    assert_eq!(
        (q.header().qdcount, q.header().ancount, q.header().arcount),
        (1, 0, 1)
    );
    let found = find(&q).unwrap().unwrap();
    assert_eq!(found.data, data);
    assert_eq!(find_request(&q).unwrap(), found);

    let mut rbuf = [0u8; 512];
    let mut r = MessageBuilder::new(&mut rbuf).unwrap();
    let assigned: NameBuf = "89n3mDgX072pp.server1.example.com".parse().unwrap();
    build_response(&mut r, &q, &assigned, &data.with_error(TsigRcode::BADALG)).unwrap();
    let resp = Message::parse_validated(r.finish()).unwrap();
    assert_eq!(resp.id(), 77);
    assert!(resp.flags().qr());
    assert_eq!(
        resp.questions().next().unwrap().unwrap().name(),
        key.as_name()
    );
    let rr = resp.answers().next().unwrap().unwrap();
    assert_eq!((rr.class(), rr.ttl()), (Class::ANY, 0));
    let found = find(&resp).unwrap().unwrap();
    assert_eq!(found.key_name, assigned.as_name());
    assert_eq!(found.section, Section::Answer);
    assert_eq!(found.data.error, TsigRcode::BADALG);
    assert_eq!(find_answer(&resp).unwrap(), found);
}

#[test]
fn errors_leave_the_builder_unchanged() {
    let (key, alg) = names();
    let data = Tkey::new(alg.as_name(), 1, 2, TkeyMode::GSSAPI, &[0; 64]);
    // Not empty.
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.push_question(&key, Rtype::A, Class::IN).unwrap();
    let before = b.as_bytes().to_vec();
    assert_eq!(build_query(&mut b, &key, &data), Err(Error::SectionOrder));
    assert_eq!(b.as_bytes(), before);
    // Too small for the TKEY record: nothing (not even the question)
    // is left behind, and the flags are restored.
    let mut small = [0u8; 60];
    let mut b = MessageBuilder::new(&mut small).unwrap();
    b.set_flags(Flags::default().with_rd(true));
    let before = b.as_bytes().to_vec();
    assert_eq!(build_query(&mut b, &key, &data), Err(Error::BufferTooSmall));
    assert_eq!(b.as_bytes(), before);
    assert!(b.header().flags.rd());
    // The same with a KEY that does not fit after the TKEY.
    let mut buf = [0u8; 160];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    let big = Key::new(0, 3, crate::dnssec::Algorithm::DH, &[7; 100]);
    assert_eq!(
        build_query_with_key(&mut b, &key, &data, &key, &big),
        Err(Error::BufferTooSmall)
    );
    assert!(b.is_empty());
    assert_eq!(b.header().flags, Flags::default());
    // Response: the same.
    let mut qbuf = [0u8; 512];
    let mut q = MessageBuilder::new(&mut qbuf).unwrap();
    build_query(&mut q, &key, &data).unwrap();
    let q = Message::parse(q.finish()).unwrap();
    let mut b = MessageBuilder::new(&mut small).unwrap();
    b.set_id(5);
    let before = b.as_bytes().to_vec();
    assert_eq!(
        build_response(&mut b, &q, &key, &data),
        Err(Error::BufferTooSmall)
    );
    assert_eq!(b.as_bytes(), before);
    assert_eq!(b.header().id, 5);
}

#[test]
fn find_errors() {
    let (key, alg) = names();
    let data = Tkey::new(alg.as_name(), 1, 2, TkeyMode::GSSAPI, &[]);
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    build_query(&mut b, &key, &data).unwrap();
    let mut wire = b.finish().to_vec();
    // Truncate the TKEY RDATA: its RDLENGTH now overruns the message.
    wire.pop();
    let msg = Message::parse(&wire).unwrap();
    assert_eq!(find(&msg), Err(Error::UnexpectedEof));
    assert_eq!(find_request(&msg), Err(Error::UnexpectedEof));
    // Every truncation of a valid request fails cleanly.
    let wire = build(|b| build_query(b, &key, &data).unwrap());
    for end in 12..wire.len() {
        if let Ok(msg) = Message::parse(&wire[..end]) {
            assert!(find_request(&msg).is_err(), "{end}");
        }
    }
}

#[test]
fn request_rules() {
    let (key, alg) = names();
    let other: NameBuf = "other.example".parse().unwrap();
    let data = Tkey::new(alg.as_name(), 1, 2, TkeyMode::GSSAPI, &[1]);
    fn check(wire: &[u8]) -> Result<TkeyRecord<'_>> {
        find_request(&Message::parse(wire).unwrap())
    }
    let good = build(|b| build_query(b, &key, &data).unwrap());
    assert_eq!(check(&good).unwrap().data, data);
    // A response, another opcode.
    let mut bad = good.clone();
    bad[2] |= 0x80;
    assert_eq!(check(&bad), Err(Error::InvalidTkey));
    let mut bad = good.clone();
    bad[2] = Opcode::UPDATE.get() << 3;
    assert_eq!(check(&bad), Err(Error::InvalidTkey));
    // Hand-built shapes.
    let shape = |questions: &[(&NameBuf, Rtype)], records: &[(Section, &NameBuf)]| {
        build(|b| {
            for (n, t) in questions {
                b.push_question(*n, *t, Class::ANY).unwrap();
            }
            for (s, n) in records {
                b.push_record(*s, *n, Class::ANY, 0, &data).unwrap();
            }
        })
    };
    let add = Section::Additional;
    for wire in [
        // No question, two questions, another type.
        shape(&[], &[(add, &key)]),
        shape(&[(&key, Rtype::TKEY), (&key, Rtype::TKEY)], &[(add, &key)]),
        shape(&[(&key, Rtype::A)], &[(add, &key)]),
        // No TKEY, two, another owner, the authority section.
        shape(&[(&key, Rtype::TKEY)], &[]),
        shape(&[(&key, Rtype::TKEY)], &[(add, &key), (add, &key)]),
        shape(
            &[(&key, Rtype::TKEY)],
            &[(Section::Answer, &key), (add, &key)],
        ),
        shape(&[(&key, Rtype::TKEY)], &[(add, &other)]),
        shape(&[(&key, Rtype::TKEY)], &[(Section::Authority, &key)]),
    ] {
        assert_eq!(check(&wire), Err(Error::InvalidTkey));
    }
    // Windows 2000 put the TKEY in the answer section; BIND accepts it.
    let win = shape(&[(&key, Rtype::TKEY)], &[(Section::Answer, &key)]);
    assert_eq!(check(&win).unwrap().section, Section::Answer);
    // Names compare case-insensitively.
    let upper: NameBuf = "KEY.Example".parse().unwrap();
    let mixed = shape(&[(&key, Rtype::TKEY)], &[(add, &upper)]);
    assert!(check(&mixed).is_ok());
}

#[test]
fn answer_rules() {
    let (key, alg) = names();
    let data = Tkey::new(alg.as_name(), 1, 2, TkeyMode::GSSAPI, &[1]);
    let query = build(|b| build_query(b, &key, &data).unwrap());
    let q = Message::parse(&query).unwrap();
    assert_eq!(find_answer(&q), Err(Error::InvalidTkey));
    let good = build(|b| build_response(b, &q, &key, &data).unwrap());
    assert!(find_answer(&Message::parse(&good).unwrap()).is_ok());
    // An error RCODE.
    let refused = build(|b| {
        b.start_response(&q).unwrap();
        b.set_rcode(Rcode::NOTAUTH);
    });
    assert_eq!(
        find_answer(&Message::parse(&refused).unwrap()),
        Err(Error::ErrorResponse)
    );
    // No TKEY in the answer section: none, or only a spontaneous one.
    let none = build(|b| b.start_response(&q).unwrap());
    let spontaneous = build(|b| {
        b.start_response(&q).unwrap();
        b.push_additional(&key, Class::ANY, 0, &data).unwrap();
    });
    let two = build(|b| {
        build_response(b, &q, &key, &data).unwrap();
        b.push_answer(&key, Class::ANY, 0, &data).unwrap();
    });
    for wire in [none, spontaneous, two] {
        assert_eq!(
            find_answer(&Message::parse(&wire).unwrap()),
            Err(Error::InvalidTkey)
        );
    }
}

#[test]
fn key_records() {
    let (key, alg) = names();
    let rsa = Key::new(0x0200, 3, crate::dnssec::Algorithm::RSASHA256, &[1, 3, 5]);
    let wire = build(|b| {
        build_query(
            b,
            &key,
            &Tkey::new(alg.as_name(), 0, 0, TkeyMode::GSSAPI, &[]),
        )
        .unwrap();
        b.push_additional(&key, Class::ANY, 0, &rsa).unwrap();
        // A KEY too short for its fixed fields.
        b.push_additional(&key, Class::ANY, 0, &UnknownRdata::new(Rtype::KEY, &[1, 2]))
            .unwrap();
        b.push_additional(&key, Class::ANY, 0, &rsa).unwrap();
    });
    let msg = Message::parse(&wire).unwrap();
    let found: Vec<_> = keys(&msg, Section::Additional).collect();
    assert_eq!(found, [Ok((key.as_name(), rsa)), Err(Error::UnexpectedEof)]);
    assert_eq!(keys(&msg, Section::Question).count(), 0);
    // A truncated message ends the iteration with its error.
    let cut = Message::parse(&wire[..wire.len() - 1]).unwrap();
    let last = keys(&cut, Section::Additional).last().unwrap();
    assert_eq!(last, Err(Error::UnexpectedEof));
}

#[test]
fn deletion() {
    let (key, alg) = names();
    let now = 1_791_104_299;
    let query = build(|b| build_deletion_query(b, &key, &alg, now).unwrap());
    let q = Message::parse_validated(&query).unwrap();
    let request = find_request(&q).unwrap();
    assert_eq!(
        request.data,
        Tkey::new(alg.as_name(), now, now, TkeyMode::KEY_DELETION, &[])
    );
    assert_eq!(find_deletion(&q), Err(Error::InvalidTkey));
    for (deleted, error) in [(true, TsigRcode::NOERROR), (false, TsigRcode::BADNAME)] {
        let response = build(|b| build_deletion_response(b, &q, &request, deleted).unwrap());
        let r = Message::parse_validated(&response).unwrap();
        let answer = find_deletion(&r).unwrap().unwrap();
        assert_eq!(answer.data, request.data.with_error(error));
        assert_eq!(
            (answer.key_name, answer.section),
            (key.as_name(), Section::Answer)
        );
    }
    // Not a deletion request.
    let gss = build(|b| {
        build_query(
            b,
            &key,
            &Tkey::new(alg.as_name(), 0, 0, TkeyMode::GSSAPI, &[1]),
        )
        .unwrap();
    });
    let gss = Message::parse(&gss).unwrap();
    let other = find_request(&gss).unwrap();
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    assert_eq!(
        build_deletion_response(&mut b, &gss, &other, true),
        Err(Error::InvalidTkey)
    );
    assert!(b.is_empty());
    let answered = build(|b| build_response(b, &gss, &key, &other.data).unwrap());
    assert_eq!(find_deletion(&Message::parse(&answered).unwrap()), Ok(None));
    // A notice after the additional section's other records.
    let notice = build(|b| {
        b.start_response(&gss).unwrap();
        b.push_additional(
            &key,
            Class::IN,
            60,
            &crate::rdata::A::new([192, 0, 2, 1].into()),
        )
        .unwrap();
        push_deletion_notice(b, &key, &alg, now).unwrap();
    });
    let n = Message::parse_validated(&notice).unwrap();
    let found = find_deletion(&n).unwrap().unwrap();
    assert_eq!(
        (found.section, found.data.mode),
        (Section::Additional, TkeyMode::KEY_DELETION)
    );
}

/// A deletion request signed with the key it deletes (RFC 2930 §4.2),
/// and the server's answer signed with it before it is discarded.
#[cfg(all(feature = "tsig", feature = "alloc"))]
#[test]
fn deletion_signed_with_the_key() {
    use crate::tsig::{self, HmacKey, TsigAlgorithm, TsigSigner, TsigVerifier};
    let (key_name, _) = names();
    let key = HmacKey::new(&key_name, TsigAlgorithm::HmacSha256, b"established by TKEY");
    let now = 1_791_104_299u32;
    let mut b = MessageBuilder::new_vec();
    build_deletion_query(&mut b, &key_name, TsigAlgorithm::HmacSha256.name(), now).unwrap();
    let mac = TsigSigner::request(&key).sign(&mut b, now.into()).unwrap();
    let query = b.finish();
    let q = Message::parse_validated(&query).unwrap();
    let verified = tsig::verify_request(&q, &key, now.into())
        .verified()
        .unwrap();
    let request = find_request(&q).unwrap();
    assert_eq!(request.key_name, key_name.as_name());
    let mut r = MessageBuilder::new_vec();
    build_deletion_response(&mut r, &q, &request, true).unwrap();
    verified.signer().sign(&mut r, now.into()).unwrap();
    let response = r.finish();
    let resp = Message::parse_validated(&response).unwrap();
    let mut v = TsigVerifier::new(&key, mac.as_slice()).unwrap();
    assert!(v.verify(&resp, now.into()).unwrap().is_some());
    let gone = find_deletion(&resp).unwrap().unwrap();
    assert_eq!(
        (gone.key_name, gone.data.error),
        (key_name.as_name(), TsigRcode::NOERROR)
    );
}

#[cfg(feature = "tkey")]
mod crypto {
    use super::*;
    use crate::dnssec::Algorithm;
    use crate::testutil::hex;
    use crate::tsig::{self, TsigAlgorithm, TsigSigner, TsigVerifier};
    use purecrypto::bignum::BoxedUint;
    use purecrypto::hash::Sha256;
    use purecrypto::rng::HmacDrbg;
    use purecrypto::rsa::BoxedRsaPrivateKey;
    use std::format;
    use std::sync::OnceLock;

    fn rng(seed: &[u8]) -> HmacDrbg<Sha256> {
        HmacDrbg::new(seed, b"dnsbox tkey tests", b"")
    }

    fn seq(start: u8) -> [u8; 32] {
        core::array::from_fn(|i| start.wrapping_add(i as u8))
    }

    fn dh(pair: &DhKeyPair) -> DhKey<'_> {
        DhKey::parse(pair.public_key()).unwrap()
    }

    // Computed with an independent Python implementation (pow() and
    // hashlib.md5) of RFC 2930 §4.1: private exponents 0x0102..20 and
    // 0xa1a2..c0, query nonce 00..0f, server nonce 10..1f.
    const VECTORS: [(u16, &str, &str, &str, &str); 2] = [
        (
            1,
            "2002119f47b6ef040d0c814d13a0743cd226f1fe3b7b4263de6a19cd91497fbf57916ed4dac22c535858e4cdb2a20c2d8ece495cb825fb8e4c7cb2f54e2785fa7a32e461948d2aaae617901ae10744d2cc3c4ed713c5572ff9eba7000ed9e3f1",
            "844a9598475366f87730a1ddf64c6721c520a99a8239192ea5c4972a27d7188469494dd868b7bbc3f3a30d414b4934a1a5e4649abefed78314fc492c77585d34962f051b1b4704366b78b5462cfe4325067e6c7ce68760fcf55074d951e2e2ce",
            "4d2687d6e515d17447f1c61d6bd43927be73f19f3cd5a2036124025c45d35b155cf0c15628d9b0d3a640ea9290e69bc5dd3b77ec73b5f6f847bf1c26aacc89f93b9d77d073ff6891366345febc6fed2e674c5f977327a019adeb03f7e2c5df4d",
            "e6bb3b345423649ec6535edf98037b73519f66f3ff7240f8357bb361cd5a4d805cf0c15628d9b0d3a640ea9290e69bc5dd3b77ec73b5f6f847bf1c26aacc89f93b9d77d073ff6891366345febc6fed2e674c5f977327a019adeb03f7e2c5df4d",
        ),
        (
            2,
            "457120764f3a1e6fd58103e41a4093a6c8bc1d97cb8759de41c21afdd2d3048a5ef3d88ce24aa6ba4fe30bcfb0b0f75abf1a8aeaff3723f1bf53740c902005e1199fabad7c538e94a7034fd585339a02f3634893f748929d2a7257643e398130541ae64124c17d4507a97f1cbebeb7b933642b8df479eb59e36cfeffbf1671dd",
            "0924d5187b7fa13511c4de16e076db4f96b299e0ad25bb6b9a81d2e70f33904234e07563f23b7506351c1334fb6eb219d78d44bfe3d6d78551dbef755493db8c9131bcd2d82769769035b3d5ee9925fac351ee9a7989bf3d16a4e5788073e8c1e2cbc425b897dba9b3ca911902bfbaa5cebe0cd4980362c043533f2f60ea4150",
            "9bda870b3394f14eb03369a865b15ad4e546fe831e7aaf3ba0a7dd16b2177fb9ed2fae5a4d993fd7a943eae84b044b2d61d327e796db572f1ee6078d1278c7984a4c67a865f6d17cc688041c60989eddb1fd85402494840c8bba509a678337a36b982e06acf2490887a34603d2526768aa9e389929b280b3e8c10b5fbbc21bf8",
            "790fa3bca900d56502d88baaf9ed2777b563874a04a8dfd3c55d2bcf5740d4baed2fae5a4d993fd7a943eae84b044b2d61d327e796db572f1ee6078d1278c7984a4c67a865f6d17cc688041c60989eddb1fd85402494840c8bba509a678337a36b982e06acf2490887a34603d2526768aa9e389929b280b3e8c10b5fbbc21bf8",
        ),
    ];

    #[test]
    fn independent_vectors() {
        let query_nonce: Vec<u8> = (0..16).collect();
        let server_nonce: Vec<u8> = (16..32).collect();
        for (group, a, b, z, k) in VECTORS {
            let g = DhGroup::well_known(group).unwrap();
            let alice = DhKeyPair::from_private_bytes(g.clone(), &seq(1)).unwrap();
            let bob = DhKeyPair::from_private_bytes(g, &seq(0xa1)).unwrap();
            assert_eq!(dh(&alice).public_value, hex(a));
            assert_eq!(dh(&bob).public_value, hex(b));
            assert_eq!(dh(&alice).prime, DhPrime::WellKnown(group));
            let z_ab = alice.dh_value(&dh(&bob)).unwrap();
            assert_eq!(z_ab, hex(z));
            assert_eq!(bob.dh_value(&dh(&alice)).unwrap(), z_ab);
            assert_eq!(
                dh_keying_material(&z_ab, &query_nonce, &server_nonce),
                hex(k)
            );
        }
        // Short DH values: the digests are the longer operand.
        assert_eq!(
            dh_keying_material(&[1, 2, 3], b"q", b"s"),
            hex("04ff6d9719f2c5ad9bb488c93ce0c9b368a45b1489171c6dbc08860ba892a4d3")
        );
        assert_eq!(
            dh_keying_material(&[0; 40], b"", b""),
            hex("fd4b38e94292e00251b9f39c47ee5710fd4b38e94292e00251b9f39c47ee57100000000000000000")
        );
    }

    /// The Diffie-Hellman exchange of the fuzz seeds, whose messages were
    /// assembled independently (Python `struct`) from the vectors above.
    #[test]
    fn independently_built_messages() {
        let seed = |name: &str| {
            let path = format!("{}/fuzz/seeds/message/{name}", env!("CARGO_MANIFEST_DIR"));
            std::fs::read(path).unwrap()
        };
        let (query, response) = (seed("tkey-dh-query"), seed("tkey-dh-response"));
        let (q, r) = (
            Message::parse_validated(&query).unwrap(),
            Message::parse_validated(&response).unwrap(),
        );
        let g = DhGroup::well_known(2).unwrap();
        let client = DhKeyPair::from_private_bytes(g.clone(), &seq(1)).unwrap();
        let server = DhKeyPair::from_private_bytes(g, &seq(0xa1)).unwrap();
        let ours = client.complete(&q, &r).unwrap();
        let z = hex(VECTORS[1].3);
        assert_eq!(
            ours.secret(),
            dh_keying_material(&z, &[0x11; 16], &[0x22; 16])
        );
        // dnsbox's server writes the same response, byte for byte (but
        // for name compression, which the seed does not use).
        let owner: NameBuf = "server.example".parse().unwrap();
        let grant = KeyGrant::new(
            find_request(&q).unwrap().key_name,
            1_791_104_299,
            1_791_107_899,
        );
        let mut b = MessageBuilder::new_vec();
        b.set_compression(false);
        let theirs = server
            .respond(&mut b, &q, &owner, &grant, &[0x22; 16])
            .unwrap();
        assert_eq!(b.finish(), response);
        assert_eq!(theirs.secret(), ours.secret());
        let notice = seed("tkey-deletion-notice");
        let n = Message::parse_validated(&notice).unwrap();
        assert_eq!(find_deletion(&n).unwrap().unwrap().key_name, grant.key_name);
    }

    #[test]
    fn groups() {
        assert_eq!(DhGroup::well_known(0).unwrap_err(), Error::InvalidKey);
        assert_eq!(DhGroup::well_known(4).unwrap_err(), Error::InvalidKey);
        assert_eq!(DhGroup::rfc3526(13).unwrap_err(), Error::InvalidKey);
        for (i, bits) in [(1, 768), (2, 1024), (3, 1536)] {
            let g = DhGroup::well_known(i).unwrap();
            assert_eq!((g.bits(), g.generator()), (bits, &[2][..]));
            assert!(format!("{g:?}").contains(&format!("{bits}")));
        }
        for (i, bits) in [(14, 2048), (15, 3072), (16, 4096), (17, 6144), (18, 8192)] {
            let g = DhGroup::rfc3526(i).unwrap();
            assert_eq!((g.bits(), g.prime().len() * 8), (bits, bits));
        }
        // Explicit groups: too small, even, oversized, bad generator.
        let p2 = well_known_prime(2).unwrap();
        assert_eq!(DhGroup::explicit(p2, &[2]).unwrap_err(), Error::InvalidKey);
        let p14 = DhGroup::rfc3526(14).unwrap().prime().to_vec();
        let mut even = p14.clone();
        *even.last_mut().unwrap() ^= 1;
        assert_eq!(
            DhGroup::explicit(&even, &[2]).unwrap_err(),
            Error::InvalidKey
        );
        assert_eq!(
            DhGroup::explicit(&[0xff; 2100], &[2]).unwrap_err(),
            Error::InvalidKey
        );
        assert_eq!(
            DhGroup::explicit(&p14, &[1]).unwrap_err(),
            Error::InvalidKey
        );
        assert_eq!(
            DhGroup::explicit(&p14, &p14).unwrap_err(),
            Error::InvalidKey
        );
    }

    /// RFC 3526 group 14 through `explicit` (the full safe-prime check),
    /// with leading zeros, and an exchange in it: KEYs carry the prime.
    #[test]
    fn explicit_group_exchange() {
        let mut padded = std::vec![0u8];
        padded.extend_from_slice(DhGroup::rfc3526(14).unwrap().prime());
        let g = DhGroup::explicit(&padded, &[0, 2]).unwrap();
        assert_eq!((g.bits(), g.well_known_index()), (2048, None));
        let mut r = rng(b"explicit");
        let a = DhKeyPair::generate(g, &mut r);
        let b = DhKeyPair::generate(DhGroup::rfc3526(14).unwrap(), &mut r);
        let key = dh(&a);
        assert!(matches!(key.prime, DhPrime::Explicit(p) if p.len() == 256));
        assert_eq!(key.generator, [2]);
        assert_eq!(a.dh_value(&dh(&b)).unwrap(), b.dh_value(&key).unwrap());
        // Other groups are BADKEY.
        let c = DhKeyPair::generate(DhGroup::well_known(2).unwrap(), &mut r);
        assert_eq!(a.dh_value(&dh(&c)), Err(Error::BadKey));
        assert_eq!(c.dh_value(&key), Err(Error::BadKey));
    }

    #[test]
    fn hostile_public_values() {
        let g = DhGroup::well_known(1).unwrap();
        let pair = DhKeyPair::from_private_bytes(g, &seq(7)).unwrap();
        let p = well_known_prime(1).unwrap();
        let mut p_minus_1 = p.to_vec();
        *p_minus_1.last_mut().unwrap() -= 1;
        let mut long = std::vec![1u8; 97];
        long[0] = 0;
        let too_long = [1u8; 97];
        for value in [
            &[0][..],
            &[1],
            &[0, 0, 1],
            &p_minus_1[..],
            p,
            &[0xff; 96],
            &too_long[..],
        ] {
            let key = DhKey {
                prime: DhPrime::WellKnown(1),
                generator: &[],
                public_value: value,
            };
            assert_eq!(pair.dh_value(&key), Err(Error::InvalidKey), "{value:02x?}");
        }
        // Leading zeros are the same number.
        let key = DhKey {
            prime: DhPrime::WellKnown(1),
            generator: &[],
            public_value: &long,
        };
        assert!(pair.dh_value(&key).is_ok());
    }

    #[test]
    fn key_pairs() {
        let g = DhGroup::well_known(2).unwrap();
        assert_eq!(
            DhKeyPair::from_private_bytes(g.clone(), &[]).unwrap_err(),
            Error::InvalidKey
        );
        let p = well_known_prime(2).unwrap();
        assert_eq!(
            DhKeyPair::from_private_bytes(g.clone(), p).unwrap_err(),
            Error::InvalidKey
        );
        let pair = DhKeyPair::from_private_bytes(g.clone(), &seq(3)).unwrap();
        let again = DhKeyPair::from_private_bytes(g.clone(), &pair.private_bytes()).unwrap();
        assert_eq!(again.public_key(), pair.public_key());
        assert_eq!(pair.key().algorithm, Algorithm::DH);
        assert_eq!(pair.key().public_key, pair.public_key());
        assert!(!format!("{pair:?}").contains("private"));
        // Generated pairs differ.
        let mut r = rng(b"pairs");
        let a = DhKeyPair::generate(g.clone(), &mut r);
        let b = DhKeyPair::generate(g, &mut r);
        assert_ne!(a.public_key(), b.public_key());
        assert_ne!(a.private_bytes(), b.private_bytes());
    }

    struct Setup {
        server: DhKeyPair,
        client: DhKeyPair,
        key_name: NameBuf,
        alg: NameBuf,
        client_owner: NameBuf,
        server_owner: NameBuf,
    }

    fn setup(group: u16) -> Setup {
        let g = DhGroup::well_known(group).unwrap();
        Setup {
            server: DhKeyPair::from_private_bytes(g.clone(), &seq(0x40)).unwrap(),
            client: DhKeyPair::from_private_bytes(g, &seq(0x80)).unwrap(),
            key_name: "k1.client.example".parse().unwrap(),
            alg: "hmac-sha256".parse().unwrap(),
            client_owner: "client.example".parse().unwrap(),
            server_owner: "server.example".parse().unwrap(),
        }
    }

    const NOW: u32 = 1_791_104_299;

    impl Setup {
        fn request<'a>(&'a self, nonce: &'a [u8]) -> Tkey<'a> {
            Tkey::new(
                self.alg.as_name(),
                NOW,
                NOW + 86_400,
                TkeyMode::DIFFIE_HELLMAN,
                nonce,
            )
        }

        fn query(&self) -> Vec<u8> {
            build(|b| {
                self.client
                    .build_query(
                        b,
                        &self.key_name,
                        &self.request(&[0x11; 16]),
                        &self.client_owner,
                    )
                    .unwrap();
            })
        }

        fn grant(&self) -> KeyGrant<'_> {
            KeyGrant::new(self.key_name.as_name(), NOW, NOW + 3600)
        }
    }

    /// The whole exchange, authenticated with a key the parties already
    /// share (RFC 2930 §3), and the new key in use afterwards.
    #[test]
    fn dh_exchange_signed() {
        let s = setup(2);
        let admin: NameBuf = "admin.example".parse().unwrap();
        let admin_key = crate::tsig::HmacKey::new(&admin, TsigAlgorithm::HmacSha256, b"pre-shared");
        let now = u64::from(NOW);
        let mut b = MessageBuilder::new_vec();
        b.set_id(0x2930);
        let nonce = [0x11; 16];
        s.client
            .build_query(&mut b, &s.key_name, &s.request(&nonce), &s.client_owner)
            .unwrap();
        let request_mac = TsigSigner::request(&admin_key).sign(&mut b, now).unwrap();
        let query = b.finish();
        let q = Message::parse_validated(&query).unwrap();

        let verified = tsig::verify_request(&q, &admin_key, now)
            .verified()
            .unwrap();
        let mut r = MessageBuilder::new_vec();
        let theirs = s
            .server
            .respond(&mut r, &q, &s.server_owner, &s.grant(), &[0x22; 16])
            .unwrap();
        verified.signer().sign(&mut r, now).unwrap();
        let response = r.finish();
        let resp = Message::parse_validated(&response).unwrap();
        // TKEY and server KEY in the answer, the echoed client KEY and the
        // TSIG in the additional section.
        assert_eq!((resp.header().ancount, resp.header().arcount), (2, 2));
        let answer: Vec<_> = resp.answers().map(|r| r.unwrap().rtype()).collect();
        assert_eq!(answer, [Rtype::TKEY, Rtype::KEY]);
        let echoed = keys(&resp, Section::Additional).next().unwrap().unwrap();
        assert_eq!(echoed, (s.client_owner.as_name(), s.client.key()));
        let mut v = TsigVerifier::new(&admin_key, request_mac.as_slice()).unwrap();
        assert!(v.verify(&resp, now).unwrap().is_some());

        let ours = s.client.complete(&q, &resp).unwrap();
        assert_eq!(ours.secret(), theirs.secret());
        assert_eq!(ours.secret().len(), 128);
        assert_eq!(
            (ours.name(), ours.algorithm()),
            (s.key_name.as_name(), s.alg.as_name())
        );
        assert_eq!((ours.inception(), ours.expiration()), (NOW, NOW + 3600));
        assert_eq!(
            (theirs.name(), theirs.expiration()),
            (ours.name(), ours.expiration())
        );
        // The secret is the RFC's mixing of the DH value and the nonces.
        let z = s.client.dh_value(&dh(&s.server)).unwrap();
        assert_eq!(ours.secret(), dh_keying_material(&z, &nonce, &[0x22; 16]));

        // The new key signs a message the server verifies.
        let client_key = ours.hmac_key().unwrap();
        let server_key = theirs.hmac_key().unwrap();
        let mut b = MessageBuilder::new_vec();
        b.push_question(&s.key_name, Rtype::SOA, Class::IN).unwrap();
        TsigSigner::request(&client_key).sign(&mut b, now).unwrap();
        let signed = b.finish();
        let m = Message::parse(&signed).unwrap();
        assert!(
            tsig::verify_request(&m, &server_key, now)
                .verified()
                .is_some()
        );
    }

    /// BIND puts the resolver's KEY in the answer section next to its own;
    /// the resolver skips its own.
    #[test]
    fn complete_bind_layout() {
        let s = setup(1);
        let query = s.query();
        let q = Message::parse(&query).unwrap();
        let reply = Tkey {
            key: &[0x33; 16],
            ..s.request(&[])
        };
        let response = build(|b| {
            build_response(b, &q, &s.key_name, &reply).unwrap();
            b.push_answer(&s.client_owner, Class::ANY, 0, &s.client.key())
                .unwrap();
            b.push_answer(&s.server_owner, Class::ANY, 0, &s.server.key())
                .unwrap();
        });
        let key = s
            .client
            .complete(&q, &Message::parse(&response).unwrap())
            .unwrap();
        let z = s.server.dh_value(&dh(&s.client)).unwrap();
        assert_eq!(
            key.secret(),
            dh_keying_material(&z, &[0x11; 16], &[0x33; 16])
        );
    }

    #[test]
    fn respond_errors() {
        let s = setup(2);
        let q_with = |keys: &[(&NameBuf, Key<'_>)], mode: TkeyMode| {
            build(|b| {
                let request = Tkey {
                    mode,
                    ..s.request(&[1; 16])
                };
                build_query(b, &s.key_name, &request).unwrap();
                for (owner, key) in keys {
                    b.push_additional(*owner, Class::ANY, 0, key).unwrap();
                }
            })
        };
        let respond = |wire: &[u8]| {
            let mut b = MessageBuilder::new_vec();
            let res = s.server.respond(
                &mut b,
                &Message::parse(wire).unwrap(),
                &s.server_owner,
                &s.grant(),
                &[2; 16],
            );
            if res.is_err() {
                assert!(b.is_empty());
            }
            res.map(|k| k.secret().to_vec())
        };
        let owner = &s.client_owner;
        let dh_mode = TkeyMode::DIFFIE_HELLMAN;
        let other_group =
            DhKeyPair::from_private_bytes(DhGroup::well_known(1).unwrap(), &[5]).unwrap();
        let rsa = Key::new(0x0200, 3, Algorithm::RSASHA256, &[1, 3, 0xc5]);
        let mut garbage = s.client.key();
        garbage.public_key = &[0, 3, 1];
        let mut bad_value = s.client.key();
        bad_value.public_key = &[0, 1, 2, 0, 0, 0, 1, 1];
        // No KEY, no DH KEY, the server's own KEY: FORMERR.
        assert_eq!(respond(&q_with(&[], dh_mode)), Err(Error::InvalidTkey));
        assert_eq!(
            respond(&q_with(&[(owner, rsa)], dh_mode)),
            Err(Error::InvalidTkey)
        );
        assert_eq!(
            respond(&q_with(&[(owner, s.server.key())], dh_mode)),
            Err(Error::InvalidTkey)
        );
        // Other groups or malformed DH KEYs: BADKEY.
        assert_eq!(
            respond(&q_with(&[(owner, other_group.key())], dh_mode)),
            Err(Error::BadKey)
        );
        assert_eq!(
            respond(&q_with(&[(owner, garbage)], dh_mode)),
            Err(Error::BadKey)
        );
        assert_eq!(
            respond(&q_with(&[(owner, bad_value)], dh_mode)),
            Err(Error::InvalidKey)
        );
        // Another mode.
        assert_eq!(
            respond(&q_with(&[(owner, s.client.key())], TkeyMode::GSSAPI)),
            Err(Error::InvalidTkey)
        );
        // Many unusable KEYs before a good one: one computation.
        let many: Vec<_> = (0..300)
            .map(|_| (owner, other_group.key()))
            .chain([(owner, s.client.key())])
            .collect();
        assert!(respond(&q_with(&many, dh_mode)).is_ok());
        // The response does not fit: the builder is left unchanged.
        let query = s.query();
        let mut buf = [0u8; 300];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.set_id(9);
        let q = Message::parse(&query).unwrap();
        let res = s
            .server
            .respond(&mut b, &q, &s.server_owner, &s.grant(), &[2; 16]);
        assert_eq!(res.unwrap_err(), Error::BufferTooSmall);
        assert!(b.is_empty() && b.header().id == 9);
        // Not a query at all.
        let mut bad = query.clone();
        bad[2] |= 0x80;
        assert_eq!(respond(&bad), Err(Error::InvalidTkey));
    }

    #[test]
    fn complete_errors() {
        let s = setup(2);
        let query = s.query();
        let q = Message::parse(&query).unwrap();
        let reply = Tkey {
            key: &[0x33; 16],
            ..s.request(&[])
        };
        let complete = |f: &dyn Fn(&mut MessageBuilder<WireWriter<'_>>)| {
            let wire = build(|b| f(b));
            s.client
                .complete(&q, &Message::parse(&wire).unwrap())
                .map(|_| ())
        };
        let server_key = s.server.key();
        let other = DhKeyPair::from_private_bytes(DhGroup::well_known(1).unwrap(), &[5]).unwrap();
        // No server KEY, only the client's own, another group.
        assert_eq!(
            complete(&|b| build_response(b, &q, &s.key_name, &reply).unwrap()),
            Err(Error::InvalidTkey)
        );
        assert_eq!(
            complete(&|b| {
                build_response(b, &q, &s.key_name, &reply).unwrap();
                b.push_answer(&s.client_owner, Class::ANY, 0, &s.client.key())
                    .unwrap();
            }),
            Err(Error::InvalidTkey)
        );
        assert_eq!(
            complete(&|b| {
                build_response(b, &q, &s.key_name, &reply).unwrap();
                b.push_answer(&s.server_owner, Class::ANY, 0, &other.key())
                    .unwrap();
            }),
            Err(Error::BadKey)
        );
        // The server KEY must be in the answer section.
        assert_eq!(
            complete(&|b| {
                build_response(b, &q, &s.key_name, &reply).unwrap();
                b.push_additional(&s.server_owner, Class::ANY, 0, &server_key)
                    .unwrap();
            }),
            Err(Error::InvalidTkey)
        );
        // Another algorithm, another mode, a TKEY error.
        let alg: NameBuf = "hmac-sha512".parse().unwrap();
        for (tkey, err) in [
            (
                Tkey {
                    algorithm: alg.as_name(),
                    ..reply
                },
                Error::InvalidTkey,
            ),
            (
                Tkey {
                    mode: TkeyMode::SERVER_ASSIGNMENT,
                    ..reply
                },
                Error::InvalidTkey,
            ),
            (reply.with_error(TsigRcode::BADKEY), Error::ErrorResponse),
        ] {
            assert_eq!(
                complete(&|b| {
                    build_response(b, &q, &s.key_name, &tkey).unwrap();
                    b.push_answer(&s.server_owner, Class::ANY, 0, &server_key)
                        .unwrap();
                }),
                Err(err)
            );
        }
        // The right response works.
        assert!(
            complete(&|b| {
                build_response(b, &q, &s.key_name, &reply).unwrap();
                b.push_answer(&s.server_owner, Class::ANY, 0, &server_key)
                    .unwrap();
            })
            .is_ok()
        );
    }

    #[test]
    fn build_query_checks_the_mode() {
        let s = setup(1);
        let mut b = MessageBuilder::new_vec();
        let gss = Tkey {
            mode: TkeyMode::GSSAPI,
            ..s.request(&[])
        };
        assert_eq!(
            s.client
                .build_query(&mut b, &s.key_name, &gss, &s.client_owner),
            Err(Error::InvalidTkey)
        );
        assert!(b.is_empty());
    }

    #[test]
    fn shared_keys() {
        let name: NameBuf = "k.example".parse().unwrap();
        for alg in TsigAlgorithm::ALL {
            let key = SharedKey::new(&name, alg.name(), 0, 10, &[7; 32]);
            assert_eq!(key.hmac_key().unwrap().algorithm_id(), alg);
        }
        let unknown: NameBuf = "hmac-sha3-256".parse().unwrap();
        let key = SharedKey::new(&name, &unknown, 0, 10, &[7; 32]);
        assert_eq!(key.hmac_key().unwrap_err(), Error::UnsupportedAlgorithm);
        let shown = format!("{:?}", key.clone());
        assert!(shown.contains("secret_len: 32") && !shown.contains("7, 7"));
        assert!(key.is_valid_at(5) && !key.is_valid_at(11));
    }

    /// One 1024-bit RSA key per role, generated once.
    fn rsa(which: usize) -> &'static BoxedRsaPrivateKey {
        static KEYS: OnceLock<[BoxedRsaPrivateKey; 2]> = OnceLock::new();
        let keys = KEYS.get_or_init(|| {
            let mut r = rng(b"rsa keys");
            let e = || BoxedUint::from_u64(65537);
            [
                BoxedRsaPrivateKey::generate(1024, e(), &mut r, 0),
                BoxedRsaPrivateKey::generate(1024, e(), &mut r, 0),
            ]
        });
        &keys[which]
    }

    fn rsa_key(public: &[u8]) -> Key<'_> {
        Key::new(0x0200, 3, Algorithm::RSASHA256, public)
    }

    #[test]
    fn rsa_encryption() {
        let private = rsa(0);
        let public = rsa_public_key(private).unwrap();
        let key = rsa_key(&public);
        let mut r = rng(b"encrypt");
        // One, three and too many blocks (117 octets per 1024-bit block).
        for (len, blocks) in [(1, 1), (117, 1), (118, 2), (300, 3), (468, 4)] {
            let material: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let data = encrypt_keying_material(&key, &material, &mut r).unwrap();
            assert_eq!(data.len(), 128 * blocks, "{len}");
            assert_eq!(decrypt_keying_material(private, &data).unwrap(), material);
        }
        assert_eq!(
            encrypt_keying_material(&key, &[1; 469], &mut r),
            Err(Error::LimitExceeded)
        );
        assert_eq!(
            encrypt_keying_material(&key, &[], &mut r),
            Err(Error::InvalidTkey)
        );
        assert_eq!(
            decrypt_keying_material(private, &std::vec![1; 128 * 5]),
            Err(Error::LimitExceeded)
        );
        for bad in [&[][..], &[1; 127], &[1; 129]] {
            assert_eq!(
                decrypt_keying_material(private, bad),
                Err(Error::InvalidTkey)
            );
        }
        // A tampered ciphertext decrypts to something else, with no error
        // to serve as a padding oracle.
        let mut data = encrypt_keying_material(&key, &[9; 32], &mut r).unwrap();
        data[5] ^= 1;
        assert_ne!(
            decrypt_keying_material(private, &data).ok(),
            Some(std::vec![9; 32])
        );
        // Under another key, likewise.
        let data = encrypt_keying_material(&key, &[9; 32], &mut r).unwrap();
        assert_ne!(
            decrypt_keying_material(rsa(1), &data).ok(),
            Some(std::vec![9; 32])
        );
    }

    #[test]
    fn rsa_key_checks() {
        let public = rsa_public_key(rsa(0)).unwrap();
        let encrypt =
            |key: Key<'_>| encrypt_keying_material(&key, &[1; 16], &mut rng(b"x")).map(|_| ());
        // Flags prohibiting confidentiality, or no key at all.
        for flags in [0x4000, 0xc000, 0x4200] {
            let key = Key {
                flags,
                ..rsa_key(&public)
            };
            assert_eq!(encrypt(key), Err(Error::InvalidKey), "{flags:#x}");
        }
        // Authentication-only keys may encrypt; so may every RSA algorithm.
        assert!(
            encrypt(Key {
                flags: 0x8000,
                ..rsa_key(&public)
            })
            .is_ok()
        );
        assert!(
            encrypt(Key {
                algorithm: Algorithm::RSAMD5,
                ..rsa_key(&public)
            })
            .is_ok()
        );
        assert_eq!(
            encrypt(Key {
                algorithm: Algorithm::ECDSAP256SHA256,
                ..rsa_key(&public)
            }),
            Err(Error::UnsupportedAlgorithm)
        );
        // Sizes and shapes.
        let mut small = std::vec![3u8, 1, 0, 1];
        small.extend([0xc5; 64]);
        let mut huge = std::vec![3u8, 1, 0, 1];
        huge.extend([0xc5; 513]);
        let mut even = public.clone();
        *even.last_mut().unwrap() &= 0xfe;
        let mut e_one = std::vec![1u8, 1];
        e_one.extend_from_slice(&public[4..]);
        let mut e_big = std::vec![33u8];
        e_big.extend([0xff; 33]);
        e_big.extend_from_slice(&public[4..]);
        for bad in [&small, &huge, &even, &e_one, &e_big, &std::vec![0u8]] {
            assert_eq!(encrypt(rsa_key(bad)), Err(Error::InvalidKey), "{bad:02x?}");
        }
    }

    #[test]
    fn server_assignment() {
        let resolver = rsa(0);
        let public = rsa_public_key(resolver).unwrap();
        let (requested, owner, alg): (NameBuf, NameBuf, NameBuf) = (
            "k1.resolver.example".parse().unwrap(),
            "resolver.example".parse().unwrap(),
            "hmac-sha256".parse().unwrap(),
        );
        let request = Tkey::new(
            alg.as_name(),
            NOW,
            NOW + 86_400,
            TkeyMode::SERVER_ASSIGNMENT,
            &[4; 8],
        );
        let dh_key = setup(2).client;
        let query = build(|b| {
            build_query(b, &requested, &request).unwrap();
            // A DH KEY first: skipped, the RSA KEY is used.
            b.push_additional(&owner, Class::ANY, 0, &dh_key.key())
                .unwrap();
            b.push_additional(&owner, Class::ANY, 0, &rsa_key(&public))
                .unwrap();
        });
        let q = Message::parse(&query).unwrap();
        let assigned: NameBuf = "89n3mdgx072pp.server.example".parse().unwrap();
        let grant = KeyGrant::new(assigned.as_name(), NOW, NOW + 3600);
        let mut r = rng(b"server assignment");
        let mut b = MessageBuilder::new_vec();
        let theirs = respond_server_assigned(&mut b, &q, &grant, &[0x37; 32], &mut r).unwrap();
        let response = b.finish();
        let resp = Message::parse_validated(&response).unwrap();
        let answer = find_answer(&resp).unwrap();
        assert_eq!(answer.key_name, assigned.as_name());
        assert_eq!(answer.data.key.len(), 128);
        let echoed = keys(&resp, Section::Additional).next().unwrap().unwrap();
        assert_eq!(echoed, (owner.as_name(), rsa_key(&public)));
        let ours = server_assigned_key(&q, &resp, resolver).unwrap();
        assert_eq!(ours.secret(), [0x37; 32]);
        assert_eq!(ours.secret(), theirs.secret());
        assert_eq!(
            (ours.name(), ours.expiration()),
            (assigned.as_name(), NOW + 3600)
        );
        assert_eq!(
            (theirs.name(), theirs.algorithm()),
            (assigned.as_name(), alg.as_name())
        );
        // Decrypted by the wrong key: implicit rejection, a wrong secret.
        let wrong = server_assigned_key(&q, &resp, rsa(1)).map(|k| k.secret().to_vec());
        assert_ne!(wrong.ok(), Some(std::vec![0x37; 32]));

        // Errors: no RSA KEY (FORMERR), another mode, an unusable KEY.
        let without = build(|b| {
            build_query(b, &requested, &request).unwrap();
            b.push_additional(&owner, Class::ANY, 0, &dh_key.key())
                .unwrap();
        });
        let other_mode = build(|b| {
            let gss = Tkey {
                mode: TkeyMode::GSSAPI,
                ..request
            };
            build_query_with_key(b, &requested, &gss, &owner, &rsa_key(&public)).unwrap();
        });
        let no_conf = build(|b| {
            let key = Key {
                flags: 0x4000,
                ..rsa_key(&public)
            };
            build_query_with_key(b, &requested, &request, &owner, &key).unwrap();
        });
        for (wire, err) in [
            (without, Error::InvalidTkey),
            (other_mode, Error::InvalidTkey),
            (no_conf, Error::InvalidKey),
        ] {
            let mut b = MessageBuilder::new_vec();
            let m = Message::parse(&wire).unwrap();
            let res = respond_server_assigned(&mut b, &m, &grant, &[0x37; 32], &mut r);
            assert_eq!(res.map(|_| ()), Err(err));
            assert!(b.is_empty());
        }
        // The resolver's side: a refusal, a mode mismatch.
        let refusal = build(|b| {
            build_response(b, &q, &requested, &request.with_error(TsigRcode::BADKEY)).unwrap();
        });
        let refusal = Message::parse(&refusal).unwrap();
        assert_eq!(
            server_assigned_key(&q, &refusal, resolver).map(|_| ()),
            Err(Error::ErrorResponse)
        );
        let odd = build(|b| {
            build_response(
                b,
                &q,
                &requested,
                &Tkey {
                    key: &[1; 100],
                    ..request
                },
            )
            .unwrap();
        });
        assert_eq!(
            server_assigned_key(&q, &Message::parse(&odd).unwrap(), resolver).map(|_| ()),
            Err(Error::InvalidTkey)
        );
    }

    #[test]
    fn resolver_assignment() {
        let server = rsa(1);
        let public = rsa_public_key(server).unwrap();
        let server_key = rsa_key(&public);
        let (key_name, server_owner, alg): (NameBuf, NameBuf, NameBuf) = (
            "6d1f2a.resolver.example".parse().unwrap(),
            "server.example".parse().unwrap(),
            "hmac-sha512".parse().unwrap(),
        );
        let secret = [0x29; 64];
        let request = Tkey::new(
            alg.as_name(),
            NOW,
            NOW + 86_400,
            TkeyMode::RESOLVER_ASSIGNMENT,
            &[],
        );
        let mut r = rng(b"resolver assignment");
        let mut b = MessageBuilder::new_vec();
        build_resolver_assigned_query(
            &mut b,
            &key_name,
            &request,
            &server_owner,
            &server_key,
            &secret,
            &mut r,
        )
        .unwrap();
        let query = b.finish();
        let q = Message::parse_validated(&query).unwrap();
        let sent = find_request(&q).unwrap();
        assert_eq!(
            (sent.data.mode, sent.data.key.len()),
            (TkeyMode::RESOLVER_ASSIGNMENT, 128)
        );

        let mut b = MessageBuilder::new_vec();
        let accepted = accept_resolver_assigned(&mut b, &q, server, NOW, NOW + 3600).unwrap();
        assert_eq!(accepted.secret(), secret);
        assert_eq!(
            (accepted.name(), accepted.algorithm()),
            (key_name.as_name(), alg.as_name())
        );
        let response = b.finish();
        let resp = Message::parse_validated(&response).unwrap();
        let answer = find_answer(&resp).unwrap();
        assert!(answer.data.key.is_empty());
        let key = resolver_assigned_key(&q, &resp, &secret).unwrap();
        assert_eq!(key.secret(), secret);
        assert_eq!((key.inception(), key.expiration()), (NOW, NOW + 3600));
        assert_eq!(
            key.hmac_key().unwrap().algorithm_id(),
            TsigAlgorithm::HmacSha512
        );
        // The server's KEY with the long form of the exponent length
        // (RFC 3110 §2) is still the server's.
        let mut long = std::vec![0u8, 0];
        long.extend_from_slice(&public);
        let long_key = rsa_key(&long);
        let query = build(|b| {
            let owner = &server_owner;
            build_resolver_assigned_query(
                b, &key_name, &request, owner, &long_key, &secret, &mut r,
            )
            .unwrap();
        });
        let mut b = MessageBuilder::new_vec();
        let q2 = Message::parse(&query).unwrap();
        let accepted = accept_resolver_assigned(&mut b, &q2, server, 0, 1).unwrap();
        assert_eq!(accepted.secret(), secret);

        // Errors on the server side.
        let mut b = MessageBuilder::new_vec();
        let other_mode = Tkey {
            mode: TkeyMode::SERVER_ASSIGNMENT,
            ..request
        };
        assert_eq!(
            build_resolver_assigned_query(
                &mut b,
                &key_name,
                &other_mode,
                &server_owner,
                &server_key,
                &secret,
                &mut r
            ),
            Err(Error::InvalidTkey)
        );
        assert!(b.is_empty());
        let other_public = rsa_public_key(rsa(0)).unwrap();
        let not_ours = build(|b| {
            build_resolver_assigned_query(
                b,
                &key_name,
                &request,
                &server_owner,
                &rsa_key(&other_public),
                &secret,
                &mut r,
            )
            .unwrap();
        });
        let no_key = build(|b| {
            build_query(
                b,
                &key_name,
                &Tkey {
                    key: &[1; 128],
                    ..request
                },
            )
            .unwrap();
        });
        let bad_length = build(|b| {
            let t = Tkey {
                key: &[1; 100],
                ..request
            };
            build_query_with_key(b, &key_name, &t, &server_owner, &server_key).unwrap();
        });
        let wrong_mode = build(|b| {
            let t = Tkey {
                key: &[1; 128],
                mode: TkeyMode::SERVER_ASSIGNMENT,
                ..request
            };
            build_query_with_key(b, &key_name, &t, &server_owner, &server_key).unwrap();
        });
        let too_many = build(|b| {
            let data = std::vec![1u8; 128 * 5];
            let t = Tkey {
                key: &data,
                ..request
            };
            build_query_with_key(b, &key_name, &t, &server_owner, &server_key).unwrap();
        });
        for (wire, err) in [
            (not_ours, Error::BadKey),
            (no_key, Error::InvalidTkey),
            (bad_length, Error::InvalidTkey),
            (wrong_mode, Error::InvalidTkey),
            (too_many, Error::LimitExceeded),
        ] {
            let mut b = MessageBuilder::new_vec();
            let res =
                accept_resolver_assigned(&mut b, &Message::parse(&wire).unwrap(), server, 0, 1);
            assert_eq!(res.map(|_| ()), Err(err));
            assert!(b.is_empty());
        }
        // Errors on the resolver side: a refusal, another key name.
        let refusal = build(|b| {
            build_response(b, &q, &key_name, &request.with_error(TsigRcode::BADNAME)).unwrap();
        });
        assert_eq!(
            resolver_assigned_key(&q, &Message::parse(&refusal).unwrap(), &secret).map(|_| ()),
            Err(Error::ErrorResponse)
        );
        let renamed = build(|b| build_response(b, &q, &server_owner, &request).unwrap());
        assert_eq!(
            resolver_assigned_key(&q, &Message::parse(&renamed).unwrap(), &secret).map(|_| ()),
            Err(Error::InvalidTkey)
        );
    }
}
