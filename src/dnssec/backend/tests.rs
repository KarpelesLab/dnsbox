//! purecrypto backend tests: the RFC 5702, RFC 6605 and RFC 8080 example
//! keys and signatures, sign→verify round trips for every algorithm, and
//! malformed keys and signatures.

use super::*;
use crate::dnssec::testvec::b64;
use crate::dnssec::{DigestType, Rrset, Timestamp, ZoneKey, sign_rrset, verify_ds, verify_rrsig};
use crate::rdata::{A, ComposeRdata, Dnskey, Ds, Mx, Rrsig};
use crate::testutil::hex;
use crate::{Class, NameBuf, Rtype};
use purecrypto::rng::HmacDrbg;
use std::vec::Vec;

fn name(s: &str) -> NameBuf {
    NameBuf::from_text(s.as_bytes()).unwrap()
}

fn time(s: &str) -> u32 {
    s.parse::<Timestamp>().unwrap().get()
}

fn rng(seed: &[u8]) -> HmacDrbg<Sha256> {
    HmacDrbg::new(seed, b"dnsbox test nonce", b"")
}

/// A published example: a key, its DNSKEY and DS, and one signed RRset.
struct Vector<'a, D> {
    key: SigningKey,
    zone: &'a str,
    flags: u16,
    public_key: &'a str,
    key_tag: u16,
    ds: Option<(DigestType, &'a str)>,
    owner: &'a str,
    rdata: D,
    inception: u32,
    expiration: u32,
    /// The published signature, if it is valid over the RRset.
    signature: Option<&'a str>,
    /// Whether the example signature can be reproduced exactly
    /// (deterministic signature schemes).
    deterministic: bool,
}

fn check<D: ComposeRdata + Copy>(v: Vector<'_, D>) {
    let alg = v.key.algorithm();
    assert_eq!(v.key.public_key(), b64(v.public_key), "{alg}: public key");
    let dnskey = v.key.dnskey(v.flags);
    assert_eq!(dnskey.key_tag(), v.key_tag, "{alg}: key tag");
    let zone = name(v.zone);
    let zk = ZoneKey::new(zone.as_name(), dnskey);
    if let Some((dt, digest)) = v.ds {
        let digest = hex(digest);
        assert_eq!(zk.ds(dt).unwrap().digest(), digest, "{alg}: DS");
        let ds = Ds::new(v.key_tag, alg, dt, &digest);
        assert_eq!(verify_ds(&ds, zone.as_name(), &dnskey), Ok(()));
    }

    let owner = name(v.owner);
    let rdata = [v.rdata];
    let rrset = Rrset::new(owner.as_name(), Class::IN, &rdata);
    let template = zk.rrsig_template(
        owner.as_name(),
        v.rdata.rtype(),
        3600,
        v.inception,
        v.expiration,
    );
    let mut scratch = Vec::new();
    let now = v.inception.wrapping_add(1);
    let mut sig = [0u8; 512];
    let len = sign_rrset(&v.key, &template, rrset, &mut scratch, &mut sig).unwrap();
    assert_eq!(len, v.key.signature_len());
    let ours = template.with_signature(&sig[..len]);
    assert_eq!(
        verify_rrsig(&PurecryptoVerifier, &zk, &ours, rrset, now, &mut scratch),
        Ok(())
    );
    assert!(scratch.is_empty());

    let expected = match v.signature {
        Some(published) => {
            let expected = b64(published);
            let rrsig = template.with_signature(&expected);
            assert_eq!(
                verify_rrsig(&PurecryptoVerifier, &zk, &rrsig, rrset, now, &mut scratch),
                Ok(()),
                "{alg}: published signature"
            );
            if v.deterministic {
                assert_eq!(sig[..len], expected[..], "{alg}: reproduced signature");
            }
            expected
        }
        None => sig[..len].to_vec(),
    };
    let rrsig = template.with_signature(&expected);

    // Any change to the signature or the data breaks it.
    let mut bad = expected.clone();
    bad[len / 2] ^= 0x40;
    let bad_rrsig = template.with_signature(&bad);
    assert_eq!(
        verify_rrsig(
            &PurecryptoVerifier,
            &zk,
            &bad_rrsig,
            rrset,
            now,
            &mut scratch
        ),
        Err(Error::BadSignature),
        "{alg}"
    );
    let other = [A::new([198, 51, 100, 7].into())];
    let rrsig_a = Rrsig {
        type_covered: Rtype::A,
        ..rrsig
    };
    assert_eq!(
        verify_rrsig(
            &PurecryptoVerifier,
            &zk,
            &rrsig_a,
            Rrset::new(owner.as_name(), Class::IN, &other),
            now,
            &mut scratch
        ),
        Err(Error::BadSignature),
        "{alg}"
    );
    let ttl = Rrsig {
        original_ttl: 3601,
        ..rrsig
    };
    assert_eq!(
        verify_rrsig(&PurecryptoVerifier, &zk, &ttl, rrset, now, &mut scratch),
        Err(Error::BadSignature),
        "{alg}"
    );
}

/// The RFC 8080 §6 example RRSIGs are printed as `RRSIG MX 3 3600 ...`:
/// the algorithm field is missing and the signatures were made with a
/// labels field of 3, which is invalid for `example.com.` (two labels).
/// Rebuild that signed data by hand to check that the published
/// signatures are reproduced byte for byte and verify, and that
/// `verify_rrsig` rejects such an RRSIG.
fn rfc8080_published(key: &SigningKey, signature: &str) {
    let zone = name("example.com");
    let mail = name("mail.example.com");
    let mx = Mx {
        preference: 10,
        exchange: mail.as_name(),
    };
    let zk = ZoneKey::new(zone.as_name(), key.dnskey(257));
    let template = zk.rrsig_template(
        zone.as_name(),
        Rtype::MX,
        3600,
        1_438_207_200,
        1_440_021_600,
    );
    let template = Rrsig {
        labels: 3,
        ..template
    };
    let mut data = Vec::new();
    template.compose_unsigned(&mut data).unwrap();
    let mut set =
        crate::dnssec::CanonicalRrset::new(&mut data, zone.as_name(), Rtype::MX, Class::IN, 3600);
    set.push(&mx).unwrap();
    set.finish().unwrap();
    let expected = b64(signature);
    let mut sig = [0u8; 114];
    let len = key.sign(&data, &mut sig).unwrap();
    assert_eq!(sig[..len], expected[..]);
    assert_eq!(
        PurecryptoVerifier.verify(key.algorithm(), key.public_key(), &data, &expected),
        Ok(())
    );
    let rrsig = template.with_signature(&expected);
    let rdata = [mx];
    let rrset = Rrset::new(zone.as_name(), Class::IN, &rdata);
    assert_eq!(
        verify_rrsig(
            &PurecryptoVerifier,
            &zk,
            &rrsig,
            rrset,
            1_438_207_201,
            &mut Vec::new()
        ),
        Err(Error::RrsetMismatch)
    );
}

#[test]
fn rfc8080_ed25519() {
    // RFC 8080 §6.1, re-signed with a valid labels field; see
    // `rfc8080_published` for the published signatures.
    let mail = name("mail.example.com");
    let mx = Mx {
        preference: 10,
        exchange: mail.as_name(),
    };
    for (private, public, tag, ds, sig) in [
        (
            "ODIyNjAzODQ2MjgwODAxMjI2NDUxOTAyMDQxNDIyNjI=",
            "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=",
            3613,
            "3aa5ab37efce57f737fc1627013fee07bdf241bd10f3b1964ab55c78e79a304b",
            "Edk+IB9KNNWg0HAjm7FazXyrd5m3Rk8zNZbvNpAcM+eysqcUOMIjWoevFkj
             H5GaMWeG96GUVZu6ECKOQmemHDg==",
        ),
        (
            "DSSF3o0s0f+ElWzj9E/Osxw8hLpk55chkmx0LYN5WiY=",
            "zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs=",
            35217,
            "401781b934e392de492ec77ae2e15d70f6575a1c0bc59c5275c04ebe80c6614c",
            "5LL2obmzdqjWI+Xto5eP5adXt/T5tMhasWvwcyW4L3SzfcRawOle9bodhC+
             oip9ayUGjY9T/rL4rN3bOuESGDA==",
        ),
    ] {
        let key = SigningKey::from_private_bytes(Algorithm::ED25519, &b64(private)).unwrap();
        rfc8080_published(&key, sig);
        check(Vector {
            key,
            zone: "example.com",
            flags: 257,
            public_key: public,
            key_tag: tag,
            ds: Some((DigestType::SHA256, ds)),
            owner: "example.com",
            rdata: mx,
            inception: 1_438_207_200,
            expiration: 1_440_021_600,
            signature: None,
            deterministic: true,
        });
    }
}

#[test]
fn rfc8080_ed448() {
    // RFC 8080 §6.2, as above.
    let mail = name("mail.example.com");
    let mx = Mx {
        preference: 10,
        exchange: mail.as_name(),
    };
    for (private, public, tag, ds, sig) in [
        (
            "xZ+5Cgm463xugtkY5B0Jx6erFTXp13rYegst0qRtNsOYnaVpMx0Z/c5EiA9x
             8wWbDDct/U3FhYWA",
            "3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+G2MpTPhpj/OiBVHHSfPodx
             1FYYUcJKm1MDpJtIA",
            9713,
            "6ccf18d5bc5d7fc2fceb1d59d17321402f2aa8d368048db93dd811f5cb2b19c7",
            "Nmc0rgGKpr3GKYXcB1JmqqS4NYwhmechvJTqVzt3jR+Qy/lSLFoIk1L+9e3
             9GPL+5tVzDPN3f9kAwiu8KCuPPjtl227ayaCZtRKZuJax7n9NuYlZJIusX0
             SOIOKBGzG+yWYtz1/jjbzl5GGkWvREUCUA",
        ),
        (
            "WEykD3ht3MHkU8iH4uVOLz8JLwtRBSqiBoM6fF72+Mrp/u5gjxuB1DV6NnPO
             2BlZdz4hdSTkOdOA",
            "kkreGWoccSDmUBGAe7+zsbG6ZAFQp+syPmYUurBRQc3tDjeMCJcVMRDmgcN
             Lp5HlHAMy12VoISsA",
            38353,
            "645ff078b3568f5852b70cb60e8e696cc77b75bfaaffc118cf79cbda1ba28af4",
            "+JjANio/LIzp7osmMYE5XD3H/YES8kXs5Vb9H8MjPS8OAGZMD37+LsCIcjg
             5ivt0d4Om/UaqETEAsJjaYe56CEQP5lhRWuD2ivBqE0zfwJTyp4WqvpULbp
             vaukswvv/WNEFxzEYQEIm9+xDlXj4pMAMA",
        ),
    ] {
        let key = SigningKey::from_private_bytes(Algorithm::ED448, &b64(private)).unwrap();
        rfc8080_published(&key, sig);
        check(Vector {
            key,
            zone: "example.com",
            flags: 257,
            public_key: public,
            key_tag: tag,
            ds: Some((DigestType::SHA256, ds)),
            owner: "example.com",
            rdata: mx,
            inception: 1_438_207_200,
            expiration: 1_440_021_600,
            signature: None,
            deterministic: true,
        });
    }
}

#[test]
fn rfc6605_ecdsa() {
    let a = A::new([192, 0, 2, 1].into());
    // RFC 6605 §6.1: P-256. The published signature used a random nonce,
    // so only verification is compared.
    check(Vector {
        key: SigningKey::from_private_bytes(
            Algorithm::ECDSAP256SHA256,
            &b64("GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ="),
        )
        .unwrap(),
        zone: "example.net",
        flags: 257,
        public_key: "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb
                     krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==",
        key_tag: 55648,
        ds: Some((
            DigestType::SHA256,
            "b4c8c1fe2e7477127b27115656ad6256f424625bf5c1e2770ce6d6e37df61d17",
        )),
        owner: "www.example.net",
        rdata: a,
        inception: time("20100812100439"),
        expiration: time("20100909100439"),
        signature: Some(
            "qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXA
                    yGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw==",
        ),
        deterministic: false,
    });
    // RFC 6605 §6.2: P-384, DS with SHA-384.
    check(Vector {
        key: SigningKey::from_private_bytes(
            Algorithm::ECDSAP384SHA384,
            &b64("WURgWHCcYIYUPWgeLmiPY2DJJk02vgrmTfitxgqcL4vwW7BOrbawVmVe0d9V94SR"),
        )
        .unwrap(),
        zone: "example.net",
        flags: 257,
        public_key: "xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1
                     w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8
                     /uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40",
        key_tag: 10771,
        ds: Some((
            DigestType::SHA384,
            "72d7b62976ce06438e9c0bf319013cf801f09ecc84b8d7e9495f27e305c6a9b0
             563a9b5f4d288405c3008a946df983d6",
        )),
        owner: "www.example.net",
        rdata: a,
        inception: time("20100812102025"),
        expiration: time("20100909102025"),
        signature: Some(
            "/L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP
                    95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuz
                    WTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm",
        ),
        deterministic: false,
    });
}

/// The RFC 5702 §6.1 RSA/SHA-256 example key (512 bits).
fn rfc5702_key_256(alg: Algorithm) -> SigningKey {
    SigningKey::from_rsa_components(
        alg,
        &b64("wVwaxrHF2CK64aYKRUibLiH30KpPuPBjel7E8ZydQW1HYWHfoGm
              idzC2RnhwCC293hCzw+TFR2nqn8OVSY5t2Q=="),
        &b64("AQAB"),
        &b64("UR44xX6zB3eaeyvTRzmskHADrPCmPWnr8dxsNwiDGHzrMKLN+i/
              HAam+97HxIKVWNDH2ba9Mf1SA8xu9dcHZAQ=="),
        &b64("4c8IvFu1AVXGWeFLLFh5vs7fbdzdC6U82fduE6KkSWk="),
        &b64("2zZpBE8ZXVnL74QjG4zINlDfH+EOEtjJJ3RtaYDugvE="),
    )
    .unwrap()
}

/// The RFC 5702 §6.2 RSA/SHA-512 example key (1024 bits).
fn rfc5702_key_512(alg: Algorithm, with_primes: bool) -> SigningKey {
    let (p, q) = if with_primes {
        (
            b64("8mbtsu9Tl9v7tKSHdCIeprLIQXQLzxlSZun5T1n/OjvXSUtvD7x
                 nZJ+LHqaBj1dIgMbCq2U8O04QVcK3TS9GiQ=="),
            b64("3a6gkfs74d0Jb7yL4j4adAif4fcp7ZrGt7G5NRVDDY/Mv4TERAK
                 Ma0TKN3okKE0A7X+Rv2K84mhT4QLDlllEcw=="),
        )
    } else {
        (Vec::new(), Vec::new())
    };
    SigningKey::from_rsa_components(
        alg,
        &b64("0eg1M5b563zoq4k5ZEOnWmd2/BvpjzedJVdfIsDcMuuhE5SQ3pf
              Q7qmdaeMlC6Nf8DKGoUPGPXe06cP27/WRODtxXquSUytkO0kJDk
              8KX8PtA0+yBWwy7UnZDyCkynO00Uuk8HPVtZeMO1pHtlAGVnc8V
              jXZlNKdyit99waaE4s="),
        &b64("AQAB"),
        &b64("rFS1IPbJllFFgFc33B5DDlC1egO8e81P4fFadODbp56V7sphKa6
              AZQCx8NYAew6VXFFPAKTw41QdHnK5kIYOwxvfFDjDcUGza88qbj
              yrDPSJenkeZbISMUSSqy7AMFzEolkk6WSn6k3thUVRgSlqDoOV3
              SEIAsrB043XzGrKIVE="),
        &p,
        &q,
    )
    .unwrap()
}

#[test]
fn rfc5702_rsa() {
    let a = A::new([192, 0, 2, 91].into());
    check(Vector {
        key: rfc5702_key_256(Algorithm::RSASHA256),
        zone: "example.net",
        flags: 256,
        public_key: "AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8P
                     kxUdp6p/DlUmObdk=",
        key_tag: 9033,
        ds: None,
        owner: "www.example.net",
        rdata: a,
        inception: time("20000101000000"),
        expiration: time("20300101000000"),
        signature: Some(
            "kRCOH6u7l0QGy9qpC9l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEa
                    cFYK/lPtPiVYP4bwg==",
        ),
        deterministic: true,
    });
    for with_primes in [true, false] {
        check(Vector {
            key: rfc5702_key_512(Algorithm::RSASHA512, with_primes),
            zone: "example.net",
            flags: 256,
            public_key:
                "AwEAAdHoNTOW+et86KuJOWRDp1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFD
                         xj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8g
                         pMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL",
            key_tag: 3740,
            ds: None,
            owner: "www.example.net",
            rdata: a,
            inception: time("20000101000000"),
            expiration: time("20300101000000"),
            signature: Some(
                "tsb4wnjRUDnB1BUi+t6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0CbxrVDYd0xDtsuJRa
                        eUw1ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfReKBzMweOL
                        DiNa8iP5g9vMhpuv6OPlvpXwm9Sa9ZXIbNl1MBGk0fthPgxdDLw=",
            ),
            deterministic: true,
        });
    }
}

/// Signs and verifies an RRset with `key`, then checks a few failures.
fn round_trip(key: &SigningKey) {
    let alg = key.algorithm();
    let zone = name("example.org");
    let zk = ZoneKey::new(zone.as_name(), key.dnskey(Dnskey::ZONE));
    let owner = name("*.Example.ORG");
    let target = name("Host.Example.org");
    let rdata = [
        Mx {
            preference: 20,
            exchange: target.as_name(),
        },
        Mx {
            preference: 10,
            exchange: target.as_name(),
        },
    ];
    let template = zk.rrsig_template(owner.as_name(), Rtype::MX, 300, 1000, 5000);
    assert_eq!(template.labels, 2);
    let mut scratch = Vec::new();
    let mut sig = std::vec![0u8; key.signature_len()];
    let rrset = Rrset::new(owner.as_name(), Class::IN, &rdata);
    let len = sign_rrset(key, &template, rrset, &mut scratch, &mut sig).unwrap();
    assert_eq!(len, key.signature_len(), "{alg}");
    if let Some(l) = alg.signature_len() {
        assert_eq!(len, l);
    }
    let rrsig = template.with_signature(&sig[..len]);

    // Verifies at the wildcard itself and at an expansion of it
    // (RFC 4035 §5.3.2), in any record order and case.
    let reversed = [rdata[1], rdata[0]];
    for (o, data) in [
        ("*.example.org", &rdata),
        ("a.b.example.org", &reversed),
        ("X.EXAMPLE.org", &rdata),
    ] {
        let o = name(o);
        let set = Rrset::new(o.as_name(), Class::IN, data);
        assert_eq!(
            verify_rrsig(&PurecryptoVerifier, &zk, &rrsig, set, 3000, &mut scratch),
            Ok(()),
            "{alg} at {o}"
        );
    }
    // Wrong class, wrong signer, wrong time, unsupported verifier.
    let set = Rrset::new(owner.as_name(), Class::CH, &rdata);
    assert_eq!(
        verify_rrsig(&PurecryptoVerifier, &zk, &rrsig, set, 3000, &mut scratch),
        Err(Error::BadSignature)
    );
    let other = name("example.net");
    let zk2 = ZoneKey::new(other.as_name(), zk.dnskey);
    assert_eq!(
        verify_rrsig(&PurecryptoVerifier, &zk2, &rrsig, rrset, 3000, &mut scratch),
        Err(Error::KeyMismatch)
    );
    assert_eq!(
        verify_rrsig(&PurecryptoVerifier, &zk, &rrsig, rrset, 6000, &mut scratch),
        Err(Error::SignatureExpired)
    );
    assert!(scratch.is_empty());

    // The output buffer must be large enough.
    let mut small = std::vec![0u8; len - 1];
    assert_eq!(
        sign_rrset(key, &template, rrset, &mut scratch, &mut small),
        Err(Error::BufferTooSmall)
    );
    // The template must match the key's algorithm.
    let wrong = Rrsig {
        algorithm: Algorithm::new(200),
        ..template
    };
    assert_eq!(
        sign_rrset(key, &wrong, rrset, &mut scratch, &mut sig),
        Err(Error::KeyMismatch)
    );
    assert!(scratch.is_empty());
}

#[test]
fn round_trips() {
    let mut keys = std::vec![
        rfc5702_key_256(Algorithm::RSASHA1),
        rfc5702_key_256(Algorithm::RSASHA1_NSEC3_SHA1),
        rfc5702_key_256(Algorithm::RSASHA256),
        rfc5702_key_512(Algorithm::RSASHA512, true),
    ];
    for alg in [
        Algorithm::ECDSAP256SHA256,
        Algorithm::ECDSAP384SHA384,
        Algorithm::ED25519,
        Algorithm::ED448,
    ] {
        let key = SigningKey::generate(alg, &mut rng(&[alg.get(); 32])).unwrap();
        assert!(std::format!("{key:?}").starts_with("SigningKey { algorithm: "));
        keys.push(key);
    }
    for key in &keys {
        round_trip(key);
        assert!(PurecryptoVerifier.supports(key.algorithm()));
        // The key can be rebuilt from its parts.
        let again = SigningKey::new(key.algorithm(), key.private_key().clone()).unwrap();
        assert_eq!(again.public_key(), key.public_key());
    }
}

#[test]
fn rsa_generation() {
    let key = SigningKey::generate_rsa(Algorithm::RSASHA256, 1024, &mut rng(b"rsa")).unwrap();
    assert_eq!(key.signature_len(), 128);
    let pk = crate::dnssec::RsaPublicKey::from_dnskey(key.public_key()).unwrap();
    assert_eq!((pk.exponent, pk.modulus_bits()), (&[1, 0, 1][..], 1024));
    round_trip(&key);
    for (alg, bits) in [
        (Algorithm::RSASHA256, 1023),
        (Algorithm::RSASHA256, 512),
        (Algorithm::RSASHA256, 8192),
    ] {
        assert_eq!(
            SigningKey::generate_rsa(alg, bits, &mut rng(b"x")).err(),
            Some(Error::InvalidKey)
        );
    }
    for alg in [Algorithm::RSAMD5, Algorithm::ED25519] {
        assert_eq!(
            SigningKey::generate_rsa(alg, 1024, &mut rng(b"x")).err(),
            Some(Error::UnsupportedAlgorithm)
        );
    }
}

#[test]
fn key_errors() {
    let mut r = rng(b"keys");
    for alg in [Algorithm::RSAMD5, Algorithm::DSA, Algorithm::new(99)] {
        assert_eq!(
            SigningKey::generate(alg, &mut r).err(),
            Some(Error::UnsupportedAlgorithm)
        );
    }
    // Key type and algorithm must agree.
    let ed = SigningKey::from_private_bytes(Algorithm::ED25519, &[1; 32]).unwrap();
    assert_eq!(
        SigningKey::new(Algorithm::ED448, ed.private_key().clone()).err(),
        Some(Error::UnsupportedAlgorithm)
    );
    assert_eq!(
        std::format!("{:?}", ed.private_key()),
        "PrivateKey::Ed25519(..)"
    );
    let rsa = rfc5702_key_256(Algorithm::RSASHA256);
    assert_eq!(
        std::format!("{:?}", rsa.private_key()),
        "PrivateKey::Rsa(..)"
    );
    // RSASHA512 needs at least 1024 bits (RFC 5702 §2).
    assert_eq!(
        SigningKey::new(Algorithm::RSASHA512, rsa.private_key().clone()).err(),
        Some(Error::InvalidKey)
    );
    assert_eq!(
        SigningKey::new(Algorithm::RSAMD5, rsa.private_key().clone()).err(),
        Some(Error::UnsupportedAlgorithm)
    );
    let p256 = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut r);
    assert_eq!(
        SigningKey::new(Algorithm::ECDSAP384SHA384, PrivateKey::EcdsaP384(p256)).err(),
        Some(Error::InvalidKey)
    );
    // Private key bytes.
    for (alg, len) in [
        (Algorithm::ECDSAP256SHA256, 32),
        (Algorithm::ECDSAP384SHA384, 48),
        (Algorithm::ED25519, 32),
        (Algorithm::ED448, 57),
    ] {
        assert!(SigningKey::from_private_bytes(alg, &std::vec![1; len]).is_ok());
        assert_eq!(
            SigningKey::from_private_bytes(alg, &std::vec![1; len + 1]).err(),
            Some(Error::InvalidKey)
        );
    }
    for alg in [Algorithm::ECDSAP256SHA256, Algorithm::ECDSAP384SHA384] {
        let size = if alg == Algorithm::ECDSAP256SHA256 {
            32
        } else {
            48
        };
        // Zero and all-ones are outside [1, n-1].
        for b in [0u8, 0xff] {
            assert_eq!(
                SigningKey::from_private_bytes(alg, &std::vec![b; size]).err(),
                Some(Error::InvalidKey)
            );
        }
    }
    assert_eq!(
        SigningKey::from_private_bytes(Algorithm::RSASHA256, &[1; 32]).err(),
        Some(Error::UnsupportedAlgorithm)
    );
    // RSA components.
    let n = b64(
        "wVwaxrHF2CK64aYKRUibLiH30KpPuPBjel7E8ZydQW1HYWHfoGmidzC2RnhwCC293hCzw+TFR2nqn8OVSY5t2Q==",
    );
    let mut even = n.clone();
    *even.last_mut().unwrap() &= 0xfe;
    let (n, even, f4): (&[u8], &[u8], &[u8]) = (&n, &even, &[1, 0, 1]);
    type Case<'a> = (Algorithm, &'a [u8], &'a [u8], &'a [u8], &'a [u8]);
    let cases: [Case<'_>; 7] = [
        (Algorithm::RSAMD5, n, f4, &[5], &[]),
        (Algorithm::ED25519, n, f4, &[5], &[]),
        (Algorithm::RSASHA256, even, f4, &[5], &[]),
        (Algorithm::RSASHA256, n, &[2], &[5], &[]),
        (Algorithm::RSASHA256, n, f4, &[], &[]),
        (Algorithm::RSASHA256, n, f4, &[5], &[7]),
        (Algorithm::RSASHA256, &[0x0b], &[3], &[5], &[]),
    ];
    for (alg, n, e, d, p) in cases {
        let r = SigningKey::from_rsa_components(alg, n, e, d, p, &[]);
        assert!(r.is_err(), "{alg} {n:?} {e:?} {d:?} {p:?}");
    }
}

#[test]
fn verify_errors() {
    let v = PurecryptoVerifier;
    for alg in [
        Algorithm::RSAMD5,
        Algorithm::DSA,
        Algorithm::ECC_GOST,
        Algorithm::new(200),
    ] {
        assert!(!v.supports(alg));
        assert_eq!(
            v.verify(alg, &[], b"", &[]),
            Err(Error::UnsupportedAlgorithm)
        );
    }
    // Wrong key and signature sizes.
    for (alg, key_len, sig_len) in [
        (Algorithm::ECDSAP256SHA256, 64, 64),
        (Algorithm::ECDSAP384SHA384, 96, 96),
        (Algorithm::ED25519, 32, 64),
        (Algorithm::ED448, 57, 114),
    ] {
        let key = SigningKey::generate(alg, &mut rng(b"v")).unwrap();
        let mut sig = std::vec![0u8; sig_len];
        key.sign(b"msg", &mut sig).unwrap();
        assert_eq!(v.verify(alg, key.public_key(), b"msg", &sig), Ok(()));
        assert_eq!(
            v.verify(alg, key.public_key(), b"msG", &sig),
            Err(Error::BadSignature)
        );
        assert_eq!(
            v.verify(alg, &key.public_key()[1..], b"msg", &sig),
            Err(Error::InvalidKey)
        );
        assert_eq!(
            v.verify(alg, key.public_key(), b"msg", &sig[1..]),
            Err(Error::BadSignature)
        );
        assert_eq!(
            v.verify(
                alg,
                key.public_key(),
                b"msg",
                &[sig.clone(), std::vec![0]].concat()
            ),
            Err(Error::BadSignature)
        );
        // A zero signature never verifies.
        assert_eq!(
            v.verify(alg, key.public_key(), b"msg", &std::vec![0u8; sig_len]),
            Err(Error::BadSignature)
        );
        assert_eq!(key_len, key.public_key().len());
    }
    // ECDSA points must be on the curve.
    assert_eq!(
        v.verify(Algorithm::ECDSAP256SHA256, &[1; 64], b"", &[1; 64]),
        Err(Error::InvalidKey)
    );
    assert_eq!(
        v.verify(Algorithm::ECDSAP384SHA384, &[1; 96], b"", &[1; 96]),
        Err(Error::InvalidKey)
    );

    // RSA keys.
    let key = rfc5702_key_512(Algorithm::RSASHA256, true);
    let mut sig = [0u8; 128];
    key.sign(b"msg", &mut sig).unwrap();
    let pk = key.public_key();
    assert_eq!(v.verify(Algorithm::RSASHA256, pk, b"msg", &sig), Ok(()));
    assert_eq!(
        v.verify(Algorithm::RSASHA512, pk, b"msg", &sig),
        Err(Error::BadSignature)
    );
    let long = [&[0u8][..], &sig].concat();
    assert_eq!(
        v.verify(Algorithm::RSASHA256, pk, b"msg", &long),
        Err(Error::BadSignature)
    );
    assert_eq!(
        v.verify(Algorithm::RSASHA256, pk, b"msg", &sig[1..]),
        Err(Error::BadSignature)
    );
    // A modulus-sized value >= n is rejected.
    assert_eq!(
        v.verify(Algorithm::RSASHA256, pk, b"msg", &[0xff; 128]),
        Err(Error::BadSignature)
    );
    let modulus = &pk[4..];
    let make = |e: &[u8], n: &[u8]| {
        let mut out = Vec::new();
        crate::dnssec::RsaPublicKey {
            exponent: e,
            modulus: n,
        }
        .compose(&mut out)
        .unwrap();
        out
    };
    let mut even = modulus.to_vec();
    *even.last_mut().unwrap() &= 0xfe;
    for bad in [
        std::vec![],
        std::vec![3, 1, 0],
        make(&[1, 0, 1], &modulus[..63]), // 504 bits
        make(
            &[1, 0, 1],
            &[modulus, modulus, modulus, modulus, &[1]].concat(),
        ), // > 4096 bits
        make(&[1, 0, 1], &even),
        make(&[2], modulus),
        make(&[1], modulus),
        make(&[0xff; 33], modulus),
        make(modulus, &modulus[..64]),
    ] {
        assert_eq!(
            v.verify(Algorithm::RSASHA256, &bad, b"msg", &sig),
            Err(Error::InvalidKey),
            "{bad:?}"
        );
    }
    // 512-bit keys are fine for RSASHA256 but not RSASHA512 (RFC 5702 §2).
    let small = rfc5702_key_256(Algorithm::RSASHA256);
    let mut sig = [0u8; 64];
    small.sign(b"msg", &mut sig).unwrap();
    assert_eq!(
        v.verify(Algorithm::RSASHA256, small.public_key(), b"msg", &sig),
        Ok(())
    );
    assert_eq!(
        v.verify(Algorithm::RSASHA512, small.public_key(), b"msg", &sig),
        Err(Error::InvalidKey)
    );
}

fn sign_with<S: Signer>(s: S, data: &[u8], out: &mut [u8]) -> Result<(Algorithm, usize, usize)> {
    let len = s.sign(data, out)?;
    assert_eq!(
        s.public_key().len(),
        s.algorithm().public_key_len().unwrap()
    );
    Ok((s.algorithm(), s.signature_len(), len))
}

fn verify_with<V: Verifier>(
    v: V,
    alg: Algorithm,
    key: &[u8],
    data: &[u8],
    sig: &[u8],
) -> Result<()> {
    assert!(v.supports(alg));
    v.verify(alg, key, data, sig)
}

#[test]
fn verifier_and_signer_by_reference() {
    let key = SigningKey::from_private_bytes(Algorithm::ED25519, &[9; 32]).unwrap();
    let by_ref: &dyn Signer = &key;
    let mut sig = [0u8; 64];
    assert_eq!(
        sign_with(by_ref, b"x", &mut sig),
        Ok((Algorithm::ED25519, 64, 64))
    );
    assert_eq!(
        sign_with(&key, b"x", &mut sig),
        Ok((Algorithm::ED25519, 64, 64))
    );
    let v: &dyn Verifier = &PurecryptoVerifier;
    assert_eq!(
        verify_with(v, Algorithm::ED25519, key.public_key(), b"x", &sig),
        Ok(())
    );
    assert_eq!(
        verify_with(
            PurecryptoVerifier,
            Algorithm::ED25519,
            key.public_key(),
            b"y",
            &sig
        ),
        Err(Error::BadSignature)
    );
}

#[test]
fn signed_data_from_rdata_enum() {
    // RData values work as RRset members too.
    let key = SigningKey::from_private_bytes(Algorithm::ED25519, &[3; 32]).unwrap();
    let zone = name("example");
    let zk = ZoneKey::new(zone.as_name(), key.dnskey(Dnskey::ZONE | Dnskey::SEP));
    let dnskey = zk.dnskey;
    let rdata = [crate::rdata::RData::Dnskey(dnskey)];
    let set = Rrset::new(zone.as_name(), Class::IN, &rdata);
    let template = zk.rrsig_template(zone.as_name(), Rtype::DNSKEY, 3600, 0, 100);
    let mut sig = [0u8; 64];
    let mut scratch = [0u8; 256];
    let mut w = crate::WireWriter::new(&mut scratch);
    let len = sign_rrset(&key, &template, set, &mut w, &mut sig).unwrap();
    let rrsig = template.with_signature(&sig[..len]);
    assert_eq!(
        verify_rrsig(&PurecryptoVerifier, &zk, &rrsig, set, 50, &mut w),
        Ok(())
    );
    // A scratch buffer too small for the signed data.
    let mut tiny = [0u8; 40];
    let mut w = crate::WireWriter::new(&mut tiny);
    assert_eq!(
        verify_rrsig(&PurecryptoVerifier, &zk, &rrsig, set, 50, &mut w),
        Err(Error::BufferTooSmall)
    );
    assert!(w.is_empty());
}

#[test]
fn hostile_keys_and_signatures() {
    // Random keys and signatures of every size around the expected ones,
    // for every algorithm: verification fails cleanly, never panics.
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let v = PurecryptoVerifier;
    let rsa = rfc5702_key_256(Algorithm::RSASHA256);
    let real_rsa = rsa.public_key().to_vec();
    for round in 0..600 {
        let alg = [5u8, 7, 8, 10, 13, 14, 15, 16][round % 8];
        let alg = Algorithm::new(alg);
        let key_len = match alg.public_key_len() {
            Some(l) => l + (next() % 3) as usize - 1,
            None => (next() % 140) as usize,
        };
        let sig_len = match alg.signature_len() {
            Some(l) => l + (next() % 3) as usize - 1,
            None => (next() % 140) as usize,
        };
        let mut key: Vec<u8> = (0..key_len).map(|_| next() as u8).collect();
        if alg.is_rsa() && round % 3 == 0 {
            // A valid RSA key with a random signature.
            key = real_rsa.clone();
        } else if alg.is_rsa() && key.len() > 2 {
            // Plausible RFC 3110 layouts: short exponent, odd modulus.
            key[0] = (next() % 4) as u8;
            if let Some(last) = key.last_mut() {
                *last |= 1;
            }
        }
        let sig: Vec<u8> = (0..sig_len).map(|_| next() as u8).collect();
        let r = v.verify(alg, &key, b"data", &sig);
        assert!(
            matches!(r, Err(Error::InvalidKey | Error::BadSignature)),
            "{alg} {r:?}"
        );
    }
}
