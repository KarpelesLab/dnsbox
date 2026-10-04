//! RRSIG flow tests: signed-data construction, the RFC 4035 §5.3 checks,
//! and (with the `dnssec` feature) the signed example zones of RFC 4035
//! Appendix A/B (RSASHA1) and RFC 5155 Appendix A (RSASHA1-NSEC3-SHA1).

use super::*;
use crate::dnssec::Algorithm;
#[cfg(feature = "dnssec")]
use crate::dnssec::testvec::b64;
use crate::rdata::{A, Mx};
use crate::{Message, NameBuf, WireWriter};
use std::string::ToString;
use std::vec::Vec;

fn name(s: &str) -> NameBuf {
    NameBuf::from_text(s.as_bytes()).unwrap()
}

#[cfg(feature = "dnssec")]
/// An owned RRSIG parsed from (a subset of) presentation format:
/// `TYPE alg labels ttl expiration inception tag signer base64...`.
struct OwnedRrsig {
    type_covered: Rtype,
    algorithm: Algorithm,
    labels: u8,
    original_ttl: u32,
    expiration: u32,
    inception: u32,
    key_tag: u16,
    signer: NameBuf,
    signature: Vec<u8>,
}

#[cfg(feature = "dnssec")]
impl OwnedRrsig {
    fn parse(text: &str) -> Self {
        let f: Vec<&str> = text.split_whitespace().collect();
        let time = |s: &str| s.parse::<crate::dnssec::Timestamp>().unwrap().get();
        OwnedRrsig {
            type_covered: f[0].parse().unwrap(),
            algorithm: f[1].parse().unwrap(),
            labels: f[2].parse().unwrap(),
            original_ttl: f[3].parse().unwrap(),
            expiration: time(f[4]),
            inception: time(f[5]),
            key_tag: f[6].parse().unwrap(),
            signer: name(f[7]),
            signature: b64(&f[8..].concat()),
        }
    }

    fn view(&self) -> Rrsig<'_> {
        Rrsig {
            type_covered: self.type_covered,
            algorithm: self.algorithm,
            labels: self.labels,
            original_ttl: self.original_ttl,
            expiration: self.expiration,
            inception: self.inception,
            key_tag: self.key_tag,
            signer_name: self.signer.as_name(),
            signature: &self.signature,
        }
    }
}

/// Encodes a type bitmap.
#[cfg(feature = "dnssec")]
fn bitmap(types: &[Rtype]) -> Vec<u8> {
    let mut out = Vec::new();
    crate::rdata::TypeBitmap::compose(types, &mut out).unwrap();
    out
}

fn key<'a>(apex: &'a NameBuf, flags: u16, public_key: &'a [u8]) -> ZoneKey<'a> {
    ZoneKey::new(
        apex.as_name(),
        Dnskey::new(flags, 3, Algorithm::ED25519, public_key),
    )
}

#[test]
fn owner_reconstruction() {
    let apex = name("example");
    let pk = [1u8; 32];
    let k = key(&apex, Dnskey::ZONE, &pk);
    let wildcard = name("*.W.Example");
    let t = k.rrsig_template(wildcard.as_name(), Rtype::MX, 60, 0, 1);
    assert_eq!(t.labels, 2);
    for (owner, expected) in [
        ("A.Z.W.example", "*.w.example."),
        ("Z.w.example", "*.w.example."),
        ("*.W.example", "*.w.example."),
        ("W.Example", "w.example."),
    ] {
        assert_eq!(
            rrsig_owner(&t, name(owner).as_name()).unwrap().to_string(),
            expected,
            "{owner}"
        );
    }
    assert_eq!(
        rrsig_owner(&t, name("example").as_name()),
        Err(Error::RrsetMismatch)
    );
    // The root: labels 0.
    let root = k.rrsig_template(Name::ROOT, Rtype::NS, 60, 0, 1);
    assert_eq!(root.labels, 0);
    assert_eq!(rrsig_owner(&root, Name::ROOT).unwrap().to_string(), ".");
    assert_eq!(
        rrsig_owner(&root, name("com").as_name())
            .unwrap()
            .to_string(),
        "*."
    );
}

#[test]
fn rrsig_checks() {
    let apex = name("Example");
    let pk = [1u8; 32];
    let k = key(&apex, Dnskey::ZONE, &pk);
    let www = name("www.example");
    let t = k.rrsig_template(www.as_name(), Rtype::A, 60, 100, 200);
    assert_eq!(check_rrsig(&t, www.as_name(), 150), Ok(()));
    assert_eq!(
        check_rrsig(&t, www.as_name(), 99),
        Err(Error::SignatureNotYetValid)
    );
    assert_eq!(
        check_rrsig(&t, www.as_name(), 201),
        Err(Error::SignatureExpired)
    );
    // Owner outside the signer's zone, or fewer labels than claimed.
    assert_eq!(
        check_rrsig(&t, name("www.example.net").as_name(), 150),
        Err(Error::RrsetMismatch)
    );
    assert_eq!(
        check_rrsig(&t, name("example").as_name(), 150),
        Err(Error::RrsetMismatch)
    );

    // Key matching (RFC 4035 §5.3.1).
    assert_eq!(k.check_rrsig(&t), Ok(()));
    let upper = name("EXAMPLE");
    assert_eq!(key(&upper, Dnskey::ZONE, &pk).check_rrsig(&t), Ok(()));
    let other = name("example.net");
    for bad in [
        ZoneKey::new(other.as_name(), k.dnskey),
        ZoneKey::new(
            apex.as_name(),
            Dnskey {
                protocol: 4,
                ..k.dnskey
            },
        ),
        ZoneKey::new(
            apex.as_name(),
            Dnskey {
                flags: 0,
                ..k.dnskey
            },
        ),
        ZoneKey::new(
            apex.as_name(),
            Dnskey {
                algorithm: Algorithm::ED448,
                ..k.dnskey
            },
        ),
        ZoneKey::new(
            apex.as_name(),
            Dnskey {
                public_key: &[2; 32],
                ..k.dnskey
            },
        ),
    ] {
        assert_eq!(bad.check_rrsig(&t), Err(Error::KeyMismatch), "{bad:?}");
    }
    assert_eq!(k.key_tag(), t.key_tag);
}

#[test]
fn signed_data_layout() {
    let apex = name("Example");
    let pk = [1u8; 32];
    let k = key(&apex, Dnskey::ZONE, &pk);
    let owner = name("WWW.Example");
    let t = k.rrsig_template(owner.as_name(), Rtype::A, 0x0e10, 0x01020304, 0x05060708);
    let rdata = [
        A::new([192, 0, 2, 2].into()),
        A::new([192, 0, 2, 1].into()),
        A::new([192, 0, 2, 2].into()),
    ];
    let mut buf = [0u8; 256];
    let mut out = WireWriter::new(&mut buf);
    signed_data(&mut out, &t, Rrset::new(owner.as_name(), Class::IN, &rdata)).unwrap();
    let mut expected = Vec::new();
    // RRSIG RDATA without signature; signer lowercased.
    expected.extend(b"\x00\x01\x0f\x02\x00\x00\x0e\x10\x05\x06\x07\x08\x01\x02\x03\x04");
    expected.extend(t.key_tag.to_be_bytes());
    expected.extend(b"\x07example\x00");
    // RRs: lowercase owner, original TTL, sorted, deduplicated.
    for last in [1, 2] {
        expected.extend(b"\x03www\x07example\x00\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04");
        expected.extend([192, 0, 2, last]);
    }
    assert_eq!(out.as_bytes(), expected);

    // Failures leave the output untouched.
    let before = out.as_bytes().to_vec();
    let mx = name("mx.example");
    let wrong = [Mx {
        preference: 1,
        exchange: mx.as_name(),
    }];
    assert_eq!(
        signed_data(&mut out, &t, Rrset::new(owner.as_name(), Class::IN, &wrong)),
        Err(Error::RrsetMismatch)
    );
    let empty: [A; 0] = [];
    assert_eq!(
        signed_data(&mut out, &t, Rrset::new(owner.as_name(), Class::IN, &empty)),
        Err(Error::RrsetMismatch)
    );
    assert_eq!(
        signed_data(&mut out, &t, Rrset::new(apex.as_name(), Class::IN, &rdata)),
        Err(Error::RrsetMismatch)
    );
    assert_eq!(out.as_bytes(), before);
    let mut small = [0u8; 60];
    let mut w = WireWriter::new(&mut small);
    assert_eq!(
        signed_data(&mut w, &t, Rrset::new(owner.as_name(), Class::IN, &rdata)),
        Err(Error::BufferTooSmall)
    );
    assert!(w.is_empty());
}

#[test]
#[cfg(feature = "alloc")]
fn record_rdata_adapter() {
    use crate::rdata::{RData, UnknownRdata};
    use crate::{MessageBuilder, Section};
    // An MX whose exchange is compressed against the owner; RecordRdata
    // composes it expanded and, in canonical form, lowercased.
    let owner = name("Example.COM");
    let mut b = MessageBuilder::new_vec();
    let exchange = name("MAIL.example.com");
    b.push_answer(
        &owner,
        Class::IN,
        300,
        &Mx {
            preference: 5,
            exchange: exchange.as_name(),
        },
    )
    .unwrap();
    b.push_answer(
        &owner,
        Class::IN,
        300,
        &UnknownRdata::new(Rtype::new(65280), b"\x01"),
    )
    .unwrap();
    let wire = b.finish();
    let msg = Message::parse_validated(&wire).unwrap();
    let rrs: Vec<_> = msg.section(Section::Answer).map(Result::unwrap).collect();
    let mx = RecordRdata(rrs[0]);
    assert_eq!(mx.rtype(), Rtype::MX);
    assert_eq!(
        crate::dnssec::canonical_rdata(&mx).unwrap(),
        b"\x00\x05\x04mail\x07example\x03com\x00"
    );
    assert_eq!(
        crate::dnssec::canonical_rdata(&RecordRdata(rrs[1])).unwrap(),
        b"\x01"
    );
    assert_eq!(
        crate::dnssec::canonical_rdata(&RData::Unknown(UnknownRdata::new(Rtype::A, &[]))).unwrap(),
        b""
    );
}

#[test]
#[cfg(feature = "alloc")]
fn large_rrsets_are_cheap() {
    // Thousands of distinct records with long RDATA: the canonical sort is
    // O(n log n), so this stays fast.
    use crate::rdata::UnknownRdata;
    let apex = NameBuf::root();
    let pk = [1u8; 32];
    let k = key(&apex, Dnskey::ZONE, &pk);
    let owner = name("x");
    let t = k.rrsig_template(owner.as_name(), Rtype::new(65000), 60, 0, 1);
    let datas: Vec<Vec<u8>> = (0..4000u32)
        .map(|i| {
            let mut d = std::vec![0x55u8; 250];
            d.extend(i.wrapping_mul(2_654_435_761).to_be_bytes());
            d
        })
        .collect();
    let rdata: Vec<_> = datas
        .iter()
        .map(|d| UnknownRdata::new(Rtype::new(65000), d))
        .collect();
    let mut out = Vec::new();
    signed_data(&mut out, &t, Rrset::new(owner.as_name(), Class::IN, &rdata)).unwrap();
    let prefix = 18 + 1;
    let rr_len = 3 + 10 + 254;
    assert_eq!(out.len(), prefix + 4000 * rr_len);
    // Sorted: each RDATA's last four octets increase.
    let tails: Vec<&[u8]> = (0..4000)
        .map(|i| &out[prefix + (i + 1) * rr_len - 4..prefix + (i + 1) * rr_len])
        .collect();
    assert!(tails.windows(2).all(|w| w[0] < w[1]));
}

#[test]
fn record_rdata_errors() {
    // A message whose MX answer has one byte of RDATA: the record parses,
    // its data does not, and composing reports the error.
    let wire = b"\x00\x00\x81\x80\x00\x00\x00\x01\x00\x00\x00\x00\
                 \x00\x00\x0f\x00\x01\x00\x00\x00\x3c\x00\x01\x00";
    let msg = Message::parse(wire).unwrap();
    let rr = msg.answers().next().unwrap().unwrap();
    let mut buf = [0u8; 16];
    let mut w = WireWriter::new(&mut buf);
    assert_eq!(
        RecordRdata(rr).compose_rdata(&mut w),
        Err(Error::UnexpectedEof)
    );
    let apex = NameBuf::root();
    let pk = [1u8; 32];
    let k = key(&apex, Dnskey::ZONE, &pk);
    let t = k.rrsig_template(Name::ROOT, Rtype::MX, 60, 0, 1);
    let mut buf = [0u8; 128];
    let mut out = WireWriter::new(&mut buf);
    assert_eq!(
        signed_data(
            &mut out,
            &t,
            Rrset::new(Name::ROOT, Class::IN, [RecordRdata(rr)])
        ),
        Err(Error::UnexpectedEof)
    );
    assert!(out.is_empty());
}

/// RFC 4035 Appendix A and B: the signed `example.` zone (RSASHA1, keys
/// 38519 and 9465; signatures valid 2004-04-09 to 2004-05-09).
#[cfg(feature = "dnssec")]
mod rfc4035 {
    use super::*;
    use crate::dnssec::PurecryptoVerifier;
    use crate::rdata::{Ds, Hinfo, Ns, Nsec, Soa, TypeBitmap};
    use crate::{CharStr, ComposeRdata, Rtype};

    pub(super) const ZSK: &str = "AQOy1bZVvpPqhg4j7EJoM9rI3ZmyEx2OzDBV
        rZy/lvI5CQePxXHZS4i8dANH4DX3tbHol61e k8EFMcsGXxKciJFHyhl94C+NwILQdzsUlSFo
        vBZsyl/NX6yEbtw/xN9ZNcrbYvgjjZ/UVPZI ySFNsgEYvh0z2542lzMKR4Dh8uZffQ==";
    pub(super) const KSK: &str = "AQOeX7+baTmvpVHb2CcLnL1dMRWbuscRvHXl
        LnXwDzvqp4tZVKp1sZMepFb8MvxhhW3y/0QZ syCjczGJ1qk8vJe52iOhInKROVLRwxGpMfzP
        RLMlGybr51bOV/1se0ODacj3DomyB4QB5gKT Yot/K9alk5/j8vfd4jWCWD+E1Sze0Q==";
    const NOW: u32 = 1_081_800_000; // 2004-04-12

    fn verify<D: ComposeRdata>(owner: &str, rdata: &[D], rrsig: &str, key: &ZoneKey<'_>) {
        let owner = name(owner);
        let rrsig = OwnedRrsig::parse(rrsig);
        let rrset = Rrset::new(owner.as_name(), Class::IN, rdata);
        let mut scratch = Vec::new();
        assert_eq!(
            verify_rrsig(
                &PurecryptoVerifier,
                key,
                &rrsig.view(),
                rrset,
                NOW,
                &mut scratch
            ),
            Ok(()),
            "{owner} {}",
            rrsig.type_covered
        );
        // Flipping any bit of the signature breaks it.
        let mut bad = rrsig.signature.clone();
        bad[10] ^= 1;
        let bad_rrsig = Rrsig {
            signature: &bad,
            ..rrsig.view()
        };
        assert_eq!(
            verify_rrsig(
                &PurecryptoVerifier,
                key,
                &bad_rrsig,
                rrset,
                NOW,
                &mut scratch
            ),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn signed_zone() {
        let apex = name("example");
        let zsk_pk = b64(ZSK);
        let ksk_pk = b64(KSK);
        let zsk_rdata = Dnskey::new(256, 3, Algorithm::RSASHA1, &zsk_pk);
        let ksk_rdata = Dnskey::new(257, 3, Algorithm::RSASHA1, &ksk_pk);
        let zsk = ZoneKey::new(apex.as_name(), zsk_rdata);
        let ksk = ZoneKey::new(apex.as_name(), ksk_rdata);
        assert_eq!((zsk.key_tag(), ksk.key_tag()), (38519, 9465));

        let (ns1, ns2, xx, bugs) = (
            name("ns1.example"),
            name("ns2.example"),
            name("xx.example"),
            name("bugs.x.w.example"),
        );
        let soa = Soa {
            mname: ns1.as_name(),
            rname: bugs.as_name(),
            serial: 1_081_539_377,
            refresh: 3600,
            retry: 300,
            expire: 3_600_000,
            minimum: 3600,
        };
        verify(
            "example",
            &[soa],
            "SOA 5 1 3600 20040509183619 20040409183619 38519 example.
             ONx0k36rcjaxYtcNgq6iQnpNV5+drqYAsC9h 7TSJaHCqbhE67Sr6aH2xDUGcqQWu/n0UVzrF
             vkgO9ebarZ0GWDKcuwlM6eNB5SiX2K74l5LW DA7S/Un/IbtDq4Ay8NMNLQI7Dw7n4p8/rjkB
             jV7j86HyQgM5e7+miRAz8V01b0I=",
            &zsk,
        );
        verify(
            "example",
            &[Ns::new(ns2.as_name()), Ns::new(ns1.as_name())],
            "NS 5 1 3600 20040509183619 20040409183619 38519 example.
             gl13F00f2U0R+SWiXXLHwsMY+qStYy5k6zfd EuivWc+wd1fmbNCyql0Tk7lHTX6UOxc8AgNf
             4ISFve8XqF4q+o9qlnqIzmppU3LiNeKT4FZ8 RO5urFOvoMRTbQxW3U0hXWuggE4g3ZpsHv48
             0HjMeRaZB/FRPGfJPajngcq6Kwg=",
            &zsk,
        );
        verify(
            "example",
            &[Mx {
                preference: 1,
                exchange: xx.as_name(),
            }],
            "MX 5 1 3600 20040509183619 20040409183619 38519 example.
             HyDHYVT5KHSZ7HtO/vypumPmSZQrcOP3tzWB 2qaKkHVPfau/DgLgS/IKENkYOGL95G4N+NzE
             VyNU8dcTOckT+ChPcGeVjguQ7a3Ao9Z/ZkUO 6gmmUW4b89rz1PUxW4jzUxj66PTwoVtUU/iM
             W6OISukd1EQt7a0kygkg+PEDxdI=",
            &zsk,
        );
        let a_ex = name("a.example");
        let types = bitmap(&[
            Rtype::NS,
            Rtype::SOA,
            Rtype::MX,
            Rtype::RRSIG,
            Rtype::NSEC,
            Rtype::DNSKEY,
        ]);
        verify(
            "example",
            &[Nsec::new(a_ex.as_name(), TypeBitmap::new(&types).unwrap())],
            "NSEC 5 1 3600 20040509183619 20040409183619 38519 example.
             O0k558jHhyrC97ISHnislm4kLMW48C7U7cBm FTfhke5iVqNRVTB1STLMpgpbDIC9hcryoO0V
             Z9ME5xPzUEhbvGnHd5sfzgFVeGxr5Nyyq4tW SDBgIBiLQUv1ivy29vhXy7WgR62dPrZ0PWvm
             jfFJ5arXf4nPxp/kEowGgBRzY/U=",
            &zsk,
        );
        let keys = [zsk_rdata, ksk_rdata];
        verify(
            "example",
            &keys,
            "DNSKEY 5 1 3600 20040509183619 20040409183619 9465 example.
             ZxgauAuIj+k1YoVEOSlZfx41fcmKzTFHoweZ xYnz99JVQZJ33wFS0Q0jcP7VXKkaElXk9nYJ
             XevO/7nAbo88iWsMkSpSR6jWzYYKwfrBI/L9 hjYmyVO9m6FjQ7uwM4dCP/bIuV/DKqOAK9NY
             NC3AHfvCV1Tp4VKDqxqG7R5tTVM=",
            &ksk,
        );
        verify(
            "example",
            &keys,
            "DNSKEY 5 1 3600 20040509183619 20040409183619 38519 example.
             eGL0s90glUqcOmloo/2y+bSzyEfKVOQViD9Z DNhLz/Yn9CQZlDVRJffACQDAUhXpU/oP34ri
             bKBpysRXosczFrKqS5Oa0bzMOfXCXup9qHAp eFIku28Vqfr8Nt7cigZLxjK+u0Ws/4lIRjKk
             7z5OXogYVaFzHKillDt3HRxHIZM=",
            &zsk,
        );
        let digest = crate::testutil::hex("B6DCD485719ADCA18E5F3D48A2331627FDD3636B");
        verify(
            "a.example",
            &[Ds::new(
                57855,
                Algorithm::RSASHA1,
                crate::dnssec::DigestType::SHA1,
                &digest,
            )],
            "DS 5 2 3600 20040509183619 20040409183619 38519 example.
             oXIKit/QtdG64J/CB+Gi8dOvnwRvqrto1AdQ oRkAN15FP3iZ7suB7gvTBmXzCjL7XUgQVcoH
             kdhyCuzp8W9qJHgRUSwKKkczSyuL64nhgjuD EML8l9wlWVsl7PR2VnZduM9bLyBhaaPmRKX/
             Fm+v6ccF2EGNLRiY08kdkz+XHHo=",
            &zsk,
        );
        verify(
            "ai.example",
            &[A::new([192, 0, 2, 9].into())],
            "A 5 2 3600 20040509183619 20040409183619 38519 example.
             pAOtzLP2MU0tDJUwHOKE5FPIIHmdYsCgTb5B ERGgpnJluA9ixOyf6xxVCgrEJW0WNZSsJicd
             hBHXfDmAGKUajUUlYSAH8tS4ZnrhyymIvk3u ArDu2wfT130e9UHnumaHHMpUTosKe22PblOy
             6zrTpg9FkS0XGVmYRvOTNYx2HvQ=",
            &zsk,
        );
        verify(
            "ai.example",
            &[Hinfo {
                cpu: CharStr::new(b"KLH-10").unwrap(),
                os: CharStr::new(b"ITS").unwrap(),
            }],
            "HINFO 5 2 3600 20040509183619 20040409183619 38519 example.
             Iq/RGCbBdKzcYzlGE4ovbr5YcB+ezxbZ9W0l e/7WqyvhOO9J16HxhhL7VY/IKmTUY0GGdcfh
             ZEOCkf4lEykZF9NPok1/R/fWrtzNp8jobuY7 AZEcZadp1WdDF3jc2/ndCa5XZhLKD3JzOsBw
             FvL8sqlS5QS6FY/ijFEDnI4RkZA=",
            &zsk,
        );
        verify(
            "ai.example",
            &[crate::rdata::Aaaa::new(
                "2001:db8::f00:baa9".parse().unwrap(),
            )],
            "AAAA 5 2 3600 20040509183619 20040409183619 38519 example.
             nLcpFuXdT35AcE+EoafOUkl69KB+/e56XmFK kewXG2IadYLKAOBIoR5+VoQV3XgTcofTJNsh
             1rnF6Eav2zpZB3byI6yo2bwY8MNkr4A7cL9T cMmDwV/hWFKsbGBsj8xSCN/caEL2CWY/5XP2
             sZM6QjBBLmukH30+w1z3h8PUP2o=",
            &zsk,
        );

        // Appendix B.6: an answer synthesized from *.w.example (labels 2
        // for a four-label owner), and the NSEC proving a.z.w.example
        // does not exist.
        let ai = name("ai.example");
        verify(
            "a.z.w.example",
            &[Mx {
                preference: 1,
                exchange: ai.as_name(),
            }],
            "MX 5 2 3600 20040509183619 20040409183619 38519 example.
             OMK8rAZlepfzLWW75Dxd63jy2wswESzxDKG2 f9AMN1CytCd10cYISAxfAdvXSZ7xujKAtPbc
             tvOQ2ofO7AZJ+d01EeeQTVBPq4/6KCWhqe2X TjnkVLNvvhnc0u28aoSsG0+4InvkkOHknKxw
             4kX18MMR34i8lC36SR5xBni8vHI=",
            &zsk,
        );
        let types = bitmap(&[Rtype::MX, Rtype::RRSIG, Rtype::NSEC]);
        let nsec = Nsec::new(xx.as_name(), TypeBitmap::new(&types).unwrap());
        verify(
            "x.y.w.example",
            &[nsec],
            "NSEC 5 4 3600 20040509183619 20040409183619 38519 example.
             OvE6WUzN2ziieJcvKPWbCAyXyP6ef8cr6Csp ArVSTzKSquNwbezZmkU7E34o5lmb6CWSSSpg
             xw098kNUFnHcQf/LzY2zqRomubrNQhJTiDTX a0ArunJQCzPjOYq5t0SLjm6qp6McJI1AP5Vr
             QoKqJDCLnoAlcPOPKAm/jJkn3jk=",
            &zsk,
        );
        assert!(nsec.covers(
            &name("x.y.w.example").as_name(),
            &name("a.z.w.example").as_name()
        ));
        // The DS of RFC 4034 §5.4 style for the KSK.
        assert_eq!(
            crate::dnssec::verify_ds(
                &Ds::new(
                    9465,
                    Algorithm::RSASHA1,
                    crate::dnssec::DigestType::SHA1,
                    &[0; 20]
                ),
                apex.as_name(),
                &ksk_rdata
            ),
            Err(Error::BadSignature)
        );
    }
}

/// RFC 5155 Appendix A: the NSEC3-signed `example.` zone
/// (RSASHA1-NSEC3-SHA1, keys 40430 and 12708; signatures valid
/// 2005-10-21 to 2015-04-20).
#[cfg(feature = "dnssec")]
mod rfc5155 {
    use super::*;
    use crate::dnssec::{Nsec3Hash, Nsec3HashAlgorithm, PurecryptoVerifier, nsec3_hash};
    use crate::rdata::{Nsec3, Nsec3param, RData, TypeBitmap};

    const NOW: u32 = 1_200_000_000; // 2008-01-10

    #[test]
    fn signed_zone() {
        let apex = name("example");
        let zsk_pk = b64(
            "AwEAAaetidLzsKWUt4swWR8yu0wPHPiUi8LU sAD0QPWU+wzt89epO6tHzkMBVDkC7qphQO2h
                          TY4hHn9npWFRw5BYubE=",
        );
        let ksk_pk = b64(
            "AwEAAcUlFV1vhmqx6NSOUOq2R/dsR7Xm3upJ j7IommWSpJABVfW8Q0rOvXdM6kzt+TAu92L9
                          AbsUdblMFin8CVF3n4s=",
        );
        let zsk_rdata = Dnskey::new(256, 3, Algorithm::RSASHA1_NSEC3_SHA1, &zsk_pk);
        let ksk_rdata = Dnskey::new(257, 3, Algorithm::RSASHA1_NSEC3_SHA1, &ksk_pk);
        let zsk = ZoneKey::new(apex.as_name(), zsk_rdata);
        let ksk = ZoneKey::new(apex.as_name(), ksk_rdata);
        assert_eq!((zsk.key_tag(), ksk.key_tag()), (40430, 12708));
        let mut scratch = Vec::new();
        let mut check = |owner: &NameBuf, rdata: &[RData<'_>], text: &str, key: &ZoneKey<'_>| {
            let rrsig = OwnedRrsig::parse(text);
            let rrset = Rrset::new(owner.as_name(), Class::IN, rdata);
            verify_rrsig(
                &PurecryptoVerifier,
                key,
                &rrsig.view(),
                rrset,
                NOW,
                &mut scratch,
            )
        };

        let keys = [RData::Dnskey(zsk_rdata), RData::Dnskey(ksk_rdata)];
        assert_eq!(
            check(
                &apex,
                &keys,
                "DNSKEY 7 1 3600 20150420235959 20051021000000 12708 example.
                 AuU4juU9RaxescSmStrQks3Gh9FblGBlVU31 uzMZ/U/FpsUb8aC6QZS+sTsJXnLnz7flGOsm
                 MGQZf3bH+QsCtg==",
                &ksk
            ),
            Ok(())
        );
        let salt = [0xaa, 0xbb, 0xcc, 0xdd];
        let param = Nsec3param {
            hash_algorithm: Nsec3HashAlgorithm::SHA1,
            flags: 0,
            iterations: 12,
            salt: &salt,
        };
        assert_eq!(
            check(
                &apex,
                &[RData::Nsec3param(param)],
                "NSEC3PARAM 7 1 3600 20150420235959 20051021000000 40430 example.
                 C1Gl8tPZNtnjlrYWDeeUV/sGLCyy/IHie2re rN05XSA3Pq0U3+4VvGWYWdUMfflOdxqnXHwJ
                 TLQsjlkynhG6Cg==",
                &zsk
            ),
            Ok(())
        );

        // The NSEC3 for the apex: its owner is H(example).
        let h = nsec3_hash(
            apex.as_name(),
            param.hash_algorithm,
            param.iterations,
            param.salt,
        )
        .unwrap();
        let owner = h.owner_name(apex.as_name()).unwrap();
        assert_eq!(
            owner.to_string(),
            "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example."
        );
        let next =
            Nsec3Hash::from_owner(name("2t7b4g4vsa5smi47k61mv5bv1a22bojr.example").as_name())
                .unwrap();
        let types = bitmap(&[
            Rtype::MX,
            Rtype::DNSKEY,
            Rtype::NS,
            Rtype::SOA,
            Rtype::NSEC3PARAM,
            Rtype::RRSIG,
        ]);
        let nsec3 = Nsec3 {
            hash_algorithm: Nsec3HashAlgorithm::SHA1,
            flags: 1,
            iterations: 12,
            salt: &salt,
            next_hashed_owner: next.as_bytes(),
            types: TypeBitmap::new(&types).unwrap(),
        };
        assert_eq!(
            check(
                &owner,
                &[RData::Nsec3(nsec3)],
                "NSEC3 7 2 3600 20150420235959 20051021000000 40430 example.
                 OSgWSm26B+cS+dDL8b5QrWr/dEWhtCsKlwKL IBHYH6blRxK9rC0bMJPwQ4mLIuw85H2EY762
                 BOCXJZMnpuwhpA==",
                &zsk
            ),
            Ok(())
        );
        // Hash order: H(example) < H(ns1.example)? No: 0p9m... > 2t7b...,
        // so this is not a wrap-around record and covers names whose hash
        // lies between the two.
        let c = nsec3_hash(
            name("c.x.w.example").as_name(),
            Nsec3HashAlgorithm::SHA1,
            12,
            &salt,
        )
        .unwrap();
        assert_eq!(
            c.to_string().to_ascii_lowercase(),
            "0va5bpr2ou0vk0lbqeeljri88laipsfh"
        );
        assert!(nsec3.covers(h.as_bytes(), c.as_bytes()));
        assert!(!nsec3.covers(h.as_bytes(), h.as_bytes()));

        let ns_owner = name("2t7b4g4vsa5smi47k61mv5bv1a22bojr.example");
        assert_eq!(
            check(
                &ns_owner,
                &[RData::A(A::new([192, 0, 2, 127].into()))],
                "A 7 2 3600 20150420235959 20051021000000 40430 example.
                 h6c++bzhRuWWt2bykN6mjaTNBcXNq5UuL5Ed K+iDP4eY8I0kSiKaCjg3tC1SQkeloMeub2GW
                 k8p6xHMPZumXlw==",
                &zsk
            ),
            Ok(())
        );
    }
}
