//! Chain-of-trust tests: DNSKEY authentication from DS records and trust
//! anchors, RRset verification with key selection, wildcard expansions and
//! the work bound, with a crypto-free verifier; then real signatures (an
//! Ed25519 zone, and the RFC 5155 Appendix A zone with its published
//! RSASHA1-NSEC3-SHA1 signatures).

use core::cell::Cell;

use super::*;
use crate::dnssec::denial::tests::{OwnedNsec, name};
use crate::dnssec::{Denial, DenialStatus, NsecProof, NsecRecord};
use crate::rdata::{A, Mx};
use crate::wire::WireWriter;
use crate::{NameBuf, Rtype};
use std::vec::Vec;

const NOW: u32 = 1_500;

/// A crypto-free verifier: a signature is valid when it equals the public
/// key. Supports Ed25519 only and counts its calls.
#[derive(Default)]
struct Fake {
    calls: Cell<usize>,
}

impl Verifier for Fake {
    fn supports(&self, algorithm: Algorithm) -> bool {
        algorithm == Algorithm::ED25519
    }

    fn verify(&self, algorithm: Algorithm, key: &[u8], _: &[u8], signature: &[u8]) -> Result<()> {
        assert_eq!(algorithm, Algorithm::ED25519);
        self.calls.set(self.calls.get() + 1);
        if key == signature {
            Ok(())
        } else {
            Err(Error::BadSignature)
        }
    }
}

const KSK_KEY: [u8; 32] = [1; 32];
const ZSK_KEY: [u8; 32] = [2; 32];
const KSK: Dnskey<'static> = Dnskey::new(257, 3, Algorithm::ED25519, &KSK_KEY);
const ZSK: Dnskey<'static> = Dnskey::new(256, 3, Algorithm::ED25519, &ZSK_KEY);

/// An RRSIG over `owner`/`rtype` by `key` of `zone`, valid for the fake
/// verifier.
fn fake_rrsig<'k>(zone: &'k NameBuf, key: Dnskey<'k>, owner: &NameBuf, rtype: Rtype) -> Rrsig<'k> {
    ZoneKey::new(zone.as_name(), key)
        .rrsig_template(owner.as_name(), rtype, 3600, 1_000, 2_000)
        .with_signature(key.public_key)
}

fn scratch_buf() -> [u8; 4096] {
    [0; 4096]
}

fn a_rdata() -> [A; 2] {
    [A::new([192, 0, 2, 1].into()), A::new([192, 0, 2, 2].into())]
}

#[test]
fn verify_rrset_selects_the_key() {
    let zone = name("example");
    let www = name("www.example");
    let keys = TrustedKeys::assume_trusted(zone.as_name(), Class::IN, [KSK, ZSK]);
    assert_eq!(keys.zone(), zone.as_name());
    assert_eq!(keys.class(), Class::IN);
    assert_eq!(keys.keys(), [KSK, ZSK]);
    let rdata = a_rdata();
    let rrset = Rrset::new(www.as_name(), Class::IN, &rdata);
    let mut buf = scratch_buf();
    let mut scratch = WireWriter::new(&mut buf);
    let v = Fake::default();

    let good = fake_rrsig(&zone, ZSK, &www, Rtype::A);
    let verified = keys
        .verify_rrset(&v, rrset, [good], NOW, &mut scratch)
        .unwrap();
    assert_eq!(
        verified,
        Verified {
            key_tag: ZSK.key_tag(),
            algorithm: Algorithm::ED25519,
            labels: 2,
            original_ttl: 3600,
            expiration: 2_000,
            wildcard: None,
        }
    );
    assert!(!verified.is_wildcard_expansion());
    assert_eq!(v.calls.get(), 1);
    assert!(scratch.is_empty());

    // One valid signature among bad ones suffices (RFC 6840 §5.11), and
    // RRSIGs of other types, signers or unknown keys are skipped (§5.12).
    let bad = good.with_signature(&[9; 32]);
    let other_type = fake_rrsig(&zone, ZSK, &www, Rtype::AAAA);
    let other_zone = name("other");
    let other_signer = fake_rrsig(&other_zone, ZSK, &www, Rtype::A);
    let unknown_key = Rrsig {
        key_tag: ZSK.key_tag().wrapping_add(1),
        ..good
    };
    let v = Fake::default();
    let sigs = [other_type, other_signer, unknown_key, bad, good];
    assert!(
        keys.verify_rrset(&v, rrset, sigs, NOW, &mut scratch)
            .is_ok()
    );
    assert_eq!(v.calls.get(), 2);

    // Failures, from the least to the most informative.
    let v = Fake::default();
    let none: [Rrsig<'_>; 0] = [];
    assert_eq!(
        keys.verify_rrset(&v, rrset, none, NOW, &mut scratch),
        Err(Error::Unsigned)
    );
    assert_eq!(
        keys.verify_rrset(&v, rrset, [other_type, other_signer], NOW, &mut scratch),
        Err(Error::Unsigned)
    );
    assert_eq!(
        keys.verify_rrset(&v, rrset, [unknown_key, other_type], NOW, &mut scratch),
        Err(Error::KeyMismatch)
    );
    assert_eq!(
        keys.verify_rrset(&v, rrset, [bad, unknown_key], NOW, &mut scratch),
        Err(Error::BadSignature)
    );
    assert_eq!(
        keys.verify_rrset(&v, rrset, [good], 2_001, &mut scratch),
        Err(Error::SignatureExpired)
    );
    assert_eq!(
        keys.verify_rrset(&v, rrset, [good], 999, &mut scratch),
        Err(Error::SignatureNotYetValid)
    );
    assert!(scratch.is_empty());

    // RRsets the keys cannot sign.
    let empty: [A; 0] = [];
    assert_eq!(
        keys.verify_rrset(
            &v,
            Rrset::new(www.as_name(), Class::IN, &empty),
            [good],
            NOW,
            &mut scratch
        ),
        Err(Error::RrsetMismatch)
    );
    let outside = name("www.example.com");
    assert_eq!(
        keys.verify_rrset(
            &v,
            Rrset::new(outside.as_name(), Class::IN, &rdata),
            [good],
            NOW,
            &mut scratch
        ),
        Err(Error::RrsetMismatch)
    );
}

#[test]
fn unusable_keys() {
    let zone = name("example");
    let www = name("www.example");
    let rdata = a_rdata();
    let rrset = Rrset::new(www.as_name(), Class::IN, &rdata);
    let mut buf = scratch_buf();
    let mut scratch = WireWriter::new(&mut buf);
    let v = Fake::default();
    // Revoked (RFC 5011 §2.1), not a zone key, wrong protocol.
    for flags in [256 | Dnskey::REVOKE, 0] {
        let key = Dnskey::new(flags, 3, Algorithm::ED25519, &ZSK_KEY);
        let keys = TrustedKeys::assume_trusted(zone.as_name(), Class::IN, [key]);
        let rrsig = fake_rrsig(&zone, key, &www, Rtype::A);
        assert_eq!(
            keys.verify_rrset(&v, rrset, [rrsig], NOW, &mut scratch),
            Err(Error::KeyMismatch),
            "{flags}"
        );
    }
    let key = Dnskey::new(256, 2, Algorithm::ED25519, &ZSK_KEY);
    let keys = TrustedKeys::assume_trusted(zone.as_name(), Class::IN, [key]);
    let rrsig = fake_rrsig(&zone, key, &www, Rtype::A);
    assert_eq!(
        keys.verify_rrset(&v, rrset, [rrsig], NOW, &mut scratch),
        Err(Error::KeyMismatch)
    );
    // An algorithm the verifier does not support.
    let key = Dnskey::new(256, 3, Algorithm::RSASHA256, &[3, 1, 0, 1, 0xc3]);
    let keys = TrustedKeys::assume_trusted(zone.as_name(), Class::IN, [key]);
    let rrsig = fake_rrsig(&zone, key, &www, Rtype::A);
    assert_eq!(
        keys.verify_rrset(&v, rrset, [rrsig], NOW, &mut scratch),
        Err(Error::UnsupportedAlgorithm)
    );
    assert_eq!(v.calls.get(), 0);
}

#[test]
fn work_is_bounded() {
    // KeyTrap (CVE-2023-50387): many keys with the same tag and many
    // signatures cost at most MAX_CRYPTO_OPERATIONS verifications.
    let zone = name("example");
    let www = name("www.example");
    let rdata = a_rdata();
    let rrset = Rrset::new(www.as_name(), Class::IN, &rdata);
    let mut buf = scratch_buf();
    let mut scratch = WireWriter::new(&mut buf);
    let keys = [ZSK; 50];
    let keys = TrustedKeys::assume_trusted(zone.as_name(), Class::IN, keys);
    let good = fake_rrsig(&zone, ZSK, &www, Rtype::A);
    let bad = good.with_signature(&[9; 32]);
    let mut sigs = [bad; 50];
    sigs[49] = good;
    let v = Fake::default();
    assert_eq!(
        keys.verify_rrset(&v, rrset, sigs, NOW, &mut scratch),
        Err(Error::BadSignature)
    );
    assert_eq!(v.calls.get(), MAX_CRYPTO_OPERATIONS);
    assert!(scratch.is_empty());
    // A good signature within the budget is found.
    let keys = TrustedKeys::assume_trusted(zone.as_name(), Class::IN, [ZSK]);
    let mut sigs = [bad; 50];
    sigs[MAX_CRYPTO_OPERATIONS - 1] = good;
    let v = Fake::default();
    assert!(
        keys.verify_rrset(&v, rrset, sigs, NOW, &mut scratch)
            .is_ok()
    );
    assert_eq!(v.calls.get(), MAX_CRYPTO_OPERATIONS);
}

#[test]
fn from_anchors() {
    let zone = name("example");
    let dnskeys = [KSK, ZSK];
    let rrset = Rrset::new(zone.as_name(), Class::IN, dnskeys);
    let by_ksk = fake_rrsig(&zone, KSK, &zone, Rtype::DNSKEY);
    let by_zsk = fake_rrsig(&zone, ZSK, &zone, Rtype::DNSKEY);
    let mut buf = scratch_buf();
    let mut scratch = WireWriter::new(&mut buf);
    let v = Fake::default();

    let keys =
        TrustedKeys::from_anchors(&v, rrset, [KSK], [by_zsk, by_ksk], NOW, &mut scratch).unwrap();
    assert_eq!(keys.zone(), zone.as_name());
    // The authenticated keys verify the zone's data.
    let www = name("www.example");
    let rdata = a_rdata();
    let a = Rrset::new(www.as_name(), Class::IN, &rdata);
    let sig = fake_rrsig(&zone, ZSK, &www, Rtype::A);
    assert!(keys.verify_rrset(&v, a, [sig], NOW, &mut scratch).is_ok());

    // An anchor matching a key that did not sign the set.
    assert_eq!(
        TrustedKeys::from_anchors(&v, rrset, [KSK], [by_zsk], NOW, &mut scratch).err(),
        Some(Error::KeyMismatch)
    );
    // An anchor not in the set.
    let other = Dnskey::new(257, 3, Algorithm::ED25519, &[7; 32]);
    assert_eq!(
        TrustedKeys::from_anchors(&v, rrset, [other], [by_ksk], NOW, &mut scratch).err(),
        Some(Error::KeyMismatch)
    );
    // The anchored key's signature is bad.
    let forged = by_ksk.with_signature(&ZSK_KEY);
    assert_eq!(
        TrustedKeys::from_anchors(&v, rrset, [KSK], [forged], NOW, &mut scratch).err(),
        Some(Error::BadSignature)
    );
    let none: [Rrsig<'_>; 0] = [];
    assert_eq!(
        TrustedKeys::from_anchors(&v, rrset, [KSK], none, NOW, &mut scratch).err(),
        Some(Error::Unsigned)
    );
}

#[cfg(feature = "dnssec-digest")]
#[test]
fn from_ds() {
    use crate::dnssec::DigestType;
    use crate::rdata::Ds;

    let zone = name("example");
    let dnskeys = [KSK, ZSK];
    let rrset = Rrset::new(zone.as_name(), Class::IN, dnskeys);
    let by_ksk = fake_rrsig(&zone, KSK, &zone, Rtype::DNSKEY);
    let by_zsk = fake_rrsig(&zone, ZSK, &zone, Rtype::DNSKEY);
    let mut buf = scratch_buf();
    let mut scratch = WireWriter::new(&mut buf);
    let v = Fake::default();

    let ksk = ZoneKey::new(zone.as_name(), KSK);
    let sha256 = ksk.ds(DigestType::SHA256).unwrap();
    let sha1 = ksk.ds(DigestType::SHA1).unwrap();
    let sha384 = ksk.ds(DigestType::SHA384).unwrap();
    let ds256 = sha256.to_ds();
    let ds1 = sha1.to_ds();

    let keys = TrustedKeys::from_ds(&v, rrset, [ds256], [by_ksk], NOW, &mut scratch).unwrap();
    assert_eq!(keys.keys(), dnskeys);
    assert!(TrustedKeys::from_ds(&v, rrset, [sha384.to_ds()], [by_ksk], NOW, &mut scratch).is_ok());
    assert!(TrustedKeys::from_ds(&v, rrset, [ds1], [by_ksk], NOW, &mut scratch).is_ok());
    // Several DS and RRSIGs: one matching pair suffices.
    let unrelated = Ds::new(1, Algorithm::ED25519, DigestType::SHA256, &[0; 32]);
    assert!(
        TrustedKeys::from_ds(
            &v,
            rrset,
            [unrelated, ds256],
            [by_zsk, by_ksk],
            NOW,
            &mut scratch
        )
        .is_ok()
    );

    // The DS-matched key must be the signer.
    assert_eq!(
        TrustedKeys::from_ds(&v, rrset, [ds256], [by_zsk], NOW, &mut scratch).err(),
        Some(Error::KeyMismatch)
    );
    // A wrong digest.
    let mut digest = sha256.digest().to_vec();
    digest[0] ^= 1;
    let wrong = Ds::new(ds256.key_tag, ds256.algorithm, DigestType::SHA256, &digest);
    assert_eq!(
        TrustedKeys::from_ds(&v, rrset, [wrong], [by_ksk], NOW, &mut scratch).err(),
        Some(Error::KeyMismatch)
    );
    // SHA-1 is ignored next to SHA-256 (RFC 4509 §3).
    assert_eq!(
        TrustedKeys::from_ds(&v, rrset, [ds1, wrong], [by_ksk], NOW, &mut scratch).err(),
        Some(Error::KeyMismatch)
    );
    // No signature at all.
    let none: [Rrsig<'_>; 0] = [];
    assert_eq!(
        TrustedKeys::from_ds(&v, rrset, [ds256], none, NOW, &mut scratch).err(),
        Some(Error::Unsigned)
    );
    // Only unsupported digests or algorithms: insecure (RFC 4035 §5.2,
    // RFC 6840 §5.2).
    for ds in [
        Ds::new(
            ds256.key_tag,
            Algorithm::ED25519,
            DigestType::GOST,
            &[0; 32],
        ),
        Ds::new(
            ds256.key_tag,
            Algorithm::ED25519,
            DigestType::new(200),
            &[0; 32],
        ),
        Ds::new(
            ds256.key_tag,
            Algorithm::RSASHA256,
            DigestType::SHA256,
            sha256.digest(),
        ),
    ] {
        assert_eq!(
            TrustedKeys::from_ds(&v, rrset, [ds], [by_ksk], NOW, &mut scratch).err(),
            Some(Error::UnsupportedAlgorithm)
        );
    }
    let empty: [Ds<'_>; 0] = [];
    assert_eq!(
        TrustedKeys::from_ds(&v, rrset, empty, [by_ksk], NOW, &mut scratch).err(),
        Some(Error::UnsupportedAlgorithm)
    );
    // A revoked KSK cannot be the entry point.
    let revoked = Dnskey::new(257 | Dnskey::REVOKE, 3, Algorithm::ED25519, &KSK_KEY);
    let set = [revoked, ZSK];
    let rrset = Rrset::new(zone.as_name(), Class::IN, set);
    let ds = ZoneKey::new(zone.as_name(), revoked)
        .ds(DigestType::SHA256)
        .unwrap();
    let sig = fake_rrsig(&zone, revoked, &zone, Rtype::DNSKEY);
    assert_eq!(
        TrustedKeys::from_ds(&v, rrset, [ds.to_ds()], [sig], NOW, &mut scratch).err(),
        Some(Error::KeyMismatch)
    );
    assert!(scratch.is_empty());
}

#[cfg(feature = "dnssec-digest")]
#[test]
fn from_ds_work_is_bounded() {
    use crate::dnssec::DigestType;

    let zone = name("example");
    let set = [KSK; 40];
    let rrset = Rrset::new(zone.as_name(), Class::IN, set);
    let by_ksk = fake_rrsig(&zone, KSK, &zone, Rtype::DNSKEY);
    let bad = by_ksk.with_signature(&[0; 32]);
    let ds = ZoneKey::new(zone.as_name(), KSK)
        .ds(DigestType::SHA256)
        .unwrap();
    let mut buf = scratch_buf();
    let mut scratch = WireWriter::new(&mut buf);
    let v = Fake::default();
    // Each (RRSIG, key) pair costs a DS digest and a verification.
    assert_eq!(
        TrustedKeys::from_ds(&v, rrset, [ds.to_ds(); 40], [bad; 40], NOW, &mut scratch).err(),
        Some(Error::BadSignature)
    );
    assert!(v.calls.get() <= MAX_CRYPTO_OPERATIONS / 2);
}

/// The NSEC chain of a zone with a wildcard: `example.`, `*.example.`,
/// `www.example.`.
fn wildcard_chain() -> [OwnedNsec; 3] {
    [
        OwnedNsec::new(
            "example",
            "*.example",
            &[Rtype::SOA, Rtype::NS, Rtype::NSEC],
        ),
        OwnedNsec::new("*.example", "www.example", &[Rtype::MX, Rtype::NSEC]),
        OwnedNsec::new("www.example", "example", &[Rtype::A, Rtype::NSEC]),
    ]
}

#[test]
fn wildcard_answers() {
    let zone = name("example");
    let wildcard = name("*.example");
    let keys = TrustedKeys::assume_trusted(zone.as_name(), Class::IN, [ZSK]);
    let mx_storage = name("mail.example");
    let mx = [Mx {
        preference: 10,
        exchange: mx_storage.as_name(),
    }];
    let rrsig = fake_rrsig(&zone, ZSK, &wildcard, Rtype::MX);
    assert_eq!(rrsig.labels, 1);
    let chain = wildcard_chain();
    let records: Vec<NsecRecord<'_>> = chain.iter().map(OwnedNsec::record).collect();
    let proof = NsecProof::new(zone.as_name(), &records);
    let mut buf = scratch_buf();
    let mut scratch = WireWriter::new(&mut buf);
    let v = Fake::default();

    // a.z.example. synthesized from *.example.
    let q = name("a.z.example");
    let answer = keys
        .verify_answer(
            &v,
            Rrset::new(q.as_name(), Class::IN, &mx),
            [rrsig],
            &proof,
            NOW,
            &mut scratch,
        )
        .unwrap();
    let Answer::Wildcard { verified, proof: p } = answer else {
        panic!("{answer:?}")
    };
    assert_eq!(verified.wildcard, Some(1));
    assert!(verified.is_wildcard_expansion());
    assert_eq!(p, DenialStatus::Secure(Denial::WildcardAnswer));
    assert!(answer.is_secure());
    assert_eq!(answer.verified(), &verified);

    // The wildcard queried by its own name is not an expansion.
    let answer = keys
        .verify_answer(
            &v,
            Rrset::new(wildcard.as_name(), Class::IN, &mx),
            [rrsig],
            &proof,
            NOW,
            &mut scratch,
        )
        .unwrap();
    assert!(matches!(answer, Answer::Exact(v) if v.wildcard.is_none()));
    assert!(answer.is_secure());

    // An expansion over an existing name: the proof fails, so does the
    // answer.
    let www = name("www.example");
    let answer = keys
        .verify_answer(
            &v,
            Rrset::new(www.as_name(), Class::IN, &mx),
            [rrsig],
            &proof,
            NOW,
            &mut scratch,
        )
        .unwrap();
    assert_eq!(
        answer,
        Answer::Wildcard {
            verified: *answer.verified(),
            proof: DenialStatus::Bogus(crate::dnssec::BogusReason::NameExists),
        }
    );
    assert!(!answer.is_secure());

    // Without NSEC records the expansion is not proven.
    let none: [NsecRecord<'_>; 0] = [];
    let empty = NsecProof::new(zone.as_name(), &none);
    let answer = keys
        .verify_answer(
            &v,
            Rrset::new(q.as_name(), Class::IN, &mx),
            [rrsig],
            &empty,
            NOW,
            &mut scratch,
        )
        .unwrap();
    assert!(!answer.is_secure());

    // A literal wildcard under another wildcard is an expansion.
    let nested = name("*.z.example");
    let answer = keys
        .verify_answer(
            &v,
            Rrset::new(nested.as_name(), Class::IN, &mx),
            [rrsig],
            &proof,
            NOW,
            &mut scratch,
        )
        .unwrap();
    assert_eq!(answer.verified().wildcard, Some(1));
    assert!(answer.is_secure());
}

#[cfg(feature = "dnssec")]
mod crypto {
    use super::*;
    use crate::dnssec::denial::tests::{OwnedNsec3, rfc5155};
    use crate::dnssec::testvec::b64;
    use crate::dnssec::{
        DigestType, InsecureReason, Nsec3Proof, PurecryptoNsec3Hasher, PurecryptoVerifier, Signer,
        SigningKey, Timestamp, sign_rrset,
    };
    use crate::rdata::Nsec3;

    fn sign<'k, I>(
        key: &SigningKey,
        zone: &'k NameBuf,
        dnskey: Dnskey<'k>,
        rrset: Rrset<'_, I>,
        rtype: Rtype,
        sig: &'k mut [u8; 64],
    ) -> Rrsig<'k>
    where
        I: IntoIterator + Clone,
        I::Item: ComposeRdata,
    {
        let template = ZoneKey::new(zone.as_name(), dnskey).rrsig_template(
            rrset.owner,
            rtype,
            3600,
            1_000,
            2_000,
        );
        let mut scratch = Vec::new();
        let len = sign_rrset(key, &template, rrset, &mut scratch, &mut sig[..]).unwrap();
        let sig: &'k [u8; 64] = sig;
        template.with_signature(&sig[..len])
    }

    #[test]
    fn ed25519_chain() {
        let ksk = SigningKey::from_private_bytes(Algorithm::ED25519, &[11; 32]).unwrap();
        let zsk = SigningKey::from_private_bytes(Algorithm::ED25519, &[12; 32]).unwrap();
        let zone = name("example");
        let (kd, zd) = (ksk.dnskey(257), zsk.dnskey(256));
        let dnskeys = [kd, zd];
        let set = Rrset::new(zone.as_name(), Class::IN, dnskeys);
        let mut s1 = [0; 64];
        let dnskey_sig = sign(&ksk, &zone, kd, set, Rtype::DNSKEY, &mut s1);
        let ds = ZoneKey::new(zone.as_name(), kd)
            .ds(DigestType::SHA256)
            .unwrap();

        let mut scratch = Vec::new();
        let v = PurecryptoVerifier;
        let keys =
            TrustedKeys::from_ds(&v, set, [ds.to_ds()], [dnskey_sig], NOW, &mut scratch).unwrap();

        let www = name("www.example");
        let rdata = a_rdata();
        let a = Rrset::new(www.as_name(), Class::IN, &rdata);
        let mut s2 = [0; 64];
        let a_sig = sign(&zsk, &zone, zd, a, Rtype::A, &mut s2);
        let chain = wildcard_chain();
        let records: Vec<NsecRecord<'_>> = chain.iter().map(OwnedNsec::record).collect();
        let proof = NsecProof::new(zone.as_name(), &records);
        let answer = keys
            .verify_answer(&v, a, [a_sig], &proof, NOW, &mut scratch)
            .unwrap();
        assert_eq!(answer.verified().key_tag, zd.key_tag());
        assert!(answer.is_secure());

        // Altered data or a signature by the wrong key.
        let other = [A::new([192, 0, 2, 3].into())];
        let altered = Rrset::new(www.as_name(), Class::IN, &other);
        assert_eq!(
            keys.verify_rrset(&v, altered, [a_sig], NOW, &mut scratch),
            Err(Error::BadSignature)
        );
        let mut s3 = [0; 64];
        let by_ksk = sign(&ksk, &zone, kd, a, Rtype::A, &mut s3);
        assert!(
            keys.verify_rrset(&v, a, [by_ksk], NOW, &mut scratch)
                .is_ok()
        );
        let forged = Rrsig {
            key_tag: zd.key_tag(),
            ..by_ksk
        };
        assert_eq!(
            keys.verify_rrset(&v, a, [forged], NOW, &mut scratch),
            Err(Error::BadSignature)
        );
        // The DNSKEY RRset signed by the ZSK only: the DS does not match.
        let mut s4 = [0; 64];
        let zsk_sig = sign(&zsk, &zone, zd, set, Rtype::DNSKEY, &mut s4);
        assert_eq!(
            TrustedKeys::from_ds(&v, set, [ds.to_ds()], [zsk_sig], NOW, &mut scratch).err(),
            Some(Error::KeyMismatch)
        );
        assert!(scratch.is_empty());
    }

    fn time(s: &str) -> u32 {
        s.parse::<Timestamp>().unwrap().get()
    }

    /// An RRSIG of the RFC 5155 Appendix A zone.
    fn rfc5155_rrsig<'a>(
        zone: &'a NameBuf,
        rtype: Rtype,
        labels: u8,
        key_tag: u16,
        signature: &'a [u8],
    ) -> Rrsig<'a> {
        Rrsig {
            type_covered: rtype,
            algorithm: Algorithm::RSASHA1_NSEC3_SHA1,
            labels,
            original_ttl: 3600,
            expiration: time("20150420235959"),
            inception: time("20051021000000"),
            key_tag,
            signer_name: zone.as_name(),
            signature,
        }
    }

    #[test]
    fn rfc5155_published_signatures() {
        // RFC 5155 Appendix A: the example. DNSKEY RRset and its RRSIG by
        // the KSK (12708), NSEC3 RRsets signed by the ZSK (40430).
        let zone = name("example");
        let zsk_key = b64(
            "AwEAAaetidLzsKWUt4swWR8yu0wPHPiUi8LUsAD0QPWU+wzt89epO6tHzkMBVDkC7qphQO2hTY4hHn9npWFRw5BYubE=",
        );
        let ksk_key = b64(
            "AwEAAcUlFV1vhmqx6NSOUOq2R/dsR7Xm3upJj7IommWSpJABVfW8Q0rOvXdM6kzt+TAu92L9AbsUdblMFin8CVF3n4s=",
        );
        let zsk = Dnskey::new(256, 3, Algorithm::RSASHA1_NSEC3_SHA1, &zsk_key);
        let ksk = Dnskey::new(257, 3, Algorithm::RSASHA1_NSEC3_SHA1, &ksk_key);
        assert_eq!((zsk.key_tag(), ksk.key_tag()), (40430, 12708));
        let dnskey_sig = b64(
            "AuU4juU9RaxescSmStrQks3Gh9FblGBlVU31uzMZ/U/FpsUb8aC6QZS+sTsJXnLnz7flGOsmMGQZf3bH+QsCtg==",
        );
        let dnskey_rrsig = rfc5155_rrsig(&zone, Rtype::DNSKEY, 1, 12708, &dnskey_sig);
        let now = time("20100101000000");
        let v = PurecryptoVerifier;
        let mut scratch = Vec::new();
        let set = Rrset::new(zone.as_name(), Class::IN, [zsk, ksk]);
        let keys =
            TrustedKeys::from_anchors(&v, set, [ksk], [dnskey_rrsig], now, &mut scratch).unwrap();
        // ... or from a DS of the KSK.
        let ds = ZoneKey::new(zone.as_name(), ksk)
            .ds(DigestType::SHA256)
            .unwrap();
        assert!(
            TrustedKeys::from_ds(&v, set, [ds.to_ds()], [dnskey_rrsig], now, &mut scratch).is_ok()
        );
        // Outside the validity period.
        assert_eq!(
            TrustedKeys::from_anchors(
                &v,
                set,
                [ksk],
                [dnskey_rrsig],
                time("20160101000000"),
                &mut scratch
            )
            .err(),
            Some(Error::SignatureExpired)
        );

        // B.1: the three NSEC3 RRsets of the name error for
        // a.c.x.w.example., each verified, then checked as a proof.
        let nsec3s = rfc5155(&["0p9m", "b4um", "35mt"], 1);
        let sigs = [
            "OSgWSm26B+cS+dDL8b5QrWr/dEWhtCsKlwKLIBHYH6blRxK9rC0bMJPwQ4mLIuw85H2EY762BOCXJZMnpuwhpA==",
            "ZkPG3M32lmoHM6pa3D6gZFGB/rhL//Bs3Omh5u4m/CUiwtblEVOaAKKZd7S959OeiX43aLX3pOv0TSTyiTxIZg==",
            "g6jPUUpduAJKRljUsN8gB4UagAX0NxY9shwQAynzo8EUWH+z6hEIBlUTPGj15eZll6VhQqgZXtAIR3chwgW+SA==",
        ];
        for (r, sig) in nsec3s.iter().zip(sigs) {
            let sig = b64(sig);
            let rrsig = rfc5155_rrsig(&zone, Rtype::NSEC3, 2, 40430, &sig);
            let rrset = Rrset::new(r.owner.as_name(), Class::IN, [r.nsec3()]);
            let verified = keys
                .verify_rrset(&v, rrset, [rrsig], now, &mut scratch)
                .unwrap();
            assert_eq!(verified.key_tag, 40430);
            assert!(!verified.is_wildcard_expansion());
            // A changed flag breaks it.
            let flipped = Nsec3 {
                flags: 0,
                ..r.nsec3()
            };
            let rrset = Rrset::new(r.owner.as_name(), Class::IN, [flipped]);
            assert_eq!(
                keys.verify_rrset(&v, rrset, [rrsig], now, &mut scratch),
                Err(Error::BadSignature)
            );
        }
        let records: Vec<_> = nsec3s.iter().map(OwnedNsec3::record).collect();
        let proof = Nsec3Proof::new(zone.as_name(), &records, PurecryptoNsec3Hasher);
        let q = name("a.c.x.w.example");
        assert_eq!(
            proof.name_error(q.as_name()),
            DenialStatus::Insecure(InsecureReason::OptOut)
        );

        // B.4: a.z.w.example. MX synthesized from *.w.example. (labels 2),
        // with the NSEC3 record covering z.w.example.
        let q04j = rfc5155(&["q04j"], 1);
        let q04j_sig = b64(
            "hV5I89b+4FHJDATp09g4bbN0R1F845CaXpL3ZxlMKimoPAyqletMlEWwLfFia7sdpSzn+ZlNNlkxWcLsIlMmUg==",
        );
        let rrsig = rfc5155_rrsig(&zone, Rtype::NSEC3, 2, 40430, &q04j_sig);
        let rrset = Rrset::new(q04j[0].owner.as_name(), Class::IN, [q04j[0].nsec3()]);
        keys.verify_rrset(&v, rrset, [rrsig], now, &mut scratch)
            .unwrap();
        let records: Vec<_> = q04j.iter().map(OwnedNsec3::record).collect();
        let proof = Nsec3Proof::new(zone.as_name(), &records, PurecryptoNsec3Hasher);
        let ai = name("ai.example");
        let mx = [Mx {
            preference: 1,
            exchange: ai.as_name(),
        }];
        let mx_sig = b64(
            "CikebjQwGQPwijVcxgcZcSJKtfynugtlBiKb9FcBTrmOoyQ4InoWVudhCWsh/URX3lc4WRUMivEBP6+4KS3ldA==",
        );
        let mx_rrsig = rfc5155_rrsig(&zone, Rtype::MX, 2, 40430, &mx_sig);
        let q = name("a.z.w.example");
        let answer = keys
            .verify_answer(
                &v,
                Rrset::new(q.as_name(), Class::IN, &mx),
                [mx_rrsig],
                &proof,
                now,
                &mut scratch,
            )
            .unwrap();
        assert_eq!(answer.verified().wildcard, Some(2));
        // The next closer name is in an Opt-Out span (RFC 5155 §9.2).
        assert_eq!(
            answer,
            Answer::Wildcard {
                verified: *answer.verified(),
                proof: DenialStatus::Insecure(InsecureReason::OptOut),
            }
        );
        assert!(!answer.is_secure());
        // The same signature over the wildcard itself (as in Appendix A).
        let w = name("*.w.example");
        let answer = keys
            .verify_answer(
                &v,
                Rrset::new(w.as_name(), Class::IN, &mx),
                [mx_rrsig],
                &proof,
                now,
                &mut scratch,
            )
            .unwrap();
        assert!(matches!(answer, Answer::Exact(_)));
        assert!(scratch.is_empty());
    }
}
