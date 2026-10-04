//! Denial-of-existence tests: the RFC 4035 Appendix B (NSEC) and RFC 5155
//! Appendix B (NSEC3) example responses, the RFC 6840 §4 corrections,
//! NSEC3 parameter checks and iteration limits, and hostile inputs.

use core::cell::Cell;

use super::*;
use crate::dnssec::{Nsec3Hash, Nsec3HashAlgorithm};
use crate::message::Message;
use crate::rdata::{Nsec, Nsec3};
use crate::wire::WireWriter;
use crate::{Class, Error, MessageBuilder, Result};
use std::string::ToString;
use std::vec::Vec;

use BogusReason as B;
use DenialStatus::{Bogus, Insecure, Secure};

pub(in crate::dnssec) fn name(s: &str) -> NameBuf {
    NameBuf::from_text(s.as_bytes()).unwrap()
}

/// The wire form of a type bitmap.
pub(in crate::dnssec) fn bitmap(types: &[Rtype]) -> Vec<u8> {
    let mut buf = [0u8; 1024];
    let mut w = WireWriter::new(&mut buf);
    TypeBitmap::compose(types, &mut w).unwrap();
    w.as_bytes().to_vec()
}

/// An owned NSEC record.
pub(in crate::dnssec) struct OwnedNsec {
    pub owner: NameBuf,
    pub next: NameBuf,
    pub bitmap: Vec<u8>,
}

impl OwnedNsec {
    pub fn new(owner: &str, next: &str, types: &[Rtype]) -> Self {
        OwnedNsec {
            owner: name(owner),
            next: name(next),
            bitmap: bitmap(types),
        }
    }

    pub fn record(&self) -> NsecRecord<'_> {
        NsecRecord::new(
            self.owner.as_name(),
            Nsec::new(self.next.as_name(), TypeBitmap::new(&self.bitmap).unwrap()),
        )
    }
}

/// An owned NSEC3 record.
pub(in crate::dnssec) struct OwnedNsec3 {
    pub owner: NameBuf,
    pub algorithm: Nsec3HashAlgorithm,
    pub flags: u8,
    pub iterations: u16,
    pub salt: Vec<u8>,
    pub next: Nsec3Hash,
    pub bitmap: Vec<u8>,
}

/// The salt of the RFC 5155 Appendix A zone.
pub(in crate::dnssec) const SALT: [u8; 4] = [0xaa, 0xbb, 0xcc, 0xdd];

impl OwnedNsec3 {
    /// An NSEC3 record of the RFC 5155 Appendix A zone (`example.`, SHA-1,
    /// 12 iterations, salt aabbccdd) with `flags`.
    pub fn new(owner_hash: &str, next_hash: &str, types: &[Rtype], flags: u8) -> Self {
        let owner = name(&std::format!("{owner_hash}.example"));
        let next = Nsec3Hash::from_owner(name(next_hash).as_name()).unwrap();
        OwnedNsec3 {
            owner,
            algorithm: Nsec3HashAlgorithm::SHA1,
            flags,
            iterations: 12,
            salt: SALT.to_vec(),
            next,
            bitmap: bitmap(types),
        }
    }

    pub fn nsec3(&self) -> Nsec3<'_> {
        Nsec3 {
            hash_algorithm: self.algorithm,
            flags: self.flags,
            iterations: self.iterations,
            salt: &self.salt,
            next_hashed_owner: self.next.as_bytes(),
            types: TypeBitmap::new(&self.bitmap).unwrap(),
        }
    }

    pub fn record(&self) -> Nsec3Record<'_> {
        Nsec3Record::new(self.owner.as_name(), self.nsec3())
    }
}

/// The NSEC3 chain of the RFC 5155 Appendix A zone: (owner hash, next
/// hash, types). Every record there has the Opt-Out flag set.
pub(in crate::dnssec) const RFC5155_CHAIN: &[(&str, &str, &[Rtype])] = &[
    (
        "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
        "2t7b4g4vsa5smi47k61mv5bv1a22bojr",
        &[
            Rtype::MX,
            Rtype::DNSKEY,
            Rtype::NS,
            Rtype::SOA,
            Rtype::NSEC3PARAM,
            Rtype::RRSIG,
        ],
    ),
    (
        "2t7b4g4vsa5smi47k61mv5bv1a22bojr",
        "2vptu5timamqttgl4luu9kg21e0aor3s",
        &[Rtype::A, Rtype::RRSIG],
    ),
    (
        "2vptu5timamqttgl4luu9kg21e0aor3s",
        "35mthgpgcu1qg68fab165klnsnk3dpvl",
        &[Rtype::MX, Rtype::RRSIG],
    ),
    (
        "35mthgpgcu1qg68fab165klnsnk3dpvl",
        "b4um86eghhds6nea196smvmlo4ors995",
        &[Rtype::NS, Rtype::DS, Rtype::RRSIG],
    ),
    (
        "b4um86eghhds6nea196smvmlo4ors995",
        "gjeqe526plbf1g8mklp59enfd789njgi",
        &[Rtype::MX, Rtype::RRSIG],
    ),
    (
        "gjeqe526plbf1g8mklp59enfd789njgi",
        "ji6neoaepv8b5o6k4ev33abha8ht9fgc",
        &[Rtype::HINFO, Rtype::A, Rtype::AAAA, Rtype::RRSIG],
    ),
    (
        "ji6neoaepv8b5o6k4ev33abha8ht9fgc",
        "k8udemvp1j2f7eg6jebps17vp3n8i58h",
        &[],
    ),
    (
        "k8udemvp1j2f7eg6jebps17vp3n8i58h",
        "kohar7mbb8dc2ce8a9qvl8hon4k53uhi",
        &[],
    ),
    (
        "kohar7mbb8dc2ce8a9qvl8hon4k53uhi",
        "q04jkcevqvmu85r014c7dkba38o0ji5r",
        &[Rtype::A, Rtype::RRSIG],
    ),
    (
        "q04jkcevqvmu85r014c7dkba38o0ji5r",
        "r53bq7cc2uvmubfu5ocmm6pers9tk9en",
        &[Rtype::A, Rtype::RRSIG],
    ),
    (
        "r53bq7cc2uvmubfu5ocmm6pers9tk9en",
        "t644ebqk9bibcna874givr6joj62mlhv",
        &[Rtype::MX, Rtype::RRSIG],
    ),
    (
        "t644ebqk9bibcna874givr6joj62mlhv",
        "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
        &[Rtype::HINFO, Rtype::A, Rtype::AAAA, Rtype::RRSIG],
    ),
];

/// The RFC 5155 Appendix A NSEC3 records whose owner hash starts with
/// one of `prefixes` (4 characters each), with `flags`.
pub(in crate::dnssec) fn rfc5155(prefixes: &[&str], flags: u8) -> Vec<OwnedNsec3> {
    prefixes
        .iter()
        .map(|p| {
            let (owner, next, types) = RFC5155_CHAIN
                .iter()
                .find(|(o, _, _)| o.starts_with(p))
                .unwrap();
            OwnedNsec3::new(owner, next, types, flags)
        })
        .collect()
}

/// NSEC3 hashes (SHA-1, 12 iterations, salt aabbccdd) of the names the
/// tests ask about. Those of RFC 5155 Appendix A and B are listed there;
/// the others were computed with `nsec3_hash` (and are checked against it
/// in `table_matches_purecrypto`).
const HASHES: &[(&str, &str)] = &[
    ("example", "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"),
    ("a.example", "35mthgpgcu1qg68fab165klnsnk3dpvl"),
    ("ai.example", "gjeqe526plbf1g8mklp59enfd789njgi"),
    ("ns1.example", "2t7b4g4vsa5smi47k61mv5bv1a22bojr"),
    ("ns2.example", "q04jkcevqvmu85r014c7dkba38o0ji5r"),
    ("w.example", "k8udemvp1j2f7eg6jebps17vp3n8i58h"),
    ("*.w.example", "r53bq7cc2uvmubfu5ocmm6pers9tk9en"),
    ("x.w.example", "b4um86eghhds6nea196smvmlo4ors995"),
    ("y.w.example", "ji6neoaepv8b5o6k4ev33abha8ht9fgc"),
    ("x.y.w.example", "2vptu5timamqttgl4luu9kg21e0aor3s"),
    ("xx.example", "t644ebqk9bibcna874givr6joj62mlhv"),
    ("c.x.w.example", "0va5bpr2ou0vk0lbqeeljri88laipsfh"),
    ("*.x.w.example", "92pqneegtaue7pjatc3l3qnk738c6v5m"),
    ("c.example", "4g6p9u5gvfshp30pqecj98b3maqbn1ck"),
    ("z.w.example", "qlu7gtfaeh0ek0c05ksfhdpbcgglbe03"),
    // Computed.
    ("a.c.x.w.example", "06pjpo0bna507odhmdh856ignbmhtjf3"),
    ("a.z.w.example", "mhgsa3oco9qvl19os4obgfeqd7q3nri2"),
    ("mc.c.example", "s71cesjmm4u9h8cafacfnsdr9ug81dne"),
    ("*.example", "jhsv97rodsnhc4f1ke4jh23egaa5agvp"),
    ("*.c.example", "7qguiho2n908loodrta97keph0aava94"),
    ("mc.a.example", "dbailvo8qk97mkp548hssernt7a1ji4k"),
    ("e.example", "nu74sith5gkbvmv0sco6aqfocnegg16u"),
];

/// A crypto-free [`Nsec3Hasher`] for the RFC 5155 zone: looks names up in
/// [`HASHES`].
pub(in crate::dnssec) fn table_hasher(
    name: Name<'_>,
    algorithm: Nsec3HashAlgorithm,
    iterations: u16,
    salt: &[u8],
) -> Result<Nsec3Hash> {
    assert_eq!(
        (algorithm, iterations, salt),
        (Nsec3HashAlgorithm::SHA1, 12, &SALT[..])
    );
    let text = name.to_string();
    let text = text.trim_end_matches('.');
    let (_, hash) = HASHES
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(text))
        .unwrap_or_else(|| panic!("no hash for {text}"));
    Nsec3Hash::from_owner(super::tests::name(hash).as_name())
}

/// The RFC 4035 Appendix A NSEC chain.
fn rfc4035_chain() -> Vec<OwnedNsec> {
    use Rtype as T;
    std::vec![
        OwnedNsec::new(
            "example",
            "a.example",
            &[T::NS, T::SOA, T::MX, T::RRSIG, T::NSEC, T::DNSKEY]
        ),
        OwnedNsec::new(
            "a.example",
            "ai.example",
            &[T::NS, T::DS, T::RRSIG, T::NSEC]
        ),
        OwnedNsec::new(
            "ai.example",
            "b.example",
            &[T::A, T::HINFO, T::AAAA, T::RRSIG, T::NSEC]
        ),
        OwnedNsec::new("b.example", "ns1.example", &[T::NS, T::RRSIG, T::NSEC]),
        OwnedNsec::new("ns1.example", "ns2.example", &[T::A, T::RRSIG, T::NSEC]),
        OwnedNsec::new("ns2.example", "*.w.example", &[T::A, T::RRSIG, T::NSEC]),
        OwnedNsec::new("*.w.example", "x.w.example", &[T::MX, T::RRSIG, T::NSEC]),
        OwnedNsec::new("x.w.example", "x.y.w.example", &[T::MX, T::RRSIG, T::NSEC]),
        OwnedNsec::new("x.y.w.example", "xx.example", &[T::MX, T::RRSIG, T::NSEC]),
        OwnedNsec::new(
            "xx.example",
            "example",
            &[T::A, T::HINFO, T::AAAA, T::RRSIG, T::NSEC]
        ),
    ]
}

/// The records of the RFC 4035 chain owned by `owners`.
fn pick<'a>(chain: &'a [OwnedNsec], owners: &[&str]) -> Vec<NsecRecord<'a>> {
    owners
        .iter()
        .map(|o| chain.iter().find(|r| r.owner == name(o)).unwrap().record())
        .collect()
}

fn nsec_check(owners: &[&str], f: impl FnOnce(&NsecProof<'_, &Vec<NsecRecord<'_>>>)) {
    let chain = rfc4035_chain();
    let records = pick(&chain, owners);
    let zone = name("example");
    f(&NsecProof::new(zone.as_name(), &records));
}

#[test]
fn rfc4035_b2_name_error() {
    nsec_check(&["b.example", "example"], |p| {
        let q = name("ml.example");
        assert_eq!(p.name_error(q.as_name()), Secure(Denial::NameError));
        let ce = p.closest_encloser(q.as_name()).unwrap();
        assert_eq!(ce.encloser, name("example").as_name());
        assert_eq!(ce.next_closer, q.as_name());
        assert!(!ce.opt_out);
        assert_eq!(ce.wildcard().unwrap(), name("*.example"));
    });
    // Without the record covering the wildcard, or the name.
    nsec_check(&["b.example"], |p| {
        let q = name("ml.example");
        assert_eq!(p.name_error(q.as_name()), Bogus(B::MissingProof));
    });
    nsec_check(&["example"], |p| {
        let q = name("ml.example");
        assert_eq!(p.name_error(q.as_name()), Bogus(B::MissingProof));
    });
}

#[test]
fn rfc4035_b3_no_data() {
    nsec_check(&["ns1.example"], |p| {
        let q = name("ns1.example");
        assert_eq!(p.no_data(q.as_name(), Rtype::MX), Secure(Denial::NoData));
        assert_eq!(p.no_data(q.as_name(), Rtype::A), Bogus(B::TypeExists));
        // NSEC and RRSIG always exist at an NSEC owner.
        assert_eq!(p.no_data(q.as_name(), Rtype::NSEC), Bogus(B::TypeExists));
        assert_eq!(p.no_data(q.as_name(), Rtype::RRSIG), Bogus(B::TypeExists));
        // The name exists.
        assert_eq!(p.name_error(q.as_name()), Bogus(B::NameExists));
        assert_eq!(p.closest_encloser(q.as_name()), Err(Bogus(B::NameExists)));
        // DS at a name that is not a delegation.
        assert_eq!(p.no_data(q.as_name(), Rtype::DS), Secure(Denial::NoData));
    });
}

#[test]
fn rfc4035_b4_b5_referrals() {
    // B.4: a.example. has a DS RRset.
    nsec_check(&["a.example"], |p| {
        let d = name("a.example");
        assert_eq!(p.unsigned_delegation(d.as_name()), Bogus(B::TypeExists));
        assert_eq!(p.no_data(d.as_name(), Rtype::DS), Bogus(B::TypeExists));
    });
    // B.5: b.example. is an unsigned delegation.
    nsec_check(&["b.example"], |p| {
        let d = name("b.example");
        assert_eq!(
            p.unsigned_delegation(d.as_name()),
            Secure(Denial::UnsignedDelegation)
        );
        assert_eq!(
            p.no_data(d.as_name(), Rtype::DS),
            Secure(Denial::UnsignedDelegation)
        );
        // RFC 6840 §4.4: the parent-side NSEC proves nothing else.
        assert_eq!(p.no_data(d.as_name(), Rtype::A), Bogus(B::ZoneCut));
        assert_eq!(p.no_data(d.as_name(), Rtype::MX), Bogus(B::ZoneCut));
        // No record for the delegation at all.
        let other = name("c.example");
        assert_eq!(
            p.unsigned_delegation(other.as_name()),
            Bogus(B::MissingProof)
        );
    });
    // A name without NS is not a delegation.
    nsec_check(&["ns1.example"], |p| {
        let d = name("ns1.example");
        assert_eq!(p.unsigned_delegation(d.as_name()), Bogus(B::NotDelegation));
    });
}

#[test]
fn rfc4035_b6_wildcard_expansion() {
    nsec_check(&["x.y.w.example"], |p| {
        let q = name("a.z.w.example");
        assert_eq!(
            p.wildcard_answer(q.as_name(), 2),
            Secure(Denial::WildcardAnswer)
        );
        let ce = p.closest_encloser(q.as_name()).unwrap();
        assert_eq!(ce.encloser, name("w.example").as_name());
        assert_eq!(ce.next_closer, name("z.w.example").as_name());
        // Claiming `*.example` produced it: `w.example` is closer.
        assert_eq!(p.wildcard_answer(q.as_name(), 1), Bogus(B::WrongWildcard));
        // Labels fields that do not denote an expansion.
        assert_eq!(p.wildcard_answer(q.as_name(), 4), Bogus(B::WrongWildcard));
        assert_eq!(p.wildcard_answer(q.as_name(), 5), Bogus(B::WrongWildcard));
        assert_eq!(p.wildcard_answer(q.as_name(), 0), Bogus(B::OutOfZone));
        // An expansion over an existing name.
        let x = name("x.y.w.example");
        assert_eq!(p.wildcard_answer(x.as_name(), 2), Bogus(B::NameExists));
    });
    // Not covered at all.
    nsec_check(&["ns1.example"], |p| {
        let q = name("a.z.w.example");
        assert_eq!(p.wildcard_answer(q.as_name(), 2), Bogus(B::MissingProof));
    });
}

#[test]
fn rfc4035_b7_wildcard_no_data() {
    nsec_check(&["x.y.w.example", "*.w.example"], |p| {
        let q = name("a.z.w.example");
        assert_eq!(
            p.no_data(q.as_name(), Rtype::AAAA),
            Secure(Denial::WildcardNoData)
        );
        // The wildcard has MX.
        assert_eq!(p.no_data(q.as_name(), Rtype::MX), Bogus(B::TypeExists));
        assert_eq!(p.no_data(q.as_name(), Rtype::NSEC), Bogus(B::TypeExists));
        // And so the name could have been synthesized.
        assert_eq!(p.name_error(q.as_name()), Bogus(B::WildcardExists));
    });
    // Without the wildcard's record.
    nsec_check(&["x.y.w.example"], |p| {
        let q = name("a.z.w.example");
        assert_eq!(p.no_data(q.as_name(), Rtype::AAAA), Bogus(B::MissingProof));
    });
}

#[test]
fn rfc4035_b8_ds_child_zone() {
    // The child apex NSEC (SOA set) cannot deny the parent-side DS.
    nsec_check(&["example"], |p| {
        let q = name("example");
        assert_eq!(p.no_data(q.as_name(), Rtype::DS), Bogus(B::ZoneCut));
        assert_eq!(p.no_data(q.as_name(), Rtype::A), Secure(Denial::NoData));
        assert_eq!(p.no_data(q.as_name(), Rtype::MX), Bogus(B::TypeExists));
        assert_eq!(p.unsigned_delegation(q.as_name()), Bogus(B::ZoneCut));
    });
    // At the root, the apex has no parent: a DS absence is a plain NODATA.
    let root = OwnedNsec::new(".", "com", &[Rtype::NS, Rtype::SOA, Rtype::NSEC]);
    let records = [root.record()];
    let p = NsecProof::new(Name::ROOT, &records);
    assert_eq!(p.no_data(Name::ROOT, Rtype::DS), Secure(Denial::NoData));
}

#[test]
fn nsec_empty_non_terminal() {
    // y.w.example. exists only because x.y.w.example. does.
    nsec_check(&["x.w.example"], |p| {
        let q = name("y.w.example");
        assert_eq!(p.no_data(q.as_name(), Rtype::A), Secure(Denial::NoData));
        assert_eq!(p.name_error(q.as_name()), Bogus(B::NameExists));
        assert_eq!(p.wildcard_answer(q.as_name(), 2), Bogus(B::NameExists));
    });
}

#[test]
fn nsec_wrap_around() {
    // xx.example. is the last name: its NSEC covers names after it.
    nsec_check(&["xx.example", "example"], |p| {
        let q = name("z.example");
        assert_eq!(p.name_error(q.as_name()), Secure(Denial::NameError));
        let q = name("deep.z.example");
        assert_eq!(p.name_error(q.as_name()), Secure(Denial::NameError));
    });
    // A one-name zone: the apex NSEC points at itself.
    let only = OwnedNsec::new("example", "example", &[Rtype::SOA, Rtype::NS]);
    let records = [only.record()];
    let zone = name("example");
    let p = NsecProof::new(zone.as_name(), &records);
    let q = name("www.example");
    assert_eq!(p.name_error(q.as_name()), Secure(Denial::NameError));
    assert_eq!(p.no_data(zone.as_name(), Rtype::A), Secure(Denial::NoData));
}

#[test]
fn nsec_ancestor_delegation() {
    // RFC 6840 §4.1: b.example.'s NSEC (NS, no SOA) covers mc.b.example.
    // in canonical order but cannot deny names below the zone cut.
    nsec_check(&["b.example", "example"], |p| {
        let q = name("mc.b.example");
        assert_eq!(p.name_error(q.as_name()), Bogus(B::ZoneCut));
        assert_eq!(p.no_data(q.as_name(), Rtype::A), Bogus(B::ZoneCut));
        assert_eq!(p.closest_encloser(q.as_name()), Err(Bogus(B::ZoneCut)));
        assert_eq!(p.wildcard_answer(q.as_name(), 2), Bogus(B::ZoneCut));
    });
    // Same for a signed delegation.
    nsec_check(&["a.example"], |p| {
        let q = name("mc.a.example");
        assert_eq!(p.name_error(q.as_name()), Bogus(B::ZoneCut));
    });
}

#[test]
fn nsec_dname() {
    // RFC 6840 §4.1: names below a DNAME are not in the zone.
    let d = OwnedNsec::new(
        "d.example",
        "e.example",
        &[Rtype::DNAME, Rtype::RRSIG, Rtype::NSEC],
    );
    let apex = OwnedNsec::new("example", "d.example", &[Rtype::SOA, Rtype::NS]);
    let records = [d.record(), apex.record()];
    let zone = name("example");
    let p = NsecProof::new(zone.as_name(), &records);
    let q = name("x.d.example");
    assert_eq!(p.name_error(q.as_name()), Bogus(B::ZoneCut));
    // The DNAME owner itself is fine.
    let q = name("d.example");
    assert_eq!(p.no_data(q.as_name(), Rtype::A), Secure(Denial::NoData));
    assert_eq!(p.no_data(q.as_name(), Rtype::DNAME), Bogus(B::TypeExists));
}

#[test]
fn nsec_cname_bit() {
    // RFC 6840 §4.3: a NODATA proof must also show there is no CNAME.
    let c = OwnedNsec::new(
        "c.example",
        "d.example",
        &[Rtype::CNAME, Rtype::RRSIG, Rtype::NSEC],
    );
    let records = [c.record()];
    let zone = name("example");
    let p = NsecProof::new(zone.as_name(), &records);
    let q = name("c.example");
    assert_eq!(p.no_data(q.as_name(), Rtype::A), Bogus(B::TypeExists));
    assert_eq!(p.no_data(q.as_name(), Rtype::DS), Bogus(B::TypeExists));
}

#[test]
fn nsec_out_of_zone() {
    nsec_check(&["b.example", "example"], |p| {
        let q = name("ml.example.com");
        assert_eq!(p.name_error(q.as_name()), Bogus(B::OutOfZone));
        assert_eq!(p.no_data(q.as_name(), Rtype::A), Bogus(B::OutOfZone));
        assert_eq!(p.wildcard_answer(q.as_name(), 2), Bogus(B::OutOfZone));
        assert_eq!(p.unsigned_delegation(q.as_name()), Bogus(B::OutOfZone));
        assert_eq!(p.closest_encloser(q.as_name()), Err(Bogus(B::OutOfZone)));
        assert_eq!(p.zone(), name("example").as_name());
    });
    // Records of another zone are ignored, even when they would cover.
    let other = OwnedNsec::new("a.test", "z.test", &[Rtype::A]);
    let other_apex = OwnedNsec::new("test", "a.test", &[Rtype::SOA]);
    let records = [other.record(), other_apex.record()];
    let zone = name("example");
    let p = NsecProof::new(zone.as_name(), &records);
    let q = name("m.example");
    assert_eq!(p.name_error(q.as_name()), Bogus(B::MissingProof));
    // No records at all.
    let none: [NsecRecord<'_>; 0] = [];
    let p = NsecProof::new(zone.as_name(), &none);
    assert_eq!(p.name_error(q.as_name()), Bogus(B::MissingProof));
    assert_eq!(p.no_data(q.as_name(), Rtype::A), Bogus(B::MissingProof));
}

#[test]
fn nsec_long_names() {
    // The wildcard at a 254-octet name cannot exist.
    let l63 = "a".repeat(63);
    let l52 = "b".repeat(52);
    let encloser = name(&std::format!("{l52}.{l63}.{l63}.{l63}.example"));
    assert_eq!(encloser.wire_len(), 254);
    assert!(wildcard_of(encloser.as_name()).is_none());
    let ce = ClosestEncloser {
        encloser: encloser.as_name(),
        next_closer: encloser.as_name(),
        opt_out: false,
    };
    assert_eq!(ce.wildcard(), None);
    // One octet shorter, it fits exactly.
    let encloser = name(&std::format!(
        "{}.{l63}.{l63}.{l63}.example",
        "b".repeat(51)
    ));
    assert_eq!(wildcard_of(encloser.as_name()).unwrap().wire_len(), 255);
}

#[test]
fn nsec_from_message() {
    // NSEC records read from a response's authority section, through a
    // cloneable iterator (no allocation).
    let chain = rfc4035_chain();
    let mut buf = [0u8; 1024];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    for r in pick(&chain, &["b.example", "example"]) {
        b.push_authority(r.owner, Class::IN, 3600, &r.nsec).unwrap();
    }
    let a = name("a.example");
    b.push_authority(
        a.as_name(),
        Class::IN,
        3600,
        &crate::rdata::A::new([192, 0, 2, 1].into()),
    )
    .unwrap();
    let wire = b.finish();
    let msg = Message::parse(wire).unwrap();
    let records = msg
        .authority()
        .filter_map(core::result::Result::ok)
        .filter_map(|rr| NsecRecord::from_record(&rr));
    assert_eq!(records.clone().count(), 2);
    let zone = name("example");
    let p = NsecProof::new(zone.as_name(), records);
    let q = name("ml.example");
    assert_eq!(p.name_error(q.as_name()), Secure(Denial::NameError));
    // Through the trait, by reference and as a trait object.
    let dynamic: &dyn DenialProof = &p;
    assert_eq!(
        DenialProof::name_error(&dynamic, q.as_name()),
        Secure(Denial::NameError)
    );
    // Other record types are not NSEC.
    let first = msg.authority().last().unwrap().unwrap();
    assert!(NsecRecord::from_record(&first).is_none());
    assert!(Nsec3Record::from_record(&first).is_none());
}

/// Runs the RFC 5155 Appendix B checks with `hasher`.
fn rfc5155_appendix_b<H: Nsec3Hasher + Copy>(hasher: H) {
    let zone = name("example");
    let proof = |records: &[OwnedNsec3], f: &dyn Fn(&dyn DenialProof)| {
        let records: Vec<_> = records.iter().map(OwnedNsec3::record).collect();
        f(&Nsec3Proof::new(zone.as_name(), &records, hasher));
    };

    // B.1: name error. The next closer name c.x.w.example. is in an
    // Opt-Out span, so the response is not authenticated (RFC 5155 §9.2);
    // without Opt-Out it is.
    let q = name("a.c.x.w.example");
    proof(&rfc5155(&["0p9m", "b4um", "35mt"], 1), &|p| {
        assert_eq!(p.name_error(q.as_name()), Insecure(InsecureReason::OptOut));
    });
    proof(&rfc5155(&["0p9m", "b4um", "35mt"], 0), &|p| {
        assert_eq!(p.name_error(q.as_name()), Secure(Denial::NameError));
    });
    let records = rfc5155(&["0p9m", "b4um", "35mt"], 1);
    let records: Vec<_> = records.iter().map(OwnedNsec3::record).collect();
    let p = Nsec3Proof::new(zone.as_name(), &records, hasher);
    let ce = p.closest_encloser(q.as_name()).unwrap();
    assert_eq!(ce.encloser, name("x.w.example").as_name());
    assert_eq!(ce.next_closer, name("c.x.w.example").as_name());
    assert!(ce.opt_out);
    // Missing the wildcard cover, the next closer cover, the encloser.
    proof(&rfc5155(&["0p9m", "b4um"], 0), &|p| {
        assert_eq!(p.name_error(q.as_name()), Bogus(B::MissingProof));
    });
    proof(&rfc5155(&["b4um", "35mt"], 0), &|p| {
        assert_eq!(p.name_error(q.as_name()), Bogus(B::MissingProof));
    });
    proof(&rfc5155(&["0p9m", "35mt"], 0), &|p| {
        assert_eq!(p.name_error(q.as_name()), Bogus(B::MissingProof));
    });

    // B.2: no data.
    let q = name("ns1.example");
    proof(&rfc5155(&["2t7b"], 1), &|p| {
        assert_eq!(p.no_data(q.as_name(), Rtype::MX), Secure(Denial::NoData));
        assert_eq!(p.no_data(q.as_name(), Rtype::A), Bogus(B::TypeExists));
        assert_eq!(p.name_error(q.as_name()), Bogus(B::NameExists));
        assert_eq!(p.wildcard_answer(q.as_name(), 1), Bogus(B::WrongWildcard));
    });

    // B.2.1: no data at an empty non-terminal.
    let q = name("y.w.example");
    proof(&rfc5155(&["ji6n"], 1), &|p| {
        assert_eq!(p.no_data(q.as_name(), Rtype::A), Secure(Denial::NoData));
    });

    // B.3: referral to an unsigned zone in an Opt-Out span: no record
    // matches c.example., example. is the closest provable encloser.
    let d = name("c.example");
    proof(&rfc5155(&["35mt", "0p9m"], 1), &|p| {
        assert_eq!(
            p.unsigned_delegation(d.as_name()),
            Insecure(InsecureReason::OptOut)
        );
        assert_eq!(
            p.no_data(d.as_name(), Rtype::DS),
            Insecure(InsecureReason::OptOut)
        );
    });
    proof(&rfc5155(&["35mt", "0p9m"], 0), &|p| {
        assert_eq!(p.unsigned_delegation(d.as_name()), Bogus(B::NoOptOut));
        assert_eq!(p.no_data(d.as_name(), Rtype::DS), Bogus(B::NoOptOut));
    });

    // B.4: wildcard expansion; z.w.example. is in an Opt-Out span.
    let q = name("a.z.w.example");
    proof(&rfc5155(&["q04j"], 1), &|p| {
        assert_eq!(
            p.wildcard_answer(q.as_name(), 2),
            Insecure(InsecureReason::OptOut)
        );
    });
    proof(&rfc5155(&["q04j"], 0), &|p| {
        assert_eq!(
            p.wildcard_answer(q.as_name(), 2),
            Secure(Denial::WildcardAnswer)
        );
        // Not from `*.example`: w.example. exists (no cover for it).
        assert_eq!(p.wildcard_answer(q.as_name(), 1), Bogus(B::MissingProof));
    });
    proof(&rfc5155(&["k8ud", "q04j"], 0), &|p| {
        // w.example. is matched: definitely not from `*.example`.
        assert_eq!(p.wildcard_answer(q.as_name(), 1), Bogus(B::WrongWildcard));
    });

    // B.5: wildcard no data.
    proof(&rfc5155(&["k8ud", "q04j", "r53b"], 1), &|p| {
        assert_eq!(
            p.no_data(q.as_name(), Rtype::AAAA),
            Insecure(InsecureReason::OptOut)
        );
    });
    proof(&rfc5155(&["k8ud", "q04j", "r53b"], 0), &|p| {
        assert_eq!(
            p.no_data(q.as_name(), Rtype::AAAA),
            Secure(Denial::WildcardNoData)
        );
        assert_eq!(p.no_data(q.as_name(), Rtype::MX), Bogus(B::TypeExists));
        assert_eq!(p.name_error(q.as_name()), Bogus(B::WildcardExists));
    });
    // Without the wildcard's record, and no Opt-Out.
    proof(&rfc5155(&["k8ud", "q04j"], 0), &|p| {
        assert_eq!(p.no_data(q.as_name(), Rtype::AAAA), Bogus(B::MissingProof));
    });

    // B.6: DS NODATA from the child apex.
    let q = name("example");
    proof(&rfc5155(&["0p9m"], 1), &|p| {
        assert_eq!(p.no_data(q.as_name(), Rtype::DS), Bogus(B::ZoneCut));
        assert_eq!(p.no_data(q.as_name(), Rtype::A), Secure(Denial::NoData));
        assert_eq!(p.unsigned_delegation(q.as_name()), Bogus(B::ZoneCut));
    });

    // a.example. is a signed delegation (NS DS, no SOA).
    let d = name("a.example");
    proof(&rfc5155(&["35mt"], 1), &|p| {
        assert_eq!(p.unsigned_delegation(d.as_name()), Bogus(B::TypeExists));
        assert_eq!(p.no_data(d.as_name(), Rtype::DS), Bogus(B::TypeExists));
        // RFC 6840 §4.4: the parent side proves nothing else.
        assert_eq!(p.no_data(d.as_name(), Rtype::A), Bogus(B::ZoneCut));
    });
    // RFC 5155 §8.3, RFC 6840 §4.1: a closest encloser at a delegation.
    let q = name("mc.a.example");
    proof(&rfc5155(&["35mt", "0p9m", "kohar"], 0), &|p| {
        assert_eq!(p.name_error(q.as_name()), Bogus(B::ZoneCut));
    });
    // A name that is not a delegation.
    let d = name("ns1.example");
    proof(&rfc5155(&["2t7b"], 0), &|p| {
        assert_eq!(p.unsigned_delegation(d.as_name()), Bogus(B::NotDelegation));
    });
}

#[test]
fn rfc5155_b_table_hasher() {
    rfc5155_appendix_b(table_hasher);
}

#[cfg(feature = "dnssec-digest")]
#[test]
fn rfc5155_b_purecrypto() {
    rfc5155_appendix_b(PurecryptoNsec3Hasher);
}

#[cfg(feature = "dnssec-digest")]
#[test]
fn table_matches_purecrypto() {
    for (n, _) in HASHES {
        let n = name(n);
        assert_eq!(
            table_hasher(n.as_name(), Nsec3HashAlgorithm::SHA1, 12, &SALT),
            crate::dnssec::nsec3_hash(n.as_name(), Nsec3HashAlgorithm::SHA1, 12, &SALT),
            "{n}"
        );
    }
}

#[test]
fn nsec3_dname_encloser() {
    // A closest encloser with DNAME hides its subtree (RFC 5155 §8.3).
    let records = [OwnedNsec3::new(
        "b4um86eghhds6nea196smvmlo4ors995",
        "gjeqe526plbf1g8mklp59enfd789njgi",
        &[Rtype::DNAME, Rtype::RRSIG],
        0,
    )];
    let records: Vec<_> = records.iter().map(OwnedNsec3::record).collect();
    let zone = name("example");
    let p = Nsec3Proof::new(zone.as_name(), &records, table_hasher);
    let q = name("c.x.w.example");
    assert_eq!(p.name_error(q.as_name()), Bogus(B::ZoneCut));
    assert_eq!(p.closest_encloser(q.as_name()), Err(Bogus(B::ZoneCut)));
}

#[test]
fn nsec3_record_filtering() {
    let zone = name("example");
    let q = name("ns1.example");
    let check = |records: &[OwnedNsec3]| {
        let records: Vec<_> = records.iter().map(OwnedNsec3::record).collect();
        Nsec3Proof::new(zone.as_name(), &records, table_hasher).no_data(q.as_name(), Rtype::MX)
    };
    let good = || rfc5155(&["2t7b"], 0);

    // Unknown flags (RFC 5155 §8.2) and hash algorithms (§8.1).
    let mut r = good();
    r[0].flags = 0x02;
    assert_eq!(check(&r), Bogus(B::UnusableRecords));
    let mut r = good();
    r[0].algorithm = Nsec3HashAlgorithm::new(2);
    assert_eq!(check(&r), Bogus(B::UnusableRecords));
    // A next hashed owner of a different length.
    let mut r = good();
    r[0].next = Nsec3Hash::new(&[1; 16]).unwrap();
    assert_eq!(check(&r), Bogus(B::UnusableRecords));
    // An owner that is not one base32hex label below the zone.
    let mut r = good();
    r[0].owner = name("2t7b4g4vsa5smi47k61mv5bv1a22bojr.x.example");
    assert_eq!(check(&r), Bogus(B::UnusableRecords));
    let mut r = good();
    r[0].owner = name("not-base32hex!.example");
    assert_eq!(check(&r), Bogus(B::UnusableRecords));
    let mut r = good();
    r[0].owner = name("2t7b4g4vsa5smi47k61mv5bv1a22bojr.test");
    assert_eq!(check(&r), Bogus(B::UnusableRecords));
    // An unusable record next to a good one is ignored.
    let mut r = rfc5155(&["2t7b", "0p9m"], 0);
    r[1].flags = 0xff;
    r[1].salt = std::vec![1];
    assert_eq!(check(&r), Secure(Denial::NoData));
    // Nothing at all.
    assert_eq!(check(&[]), Bogus(B::MissingProof));

    // Inconsistent parameters (RFC 5155 §8.2).
    let mut r = rfc5155(&["2t7b", "0p9m"], 0);
    r[1].salt = std::vec![1, 2, 3, 4];
    assert_eq!(check(&r), Bogus(B::InconsistentParameters));
    let mut r = rfc5155(&["2t7b", "0p9m"], 0);
    r[1].iterations = 11;
    assert_eq!(check(&r), Bogus(B::InconsistentParameters));
}

#[test]
fn nsec3_iteration_limits() {
    let zone = name("example");
    let q = name("a.c.x.w.example");
    let records = rfc5155(&["0p9m", "b4um", "35mt"], 0);
    let records: Vec<_> = records.iter().map(OwnedNsec3::record).collect();
    // Nothing is hashed when the iteration count is over a limit.
    let refuse = |_: Name<'_>, _: Nsec3HashAlgorithm, _: u16, _: &[u8]| -> Result<Nsec3Hash> {
        panic!("hashed despite the iteration limit")
    };
    let p = Nsec3Proof::new(zone.as_name(), &records, refuse);
    assert_eq!(p.limits(), Nsec3Limits::DEFAULT);
    assert_eq!(Nsec3Limits::default(), Nsec3Limits::new(100, 500));
    let p = p.with_limits(Nsec3Limits::new(11, 500));
    assert_eq!(
        p.name_error(q.as_name()),
        Insecure(InsecureReason::Iterations)
    );
    assert_eq!(
        p.no_data(q.as_name(), Rtype::A),
        Insecure(InsecureReason::Iterations)
    );
    assert_eq!(
        p.wildcard_answer(q.as_name(), 2),
        Insecure(InsecureReason::Iterations)
    );
    assert_eq!(
        p.unsigned_delegation(q.as_name()),
        Insecure(InsecureReason::Iterations)
    );
    assert_eq!(
        p.closest_encloser(q.as_name()),
        Err(Insecure(InsecureReason::Iterations))
    );
    let p = p.with_limits(Nsec3Limits::new(0, 11));
    assert_eq!(p.name_error(q.as_name()), Bogus(B::Iterations));
    // Exactly at the limits.
    let p = Nsec3Proof::new(zone.as_name(), &records, table_hasher)
        .with_limits(Nsec3Limits::new(12, 12));
    assert_eq!(p.name_error(q.as_name()), Secure(Denial::NameError));
    assert_eq!(Nsec3Limits::new(0, 0).check(0), None);
    assert_eq!(
        Nsec3Limits::DEFAULT.check(101),
        Some(Insecure(InsecureReason::Iterations))
    );
    assert_eq!(Nsec3Limits::DEFAULT.check(501), Some(Bogus(B::Iterations)));
}

#[test]
fn nsec3_hasher_failure() {
    let zone = name("example");
    let records = rfc5155(&["2t7b"], 0);
    let records: Vec<_> = records.iter().map(OwnedNsec3::record).collect();
    let fail = |_: Name<'_>, _: Nsec3HashAlgorithm, _: u16, _: &[u8]| -> Result<Nsec3Hash> {
        Err(Error::UnsupportedAlgorithm)
    };
    let p = Nsec3Proof::new(zone.as_name(), &records, fail);
    let q = name("ns1.example");
    assert_eq!(p.no_data(q.as_name(), Rtype::MX), Bogus(B::UnusableRecords));
    assert_eq!(p.zone(), zone.as_name());
}

#[test]
fn nsec3_out_of_zone() {
    let zone = name("example");
    let records = rfc5155(&["0p9m", "b4um", "35mt"], 0);
    let records: Vec<_> = records.iter().map(OwnedNsec3::record).collect();
    let p = Nsec3Proof::new(zone.as_name(), &records, table_hasher);
    let q = name("a.c.x.w.example.com");
    assert_eq!(p.name_error(q.as_name()), Bogus(B::OutOfZone));
    assert_eq!(p.no_data(q.as_name(), Rtype::A), Bogus(B::OutOfZone));
    assert_eq!(p.wildcard_answer(q.as_name(), 2), Bogus(B::OutOfZone));
    assert_eq!(p.unsigned_delegation(q.as_name()), Bogus(B::OutOfZone));
    // A labels field reaching above the zone.
    let q = name("a.z.w.example");
    assert_eq!(p.wildcard_answer(q.as_name(), 0), Bogus(B::OutOfZone));
}

#[test]
fn nsec3_bounded_work() {
    // A 124-label name (the most below example.): at most one hash per
    // label plus the wildcard, each followed by one pass over the records.
    let zone = name("example");
    let records = rfc5155(&["0p9m", "b4um", "35mt"], 0);
    let records: Vec<_> = records.iter().map(OwnedNsec3::record).collect();
    let mut deep = std::string::String::new();
    for _ in 0..123 {
        deep.push_str("a.");
    }
    deep.push_str("example");
    let q = name(&deep);
    assert_eq!((q.label_count(), q.wire_len()), (124, 255));
    let calls = Cell::new(0usize);
    let counting = |_: Name<'_>, _: Nsec3HashAlgorithm, _: u16, _: &[u8]| -> Result<Nsec3Hash> {
        calls.set(calls.get() + 1);
        // No record matches or covers this hash, so every ancestor up to
        // the apex is hashed and no encloser is found.
        Nsec3Hash::new(&[0xff; 20])
    };
    let p = Nsec3Proof::new(zone.as_name(), &records, &counting);
    assert_eq!(p.name_error(q.as_name()), Bogus(B::MissingProof));
    assert_eq!(calls.get(), 124);
}

#[test]
fn status_accessors_and_display() {
    let s = Secure(Denial::NameError);
    assert!(s.is_secure() && !s.is_insecure() && !s.is_bogus());
    assert_eq!(s.denial(), Some(Denial::NameError));
    assert_eq!(s.to_string(), "secure: name does not exist");
    let i = Insecure(InsecureReason::OptOut);
    assert!(i.is_insecure() && !i.is_secure());
    assert_eq!(i.denial(), None);
    assert_eq!(i.to_string(), "insecure: NSEC3 opt-out span");
    let b = Bogus(B::ZoneCut);
    assert!(b.is_bogus());
    assert_eq!(
        b.to_string(),
        "bogus: record from the wrong side of a zone cut"
    );
    for d in [
        Denial::NameError,
        Denial::NoData,
        Denial::WildcardNoData,
        Denial::WildcardAnswer,
        Denial::UnsignedDelegation,
    ] {
        assert!(!d.to_string().is_empty());
    }
    for r in [InsecureReason::OptOut, InsecureReason::Iterations] {
        assert!(!r.to_string().is_empty());
    }
    for r in [
        B::OutOfZone,
        B::MissingProof,
        B::NameExists,
        B::TypeExists,
        B::WildcardExists,
        B::WrongWildcard,
        B::ZoneCut,
        B::NotDelegation,
        B::NoOptOut,
        B::InconsistentParameters,
        B::UnusableRecords,
        B::Iterations,
    ] {
        assert!(!r.to_string().is_empty());
    }
}

#[test]
fn helpers() {
    let a = name("a.b.example");
    let b = name("c.b.example");
    assert_eq!(
        shared_ancestor(a.as_name(), b.as_name()),
        name("b.example").as_name()
    );
    let c = name("example.com");
    assert_eq!(shared_ancestor(a.as_name(), c.as_name()), Name::ROOT);
    assert_eq!(shared_ancestor(a.as_name(), Name::ROOT), Name::ROOT);
    assert_eq!(
        shared_ancestor(name("x.Example").as_name(), name("y.EXAMPLE").as_name()),
        name("example").as_name()
    );
    assert_eq!(wildcard_of(Name::ROOT).unwrap(), name("*"));
}
