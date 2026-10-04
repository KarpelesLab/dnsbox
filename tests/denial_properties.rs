//! Property tests for authenticated denial of existence (RFC 4035 §5.4,
//! RFC 5155 §8, RFC 4592): random zones with empty non-terminals and
//! wildcards get their complete, correct NSEC and NSEC3 chains, and every
//! proof check must agree with the ground truth computed from the zone:
//! a proof is secure exactly when the response it checks is the right one.
//!
//! NSEC3 uses a crypto-free stand-in hash (the hash function does not
//! matter to the proof logic, only the chain order does).

use std::collections::BTreeSet;

use dnsbox::dnssec::{
    Denial, DenialProof, DenialStatus, Nsec3Hash, Nsec3HashAlgorithm, Nsec3Proof, Nsec3Record,
    NsecProof, NsecRecord,
};
use dnsbox::rdata::{Nsec, Nsec3, TypeBitmap};
use dnsbox::{Name, NameBuf, Rtype, WireWriter};
use proptest::prelude::*;

/// A name relative to the apex, as its labels (leftmost first).
type Rel = Vec<&'static str>;

fn abs(rel: &[&str]) -> NameBuf {
    let mut text = String::new();
    for l in rel {
        text.push_str(l);
        text.push('.');
    }
    text.push_str("example");
    text.parse().unwrap()
}

/// The zone model: the explicit (record-holding) names below the apex.
#[derive(Debug, Clone)]
struct Zone {
    explicit: BTreeSet<Rel>,
}

/// What a query for a name gets.
#[derive(Debug, PartialEq, Eq)]
enum Truth {
    /// The name has records (A, never MX).
    Explicit,
    /// The name exists without records.
    EmptyNonTerminal,
    /// The name does not exist; the wildcard at its closest encloser (of
    /// that many labels below the apex) does.
    Wildcard(usize),
    /// The name does not exist; the closest encloser has that many labels
    /// below the apex.
    NxDomain(usize),
}

impl Zone {
    /// Every existing name: the apex, explicit names and their ancestors.
    fn existing(&self) -> BTreeSet<Rel> {
        let mut out = BTreeSet::new();
        out.insert(Vec::new());
        for n in &self.explicit {
            for skip in 0..n.len() {
                out.insert(n[skip..].to_vec());
            }
        }
        out
    }

    fn truth(&self, q: &[&'static str]) -> Truth {
        let existing = self.existing();
        if q.is_empty() || self.explicit.contains(q) {
            return Truth::Explicit;
        }
        if existing.contains(q) {
            return Truth::EmptyNonTerminal;
        }
        let ce = (1..=q.len())
            .map(|skip| &q[skip..])
            .find(|a| existing.contains(*a))
            .unwrap();
        let mut wildcard = vec!["*"];
        wildcard.extend_from_slice(ce);
        if self.explicit.contains(&wildcard) {
            Truth::Wildcard(ce.len())
        } else {
            Truth::NxDomain(ce.len())
        }
    }
}

fn label() -> impl Strategy<Value = &'static str> {
    prop::sample::select(vec!["a", "b", "c"])
}

/// Explicit names: 1–3 labels, possibly a wildcard (leftmost `*`).
fn zone() -> impl Strategy<Value = Zone> {
    let name = (prop::collection::vec(label(), 1..=3), any::<bool>()).prop_map(
        |(mut labels, wildcard)| {
            if wildcard {
                labels[0] = "*";
            }
            labels
        },
    );
    prop::collection::btree_set(name, 0..10).prop_map(|explicit| Zone { explicit })
}

fn query() -> impl Strategy<Value = Rel> {
    prop::collection::vec(label(), 0..=4)
}

fn bitmap(types: &[Rtype]) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let mut w = WireWriter::new(&mut buf);
    TypeBitmap::compose(types, &mut w).unwrap();
    w.as_bytes().to_vec()
}

/// The types at an explicit name or the apex, and at an empty
/// non-terminal (NSEC3 only).
const APEX: &[Rtype] = &[Rtype::A, Rtype::NS, Rtype::SOA, Rtype::RRSIG];
const NAME: &[Rtype] = &[Rtype::A, Rtype::RRSIG];

/// A stand-in NSEC3 hash: 20 octets mixed from the lowercase name (not
/// cryptographic; only the order it induces matters here).
fn fake_hash(name: Name<'_>, _: Nsec3HashAlgorithm, _: u16, _: &[u8]) -> dnsbox::Result<Nsec3Hash> {
    let text = name.to_string().to_ascii_lowercase();
    let mut out = [0u8; 20];
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for (i, slot) in out.iter_mut().enumerate() {
        for b in text.bytes().chain([i as u8]) {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        *slot = (h >> 32) as u8;
    }
    Nsec3Hash::new(&out)
}

/// Checks every proof for `q` against the ground truth.
fn check<P: DenialProof>(p: &P, z: &Zone, q: &[&'static str], nsec3: bool) {
    use DenialStatus::Secure;
    let qn = abs(q);
    let qn = qn.as_name();
    let truth = z.truth(q);
    let ctx = format!("{qn} {truth:?} in {:?} (nsec3: {nsec3})", z.explicit);
    let name_error = p.name_error(qn);
    let no_mx = p.no_data(qn, Rtype::MX);
    let no_a = p.no_data(qn, Rtype::A);
    match truth {
        Truth::Explicit => {
            assert!(!name_error.is_secure(), "{ctx}: {name_error}");
            assert_eq!(no_mx, Secure(Denial::NoData), "{ctx}");
            assert!(!no_a.is_secure(), "{ctx}: {no_a}");
        }
        Truth::EmptyNonTerminal => {
            assert!(!name_error.is_secure(), "{ctx}: {name_error}");
            assert_eq!(no_mx, Secure(Denial::NoData), "{ctx}");
            assert_eq!(no_a, Secure(Denial::NoData), "{ctx}");
        }
        Truth::Wildcard(_) => {
            assert!(!name_error.is_secure(), "{ctx}: {name_error}");
            assert_eq!(no_mx, Secure(Denial::WildcardNoData), "{ctx}");
            assert!(!no_a.is_secure(), "{ctx}: {no_a}");
        }
        Truth::NxDomain(_) => {
            assert_eq!(name_error, Secure(Denial::NameError), "{ctx}");
            assert!(!no_mx.is_secure(), "{ctx}: {no_mx}");
            assert!(!no_a.is_secure(), "{ctx}: {no_a}");
        }
    }
    // A wildcard answer proof shows that no closer match exists: it holds
    // for the closest encloser's wildcard, and for no shallower one. The
    // wildcard's existence itself comes from its verified RRSIG (whose
    // labels field is the argument); NSEC also pins the encloser down,
    // whereas NSEC3 takes it from that RRSIG (RFC 5155 §8.8), so deeper
    // (nonexistent) enclosers are only rejected with NSEC.
    for labels in 0..=6u8 {
        let status = p.wildcard_answer(qn, labels);
        let l = usize::from(labels);
        match truth {
            Truth::Explicit | Truth::EmptyNonTerminal => {
                assert!(!status.is_secure(), "{ctx}: labels {labels}: {status}");
            }
            Truth::Wildcard(ce) | Truth::NxDomain(ce) => {
                if l == ce + 1 {
                    assert_eq!(status, Secure(Denial::WildcardAnswer), "{ctx}: {labels}");
                } else if l < ce + 1 || !nsec3 {
                    assert!(!status.is_secure(), "{ctx}: labels {labels}: {status}");
                }
            }
        }
    }
    // Nothing here is a delegation.
    assert!(!p.unsigned_delegation(qn).is_secure(), "{ctx}");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn nsec_proofs_match_the_zone(z in zone(), queries in prop::collection::vec(query(), 1..8)) {
        // The NSEC chain: every explicit name and the apex, in canonical
        // order, each pointing at the next (the last at the apex).
        let mut owners: Vec<NameBuf> = std::iter::once(abs(&[]))
            .chain(z.explicit.iter().map(|n| abs(n)))
            .collect();
        owners.sort_by(|a, b| a.as_name().cmp_canonical(&b.as_name()));
        let apex_bitmap = bitmap(&[APEX, &[Rtype::NSEC]].concat());
        let name_bitmap = bitmap(&[NAME, &[Rtype::NSEC]].concat());
        let records: Vec<NsecRecord<'_>> = owners
            .iter()
            .enumerate()
            .map(|(i, owner)| {
                let next = &owners[(i + 1) % owners.len()];
                let types = if i == 0 { &apex_bitmap } else { &name_bitmap };
                NsecRecord::new(
                    owner.as_name(),
                    Nsec::new(next.as_name(), TypeBitmap::new(types).unwrap()),
                )
            })
            .collect();
        let apex = abs(&[]);
        let proof = NsecProof::new(apex.as_name(), &records);
        for q in &queries {
            check(&proof, &z, q, false);
            if let Truth::NxDomain(ce) | Truth::Wildcard(ce) = z.truth(q) {
                let qn = abs(q);
                let found = proof.closest_encloser(qn.as_name()).unwrap();
                prop_assert_eq!(found.encloser.label_count(), ce + 1);
                prop_assert_eq!(found.next_closer.label_count(), ce + 2);
            }
        }
    }

    #[test]
    fn nsec3_proofs_match_the_zone(z in zone(), queries in prop::collection::vec(query(), 1..8)) {
        // The NSEC3 chain: every existing name, empty non-terminals
        // included, in hash order.
        let apex = abs(&[]);
        let existing = z.existing();
        let mut hashed: Vec<(Nsec3Hash, Vec<u8>)> = existing
            .iter()
            .map(|n| {
                let name = abs(n);
                let hash = fake_hash(name.as_name(), Nsec3HashAlgorithm::SHA1, 0, &[]).unwrap();
                let types = if n.is_empty() {
                    APEX
                } else if z.explicit.contains(n) {
                    NAME
                } else {
                    &[]
                };
                (hash, bitmap(types))
            })
            .collect();
        hashed.sort_by_key(|h| h.0);
        let owners: Vec<NameBuf> = hashed
            .iter()
            .map(|(h, _)| h.owner_name(apex.as_name()).unwrap())
            .collect();
        let records: Vec<Nsec3Record<'_>> = hashed
            .iter()
            .enumerate()
            .map(|(i, (_, types))| {
                let next = &hashed[(i + 1) % hashed.len()].0;
                Nsec3Record::new(
                    owners[i].as_name(),
                    Nsec3 {
                        hash_algorithm: Nsec3HashAlgorithm::SHA1,
                        flags: 0,
                        iterations: 0,
                        salt: &[],
                        next_hashed_owner: next.as_bytes(),
                        types: TypeBitmap::new(types).unwrap(),
                    },
                )
            })
            .collect();
        let proof = Nsec3Proof::new(apex.as_name(), &records, fake_hash);
        for q in &queries {
            check(&proof, &z, q, true);
            if let Truth::NxDomain(ce) | Truth::Wildcard(ce) = z.truth(q) {
                let qn = abs(q);
                let found = proof.closest_encloser(qn.as_name()).unwrap();
                prop_assert_eq!(found.encloser.label_count(), ce + 1);
                prop_assert!(!found.opt_out);
            }
        }
    }

    #[test]
    fn partial_proofs_are_never_secure_for_existing_names(
        z in zone(),
        q in query(),
        keep in prop::collection::vec(any::<bool>(), 16),
    ) {
        // Any subset of a correct NSEC chain proves nothing false: an
        // existing name is never denied.
        let truth = z.truth(&q);
        prop_assume!(matches!(truth, Truth::Explicit | Truth::EmptyNonTerminal));
        let mut owners: Vec<NameBuf> = std::iter::once(abs(&[]))
            .chain(z.explicit.iter().map(|n| abs(n)))
            .collect();
        owners.sort_by(|a, b| a.as_name().cmp_canonical(&b.as_name()));
        let name_bitmap = bitmap(NAME);
        let records: Vec<NsecRecord<'_>> = owners
            .iter()
            .enumerate()
            .filter(|(i, _)| keep[i % keep.len()])
            .map(|(i, owner)| {
                let next = &owners[(i + 1) % owners.len()];
                NsecRecord::new(
                    owner.as_name(),
                    Nsec::new(next.as_name(), TypeBitmap::new(&name_bitmap).unwrap()),
                )
            })
            .collect();
        let apex = abs(&[]);
        let proof = NsecProof::new(apex.as_name(), &records);
        let qn = abs(&q);
        prop_assert!(!proof.name_error(qn.as_name()).is_secure());
        for labels in 0..=6u8 {
            prop_assert!(!proof.wildcard_answer(qn.as_name(), labels).is_secure());
        }
    }
}
