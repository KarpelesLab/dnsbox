//! Property checks of the trust decisions: denial-of-existence proofs, the
//! RRSIG and chain-of-trust logic, TSIG and SIG(0) verification, and zone
//! files with `$INCLUDE` and ZONEMD. Shared by the `denial`, `dnssec`,
//! `sign` and `zone` fuzz targets and by `tests/fuzz_regressions.rs`.
//!
//! - [`denial`]: NSEC and NSEC3 proofs over records generated from a small
//!   name pool (so that matches, covers, wildcards and zone cuts actually
//!   occur); verdicts must be consistent with each other and never prove
//!   anything outside the zone (RFC 4035 §5.4, RFC 5155 §8).
//! - [`dnssec`]: the signature backend on hostile keys and signatures, and
//!   `TrustedKeys` over the records of a message with a verifier that
//!   accepts every signature, so that every check *other* than the
//!   cryptography is exercised (RFC 4035 §5.3).
//! - [`sign`]: a message signed with TSIG (request and response) or SIG(0)
//!   verifies, and a changed copy (flipped, inserted, appended or removed
//!   octets) verifies only if everything the signature covers is
//!   unchanged: header (but the ID for TSIG), the octets before the
//!   signature record, and that record's data (RFC 8945, RFC 2931).
//! - [`zone`]: master files whose `$INCLUDE`s name the other parts of the
//!   input; every record is valid, and the ZONEMD collation does not depend
//!   on the order of the records (RFC 8976 §3.3.1).

use std::vec::Vec;

use dnsbox::dnssec::{
    DenialProof, DenialStatus, Nsec3Hash, Nsec3HashAlgorithm, Nsec3Limits, Nsec3Proof, Nsec3Record,
    NsecProof, NsecRecord,
};
use dnsbox::rdata::{Nsec, Nsec3, TypeBitmap};
use dnsbox::{Name, NameBuf, Rtype, WireWriter};

use super::Bytes;

// ---------------------------------------------------------------------------
// Denial of existence.
// ---------------------------------------------------------------------------

/// Labels names are built from: enough to produce siblings, descendants,
/// wildcards, case differences and canonical-order corner cases.
const LABELS: [&[u8]; 9] = [b"a", b"b", b"*", b"x", b"sub", b"z", b"A", b"\x00", b"-"];

/// Types a bitmap is built from: the ones the proofs look at.
const TYPES: [Rtype; 11] = [
    Rtype::A,
    Rtype::NS,
    Rtype::SOA,
    Rtype::CNAME,
    Rtype::DS,
    Rtype::DNAME,
    Rtype::MX,
    Rtype::RRSIG,
    Rtype::NSEC,
    Rtype::TXT,
    Rtype::NSEC3,
];

/// A name of at most four labels from [`LABELS`] below `zone` (or, rarely,
/// below another name).
fn pool_name(b: &mut Bytes<'_>, zone: &NameBuf) -> NameBuf {
    let mode = b.u8();
    let mut n = if mode & 0x70 == 0x70 {
        NameBuf::from_text(b"other").expect("static name")
    } else {
        zone.clone()
    };
    for _ in 0..(mode & 3) + u8::from(mode & 0x80 != 0) {
        let label = LABELS[usize::from(b.u8()) % LABELS.len()];
        if n.prepend_label(label).is_err() {
            break;
        }
    }
    n
}

/// A type bitmap with the [`TYPES`] selected by `mask`, written to `buf`.
fn bitmap(mask: u16, buf: &mut [u8; 64]) -> usize {
    let types: Vec<Rtype> = TYPES
        .iter()
        .enumerate()
        .filter(|(i, _)| mask & (1 << i) != 0)
        .map(|(_, &t)| t)
        .collect();
    let mut w = WireWriter::new(buf);
    TypeBitmap::compose(&types, &mut w).expect("small bitmap");
    w.len()
}

/// A cheap stand-in for SHA-1 (the proofs only compare hashes): 8 octets
/// of FNV-1a over the canonical name, the salt and the iteration count.
fn fake_hash(
    name: Name<'_>,
    _algorithm: Nsec3HashAlgorithm,
    iterations: u16,
    salt: &[u8],
) -> dnsbox::Result<Nsec3Hash> {
    let mut wire = [0u8; 255];
    let len = dnsbox::dnssec::canonical_name(name, &mut wire);
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &c in wire[..len]
        .iter()
        .chain(salt)
        .chain(&iterations.to_be_bytes())
    {
        h = (h ^ u64::from(c)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    Nsec3Hash::new(&h.to_be_bytes())
}

/// A hash near `h`: itself, or one octet changed (so that spans just
/// before and after a name's hash are produced too).
fn tweak(b: &mut Bytes<'_>, h: Nsec3Hash) -> Nsec3Hash {
    let mode = b.u8();
    let mut bytes = h.as_bytes().to_vec();
    match mode % 6 {
        0 => {
            let i = usize::from(b.u8()) % bytes.len();
            bytes[i] = bytes[i].wrapping_add(1);
        }
        1 => {
            let i = usize::from(b.u8()) % bytes.len();
            bytes[i] = bytes[i].wrapping_sub(1);
        }
        // Rarely a hash of another length (must cover nothing).
        2 if mode & 0x80 != 0 => bytes.truncate(1 + usize::from(b.u8()) % bytes.len()),
        _ => {}
    }
    Nsec3Hash::new(&bytes).unwrap_or(h)
}

/// An NSEC3 Opt-Out span: insecure, but only after a closest encloser
/// proof.
const OPT_OUT: DenialStatus = DenialStatus::Insecure(dnsbox::dnssec::InsecureReason::OptOut);

/// The checks of one proof for `qname` / `qtype`.
fn check_proof<P: DenialProof>(
    p: &P,
    zone: Name<'_>,
    qname: Name<'_>,
    qtype: Rtype,
    labels: u8,
    nsec: bool,
    ce: Result<dnsbox::dnssec::ClosestEncloser<'_>, DenialStatus>,
) {
    let name_error = p.name_error(qname);
    let no_data = p.no_data(qname, qtype);
    let wildcard = p.wildcard_answer(qname, labels);
    let delegation = p.unsigned_delegation(qname);
    let all = [name_error, no_data, wildcard, delegation];

    // Nothing outside the zone is ever proven.
    if !qname.is_subdomain_of(&zone) {
        for s in all {
            assert!(!s.is_secure() && !s.is_insecure(), "{qname}: {s}");
        }
        assert!(ce.is_err());
        return;
    }
    // A name cannot be proven both absent and present.
    assert!(
        !(name_error.is_secure() && no_data.is_secure()),
        "{qname} {qtype}: {name_error} / {no_data}"
    );
    if let Ok(ce) = ce {
        // The closest encloser is a proper ancestor in the zone, and the
        // next closer name is one label longer, towards the name.
        assert!(qname.is_subdomain_of(&ce.encloser));
        assert!(ce.encloser.label_count() < qname.label_count());
        assert!(ce.encloser.is_subdomain_of(&zone));
        assert_eq!(ce.next_closer.label_count(), ce.encloser.label_count() + 1);
        assert!(qname.is_subdomain_of(&ce.next_closer));
        assert!(ce.next_closer.is_subdomain_of(&ce.encloser));
        assert!(!nsec || !ce.opt_out);
        if name_error.is_secure() {
            assert!(!ce.opt_out, "{qname}: NXDOMAIN in an opt-out span");
        }
    } else {
        assert!(
            !name_error.is_secure(),
            "{qname}: {name_error} without encloser"
        );
        assert_ne!(name_error, OPT_OUT, "{qname}: opt-out without encloser");
    }
    if wildcard.is_secure() || wildcard == OPT_OUT {
        // The source of synthesis is a proper ancestor inside the zone.
        assert!(
            usize::from(labels) < qname.label_count(),
            "{qname} {labels}"
        );
        assert!(
            usize::from(labels) >= zone.label_count(),
            "{qname} {labels}"
        );
        if nsec {
            let ce = ce.expect("NSEC wildcard proof has an encloser");
            assert_eq!(ce.encloser.label_count(), usize::from(labels));
        }
    }
    if delegation.is_secure() {
        assert_ne!(qname, zone, "the apex is no delegation");
    }
    if qname == zone && qtype == Rtype::DS {
        assert!(!no_data.is_secure(), "a zone denied its own DS: {no_data}");
    }
    // Through the trait object, the same verdicts.
    let dynp: &dyn DenialProof = p;
    assert_eq!(dynp.name_error(qname), name_error);
    assert_eq!((&p).no_data(qname, qtype), no_data);
}

/// NSEC and NSEC3 proofs over generated records: `[qname][qtype][labels]
/// [NSEC count][NSEC records...][NSEC3 parameters][NSEC3 count][NSEC3
/// records...]`, every part drawn from the input octets.
pub fn denial(data: &[u8]) {
    let mut b = Bytes(data);
    let zone = NameBuf::from_text(b"example").expect("static name");
    let qname = pool_name(&mut b, &zone);
    let qtype = TYPES[usize::from(b.u8()) % TYPES.len()];
    let labels = b.u8() % 6;

    // NSEC records: owner and next from the pool, a bitmap.
    let n = usize::from(b.u8() % 9);
    let mut nsec_names = Vec::with_capacity(n);
    let mut nsec_maps = Vec::with_capacity(n);
    for _ in 0..n {
        nsec_names.push((pool_name(&mut b, &zone), pool_name(&mut b, &zone)));
        let mut map = [0u8; 64];
        let len = bitmap(b.u16(), &mut map);
        nsec_maps.push((map, len));
    }
    let nsec: Vec<NsecRecord<'_>> = nsec_names
        .iter()
        .zip(&nsec_maps)
        .map(|((owner, next), (map, len))| {
            let types = TypeBitmap::new(&map[..*len]).expect("valid bitmap");
            NsecRecord::new(owner.as_name(), Nsec::new(next.as_name(), types))
        })
        .collect();
    let proof = NsecProof::new(zone.as_name(), &nsec);
    let ce = proof.closest_encloser(qname.as_name());
    check_proof(
        &proof,
        zone.as_name(),
        qname.as_name(),
        qtype,
        labels,
        true,
        ce,
    );
    if proof.name_error(qname.as_name()).is_secure() {
        assert!(
            nsec.iter().all(|r| r.owner != qname.as_name()),
            "{qname}: NXDOMAIN although a record matches it"
        );
    }

    // NSEC3 records: hashes of pool names (or near them), shared
    // parameters (rarely not), flags, a bitmap.
    let iterations = u16::from(b.u8() % 4);
    let salt: &[u8] = if b.bool() { b"\xab\xcd" } else { b"" };
    let n = usize::from(b.u8() % 9);
    let mut owners = Vec::with_capacity(n);
    let mut nexts = Vec::with_capacity(n);
    let mut params = Vec::with_capacity(n);
    for _ in 0..n {
        let h = fake_hash(
            pool_name(&mut b, &zone).as_name(),
            Nsec3HashAlgorithm::SHA1,
            iterations,
            salt,
        )
        .expect("hash");
        let owner = tweak(&mut b, h);
        owners.push(owner.owner_name(zone.as_name()).expect("short label"));
        let h = fake_hash(
            pool_name(&mut b, &zone).as_name(),
            Nsec3HashAlgorithm::SHA1,
            iterations,
            salt,
        )
        .expect("hash");
        nexts.push(tweak(&mut b, h));
        let flags = match b.u8() {
            f @ 0..=0x7f => f & 1,
            f => f,
        };
        let iters = if b.u8() == 0xff {
            iterations + 1
        } else {
            iterations
        };
        let mut map = [0u8; 64];
        let len = bitmap(b.u16(), &mut map);
        params.push((flags, iters, map, len));
    }
    let nsec3: Vec<Nsec3Record<'_>> = owners
        .iter()
        .zip(&nexts)
        .zip(&params)
        .map(|((owner, next), (flags, iters, map, len))| {
            Nsec3Record::new(
                owner.as_name(),
                Nsec3 {
                    hash_algorithm: Nsec3HashAlgorithm::SHA1,
                    flags: *flags,
                    iterations: *iters,
                    salt,
                    next_hashed_owner: next.as_bytes(),
                    types: TypeBitmap::new(&map[..*len]).expect("valid bitmap"),
                },
            )
        })
        .collect();
    let proof =
        Nsec3Proof::new(zone.as_name(), &nsec3, fake_hash).with_limits(Nsec3Limits::new(2, 3));
    let ce = proof.closest_encloser(qname.as_name());
    check_proof(
        &proof,
        zone.as_name(),
        qname.as_name(),
        qtype,
        labels,
        false,
        ce,
    );
}

// ---------------------------------------------------------------------------
// DNSSEC signatures and the chain of trust.
// ---------------------------------------------------------------------------

#[cfg(feature = "dnssec")]
mod chain {
    use std::vec::Vec;

    use dnsbox::dnssec::{
        Algorithm, Answer, Nsec3Proof, Nsec3Record, NsecProof, NsecRecord, PurecryptoVerifier,
        RecordRdata, Rrset, TrustedKeys, ValidationBudget, Verifier, check_validity, key_tag,
    };
    use dnsbox::rdata::{Dnskey, Ds, Rrsig};
    use dnsbox::{Class, Message, Name, Rtype};

    use super::super::Bytes;

    /// A verifier that accepts every signature: everything but the
    /// cryptography is checked.
    struct AcceptAll;

    impl Verifier for AcceptAll {
        fn supports(&self, _: Algorithm) -> bool {
            true
        }

        fn verify(&self, _: Algorithm, _: &[u8], _: &[u8], _: &[u8]) -> dnsbox::Result<()> {
            Ok(())
        }
    }

    /// The backend on hostile input: `[algorithm][key len: u16][key]
    /// [signature len: u16][signature][data...]`. Must not panic.
    pub(super) fn backend(data: &[u8]) {
        let mut b = Bytes(data);
        let algorithm = match b.u8() % 10 {
            0 => Algorithm::RSASHA1,
            1 => Algorithm::RSASHA1_NSEC3_SHA1,
            2 => Algorithm::RSASHA256,
            3 => Algorithm::RSASHA512,
            4 => Algorithm::ECDSAP256SHA256,
            5 => Algorithm::ECDSAP384SHA384,
            6 => Algorithm::ED25519,
            7 => Algorithm::ED448,
            8 => Algorithm::RSAMD5,
            _ => Algorithm::new(b.u8()),
        };
        let klen = usize::from(b.u16()) % 1100;
        let key = b.take(klen);
        let slen = usize::from(b.u16()) % 1100;
        let sig = b.take(slen);
        let msg = b.0;
        let v = PurecryptoVerifier;
        assert_eq!(
            v.supports(algorithm),
            matches!(algorithm.get(), 5 | 7 | 8 | 10 | 13 | 14 | 15 | 16)
        );
        let _ = v.verify(algorithm, key, msg, sig);
        let _ = key_tag(256, 3, algorithm, key);
        let _ = dnsbox::dnssec::RsaPublicKey::from_dnskey(key);
    }

    /// `TrustedKeys` over a message: `[now: u32][message]`. The zone is the
    /// question name; its DNSKEYs are the keys, every RRSIG in the message
    /// is a candidate, and every RRset of the message is verified with
    /// [`AcceptAll`], then as an answer with the message's NSEC and NSEC3
    /// records as the wildcard proof. A [`ValidationBudget`] shared by all
    /// the RRsets never allows more than its limits, and changes a verdict
    /// only into `LimitExceeded`.
    pub(super) fn trust(data: &[u8]) {
        let mut b = Bytes(data);
        let now = b.u32();
        let Ok(msg) = Message::parse(b.0) else {
            return;
        };
        let Some(Ok(q)) = msg.questions().next() else {
            return;
        };
        let zone = q.name();
        let records: Vec<_> = msg.records().map_while(Result::ok).collect();
        let keys: Vec<Dnskey<'_>> = records
            .iter()
            .filter(|(_, rr)| rr.rtype() == Rtype::DNSKEY && rr.name() == zone)
            .filter_map(|(_, rr)| rr.data_as::<Dnskey<'_>>().ok())
            .collect();
        let rrsigs: Vec<Rrsig<'_>> = records
            .iter()
            .filter(|(_, rr)| rr.rtype() == Rtype::RRSIG)
            .filter_map(|(_, rr)| rr.data_as::<Rrsig<'_>>().ok())
            .collect();
        let ds: Vec<Ds<'_>> = records
            .iter()
            .filter(|(_, rr)| rr.rtype() == Rtype::DS)
            .filter_map(|(_, rr)| rr.data_as::<Ds<'_>>().ok())
            .collect();
        let nsec: Vec<NsecRecord<'_>> = records
            .iter()
            .filter_map(|(_, rr)| NsecRecord::from_record(rr))
            .collect();
        let nsec3: Vec<Nsec3Record<'_>> = records
            .iter()
            .filter_map(|(_, rr)| Nsec3Record::from_record(rr))
            .collect();
        let class = q.qclass();
        let trusted = TrustedKeys::assume_trusted(zone, class, keys.iter().copied());
        let nsec_proof = NsecProof::new(zone, &nsec);
        let nsec3_proof = Nsec3Proof::new(zone, &nsec3, super::fake_hash);
        let mut scratch = Vec::new();
        let budget = ValidationBudget::new();
        let limits = *budget.limits();

        // Every RRset (owner, type, class) of the message, up to 16.
        let mut done: Vec<(Name<'_>, Rtype, Class)> = Vec::new();
        for (_, rr) in &records {
            let key = (rr.name(), rr.rtype(), rr.class());
            if rr.rtype() == Rtype::RRSIG || rr.rtype() == Rtype::OPT || done.contains(&key) {
                continue;
            }
            done.push(key);
            if done.len() > 16 {
                break;
            }
            let rdata: Vec<RecordRdata<'_>> = records
                .iter()
                .filter(|(_, r)| (r.name(), r.rtype(), r.class()) == key)
                .map(|(_, r)| RecordRdata(*r))
                .collect();
            let rrset = Rrset::new(rr.name(), rr.class(), rdata.iter().copied());
            let res =
                trusted.verify_rrset(&AcceptAll, rrset, rrsigs.iter().copied(), now, &mut scratch);
            assert!(scratch.is_empty(), "scratch space not released");
            let rrset = Rrset::new(rr.name(), rr.class(), rdata.iter().copied());
            let before = budget.verifications();
            let shared = trusted.verify_rrset_with_budget(
                &AcceptAll,
                rrset,
                rrsigs.iter().copied(),
                now,
                &mut scratch,
                &budget,
            );
            let spent = budget.verifications() - before;
            assert!(spent <= limits.max_verifications_per_rrset);
            assert!(budget.verifications() <= limits.max_verifications);
            if shared != Err(dnsbox::Error::LimitExceeded) {
                assert_eq!(shared, res, "a shared budget changed the verdict");
            }
            let Ok(v) = res else { continue };
            // Some RRSIG justifies the verdict, and it passes every
            // non-cryptographic check of RFC 4035 §5.3.1.
            let owner = rr.name();
            assert!(owner.is_subdomain_of(&zone));
            assert_eq!(rr.class(), class);
            let ok = rrsigs.iter().any(|s| {
                s.type_covered == rr.rtype()
                    && s.signer_name == zone
                    && s.key_tag == v.key_tag
                    && s.algorithm == v.algorithm
                    && s.labels == v.labels
                    && s.original_ttl == v.original_ttl
                    && s.expiration == v.expiration
                    && check_validity(s.inception, s.expiration, now).is_ok()
            });
            assert!(ok, "{owner} {}: no RRSIG justifies {v:?}", rr.rtype());
            assert!(usize::from(v.labels) <= owner.label_count());
            assert!(usize::from(v.labels) >= zone.label_count());
            assert!(keys.iter().any(|k| k.key_tag() == v.key_tag
                && k.algorithm == v.algorithm
                && k.is_zone_key()
                && !k.is_revoked()
                && k.protocol == 3));
            if let Some(labels) = v.wildcard {
                assert!(usize::from(labels) < owner.label_count());
            }
            for proof in [
                &nsec_proof as &dyn dnsbox::dnssec::DenialProof,
                &nsec3_proof,
            ] {
                let rrset = Rrset::new(rr.name(), rr.class(), rdata.iter().copied());
                match trusted.verify_answer(
                    &AcceptAll,
                    rrset,
                    rrsigs.iter().copied(),
                    proof,
                    now,
                    &mut scratch,
                ) {
                    Ok(Answer::Exact(e)) => assert!(e.wildcard.is_none()),
                    Ok(Answer::Wildcard { verified, proof }) => {
                        assert!(verified.wildcard.is_some());
                        if proof.is_secure() {
                            assert!(usize::from(verified.labels) >= zone.label_count());
                        }
                    }
                    Ok(_) => {}
                    Err(e) => panic!("verify_answer failed after verify_rrset: {e}"),
                }
            }
        }

        // NSEC3 proofs hashing through a budget: never more hashes than
        // its limit, and the verdicts of an unlimited proof unless spent.
        let hashes = ValidationBudget::new();
        let budgeted = Nsec3Proof::new(zone, &nsec3, hashes.nsec3_hasher(super::fake_hash));
        for (_, rr) in records.iter().take(8) {
            let name = rr.name();
            for (a, b) in [
                (budgeted.name_error(name), nsec3_proof.name_error(name)),
                (
                    budgeted.no_data(name, rr.rtype()),
                    nsec3_proof.no_data(name, rr.rtype()),
                ),
                (
                    budgeted.unsigned_delegation(name),
                    nsec3_proof.unsigned_delegation(name),
                ),
            ] {
                assert!(hashes.nsec3_hashes() <= hashes.limits().max_nsec3_hashes);
                if a != dnsbox::dnssec::DenialStatus::Bogus(
                    dnsbox::dnssec::BogusReason::LimitExceeded,
                ) {
                    assert_eq!(a, b, "a hash budget changed the verdict");
                }
            }
        }

        // The DNSKEY RRset authenticated from the message's DS records and
        // from itself as trust anchors.
        let dnskeys = Rrset::new(zone, class, keys.iter().copied());
        let from_ds = TrustedKeys::from_ds(
            &AcceptAll,
            dnskeys.clone(),
            ds.iter().copied(),
            rrsigs.iter().copied(),
            now,
            &mut scratch,
        );
        if from_ds.is_ok() {
            assert!(!ds.is_empty() && !keys.is_empty());
        }
        let anchors = keys.iter().copied().take(1);
        let _ = TrustedKeys::from_anchors(
            &AcceptAll,
            dnskeys.clone(),
            anchors,
            rrsigs.iter().copied(),
            now,
            &mut scratch,
        );
        // The real backend on the same records, bounded by the
        // per-call budget.
        if keys.len() <= 4 {
            let _ = TrustedKeys::from_anchors(
                &PurecryptoVerifier,
                dnskeys,
                keys.iter().copied(),
                rrsigs.iter().copied(),
                now,
                &mut scratch,
            );
        }
        assert!(scratch.is_empty());
    }
}

/// The signature backend and the chain of trust (feature `dnssec`):
/// the first input octet picks the check.
pub fn dnssec(data: &[u8]) {
    #[cfg(feature = "dnssec")]
    match data.split_first() {
        Some((mode, rest)) if mode & 1 == 0 => chain::backend(rest),
        Some((_, rest)) => chain::trust(rest),
        None => {}
    }
    #[cfg(not(feature = "dnssec"))]
    let _ = data;
}

// ---------------------------------------------------------------------------
// TSIG and SIG(0): signed bytes cannot change.
// ---------------------------------------------------------------------------

#[cfg(all(feature = "tsig", feature = "dnssec"))]
mod signing {
    use std::vec::Vec;

    use dnsbox::dnssec::{Algorithm, PurecryptoVerifier, SigningKey};
    use dnsbox::sig0::{self, DnssecSig0Signer, DnssecSig0Verifier, Validity};
    use dnsbox::tsig::{
        HmacKey, RequestStatus, TsigAlgorithm, TsigSigner, TsigVerifier, verify_request,
    };
    use dnsbox::{Error, Message, MessageBuilder, NameBuf, Rtype, WireWriter};

    use super::super::Bytes;

    const NOW: u64 = 1_800_000_000;

    /// Copies `msg` into `buf`, leaving out signatures (they must be
    /// last), and returns the copy's length.
    fn unsigned_copy(msg: &Message<'_>, buf: &mut [u8]) -> Option<usize> {
        let mut b = MessageBuilder::new(buf).ok()?;
        b.set_id(msg.id());
        b.set_flags(msg.flags());
        for q in msg.questions() {
            b.copy_question(&q.ok()?).ok()?;
        }
        for item in msg.records() {
            let (s, rr) = item.ok()?;
            if rr.rtype() == Rtype::TSIG || rr.rtype() == Rtype::SIG {
                continue;
            }
            b.copy_record(s, &rr).ok()?;
        }
        Some(b.finish().len())
    }

    /// One mutation of a signed message, described by the input.
    #[derive(Clone, Copy, Debug)]
    enum Mutation {
        Flip { at: usize, xor: u8 },
        Append(u8),
        Truncate(usize),
        Insert { at: usize, byte: u8 },
    }

    fn mutation(b: &mut Bytes<'_>) -> Mutation {
        let kind = b.u8();
        let at = usize::from(b.u16());
        let v = b.u8();
        match kind % 4 {
            0 | 1 => Mutation::Flip { at, xor: v.max(1) },
            2 => Mutation::Append(v),
            _ if kind & 0x80 != 0 => Mutation::Truncate(1 + at % 4),
            _ => Mutation::Insert { at, byte: v },
        }
    }

    /// Applies `m` to `wire`.
    fn apply(wire: &[u8], m: Mutation) -> Vec<u8> {
        let mut out = wire.to_vec();
        match m {
            Mutation::Flip { at, xor } => {
                let at = at % out.len();
                out[at] ^= xor;
            }
            Mutation::Append(v) => out.push(v),
            Mutation::Truncate(n) => out.truncate(out.len().saturating_sub(n)),
            Mutation::Insert { at, byte } => {
                let at = at % (out.len() + 1);
                out.insert(at, byte);
            }
        }
        out
    }

    /// What a signature covers, apart from its own record: the header
    /// (without the ID when `id_free`: TSIG MACs use the original ID,
    /// RFC 8945 §4.3.1) and the octets between it and the signature record
    /// at `start`.
    fn covered(wire: &[u8], start: usize, id_free: bool) -> (Vec<u8>, &[u8]) {
        let mut header = wire.get(..12).unwrap_or(&[]).to_vec();
        if id_free {
            header.drain(..2.min(header.len()));
        }
        (header, wire.get(12..start).unwrap_or(&[]))
    }

    /// `[mutation: 4][message...]`: the message (without its signatures)
    /// is signed with TSIG as a request, as a response, and with SIG(0);
    /// each verifies. A mutated copy may only still verify if everything
    /// the signature covers is unchanged: the same header (but the ID for
    /// TSIG), the same octets before the signature record, and the same
    /// record (names compared as the signature does, case-insensitively;
    /// how the record's own owner name is encoded is not covered).
    pub(super) fn check(data: &[u8]) {
        let mut b = Bytes(data);
        let m = mutation(&mut b);
        let Ok(msg) = Message::parse(b.0) else {
            return;
        };
        let mut buf = std::vec![0u8; 16384];
        let Some(len) = unsigned_copy(&msg, &mut buf) else {
            return;
        };
        let unsigned = buf[..len].to_vec();

        // TSIG request.
        let name: NameBuf = "key.example.".parse().expect("static name");
        let key = HmacKey::new(&name, TsigAlgorithm::HmacSha256, b"fuzzing secret");
        let mut sbuf = std::vec![0u8; 16384];
        let Ok(mut builder) = rebuild(&unsigned, &mut sbuf) else {
            return;
        };
        let Ok(request_mac) = TsigSigner::request(&key).sign(&mut builder, NOW) else {
            return;
        };
        let request = builder.finish().to_vec();
        let parsed = Message::parse(&request).expect("signed message parses");
        let RequestStatus::Verified(verified) = verify_request(&parsed, &key, NOW) else {
            panic!("signed request does not verify");
        };
        let bad = apply(&request, m);
        if let Ok(bad_msg) = Message::parse(&bad)
            && let Some(v) = verify_request(&bad_msg, &key, NOW).verified()
        {
            assert_eq!(
                covered(&bad, v.record.start, true),
                covered(&request, verified.record.start, true),
                "mutated request {m:?} verifies with other content"
            );
            assert_eq!(v.record.key_name, verified.record.key_name);
            assert_eq!(v.record.data, verified.record.data, "{m:?}");
        }

        // TSIG response to it.
        let mut rbuf = std::vec![0u8; 16384];
        if let Ok(mut r) = MessageBuilder::response(&mut rbuf, &parsed)
            && verified.signer().sign(&mut r, NOW).is_ok()
        {
            let response = r.finish().to_vec();
            let mut v = TsigVerifier::new(&key, request_mac.as_slice()).expect("MAC size");
            let rec = v
                .verify(&Message::parse(&response).expect("parses"), NOW)
                .expect("signed response verifies")
                .expect("signed");
            v.finish().expect("stream complete");
            let bad = apply(&response, m);
            let mut v = TsigVerifier::new(&key, request_mac.as_slice()).expect("MAC size");
            if let Ok(bad_msg) = Message::parse(&bad)
                && let Ok(Some(got)) = v.verify(&bad_msg, NOW)
            {
                assert_eq!(
                    covered(&bad, got.start, true),
                    covered(&response, rec.start, true),
                    "mutated response {m:?} verifies with other content"
                );
                assert_eq!(got.key_name, rec.key_name);
                assert_eq!(got.data, rec.data, "{m:?}");
            }
        }

        // SIG(0).
        let sk = SigningKey::from_private_bytes(Algorithm::ED25519, &[7; 32]).expect("key");
        let owner: NameBuf = "client.example.".parse().expect("static name");
        let signer = DnssecSig0Signer::new(&sk, owner.as_name(), 512);
        let mut sbuf = std::vec![0u8; 16384];
        let Ok(mut builder) = rebuild(&unsigned, &mut sbuf) else {
            return;
        };
        let now = NOW as u32;
        match sig0::sign(&mut builder, &signer, Validity::around(now, 300), None) {
            Ok(()) => {}
            Err(Error::BufferTooSmall | Error::CountOverflow) => return,
            Err(e) => panic!("SIG(0) signing failed: {e}"),
        }
        let signed = builder.finish().to_vec();
        let verifier = DnssecSig0Verifier::new(PurecryptoVerifier, owner.as_name(), signer.key());
        let rec = sig0::verify(
            &Message::parse(&signed).expect("parses"),
            &verifier,
            now,
            None,
        )
        .expect("SIG(0) verifies");
        let bad = apply(&signed, m);
        if let Ok(bad_msg) = Message::parse(&bad)
            && let Ok(got) = sig0::verify(&bad_msg, &verifier, now, None)
        {
            assert_eq!(
                covered(&bad, got.start, false),
                covered(&signed, rec.start, false),
                "mutated SIG(0) message {m:?} verifies with other content"
            );
            assert_eq!(got.data, rec.data, "{m:?}");
        }
    }

    /// A builder continuing the already-built message `wire` (copied into
    /// `buf` again, record by record).
    fn rebuild<'b>(
        wire: &[u8],
        buf: &'b mut [u8],
    ) -> dnsbox::Result<MessageBuilder<WireWriter<'b>>> {
        let msg = Message::parse(wire)?;
        let mut b = MessageBuilder::new(buf)?;
        b.set_id(msg.id());
        b.set_flags(msg.flags());
        for q in msg.questions() {
            b.copy_question(&q?)?;
        }
        for item in msg.records() {
            let (s, rr) = item?;
            b.copy_record(s, &rr)?;
        }
        Ok(b)
    }
}

/// TSIG and SIG(0) signing and verification (features `tsig` and
/// `dnssec`).
pub fn sign(data: &[u8]) {
    #[cfg(all(feature = "tsig", feature = "dnssec"))]
    signing::check(data);
    #[cfg(not(all(feature = "tsig", feature = "dnssec")))]
    let _ = data;
}

// ---------------------------------------------------------------------------
// Zone files with includes, and ZONEMD.
// ---------------------------------------------------------------------------

/// Master files: the input split at NUL octets into up to eight files, the
/// first being the main one; `$INCLUDE <n>` includes the `n`th. Every
/// record must be valid, and with `alloc` its ZONEMD collation must not
/// depend on the order of the records.
pub fn zone(data: &[u8]) {
    #[cfg(feature = "alloc")]
    {
        use dnsbox::zone::{ZoneReader, ZoneRecordBuf};
        use std::string::String;

        let files: Vec<&[u8]> = data.split(|&c| c == 0).take(8).collect();
        let main = files.first().copied().unwrap_or(&[]);
        let origin = NameBuf::from_text(b"example.").expect("static name");
        let resolver = |path: &str| -> dnsbox::Result<String> {
            let n: usize = path.parse().map_err(|_| dnsbox::Error::BadInclude)?;
            let text = files.get(n).ok_or(dnsbox::Error::BadInclude)?;
            Ok(String::from_utf8_lossy(text).into_owned())
        };
        let mut records: Vec<ZoneRecordBuf> = Vec::new();
        let iter = ZoneReader::from_bytes(main)
            .with_origin(&origin)
            .records()
            .with_includes(resolver)
            .max_includes(16);
        // One `$GENERATE` may yield many records: cap the work per input.
        for item in iter.take(2048) {
            let Ok(rr) = item else { continue };
            let d = rr
                .data()
                .unwrap_or_else(|e| panic!("{}: zone RDATA invalid: {e}", rr.name));
            assert_eq!(d.rtype(), rr.rtype);
            records.push(rr);
        }
        zonemd(&origin, &records);
    }
    #[cfg(not(feature = "alloc"))]
    let _ = data;
}

/// The ZONEMD collation of `records` and of the same records reversed are
/// identical (RFC 8976 §3.3.1: canonical order, duplicates removed), and
/// so is the verification verdict.
#[cfg(feature = "alloc")]
fn zonemd(apex: &NameBuf, records: &[dnsbox::zone::ZoneRecordBuf]) {
    use dnsbox::dnssec::{ZoneCollation, ZonemdRecord};
    let data: Vec<_> = records
        .iter()
        .map(|r| {
            let d = r.data().expect("checked");
            ZonemdRecord::new(r.name.as_name(), r.class, r.ttl, d)
        })
        .collect();
    let forward = ZoneCollation::new(apex.as_name(), data.iter().copied());
    let backward = ZoneCollation::new(apex.as_name(), data.iter().rev().copied());
    let (forward, backward) = match (forward, backward) {
        (Ok(f), Ok(b)) => (f, b),
        (Err(_), Err(_)) => return,
        (f, b) => panic!("collation depends on order: {:?} / {:?}", f.err(), b.err()),
    };
    assert_eq!(forward.len(), backward.len());
    // Duplicates that differ only in TTL (invalid, RFC 2181 §5.2) keep the
    // TTL of whichever came first; everything else is order independent.
    for (f, b) in forward.rrs().zip(backward.rrs()) {
        assert_eq!(without_ttl(f), without_ttl(b), "collation depends on order");
    }
    let same_ttls = forward.rrs().eq(backward.rrs());
    #[cfg(not(feature = "dnssec-digest"))]
    let _ = same_ttls;
    let mut zf: Vec<&[u8]> = forward.zonemd_rdata().collect();
    let mut zb: Vec<&[u8]> = backward.zonemd_rdata().collect();
    zf.sort();
    zb.sort();
    assert_eq!(zf, zb);
    zf.dedup();
    assert_eq!(
        zf.len(),
        forward.zonemd_rdata().count(),
        "duplicate ZONEMD kept"
    );
    #[cfg(feature = "dnssec-digest")]
    if same_ttls {
        let (a, b) = (forward.verify(), backward.verify());
        match (a, b) {
            (Ok(_), Ok(_)) => {}
            (a, b) => assert_eq!(a, b),
        }
    }
}

/// A canonical RR (uncompressed owner, type, class, TTL, RDATA) with its
/// TTL zeroed.
#[cfg(feature = "alloc")]
fn without_ttl(rr: &[u8]) -> Vec<u8> {
    let mut out = rr.to_vec();
    let mut owner = 0;
    while let Some(&len) = out.get(owner) {
        owner += 1 + usize::from(len);
        if len == 0 {
            break;
        }
    }
    if let Some(ttl) = out.get_mut(owner + 4..owner + 8) {
        ttl.fill(0);
    }
    out
}
