//! Interoperability with Knot DNS 3.5 and Unbound 1.19, whose tools ran on
//! a GitHub Actions runner (`.github/workflows/interop.yml`, driven by
//! `tests/corpus/knot/run.sh`; see `tests/corpus/README.md`).
//!
//! The tests read the output directory of such a run: the one named by
//! `DNSBOX_INTEROP_DIR` (the workflow points it at its fresh captures), or
//! else the subset of a run kept in `tests/corpus/knot/`.
//!
//! - Zones signed by `kzonesign` with keys from `keymgr`, for RSASHA256,
//!   RSASHA512, ECDSAP256SHA256, ECDSAP384SHA384, ED25519 and ED448, each
//!   with NSEC, NSEC3 and NSEC3 Opt-Out: dnsbox reads Knot's presentation
//!   format, authenticates the keys from keymgr's DS records, verifies
//!   every RRSIG, finds the NSEC/NSEC3 chains it predicts, re-signs every
//!   RRset with Knot's private keys (to Knot's exact bytes with the
//!   deterministic algorithms) and, with `DNSBOX_INTEROP_WRITE` set,
//!   writes the zones re-signed by dnsbox into `<dir>/dnsbox/`, for
//!   `kzonecheck`, `ldns-verify-zone` and `dnssec-verify` to check.
//! - `knotd` serving them, queried by `kdig` and `knsupdate` (and by
//!   dnsbox's `interop_probe` example) through a recording proxy: every
//!   message parses and rebuilds, the zone file text and the AXFR wire
//!   hold the same records, kdig's text of each response reads back to its
//!   wire records, the positive and denial-of-existence answers verify
//!   and prove what they should, every TSIG MAC (six HMACs; requests,
//!   responses, multi-message transfers, UPDATE) verifies, and the IXFR
//!   after the dynamic updates turns the AXFR before them into the AXFR
//!   after them.
//! - Unbound validating with `interop.`'s trust anchor: for every case
//!   (secure answers, NSEC/NSEC3 denials, wildcards, Opt-Out and unsigned
//!   delegations, and three tampered zones), dnsbox validates the chain
//!   Unbound fetched (with CD set) and reaches Unbound's verdict: AD for
//!   secure, neither AD nor SERVFAIL for insecure, SERVFAIL for bogus.

#![cfg(all(feature = "dnssec", feature = "tsig"))]

#[path = "../fuzz/src/lib.rs"]
#[allow(dead_code)]
mod checks;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use dnsbox::dnssec::{
    Algorithm, Denial, DenialProof, DenialStatus, DigestType, InsecureReason, Nsec3Proof,
    Nsec3Record, NsecProof, NsecRecord, PurecryptoNsec3Hasher, PurecryptoVerifier, Rrset, Signer,
    SigningKey, TrustedKeys, ZoneKey, ZonemdRecord, nsec3_hash, sign_rrset, verify_ds,
    verify_zonemd, zonemd_digest,
};
use dnsbox::rdata::{Dnskey, Ds, Nsec, Nsec3, RData, Rrsig, Zonemd};
use dnsbox::tsig::{self, HmacKey, TsigAlgorithm, TsigRcode, TsigVerifier};
use dnsbox::xfr::{XfrEvent, XfrProcessor, XfrStyle};
use dnsbox::zone::{ZoneReader, ZoneRecordBuf};
use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rcode, Rtype, Section};

// ---------------------------------------------------------------------
// The run's output directory.
// ---------------------------------------------------------------------

/// The directory the tests read: `DNSBOX_INTEROP_DIR`, or the subset in
/// `tests/corpus/knot/`.
fn dir() -> PathBuf {
    match std::env::var_os("DNSBOX_INTEROP_DIR") {
        Some(d) => PathBuf::from(d),
        None => Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/knot"),
    }
}

/// Whether the tests read a fresh run rather than the kept subset.
fn live() -> bool {
    std::env::var_os("DNSBOX_INTEROP_DIR").is_some()
}

fn text(rel: &str) -> String {
    let path = dir().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The time of the run (seconds since 1970): every signature is checked
/// as of then.
fn now() -> u32 {
    text("now").trim().parse().expect("now")
}

/// Decodes a `tests/corpus/*.hex`-style file: `#` lines are comments.
fn hex_file(path: &Path) -> Vec<u8> {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let digits: Vec<u8> = text
        .lines()
        .filter(|l| !l.starts_with('#'))
        .flat_map(str::bytes)
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| (b as char).to_digit(16).expect("hex digit") as u8)
        .collect();
    assert!(digits.len().is_multiple_of(2), "{}", path.display());
    digits.chunks(2).map(|p| (p[0] << 4) | p[1]).collect()
}

/// One message of an exchange recorded by `proxy.py`.
struct Recorded {
    tcp: bool,
    query: bool,
    wire: Vec<u8>,
    file: PathBuf,
}

/// What passed through the proxy under one label: the queries and
/// responses in order, and the client's text output (kdig, knsupdate).
struct Exchange {
    label: String,
    messages: Vec<Recorded>,
    output: Option<String>,
}

impl Exchange {
    fn queries(&self) -> impl Iterator<Item = &Recorded> {
        self.messages.iter().filter(|m| m.query)
    }

    fn responses(&self) -> impl Iterator<Item = &Recorded> {
        self.messages.iter().filter(|m| !m.query)
    }

    /// The first query.
    fn query(&self) -> Message<'_> {
        let q = self
            .queries()
            .next()
            .unwrap_or_else(|| panic!("{}: no query", self.label));
        Message::parse_validated(&q.wire).unwrap()
    }

    /// The last response (the only one, but for transfers).
    fn response(&self) -> Message<'_> {
        let r = self
            .responses()
            .last()
            .unwrap_or_else(|| panic!("{}: no response", self.label));
        Message::parse_validated(&r.wire).unwrap()
    }
}

/// The exchange recorded under `label` (e.g. `knot/edns/nsid`), if the
/// directory has it.
fn exchange(label: &str) -> Option<Exchange> {
    let path = dir().join(label);
    let mut files: Vec<PathBuf> = fs::read_dir(&path)
        .ok()?
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "hex"))
        .collect();
    if files.is_empty() {
        return None;
    }
    files.sort();
    let messages = files
        .into_iter()
        .map(|file| {
            let name = file.file_name().unwrap().to_str().unwrap().to_owned();
            // NN-<udp|tcp>-<q|r>.hex
            let parts: Vec<&str> = name.trim_end_matches(".hex").split('-').collect();
            Recorded {
                tcp: parts[1] == "tcp",
                query: parts[2] == "q",
                wire: hex_file(&file),
                file,
            }
        })
        .collect();
    let output = ["kdig.txt", "knsupdate.txt"]
        .iter()
        .find_map(|f| fs::read_to_string(path.join(f)).ok());
    Some(Exchange {
        label: label.to_owned(),
        messages,
        output,
    })
}

/// Every exchange under `sub` (`knot` or `unbound`), recursively.
fn exchanges(sub: &str) -> Vec<Exchange> {
    fn walk(base: &Path, rel: &str, out: &mut Vec<String>) {
        let Ok(entries) = fs::read_dir(base.join(rel)) else {
            return;
        };
        let mut has_hex = false;
        for e in entries {
            let p = e.unwrap().path();
            let name = p.file_name().unwrap().to_str().unwrap().to_owned();
            if p.is_dir() {
                walk(base, &format!("{rel}/{name}"), out);
            } else if name.ends_with(".hex") {
                has_hex = true;
            }
        }
        if has_hex {
            out.push(rel.to_owned());
        }
    }
    let mut labels = Vec::new();
    walk(&dir(), sub, &mut labels);
    labels.sort();
    labels.iter().filter_map(|l| exchange(l)).collect()
}

/// Reads a master file with dnsbox, failing on any error.
fn read_zone(text: &str) -> Vec<ZoneRecordBuf> {
    ZoneReader::new(text)
        .with_default_ttl(3600)
        .records()
        .collect::<Result<_, _>>()
        .unwrap_or_else(|e| panic!("{e}"))
}

/// A record as comparable data: owner, type, class, TTL, uncompressed
/// RDATA.
type Rr = (NameBuf, Rtype, Class, u32, Vec<u8>);

fn rr(r: &ZoneRecordBuf) -> Rr {
    (r.name.clone(), r.rtype, r.class, r.ttl, r.rdata.clone())
}

fn rr_of(r: &dnsbox::Record<'_>) -> Rr {
    let o = dnsbox::OwnedRecord::from_record(r).unwrap();
    (
        o.name.clone(),
        o.rtype(),
        o.class,
        o.ttl,
        o.rdata.as_wire().to_vec(),
    )
}

fn sorted(mut v: Vec<Rr>) -> Vec<Rr> {
    v.sort();
    v
}

/// A record in presentation format.
fn show(r: &Rr) -> String {
    let data = RData::parse(r.1, r.2, dnsbox::WireReader::new(&r.4))
        .map_or_else(|e| format!("<{e}>"), |d| d.to_string());
    format!("{} {} {} {} {data}", r.0, r.3, r.2, r.1)
}

/// Asserts that two record multisets are equal, listing the differences.
#[track_caller]
fn assert_same_records(theirs: Vec<Rr>, ours: Vec<Rr>, what: &str) {
    let (mut a, mut b) = (sorted(theirs), sorted(ours));
    let mut only_a = Vec::new();
    for r in a.drain(..) {
        match b.iter().position(|x| *x == r) {
            Some(i) => {
                b.remove(i);
            }
            None => only_a.push(r),
        }
    }
    if only_a.is_empty() && b.is_empty() {
        return;
    }
    let mut msg = format!("{what}: records differ");
    for r in &only_a {
        msg += &format!("\n  - {}", show(r));
    }
    for r in &b {
        msg += &format!("\n  + {}", show(r));
    }
    panic!("{msg}");
}

fn name(s: &str) -> NameBuf {
    s.parse().unwrap()
}

// ---------------------------------------------------------------------
// The signed zones.
// ---------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Chain {
    Nsec,
    Nsec3,
    OptOut,
}

/// What `run.sh` did to a zone after signing it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// A zone of `child.zone`, as Knot signed it.
    Child,
    /// `interop.`, the parent of all of them (and the trust anchor).
    Parent,
    /// `www A` changed after signing.
    BogusRdata,
    /// Every NSEC changed after signing (an extra type in the bitmap).
    BogusNsec,
    /// Intact, but the parent's DS records have the wrong digests.
    BogusDs,
}

/// A line of `manifest.txt`.
#[derive(Clone, Debug)]
struct Spec {
    apex: NameBuf,
    algorithm: Algorithm,
    chain: Chain,
    kind: Kind,
}

fn manifest() -> Vec<Spec> {
    text("manifest.txt")
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let algorithm = match f[1] {
                "rsasha256" => Algorithm::RSASHA256,
                "rsasha512" => Algorithm::RSASHA512,
                "ecdsap256" => Algorithm::ECDSAP256SHA256,
                "ecdsap384" => Algorithm::ECDSAP384SHA384,
                "ed25519" => Algorithm::ED25519,
                "ed448" => Algorithm::ED448,
                a => panic!("algorithm {a}"),
            };
            let chain = match f[2] {
                "nsec" => Chain::Nsec,
                "nsec3" => Chain::Nsec3,
                "optout" => Chain::OptOut,
                c => panic!("chain {c}"),
            };
            let kind = match f.get(3).copied() {
                None => Kind::Child,
                Some("parent") => Kind::Parent,
                Some("bogus-rdata") => Kind::BogusRdata,
                Some("bogus-nsec") => Kind::BogusNsec,
                Some("bogus-ds") => Kind::BogusDs,
                Some(k) => panic!("kind {k}"),
            };
            Spec {
                apex: name(f[0]),
                algorithm,
                chain,
                kind,
            }
        })
        .collect()
}

/// A signed zone as dnsbox read it.
struct Zone {
    spec: Spec,
    /// The file name without `.zone` (the apex without its final dot).
    file: String,
    records: Vec<ZoneRecordBuf>,
    ds: Vec<ZoneRecordBuf>,
}

impl Zone {
    fn load(spec: &Spec) -> Zone {
        let apex = spec.apex.to_string();
        let file = apex.trim_end_matches('.').to_owned();
        Zone {
            spec: spec.clone(),
            records: read_zone(&text(&format!("zones/{file}.zone"))),
            ds: read_zone(&text(&format!("ds/{file}.ds"))),
            file,
        }
    }

    fn apex(&self) -> &NameBuf {
        &self.spec.apex
    }

    fn of_type<'s>(
        &'s self,
        owner: &'s NameBuf,
        rtype: Rtype,
    ) -> impl Iterator<Item = &'s ZoneRecordBuf> + Clone {
        self.records
            .iter()
            .filter(move |r| r.rtype == rtype && r.name == *owner)
    }

    fn dnskeys(&self) -> Vec<Dnskey<'_>> {
        self.of_type(self.apex(), Rtype::DNSKEY)
            .map(data_of)
            .collect()
    }

    fn ds(&self) -> Vec<Ds<'_>> {
        self.ds.iter().map(data_of).collect()
    }

    /// The RRSIGs over `rtype` at `owner`.
    fn rrsigs<'s>(&'s self, owner: &'s NameBuf, rtype: Rtype) -> Vec<Rrsig<'s>> {
        self.of_type(owner, Rtype::RRSIG)
            .map(data_of::<Rrsig<'_>>)
            .filter(|s| s.type_covered == rtype)
            .collect()
    }

    /// The RRsets: (owner, type) in canonical order.
    fn rrsets(&self) -> BTreeSet<(NameBuf, Rtype)> {
        self.records
            .iter()
            .filter(|r| r.rtype != Rtype::RRSIG)
            .map(|r| (r.name.clone(), r.rtype))
            .collect()
    }

    /// The delegation points (NS below the apex).
    fn cuts(&self) -> Vec<NameBuf> {
        self.records
            .iter()
            .filter(|r| r.rtype == Rtype::NS && r.name != *self.apex())
            .map(|r| r.name.clone())
            .collect()
    }

    /// Whether `name` is glue / occluded (strictly below a cut).
    fn below_cut(&self, name: &NameBuf) -> bool {
        self.cuts()
            .iter()
            .any(|c| name != c && name.as_name().is_subdomain_of(&c.as_name()))
    }

    /// Whether the RRset is left unsigned (RFC 4035 §2.2): delegation NS
    /// and everything below a cut.
    fn unsigned(&self, owner: &NameBuf, rtype: Rtype) -> bool {
        self.below_cut(owner) || (rtype == Rtype::NS && owner != self.apex())
    }

    fn trusted(&self) -> TrustedKeys<'_, Vec<Dnskey<'_>>> {
        TrustedKeys::from_ds(
            &PurecryptoVerifier,
            Rrset::new(self.apex().as_name(), Class::IN, self.dnskeys()),
            self.ds(),
            self.rrsigs(self.apex(), Rtype::DNSKEY),
            now(),
            &mut Vec::new(),
        )
        .unwrap_or_else(|e| panic!("{}: DNSKEY from DS: {e}", self.apex()))
    }

    fn rdata<'s>(&'s self, owner: &'s NameBuf, rtype: Rtype) -> Vec<RData<'s>> {
        self.of_type(owner, rtype)
            .map(|r| r.data().unwrap())
            .collect()
    }
}

fn data_of<'a, T: dnsbox::rdata::ParseRdata<'a>>(r: &'a ZoneRecordBuf) -> T {
    T::parse_rdata(&mut dnsbox::WireReader::new(&r.rdata)).unwrap()
}

fn zones() -> Vec<Zone> {
    let zones: Vec<Zone> = manifest().iter().map(Zone::load).collect();
    let children = zones.iter().filter(|z| z.spec.kind == Kind::Child).count();
    // Every algorithm with every chain in a fresh run; the kept subset
    // has every algorithm and every chain.
    assert!(children >= if live() { 18 } else { 6 }, "{children} zones");
    for alg in [
        Algorithm::RSASHA256,
        Algorithm::RSASHA512,
        Algorithm::ECDSAP256SHA256,
        Algorithm::ECDSAP384SHA384,
        Algorithm::ED25519,
        Algorithm::ED448,
    ] {
        assert!(zones.iter().any(|z| z.spec.algorithm == alg), "{alg}");
    }
    for chain in [Chain::Nsec, Chain::Nsec3, Chain::OptOut] {
        assert!(
            zones
                .iter()
                .any(|z| z.spec.chain == chain && z.spec.kind == Kind::Child),
            "{chain:?}"
        );
    }
    zones
}

#[test]
fn keys_authenticate_from_keymgr_ds() {
    for z in zones() {
        let keys = z.dnskeys();
        assert_eq!(keys.len(), 2, "{}", z.apex());
        let ksk = keys.iter().find(|k| k.is_sep()).unwrap();
        let ds = z.ds();
        // keymgr gives SHA-256 and SHA-384 digests.
        let digests: Vec<DigestType> = ds.iter().map(|d| d.digest_type).collect();
        assert_eq!(digests, [DigestType::SHA256, DigestType::SHA384]);
        for d in &ds {
            verify_ds(d, z.apex().as_name(), ksk).unwrap();
            assert_eq!((d.key_tag, d.algorithm), (ksk.key_tag(), z.spec.algorithm));
        }
        assert_eq!(z.trusted().zone(), z.apex().as_name());
        // With `cds-cdnskey-publish: always`, the CDS and CDNSKEY records
        // (RFC 7344) are those of the KSK.
        let cds: Vec<Ds<'_>> = z.of_type(z.apex(), Rtype::CDS).map(data_of).collect();
        let cdnskey: Vec<Dnskey<'_>> = z.of_type(z.apex(), Rtype::CDNSKEY).map(data_of).collect();
        assert_eq!(cds.len(), cdnskey.len(), "{}", z.apex());
        for c in &cds {
            verify_ds(c, z.apex().as_name(), ksk).unwrap();
        }
        for c in &cdnskey {
            assert_eq!(c, ksk);
        }
    }
}

/// Every RRSIG Knot made verifies (but the tampered ones), and Knot signed
/// exactly the RRsets RFC 4035 §2.2 wants signed.
#[test]
fn every_signature_verifies() {
    let mut total = 0;
    for z in zones() {
        let keys = z.trusted();
        let mut scratch = Vec::new();
        for (owner, rtype) in z.rrsets() {
            let rdata = z.rdata(&owner, rtype);
            let sigs = z.rrsigs(&owner, rtype);
            assert_eq!(
                sigs.is_empty(),
                z.unsigned(&owner, rtype),
                "{} {owner} {rtype}",
                z.apex()
            );
            if sigs.is_empty() {
                continue;
            }
            for sig in &sigs {
                assert_eq!(
                    sig.original_ttl,
                    z.of_type(&owner, rtype).next().unwrap().ttl
                );
            }
            let result = keys.verify_rrset(
                &PurecryptoVerifier,
                Rrset::new(owner.as_name(), Class::IN, &rdata),
                sigs.iter().copied(),
                now(),
                &mut scratch,
            );
            let tampered = match z.spec.kind {
                Kind::BogusRdata => rtype == Rtype::A && owner.to_string().starts_with("www."),
                Kind::BogusNsec => rtype == Rtype::NSEC,
                _ => false,
            };
            if tampered {
                assert_eq!(
                    result.unwrap_err(),
                    dnsbox::Error::BadSignature,
                    "{owner} {rtype}"
                );
            } else {
                result.unwrap_or_else(|e| panic!("{} {owner} {rtype}: {e}", z.apex()));
                total += sigs.len();
            }
        }
    }
    assert!(
        total >= if live() { 500 } else { 150 },
        "{total} signatures"
    );
}

/// The parent holds the children's DS records (keymgr's), and they
/// authenticate the children's keys, but those of `bogus-ds.`.
#[test]
fn parent_ds_records_authenticate_children() {
    let zones = zones();
    let parent = zones.iter().find(|z| z.spec.kind == Kind::Parent).unwrap();
    let mut checked = 0;
    for z in zones.iter().filter(|z| z.spec.kind != Kind::Parent) {
        let ds: Vec<Ds<'_>> = parent.of_type(z.apex(), Rtype::DS).map(data_of).collect();
        assert_eq!(ds.len(), 2, "{}", z.apex());
        let result = TrustedKeys::from_ds(
            &PurecryptoVerifier,
            Rrset::new(z.apex().as_name(), Class::IN, z.dnskeys()),
            ds.iter().copied(),
            z.rrsigs(z.apex(), Rtype::DNSKEY),
            now(),
            &mut Vec::new(),
        );
        if z.spec.kind == Kind::BogusDs {
            assert!(result.is_err(), "{}", z.apex());
        } else {
            result.unwrap_or_else(|e| panic!("{}: {e}", z.apex()));
            assert_eq!(ds, z.ds());
        }
        checked += 1;
    }
    assert!(checked >= 6);
}

/// The names of the zone that NSEC/NSEC3 chains cover, with their types:
/// authoritative owners (not below a cut) and, for NSEC3, the empty
/// non-terminals; NSEC/NSEC3 records themselves excluded.
fn chain_names(z: &Zone) -> BTreeMap<NameBuf, BTreeSet<Rtype>> {
    let mut names: BTreeMap<NameBuf, BTreeSet<Rtype>> = BTreeMap::new();
    let apex_labels = z.apex().as_name().label_count();
    for r in &z.records {
        if z.below_cut(&r.name) || matches!(r.rtype, Rtype::NSEC | Rtype::NSEC3) {
            continue;
        }
        if r.name.as_name().label_count() == apex_labels + 1
            && r.rtype == Rtype::RRSIG
            && data_of::<Rrsig<'_>>(r).type_covered == Rtype::NSEC3
        {
            continue; // The signature of an NSEC3 record.
        }
        names.entry(r.name.clone()).or_default().insert(r.rtype);
        let mut n = r.name.as_name();
        while let Some(p) = n.parent() {
            if !p.is_subdomain_of(&z.apex().as_name()) {
                break;
            }
            names.entry(p.to_buf()).or_default();
            n = p;
        }
    }
    names
}

#[test]
fn nsec_chains_follow_canonical_order() {
    let mut checked = 0;
    for z in zones().iter().filter(|z| z.spec.chain == Chain::Nsec) {
        let names = chain_names(z);
        let owners: Vec<&NameBuf> = names
            .iter()
            .filter(|(_, t)| !t.is_empty())
            .map(|(n, _)| n)
            .collect();
        let mut nsecs: Vec<&ZoneRecordBuf> = z
            .records
            .iter()
            .filter(|r| r.rtype == Rtype::NSEC)
            .collect();
        nsecs.sort_by(|a, b| a.name.cmp(&b.name));
        let nsec_owners: Vec<&NameBuf> = nsecs.iter().map(|r| &r.name).collect();
        assert_eq!(nsec_owners, owners, "{}", z.apex());
        for (i, r) in nsecs.iter().enumerate() {
            let nsec: Nsec<'_> = data_of(r);
            let next = owners[(i + 1) % owners.len()];
            assert_eq!(nsec.next_domain_name, next.as_name(), "{}", r.name);
            let mut types: BTreeSet<Rtype> = names[&r.name].clone();
            types.insert(Rtype::NSEC);
            if z.spec.kind == Kind::BogusNsec {
                types.insert(Rtype::SPF);
            }
            assert_eq!(
                nsec.types.iter().collect::<BTreeSet<_>>(),
                types,
                "{}",
                r.name
            );
        }
        checked += 1;
    }
    assert!(checked >= 2);
}

#[test]
fn nsec3_chains_match_dnsbox_hashes() {
    let mut checked = 0;
    for z in zones().iter().filter(|z| z.spec.chain != Chain::Nsec) {
        let param = z.of_type(z.apex(), Rtype::NSEC3PARAM).next().unwrap();
        let param: dnsbox::rdata::Nsec3param<'_> = data_of(param);
        // With Opt-Out, Knot leaves unsigned delegations (NS without DS)
        // out of the chain (RFC 5155 §7.1 allows it).
        let unsigned_cut = |n: &NameBuf, t: &BTreeSet<Rtype>| {
            n != z.apex() && t.contains(&Rtype::NS) && !t.contains(&Rtype::DS)
        };
        let mut expected: BTreeMap<NameBuf, BTreeSet<Rtype>> = BTreeMap::new();
        for (n, types) in chain_names(z) {
            if z.spec.chain == Chain::OptOut && unsigned_cut(&n, &types) {
                continue;
            }
            let h = nsec3_hash(
                n.as_name(),
                param.hash_algorithm,
                param.iterations,
                param.salt,
            )
            .unwrap();
            expected.insert(h.owner_name(z.apex().as_name()).unwrap(), types);
        }
        let mut nsec3s: Vec<&ZoneRecordBuf> = z
            .records
            .iter()
            .filter(|r| r.rtype == Rtype::NSEC3)
            .collect();
        nsec3s.sort_by(|a, b| a.name.cmp(&b.name));
        let owners: Vec<&NameBuf> = nsec3s.iter().map(|r| &r.name).collect();
        assert_eq!(owners, expected.keys().collect::<Vec<_>>(), "{}", z.apex());
        for (i, r) in nsec3s.iter().enumerate() {
            let n: Nsec3<'_> = data_of(r);
            assert_eq!(
                (n.hash_algorithm, n.iterations, n.salt),
                (param.hash_algorithm, param.iterations, param.salt)
            );
            assert_eq!(n.flags, u8::from(z.spec.chain == Chain::OptOut));
            let next = owners[(i + 1) % owners.len()];
            let next = dnsbox::dnssec::Nsec3Hash::from_owner(next.as_name()).unwrap();
            assert_eq!(n.next_hashed_owner, next.as_bytes(), "{}", r.name);
            assert_eq!(
                n.types.iter().collect::<BTreeSet<_>>(),
                expected[&r.name],
                "{}",
                r.name
            );
        }
        checked += 1;
    }
    assert!(checked >= 4);
}

/// kzonesign adds ZONEMD records (RFC 8976; `zonemd-generate`) to the
/// NSEC3 zones (SHA-384) and the Opt-Out ones (SHA-512): dnsbox computes
/// the same digests, and the records are signed like the others.
#[test]
fn knot_zonemd_digests() {
    let mut checked = 0;
    for z in zones().iter().filter(|z| z.spec.kind == Kind::Child) {
        let zonemds: Vec<Zonemd<'_>> = z.of_type(z.apex(), Rtype::ZONEMD).map(data_of).collect();
        let want = match z.spec.chain {
            Chain::Nsec => continue,
            Chain::Nsec3 => dnsbox::rdata::ZonemdHashAlg::SHA384,
            Chain::OptOut => dnsbox::rdata::ZonemdHashAlg::SHA512,
        };
        assert_eq!(zonemds.len(), 1, "{}", z.apex());
        assert_eq!(zonemds[0].hash_alg, want);
        let records = || {
            z.records
                .iter()
                .map(|r| ZonemdRecord::new(r.name.as_name(), r.class, r.ttl, r.data().unwrap()))
        };
        verify_zonemd(z.apex().as_name(), records())
            .unwrap_or_else(|e| panic!("{}: {e}", z.apex()));
        let ours = zonemd_digest(z.apex().as_name(), records(), want).unwrap();
        assert_eq!(ours.as_bytes(), zonemds[0].digest);
        assert_eq!(z.rrsigs(z.apex(), Rtype::ZONEMD).len(), 1);
        checked += 1;
    }
    assert!(checked >= 4);
}

// ---------------------------------------------------------------------
// Knot's private keys: PKCS #8 PEM files written by keymgr (GnuTLS).
// ---------------------------------------------------------------------

/// Decodes standard base64 (`None` if it is not).
fn base64(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let s: String = s.split_whitespace().collect();
    if s.is_empty() || !s.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes().filter(|&c| c != b'=') {
        acc = (acc << 6) | ALPHABET.iter().position(|&a| a == c)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// A DER TLV: (tag, contents, rest).
fn der(input: &[u8]) -> (u8, &[u8], &[u8]) {
    let tag = input[0];
    let (len, start) = match input[1] {
        n if n < 0x80 => (usize::from(n), 2),
        n => {
            let k = usize::from(n & 0x7f);
            let len = input[2..2 + k]
                .iter()
                .fold(0usize, |a, &b| (a << 8) | usize::from(b));
            (len, 2 + k)
        }
    };
    (tag, &input[start..start + len], &input[start + len..])
}

/// The elements of a DER SEQUENCE.
fn der_seq(contents: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    let mut rest = contents;
    while !rest.is_empty() {
        let (tag, c, r) = der(rest);
        out.push((tag, c));
        rest = r;
    }
    out
}

/// A DER INTEGER without its sign octet.
fn unsigned_int(i: &[u8]) -> &[u8] {
    match i {
        [0, rest @ ..] if !rest.is_empty() => rest,
        _ => i,
    }
}

/// A keymgr key file (PKCS #8 `PRIVATE KEY`) as a dnsbox signing key.
fn pem_key(algorithm: Algorithm, pem: &str) -> SigningKey {
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der_bytes = base64(&b64).expect("base64");
    let (_, info, _) = der(&der_bytes);
    // PrivateKeyInfo: version, AlgorithmIdentifier, OCTET STRING.
    let info = der_seq(info);
    let private = info[2].1;
    if algorithm.is_rsa() {
        // RSAPrivateKey: version, n, e, d, p, q, ...
        let (_, k, _) = der(private);
        let f = der_seq(k);
        let i = |n: usize| unsigned_int(f[n].1);
        SigningKey::from_rsa_components(algorithm, i(1), i(2), i(3), i(4), i(5)).unwrap()
    } else if matches!(algorithm, Algorithm::ED25519 | Algorithm::ED448) {
        // CurvePrivateKey: an OCTET STRING.
        let (_, k, _) = der(private);
        SigningKey::from_private_bytes(algorithm, k).unwrap()
    } else {
        // ECPrivateKey: version, privateKey OCTET STRING, ... (GnuTLS
        // writes the scalar with a leading zero octet).
        let (_, k, _) = der(private);
        let f = der_seq(k);
        let len = if algorithm == Algorithm::ECDSAP256SHA256 {
            32
        } else {
            48
        };
        let scalar = f[1].1;
        SigningKey::from_private_bytes(algorithm, &scalar[scalar.len() - len..]).unwrap()
    }
}

/// The zone's keys as keymgr stored them, by key tag.
fn knot_keys(z: &Zone) -> Vec<(u16, SigningKey)> {
    let list = text(&format!("keys/{}/list.txt", z.file));
    let mut out = Vec::new();
    for line in list.lines().filter(|l| !l.trim().is_empty()) {
        // <id> <tag> <KSK|ZSK> <algorithm> created=...
        let f: Vec<&str> = line.split_whitespace().collect();
        let pem = text(&format!("keys/{}/{}.pem", z.file, f[0]));
        let key = pem_key(z.spec.algorithm, &pem);
        let tag: u16 = f[1].parse().unwrap();
        out.push((tag, key));
    }
    out
}

/// The DNSKEYs dnsbox derives from keymgr's private keys are Knot's, and
/// with the deterministic algorithms (RSA PKCS #1 v1.5, Ed25519, Ed448)
/// dnsbox reproduces every signature of kzonesign byte for byte, which
/// pins down the signed data (RFC 4034 §3.1.8.1) of every RRset.
///
/// With `DNSBOX_INTEROP_WRITE` set, also writes every zone, displayed by
/// dnsbox and with every RRSIG replaced by one dnsbox made (new validity
/// period, same keys), to `<dir>/dnsbox/<zone>.zone`, for Knot's, ldns's
/// and BIND's zone checkers (`run.sh check-dnsbox`).
#[test]
fn dnsbox_resigns_knot_zones() {
    let write = std::env::var_os("DNSBOX_INTEROP_WRITE").is_some();
    if write {
        fs::create_dir_all(dir().join("dnsbox")).unwrap();
    }
    let mut identical = 0;
    for z in zones() {
        if matches!(z.spec.kind, Kind::BogusRdata | Kind::BogusNsec) {
            continue;
        }
        let signers = knot_keys(&z);
        assert_eq!(signers.len(), 2, "{}", z.apex());
        for (tag, signer) in &signers {
            let k = z
                .dnskeys()
                .into_iter()
                .find(|k| k.key_tag() == *tag)
                .unwrap();
            assert_eq!(signer.public_key(), k.public_key, "{} {tag}", z.apex());
        }
        let deterministic = !matches!(
            z.spec.algorithm,
            Algorithm::ECDSAP256SHA256 | Algorithm::ECDSAP384SHA384
        );
        // A month of validity from an hour before the run.
        let (inception, expiration) = (now() - 3600, now() + 30 * 86400);
        let mut out = format!(
            "; {} re-signed by dnsbox (tests/interop_knot.rs)\n",
            z.apex()
        );
        let mut scratch = Vec::new();
        // Signs an RRset as Knot did (same keys, new validity period) and
        // writes the RRSIGs; `rdata` replaces the RRset Knot signed.
        let mut resign = |out: &mut String, owner: &NameBuf, rtype: Rtype, rdata: &[RData<'_>]| {
            let knot_rdata = z.rdata(owner, rtype);
            for sig in z.rrsigs(owner, rtype) {
                let (_, signer) = signers.iter().find(|(t, _)| *t == sig.key_tag).unwrap();
                let mut buf = [0u8; 1024];
                if deterministic {
                    let knot_rrset = Rrset::new(owner.as_name(), Class::IN, &knot_rdata);
                    let len = sign_rrset(signer, &sig, knot_rrset, &mut scratch, &mut buf).unwrap();
                    assert_eq!(&buf[..len], sig.signature, "{owner} {rtype}");
                    identical += 1;
                }
                let rrset = Rrset::new(owner.as_name(), Class::IN, rdata);
                let template = Rrsig {
                    inception,
                    expiration,
                    signature: &[],
                    ..sig
                };
                let len = sign_rrset(signer, &template, rrset, &mut scratch, &mut buf).unwrap();
                let ours = template.with_signature(&buf[..len]);
                // The new signature verifies with the zone's key.
                let key = z
                    .dnskeys()
                    .into_iter()
                    .find(|k| k.key_tag() == sig.key_tag)
                    .unwrap();
                dnsbox::dnssec::verify_rrsig(
                    &PurecryptoVerifier,
                    &ZoneKey::new(z.apex().as_name(), key),
                    &ours,
                    rrset,
                    now(),
                    &mut scratch,
                )
                .unwrap();
                // The TTL of the RRset it covers (RFC 4034 §3). Knot reads
                // an RRSIG's TTL as its original TTL field anyway, and
                // computes its ZONEMD digest with that.
                let ttl = z.of_type(owner, rtype).next().unwrap().ttl;
                *out += &format!("{owner} {ttl} IN RRSIG {ours}\n");
            }
        };
        for (owner, rtype) in z.rrsets() {
            if rtype == Rtype::ZONEMD {
                continue; // below, once the rest is written
            }
            let rdata = z.rdata(&owner, rtype);
            for r in z.of_type(&owner, rtype) {
                out += &format!("{}\n", r.as_record());
            }
            resign(&mut out, &owner, rtype, &rdata);
        }
        // The zone's ZONEMD records (RFC 8976): digests of what dnsbox
        // wrote (the new RRSIGs change them), one per hash algorithm Knot
        // published, signed like the others.
        let knot_zonemd: Vec<Zonemd<'_>> =
            z.of_type(z.apex(), Rtype::ZONEMD).map(data_of).collect();
        if !knot_zonemd.is_empty() {
            let written = read_zone(&out);
            let records = || {
                written
                    .iter()
                    .map(|r| ZonemdRecord::new(r.name.as_name(), r.class, r.ttl, r.data().unwrap()))
            };
            let soa: dnsbox::rdata::Soa<'_> =
                data_of(z.of_type(z.apex(), Rtype::SOA).next().unwrap());
            let digests: Vec<_> = knot_zonemd
                .iter()
                .map(|k| zonemd_digest(z.apex().as_name(), records(), k.hash_alg).unwrap())
                .collect();
            let ours: Vec<RData<'_>> = digests
                .iter()
                .map(|d| RData::Zonemd(d.to_zonemd(soa.serial)))
                .collect();
            let ttl = z.of_type(z.apex(), Rtype::ZONEMD).next().unwrap().ttl;
            for d in &ours {
                out += &format!("{} {ttl} IN ZONEMD {d}\n", z.apex());
            }
            resign(&mut out, z.apex(), Rtype::ZONEMD, &ours);
        }
        if write {
            fs::write(dir().join(format!("dnsbox/{}.zone", z.file)), &out).unwrap();
        }
        // What dnsbox wrote reads back to the same records, signatures and
        // ZONEMD digests aside, and its ZONEMD records verify.
        let back = read_zone(&out);
        let strip = |v: &[ZoneRecordBuf]| {
            sorted(
                v.iter()
                    .filter(|r| !matches!(r.rtype, Rtype::RRSIG | Rtype::ZONEMD))
                    .map(rr)
                    .collect(),
            )
        };
        assert_eq!(strip(&back), strip(&z.records), "{}", z.apex());
        let count = |v: &[ZoneRecordBuf], t| v.iter().filter(|r| r.rtype == t).count();
        assert_eq!(
            count(&back, Rtype::ZONEMD),
            count(&z.records, Rtype::ZONEMD)
        );
        if count(&back, Rtype::ZONEMD) > 0 {
            verify_zonemd(
                z.apex().as_name(),
                back.iter().map(|r| {
                    ZonemdRecord::new(r.name.as_name(), r.class, r.ttl, r.data().unwrap())
                }),
            )
            .unwrap_or_else(|e| panic!("{}: {e}", z.apex()));
        }
    }
    assert!(identical >= if live() { 400 } else { 100 }, "{identical}");
}

// ---------------------------------------------------------------------
// Every captured message.
// ---------------------------------------------------------------------

/// Every message that went through the proxies (kdig's and unbound's
/// queries, knotd's and unbound's responses, dnsbox's probe) validates,
/// passes the shared fuzz checks (typed RDATA, canonical forms,
/// parse → build → parse) and rebuilds to the same message.
#[test]
fn every_captured_message_parses_and_rebuilds() {
    let mut count = 0;
    let mut identical = 0;
    for sub in ["knot", "unbound"] {
        for ex in exchanges(sub) {
            for m in &ex.messages {
                let msg = Message::parse_validated(&m.wire)
                    .unwrap_or_else(|e| panic!("{}: {e}", m.file.display()));
                assert_eq!(msg.flags().qr(), !m.query, "{}", m.file.display());
                let res = std::panic::catch_unwind(|| checks::message(&m.wire));
                assert!(res.is_ok(), "{}", m.file.display());
                let mut b = MessageBuilder::new_vec();
                b.set_id(msg.id());
                b.set_flags(msg.flags());
                for q in msg.questions() {
                    b.copy_question(&q.unwrap()).unwrap();
                }
                for rr in msg.records() {
                    let (s, rr) = rr.unwrap();
                    b.copy_record(s, &rr).unwrap();
                }
                let out = b.finish();
                let rebuilt = Message::parse_validated(&out).unwrap();
                checks::assert_same_message(&msg, &rebuilt);
                identical += usize::from(out == m.wire);
                count += 1;
            }
        }
    }
    println!("{identical} of {count} messages rebuilt byte for byte");
    assert!(count >= if live() { 2000 } else { 150 }, "{count} messages");
    // Knot and Unbound compress names like dnsbox does.
    assert!(identical * 10 >= count * 9, "{identical} of {count}");
}

// ---------------------------------------------------------------------
// TSIG.
// ---------------------------------------------------------------------

/// The secret of every TSIG key of the run: 00 01 .. 1f.
const SECRET: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

/// knotd's keys: `hmac-<hash>.key.` with algorithm `hmac-<hash>`.
fn tsig_keys() -> Vec<HmacKey<'static>> {
    [
        ("md5", TsigAlgorithm::HmacMd5),
        ("sha1", TsigAlgorithm::HmacSha1),
        ("sha224", TsigAlgorithm::HmacSha224),
        ("sha256", TsigAlgorithm::HmacSha256),
        ("sha384", TsigAlgorithm::HmacSha384),
        ("sha512", TsigAlgorithm::HmacSha512),
    ]
    .iter()
    .map(|(h, alg)| HmacKey::new(name(&format!("hmac-{h}.key")), *alg, &SECRET))
    .collect()
}

/// Every TSIG-signed exchange with knotd: dnsbox verifies the request
/// (kdig's, knsupdate's, the probe's) as a server would and every response
/// message (knotd's) as the client would; those signed with a wrong secret
/// or an unknown key are rejected with the error knotd gave.
#[test]
fn tsig_exchanges_verify() {
    let keys = tsig_keys();
    let mut by_alg: BTreeMap<String, usize> = BTreeMap::new();
    let mut rejected = 0;
    for ex in exchanges("knot") {
        let q = ex.query();
        let Some(rec) = tsig::find(&q).unwrap() else {
            continue;
        };
        let now = rec.data.time_signed;
        let status = tsig::verify_request(&q, &keys[..], now);
        if ex.label.contains("badsig") || ex.label.contains("badkey") {
            let rej = status.rejected().unwrap_or_else(|| panic!("{}", ex.label));
            let want = if ex.label.contains("badsig") {
                TsigRcode::BADSIG
            } else {
                TsigRcode::BADKEY
            };
            assert_eq!(rej.tsig_error(), want, "{}", ex.label);
            // knotd's answer: NOTAUTH, with the TSIG error dnsbox found
            // and an empty MAC (RFC 8945 §5.3.2). For an unknown key,
            // knotd leaves the TSIG record out altogether.
            let r = ex.response();
            assert_eq!(r.flags().rcode(), Rcode::NOTAUTH, "{}", ex.label);
            match tsig::find(&r).unwrap() {
                Some(theirs) => {
                    assert_eq!(theirs.data.error, want, "{}", ex.label);
                    assert!(theirs.data.mac.is_empty(), "{}", ex.label);
                }
                None => assert_eq!(want, TsigRcode::BADKEY, "{}", ex.label),
            }
            rejected += 1;
            continue;
        }
        let verified = status
            .verified()
            .unwrap_or_else(|| panic!("{}: request rejected", ex.label));
        let mut v = TsigVerifier::new(verified.key, verified.request_mac()).unwrap();
        let mut signed = 0;
        for r in ex.responses() {
            let msg = Message::parse_validated(&r.wire).unwrap();
            let t = tsig::find(&msg)
                .unwrap()
                .map_or(now, |t| t.data.time_signed);
            if v.verify(&msg, t)
                .unwrap_or_else(|e| panic!("{}: {e}", r.file.display()))
                .is_some()
            {
                signed += 1;
            }
        }
        v.finish().unwrap_or_else(|e| panic!("{}: {e}", ex.label));
        assert!(signed >= 1, "{}", ex.label);
        *by_alg.entry(rec.data.algorithm.to_string()).or_default() += 1;
    }
    println!("{by_alg:?}");
    assert_eq!(by_alg.len(), 6, "{by_alg:?}");
    assert!(by_alg.values().all(|&n| n >= 2), "{by_alg:?}");
    assert!(rejected >= 2, "{rejected}");
}

// ---------------------------------------------------------------------
// Zone transfers and dynamic updates.
// ---------------------------------------------------------------------

/// A transfer as [`XfrProcessor`] saw it.
#[derive(Debug, Default)]
struct Transfer {
    style: Option<XfrStyle>,
    done: bool,
    messages: u32,
    /// A full transfer's records (the leading SOA and the rest, not the
    /// trailing SOA).
    full: Vec<Rr>,
    /// An incremental transfer's changes in order: (added, record),
    /// SOAs included.
    changes: Vec<(bool, Rr)>,
}

fn transfer(ex: &Exchange, mut xfr: XfrProcessor) -> Transfer {
    let mut t = Transfer::default();
    for r in ex.responses() {
        let msg = Message::parse_validated(&r.wire).unwrap();
        let events = xfr
            .process(&msg)
            .unwrap_or_else(|e| panic!("{}: {e}", r.file.display()));
        for event in events {
            match event.unwrap_or_else(|e| panic!("{}: {e}", r.file.display())) {
                XfrEvent::Start { record, .. } | XfrEvent::Record(record) => {
                    t.full.push(rr_of(&record))
                }
                XfrEvent::DeleteStart { record, .. } | XfrEvent::Delete(record) => {
                    t.changes.push((false, rr_of(&record)))
                }
                XfrEvent::AddStart { record, .. } | XfrEvent::Add(record) => {
                    t.changes.push((true, rr_of(&record)))
                }
                _ => {}
            }
        }
    }
    t.style = xfr.style();
    t.done = xfr.is_done();
    t.messages = xfr.message_count();
    if t.style == Some(XfrStyle::Incremental) {
        // The leading SOA (the new version) is not part of the changes.
        t.full.clear();
    }
    t
}

/// The records of a zone file.
fn zone_file(file: &str) -> Vec<Rr> {
    sorted(
        read_zone(&text(&format!("zones/{file}.zone")))
            .iter()
            .map(rr)
            .collect(),
    )
}

/// knotd's AXFR of every signed zone (one message each) holds exactly the
/// records of the zone file kzonesign wrote: Knot's text and Knot's wire
/// agree, as dnsbox reads them.
#[test]
fn zone_files_match_axfr() {
    let mut checked = 0;
    for spec in manifest() {
        let file = spec.apex.to_string();
        let file = file.trim_end_matches('.');
        let ex = exchange(&format!("knot/{file}/axfr")).unwrap_or_else(|| panic!("{file}"));
        let t = transfer(&ex, XfrProcessor::axfr(&spec.apex));
        assert!(t.done && t.style == Some(XfrStyle::Full), "{file}");
        assert_same_records(t.full, zone_file(file), file);
        checked += 1;
    }
    assert!(checked >= 6);
}

/// The transfers of `bulk.interop.` span several messages, each signed
/// (with every HMAC in turn): they hold the zone file's records.
#[test]
fn multi_message_transfers() {
    let bulk = zone_file("bulk.interop");
    let mut checked = 0;
    for ex in exchanges("knot/tsig") {
        if !ex.label.contains("/axfr-") || ex.label.contains("bad") || ex.label.contains("unsigned")
        {
            continue;
        }
        let t = transfer(&ex, XfrProcessor::axfr(name("bulk.interop")));
        assert!(t.done, "{}", ex.label);
        assert!(t.messages >= 2, "{}: {} messages", ex.label, t.messages);
        assert_same_records(t.full, bulk.clone(), &ex.label);
        checked += 1;
    }
    assert!(checked >= 1);
    // Without a key, knotd refuses the transfer.
    if let Some(ex) = exchange("knot/tsig/axfr-unsigned") {
        assert_eq!(ex.response().flags().rcode(), Rcode::NOTAUTH);
    }
}

/// `dyn.interop.` (signed by knotd itself) before and after six
/// TSIG-signed UPDATEs from knsupdate: each IXFR from the old serial,
/// applied to the AXFR before, gives the AXFR after (RFC 1995); an IXFR
/// from the current serial is up to date, and over UDP knotd sends only
/// its SOA (RFC 1995 §2: retry over TCP).
#[test]
fn ixfr_turns_old_axfr_into_new() {
    let zone = name("dyn.interop");
    let before_ex = exchange("knot/dyn/axfr-before").expect("axfr-before");
    let before = transfer(&before_ex, XfrProcessor::axfr(&zone));
    let after = transfer(
        &exchange("knot/dyn/axfr-after").expect("axfr-after"),
        XfrProcessor::axfr(&zone),
    );
    assert!(before.done && after.done);
    let serial = |rrs: &[Rr]| -> u32 {
        let soa = rrs.iter().find(|r| r.1 == Rtype::SOA).unwrap();
        u32::from_be_bytes(
            soa.4[soa.4.len() - 20..soa.4.len() - 16]
                .try_into()
                .unwrap(),
        )
    };
    let old_serial = serial(&before.full);
    let mut checked = 0;
    for ex in exchanges("knot/dyn") {
        if !ex.label.contains("/ixfr-")
            || ex.label.ends_with("uptodate")
            || ex.label.ends_with("udp")
        {
            continue;
        }
        let t = transfer(&ex, XfrProcessor::ixfr(&zone, old_serial));
        assert!(t.done, "{}", ex.label);
        assert_eq!(t.style, Some(XfrStyle::Incremental), "{}", ex.label);
        // One difference sequence per UPDATE, applied in order.
        let sequences = t
            .changes
            .iter()
            .filter(|(add, r)| !add && r.1 == Rtype::SOA);
        assert_eq!(sequences.count(), 6, "{}", ex.label);
        let mut state = before.full.clone();
        for (add, r) in &t.changes {
            if *add {
                state.push(r.clone());
            } else {
                let i = state
                    .iter()
                    .position(|x| x == r)
                    .unwrap_or_else(|| panic!("{}: deleting a missing {r:?}", ex.label));
                state.remove(i);
            }
        }
        assert_same_records(state, after.full.clone(), &ex.label);
        checked += 1;
    }
    // One per HMAC (two in the kept subset).
    assert_eq!(checked, if live() { 6 } else { 2 });
    let new_serial = serial(&after.full);
    let t = transfer(
        &exchange("knot/dyn/ixfr-uptodate").unwrap(),
        XfrProcessor::ixfr(&zone, new_serial),
    );
    assert!(t.done);
    assert_eq!(t.style, Some(XfrStyle::UpToDate));
    let t = transfer(
        &exchange("knot/dyn/ixfr-udp").unwrap(),
        XfrProcessor::ixfr(&zone, old_serial),
    );
    assert!(!t.done, "a newer SOA alone over UDP: retry over TCP");
}

/// knsupdate's UPDATE requests (RFC 2136) as dnsbox reads them, and
/// knotd's answers: NOERROR, and YXDOMAIN for the failed prerequisite.
#[test]
fn knsupdate_requests() {
    use dnsbox::update::{Prerequisite, UpdateMessage, UpdateOp};
    let mut checked = 0;
    for ex in exchanges("knot/dyn") {
        if !ex.label.contains("/update-") {
            continue;
        }
        let up = UpdateMessage::new(ex.query()).unwrap();
        up.validate().unwrap();
        assert_eq!(up.zone_name(), name("dyn.interop").as_name());
        let pre: Vec<Prerequisite<'_>> = up.prerequisites().map(Result::unwrap).collect();
        let ops: Vec<UpdateOp<'_>> = up.updates().map(Result::unwrap).collect();
        let r = ex.response();
        if ex.label.ends_with("yxdomain") {
            assert!(matches!(pre[..], [Prerequisite::NameAbsent(_)]), "{pre:?}");
            assert_eq!(r.flags().rcode(), Rcode::YXDOMAIN);
        } else {
            assert!(
                matches!(
                    pre[..],
                    [
                        Prerequisite::NameAbsent(_),
                        Prerequisite::RrsetExists {
                            rtype: Rtype::A,
                            ..
                        }
                    ]
                ),
                "{pre:?}"
            );
            assert!(
                matches!(
                    ops[..],
                    [
                        UpdateOp::Add(_),
                        UpdateOp::Add(_),
                        UpdateOp::DeleteRrset {
                            rtype: Rtype::TXT,
                            ..
                        }
                    ]
                ),
                "{ops:?}"
            );
            assert_eq!(r.flags().rcode(), Rcode::NOERROR, "{}", ex.label);
            checked += 1;
        }
        assert_eq!(r.flags().opcode(), dnsbox::Opcode::UPDATE);
    }
    assert_eq!(checked, 6);
}

// ---------------------------------------------------------------------
// kdig's text.
// ---------------------------------------------------------------------

/// The records kdig printed for an exchange: its record lines (not `;`
/// comments), read by dnsbox's zone-file reader. TSIG records (a pseudo
/// section without a standard presentation format) are left out.
fn kdig_records(label: &str, output: &str) -> Vec<Rr> {
    let mut out = Vec::new();
    for line in output
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with(';') && !l.starts_with("Answer:"))
        .filter(|l| l.split_whitespace().nth(3) != Some("TSIG"))
    {
        let records = ZoneReader::new(line)
            .records()
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|e| panic!("{label}: {line:?}: {e}"));
        out.extend(records.iter().map(rr));
    }
    sorted(out)
}

/// kdig's presentation of every response (every record type of the
/// zones, DNSSEC records, CHAOS TXT, ...) reads back, with dnsbox's zone
/// reader, to the records of the wire messages.
#[test]
fn kdig_text_reads_back_to_the_wire() {
    let mut checked = 0;
    for sub in ["knot", "unbound"] {
        for ex in exchanges(sub) {
            let Some(output) = &ex.output else { continue };
            if output.trim_start().starts_with(['{', '[']) || ex.label.contains("/update-") {
                continue; // +json; knsupdate prints only the answer
            }
            let mut wire = Vec::new();
            // kdig shows only the TCP answer after a truncated UDP one.
            let retried = ex.responses().any(|r| r.tcp) && ex.responses().any(|r| !r.tcp);
            for r in ex.responses().filter(|r| r.tcp || !retried) {
                let msg = Message::parse_validated(&r.wire).unwrap();
                for rr in msg.records() {
                    let (_, rr) = rr.unwrap();
                    if !matches!(rr.rtype(), Rtype::OPT | Rtype::TSIG) {
                        wire.push(rr_of(&rr));
                    }
                }
            }
            assert_same_records(kdig_records(&ex.label, output), wire, &ex.label);
            checked += 1;
        }
    }
    assert!(checked >= if live() { 800 } else { 50 }, "{checked}");
}

// ---------------------------------------------------------------------
// knotd's answers.
// ---------------------------------------------------------------------

/// What a response must prove.
#[derive(Debug)]
enum Expect {
    /// The answer RRsets verify (and none is a wildcard expansion).
    Positive,
    /// The answer was synthesized from a wildcard; the proof that no
    /// closer match exists has this status.
    Wildcard(DenialStatus),
    /// The denial proof for (name, type) has this status.
    Proof(DenialStatus),
    /// A referral: the denial proof for an unsigned delegation, or none
    /// (signed delegation, DS in the authority section).
    Referral(Option<DenialStatus>),
}

/// The cases `run.sh` asks knotd for in every zone of `child.zone`:
/// (label, name relative to the apex, type, expectation).
fn expectations(chain: Chain) -> Vec<(&'static str, &'static str, Rtype, Expect)> {
    use Expect::*;
    // With Opt-Out, a proof that relies on a record covering a name,
    // rather than matching it, leaves the response insecure (RFC 5155
    // §9.2): an unsigned delegation may hide in the span.
    let secure = |d| {
        if chain == Chain::OptOut {
            DenialStatus::Insecure(InsecureReason::OptOut)
        } else {
            DenialStatus::Secure(d)
        }
    };
    let matched = DenialStatus::Secure;
    // A DS query at an unsigned delegation: with Opt-Out, Knot leaves the
    // delegation out of the chain, so only a covering record answers.
    let unsigned = secure(Denial::UnsignedDelegation);
    vec![
        ("dnskey", "", Rtype::DNSKEY, Positive),
        ("soa", "", Rtype::SOA, Positive),
        (
            "nxdomain",
            "nosuch",
            Rtype::A,
            Proof(secure(Denial::NameError)),
        ),
        ("nodata", "www", Rtype::MX, Proof(matched(Denial::NoData))),
        ("ent", "b.ent", Rtype::A, Proof(matched(Denial::NoData))),
        (
            "wildcard",
            "host.wild",
            Rtype::A,
            Wildcard(secure(Denial::WildcardAnswer)),
        ),
        (
            "wildcard-nodata",
            "host.wild",
            Rtype::MX,
            Proof(secure(Denial::WildcardNoData)),
        ),
        ("cname", "alias", Rtype::A, Positive),
        ("dname", "x.dname", Rtype::A, Positive),
        ("referral-secure", "host.secure", Rtype::A, Referral(None)),
        (
            "referral-insecure",
            "host.insecure",
            Rtype::A,
            Referral(Some(unsigned)),
        ),
        ("ds-unsigned", "other", Rtype::DS, Proof(unsigned)),
    ]
}

/// The RRsets of a section of `msg`, as (owner, type) in order.
fn rrsets_of(msg: &Message<'_>, section: Section) -> Vec<(NameBuf, Rtype)> {
    let mut out: Vec<(NameBuf, Rtype)> = Vec::new();
    for (s, rr) in msg.records().map(Result::unwrap) {
        if s != section || matches!(rr.rtype(), Rtype::RRSIG | Rtype::OPT) {
            continue;
        }
        let key = (rr.name().to_buf(), rr.rtype());
        if !out.contains(&key) {
            out.push(key);
        }
    }
    out
}

/// The RDATA and the RRSIGs of an RRset of a section.
fn rrset_in<'m>(
    msg: &Message<'m>,
    section: Section,
    owner: &NameBuf,
    rtype: Rtype,
) -> (Vec<RData<'m>>, Vec<Rrsig<'m>>) {
    let records: Vec<_> = msg
        .records()
        .map(Result::unwrap)
        .filter(|(s, r)| *s == section && r.name() == owner.as_name())
        .map(|(_, r)| r)
        .collect();
    let rdata = records
        .iter()
        .filter(|r| r.rtype() == rtype)
        .map(|r| r.data().unwrap())
        .collect();
    let sigs = records
        .iter()
        .filter_map(|r| r.data_as::<Rrsig<'_>>().ok())
        .filter(|s| s.type_covered == rtype)
        .collect();
    (rdata, sigs)
}

/// The NSEC and NSEC3 records of the authority section.
fn denial_records<'m>(msg: &Message<'m>) -> (Vec<NsecRecord<'m>>, Vec<Nsec3Record<'m>>) {
    let authority = || {
        msg.authority()
            .map(Result::unwrap)
            .filter(|r| matches!(r.rtype(), Rtype::NSEC | Rtype::NSEC3))
    };
    (
        authority()
            .filter_map(|r| NsecRecord::from_record(&r))
            .collect(),
        authority()
            .filter_map(|r| Nsec3Record::from_record(&r))
            .collect(),
    )
}

/// knotd's answers in every zone signed by kzonesign (positive, NXDOMAIN,
/// NODATA, empty non-terminal, wildcard, CNAME, DNAME, referrals): every
/// signed RRset verifies from the zone's DS, and the denial-of-existence
/// proofs give the expected status.
#[test]
fn knotd_answers_verify_and_prove() {
    let mut checked = 0;
    for z in zones().iter().filter(|z| z.spec.kind == Kind::Child) {
        let keys = z.trusted();
        let apex = z.apex().as_name();
        for (case, rel, qtype, expect) in expectations(z.spec.chain) {
            let label = format!("knot/{}/{case}", z.file);
            let ex = exchange(&label).unwrap_or_else(|| panic!("{label}"));
            let msg = ex.response();
            let q = msg.questions().next().unwrap().unwrap();
            let qname: NameBuf = if rel.is_empty() {
                z.apex().clone()
            } else {
                name(&format!("{rel}.{}", z.apex()))
            };
            assert_eq!((q.name().to_buf(), q.qtype()), (qname.clone(), qtype));
            let mut scratch = Vec::new();

            // Every signed RRset in the answer and authority sections
            // verifies; the unsigned ones are those RFC 4035 leaves
            // unsigned (referral NS, the CNAME a DNAME synthesizes).
            let mut wildcard = None;
            for section in [Section::Answer, Section::Authority] {
                for (owner, rtype) in rrsets_of(&msg, section) {
                    let (rdata, sigs) = rrset_in(&msg, section, &owner, rtype);
                    if sigs.is_empty() {
                        let ok = (section == Section::Authority && rtype == Rtype::NS)
                            || (case == "dname" && rtype == Rtype::CNAME);
                        assert!(ok, "{label}: unsigned {owner} {rtype}");
                        continue;
                    }
                    let v = keys
                        .verify_rrset(
                            &PurecryptoVerifier,
                            Rrset::new(owner.as_name(), Class::IN, &rdata),
                            sigs,
                            now(),
                            &mut scratch,
                        )
                        .unwrap_or_else(|e| panic!("{label}: {owner} {rtype}: {e}"));
                    if v.wildcard.is_some() {
                        wildcard = Some((owner.clone(), rtype));
                    }
                }
            }

            let (nsec, nsec3) = denial_records(&msg);
            let status = |f: &dyn Fn(&dyn DenialProof) -> DenialStatus| match z.spec.chain {
                Chain::Nsec => f(&NsecProof::new(apex, &nsec)),
                _ => f(&Nsec3Proof::new(apex, &nsec3, PurecryptoNsec3Hasher)),
            };
            let qn = qname.as_name();
            match expect {
                Expect::Positive => {
                    assert!(msg.header().ancount > 0, "{label}");
                    assert!(wildcard.is_none(), "{label}");
                }
                Expect::Wildcard(want) => {
                    let (owner, rtype) = wildcard.expect("a wildcard expansion");
                    assert_eq!((owner, rtype), (qname.clone(), qtype));
                    let (rdata, sigs) = rrset_in(&msg, Section::Answer, &qname, qtype);
                    let run = |proof: &dyn DenialProof| {
                        keys.verify_answer(
                            &PurecryptoVerifier,
                            Rrset::new(qn, Class::IN, &rdata),
                            sigs.iter().copied(),
                            proof,
                            now(),
                            &mut Vec::new(),
                        )
                        .unwrap()
                    };
                    let answer = match z.spec.chain {
                        Chain::Nsec => run(&NsecProof::new(apex, &nsec)),
                        _ => run(&Nsec3Proof::new(apex, &nsec3, PurecryptoNsec3Hasher)),
                    };
                    let dnsbox::dnssec::Answer::Wildcard { proof, .. } = answer else {
                        panic!("{label}: {answer:?}");
                    };
                    assert_eq!(proof, want, "{label}");
                }
                Expect::Proof(want) => {
                    let got = status(&|p| match case {
                        "nxdomain" => p.name_error(qn),
                        _ => p.no_data(qn, qtype),
                    });
                    assert_eq!(got, want, "{label}");
                }
                Expect::Referral(want) => {
                    let cut = name(&format!("{}.{}", rel.split('.').nth(1).unwrap(), z.apex()));
                    let has_ds =
                        rrsets_of(&msg, Section::Authority).contains(&(cut.clone(), Rtype::DS));
                    assert_eq!(has_ds, want.is_none(), "{label}");
                    if let Some(want) = want {
                        let got = status(&|p| p.unsigned_delegation(cut.as_name()));
                        assert_eq!(got, want, "{label}");
                    }
                }
            }
            checked += 1;
        }
    }
    assert!(
        checked >= if live() { 18 * 12 } else { 6 * 12 },
        "{checked}"
    );
}

/// knotd's EDNS (RFC 6891) and its options, as dnsbox decodes them in
/// kdig's queries and knotd's responses: NSID (RFC 5001), cookies (RFC
/// 7873; knotd's mod-cookies makes RFC 9018 server cookies, which dnsbox
/// recomputes from the configured secret), Client Subnet (RFC 7871),
/// EXPIRE (RFC 7314), ZONEVERSION (RFC 9660), Padding (RFC 7830, RFC
/// 8467), unknown options, BADVERS, and no EDNS at all.
#[test]
fn knotd_edns_options() {
    use dnsbox::edns::{ClientSubnet, Cookie, Expire, Nsid, Padding, ZoneVersion};

    fn edns<'m>(m: &Message<'m>) -> dnsbox::edns::Edns<'m> {
        m.edns().unwrap().expect("an OPT record")
    }
    fn get<'m, T: dnsbox::edns::ParseOption<'m>>(m: &Message<'m>) -> Option<T> {
        edns(m).get::<T>().map(Result::unwrap)
    }
    fn messages(ex: &Exchange) -> Vec<Message<'_>> {
        ex.messages
            .iter()
            .map(|m| Message::parse_validated(&m.wire).unwrap())
            .collect()
    }
    let Some(ex) = exchange("knot/edns/nsid") else {
        assert!(!live());
        return;
    };
    // NSID.
    assert_eq!(get::<Nsid<'_>>(&ex.query()), Some(Nsid::REQUEST));
    assert_eq!(
        get::<Nsid<'_>>(&ex.response()).unwrap().as_str(),
        Some("dnsbox-interop")
    );

    // Cookies: a client cookie alone gets BADCOOKIE (knotd's
    // badcookie-slip) with a server cookie, which the retry carries.
    for label in ["knot/edns/cookie", "knot/edns/badcookie", "knot/edns/all"] {
        let ex = exchange(label).unwrap();
        let m = messages(&ex);
        assert_eq!(m.len(), 4, "{label}");
        let c: Vec<Cookie<'_>> = m.iter().map(|m| get::<Cookie<'_>>(m).unwrap()).collect();
        assert_eq!(m[1].effective_rcode().unwrap(), Rcode::BADCOOKIE, "{label}");
        assert_eq!(m[3].effective_rcode().unwrap(), Rcode::NOERROR, "{label}");
        assert!(c.iter().all(|x| x.client() == c[0].client()), "{label}");
        assert_eq!(c[2].server(), c[1].server(), "{label}");
        let server = c[1].server_cookie_v1().expect("an RFC 9018 cookie");
        assert!(server.is_fresh(now()) || !live(), "{label}");
        // knotd's secret is 00 01 .. 0f; the client is the proxy.
        #[cfg(feature = "cookie-siphash")]
        {
            let secret: [u8; 16] = core::array::from_fn(|i| i as u8);
            let ip = std::net::IpAddr::from([127, 0, 0, 1]);
            assert!(server.verify(&secret, &c[0].client(), ip), "{label}");
        }
    }

    // Client Subnet: echoed with scope 0 (RFC 7871 §7.2.1).
    for (label, prefix) in [("knot/edns/subnet4", 24), ("knot/edns/subnet6", 56)] {
        let ex = exchange(label).unwrap();
        let q = get::<ClientSubnet>(&ex.query()).unwrap();
        let r = get::<ClientSubnet>(&ex.response()).unwrap();
        assert_eq!(q.source_prefix(), prefix);
        assert_eq!(r, q.with_scope_prefix(0).unwrap(), "{label}");
    }

    // EXPIRE: the SOA expire of a primary.
    let ex = exchange("knot/edns/expire").unwrap();
    assert_eq!(get::<Expire>(&ex.query()), Some(Expire::REQUEST));
    assert_eq!(get::<Expire>(&ex.response()), Some(Expire::new(1_209_600)));

    // ZONEVERSION: the serial of the zone, two labels from the root.
    let ex = exchange("knot/edns/zoneversion").unwrap();
    assert_eq!(
        get::<ZoneVersion<'_>>(&ex.query()),
        Some(ZoneVersion::Request)
    );
    let zv = get::<ZoneVersion<'_>>(&ex.response()).unwrap();
    assert_eq!(zv.serial(), Some(2_026_100_401));
    assert!(matches!(zv, ZoneVersion::Version { label_count: 2, .. }));

    // Padding: kdig pads its queries (to 128-byte blocks with
    // +alignment); knotd pads only over encrypted transports.
    for label in [
        "knot/edns/padding",
        "knot/edns/padding-tcp",
        "knot/edns/alignment",
    ] {
        let ex = exchange(label).unwrap();
        assert!(get::<Padding<'_>>(&ex.query()).is_some(), "{label}");
        assert!(get::<Padding<'_>>(&ex.response()).is_none(), "{label}");
    }
    let ex = exchange("knot/edns/alignment").unwrap();
    assert_eq!(ex.queries().next().unwrap().wire.len() % 128, 0);

    // An unknown option is ignored.
    let ex = exchange("knot/edns/unknown-option").unwrap();
    let q = edns(&ex.query());
    let raw = q
        .raw_options()
        .find(|o| o.code.get() == 65001)
        .expect("option 65001");
    assert_eq!(raw.data, [0xc0, 0xff, 0xee]);
    assert_eq!(edns(&ex.response()).raw_options().count(), 0);
    assert_eq!(ex.response().flags().rcode(), Rcode::NOERROR);

    // EDNS version 1: BADVERS, answered with version 0 (RFC 6891 §6.1.3).
    let ex = exchange("knot/edns/version1").unwrap();
    assert_eq!(edns(&ex.query()).version(), 1);
    assert_eq!(ex.response().effective_rcode().unwrap(), Rcode::BADVERS);
    assert_eq!(edns(&ex.response()).version(), 0);

    // No EDNS in the query, none in the response.
    let ex = exchange("knot/edns/none").unwrap();
    assert!(ex.query().edns().unwrap().is_none());
    assert!(ex.response().edns().unwrap().is_none());

    // CHAOS TXT: knotd's identity and version.
    for (label, want) in [
        ("knot/chaos/id.server", "knotd.dnsbox-interop"),
        ("knot/chaos/hostname.bind", "knotd.dnsbox-interop"),
    ] {
        let ex = exchange(label).unwrap();
        let r = ex.response();
        let rr = r.answers().next().unwrap().unwrap();
        assert_eq!(rr.class(), Class::CH);
        assert!(rr.to_string().ends_with(&format!("\"{want}\"")), "{rr}");
    }
}

/// A truncated UDP answer (TC, RFC 2181 §9) and kdig's retry over TCP,
/// whose DNSKEY RRset verifies.
#[test]
fn knotd_truncation() {
    let Some(ex) = exchange("knot/transport/truncated") else {
        assert!(!live());
        return;
    };
    let r = ex.response();
    assert!(r.flags().tc());
    let ex = exchange("knot/transport/fallback").unwrap();
    let rs: Vec<&Recorded> = ex.responses().collect();
    assert_eq!(rs.len(), 2);
    assert!(!rs[0].tcp && rs[1].tcp);
    let first = Message::parse_validated(&rs[0].wire).unwrap();
    assert!(first.flags().tc());
    let full = Message::parse_validated(&rs[1].wire).unwrap();
    assert!(!full.flags().tc());
    let apex = name("rsasha512-nsec3.interop");
    let (keys, sigs) = rrset_in(&full, Section::Answer, &apex, Rtype::DNSKEY);
    let keys: Vec<Dnskey<'_>> = keys
        .into_iter()
        .map(|k| match k {
            RData::Dnskey(k) => k,
            _ => unreachable!(),
        })
        .collect();
    TrustedKeys::from_anchors(
        &PurecryptoVerifier,
        Rrset::new(apex.as_name(), Class::IN, keys.clone()),
        keys.iter().copied().filter(Dnskey::is_sep),
        sigs,
        now(),
        &mut Vec::new(),
    )
    .unwrap();
}

// ---------------------------------------------------------------------
// Unbound.
// ---------------------------------------------------------------------

/// A validation verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    Secure,
    Insecure,
    Bogus,
}

impl Verdict {
    fn parse(s: &str) -> Verdict {
        match s {
            "secure" => Verdict::Secure,
            "insecure" => Verdict::Insecure,
            "bogus" => Verdict::Bogus,
            v => panic!("verdict {v}"),
        }
    }

    /// Unbound's verdict from its answer: SERVFAIL for bogus data, AD for
    /// secure data (RFC 4035 §3.2.3).
    fn of_unbound(msg: &Message<'_>) -> Verdict {
        if msg.flags().rcode() == Rcode::SERVFAIL {
            Verdict::Bogus
        } else if msg.flags().ad() {
            Verdict::Secure
        } else {
            Verdict::Insecure
        }
    }

    fn of_status(s: DenialStatus) -> Verdict {
        if s.is_secure() {
            Verdict::Secure
        } else if s.is_insecure() {
            Verdict::Insecure
        } else {
            Verdict::Bogus
        }
    }
}

/// The trust anchor: `interop.`'s DS records (keymgr's).
fn anchor() -> Vec<ZoneRecordBuf> {
    read_zone(&text("anchor.ds"))
}

/// Validates the answer to `qname`/`qtype` the way a resolver does, from
/// the trust anchor down (RFC 4035 §5): for every zone from `interop.` to
/// `zone`, the DS RRset (verified by the parent's keys) authenticates the
/// DNSKEY RRset, or a verified denial proves the delegation unsigned
/// (insecure); then the answer, or its denial proof, must verify with the
/// zone's keys. The data is what Unbound fetched (`case/<step>`, asked
/// with CD set, RFC 4035 §3.2.2).
fn dnsbox_verdict(case: &str, qname: &NameBuf, qtype: Rtype, zone: &NameBuf) -> Verdict {
    // The last response of every step of the case.
    let mut wires: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for ex in exchanges(&format!("unbound/{case}")) {
        let step = ex.label.rsplit('/').next().unwrap().to_owned();
        if let Some(r) = ex.responses().last() {
            wires.insert(step, r.wire.clone());
        }
    }
    let fetch = |step: &str| -> Message<'_> {
        let wire = wires
            .get(step)
            .unwrap_or_else(|| panic!("unbound/{case}/{step}: no response"));
        Message::parse_validated(wire).unwrap()
    };
    let anchors = anchor();
    let anchor_ds: Vec<Ds<'_>> = anchors.iter().map(data_of).collect();
    fn dnskeys<'m>(msg: &Message<'m>, owner: &NameBuf) -> (Vec<Dnskey<'m>>, Vec<Rrsig<'m>>) {
        let (rdata, sigs) = rrset_in(msg, Section::Answer, owner, Rtype::DNSKEY);
        let keys = rdata
            .into_iter()
            .map(|d| match d {
                RData::Dnskey(k) => k,
                _ => unreachable!(),
            })
            .collect();
        (keys, sigs)
    }
    let mut scratch = Vec::new();
    let root = name("interop");
    let (k, s) = dnskeys(&fetch("dnskey-interop."), &root);
    let Ok(mut keys) = TrustedKeys::from_ds(
        &PurecryptoVerifier,
        Rrset::new(root.as_name(), Class::IN, k),
        anchor_ds.iter().copied(),
        s,
        now(),
        &mut scratch,
    ) else {
        return Verdict::Bogus;
    };
    let mut cut = root.clone();
    // The zones below interop. down to `zone`, one label at a time.
    let mut below: Vec<NameBuf> = Vec::new();
    let mut n = zone.as_name();
    while n != root.as_name() {
        below.push(n.to_buf());
        n = n.parent().unwrap();
    }
    below.reverse();
    for child in &below {
        let ds_msg = fetch(&format!("ds-{child}"));
        let (ds, ds_sigs) = rrset_in(&ds_msg, Section::Answer, child, Rtype::DS);
        if ds.is_empty() {
            // No DS: the parent must prove the delegation unsigned.
            let (nsec, nsec3) = denial_records(&ds_msg);
            // The denial records must be signed by the parent.
            for (owner, rtype) in rrsets_of(&ds_msg, Section::Authority) {
                if !matches!(rtype, Rtype::NSEC | Rtype::NSEC3) {
                    continue;
                }
                let (rdata, sigs) = rrset_in(&ds_msg, Section::Authority, &owner, rtype);
                if keys
                    .verify_rrset(
                        &PurecryptoVerifier,
                        Rrset::new(owner.as_name(), Class::IN, &rdata),
                        sigs,
                        now(),
                        &mut scratch,
                    )
                    .is_err()
                {
                    return Verdict::Bogus;
                }
            }
            let status = if nsec3.is_empty() {
                NsecProof::new(cut.as_name(), &nsec).unsigned_delegation(child.as_name())
            } else {
                Nsec3Proof::new(cut.as_name(), &nsec3, PurecryptoNsec3Hasher)
                    .unsigned_delegation(child.as_name())
            };
            return match Verdict::of_status(status) {
                Verdict::Bogus => Verdict::Bogus,
                // A proven unsigned delegation, or one in an Opt-Out span.
                _ => Verdict::Insecure,
            };
        }
        let ds: Vec<Ds<'_>> = ds
            .into_iter()
            .map(|d| match d {
                RData::Ds(d) => d,
                _ => unreachable!(),
            })
            .collect();
        if keys
            .verify_rrset(
                &PurecryptoVerifier,
                Rrset::new(child.as_name(), Class::IN, &ds),
                ds_sigs,
                now(),
                &mut scratch,
            )
            .is_err()
        {
            return Verdict::Bogus;
        }
        let (k, s) = dnskeys(&fetch(&format!("dnskey-{child}")), child);
        let Ok(child_keys) = TrustedKeys::from_ds(
            &PurecryptoVerifier,
            Rrset::new(child.as_name(), Class::IN, k),
            ds.iter().copied(),
            s,
            now(),
            &mut scratch,
        ) else {
            return Verdict::Bogus;
        };
        keys = child_keys;
        cut = child.clone();
    }

    // The answer itself, from the zone's keys.
    let msg = fetch("cd");
    let verify_section = |section: Section, scratch: &mut Vec<u8>| -> Result<bool, ()> {
        // Every RRset of the section verifies; whether one is a wildcard
        // expansion.
        let mut wildcard = false;
        for (owner, rtype) in rrsets_of(&msg, section) {
            let (rdata, sigs) = rrset_in(&msg, section, &owner, rtype);
            let v = keys
                .verify_rrset(
                    &PurecryptoVerifier,
                    Rrset::new(owner.as_name(), Class::IN, &rdata),
                    sigs,
                    now(),
                    scratch,
                )
                .map_err(|_| ())?;
            wildcard |= v.wildcard.is_some();
        }
        Ok(wildcard)
    };
    let Ok(wildcard) = verify_section(Section::Answer, &mut scratch) else {
        return Verdict::Bogus;
    };
    if verify_section(Section::Authority, &mut scratch).is_err() {
        return Verdict::Bogus;
    }
    let (nsec, nsec3) = denial_records(&msg);
    let prove = |f: &dyn Fn(&dyn DenialProof) -> DenialStatus| {
        if nsec3.is_empty() {
            f(&NsecProof::new(cut.as_name(), &nsec))
        } else {
            f(&Nsec3Proof::new(
                cut.as_name(),
                &nsec3,
                PurecryptoNsec3Hasher,
            ))
        }
    };
    let qn = qname.as_name();
    if msg.flags().rcode() == Rcode::NXDOMAIN {
        return Verdict::of_status(prove(&|p| p.name_error(qn)));
    }
    let (rdata, sigs) = rrset_in(&msg, Section::Answer, qname, qtype);
    if rdata.is_empty() {
        return Verdict::of_status(prove(&|p| p.no_data(qn, qtype)));
    }
    if !wildcard {
        return Verdict::Secure;
    }
    let answer = prove(&|p| match keys.verify_answer(
        &PurecryptoVerifier,
        Rrset::new(qn, Class::IN, &rdata),
        sigs.iter().copied(),
        p,
        now(),
        &mut Vec::new(),
    ) {
        Ok(dnsbox::dnssec::Answer::Wildcard { proof, .. }) => proof,
        Ok(_) => DenialStatus::Secure(Denial::WildcardAnswer),
        Err(_) => DenialStatus::Bogus(dnsbox::dnssec::BogusReason::MissingProof),
    });
    Verdict::of_status(answer)
}

/// For every case of `unbound/cases.txt` (secure answers and denials in
/// every zone, wildcards, Opt-Out, unsigned delegations, a changed record,
/// changed NSEC records, a DS that matches no key), dnsbox, validating
/// what Unbound fetched, reaches Unbound's own verdict (AD, no AD,
/// SERVFAIL), which is also the one the case was made for.
#[test]
fn dnsbox_agrees_with_unbound() {
    let cases = text("unbound/cases.txt");
    let mut checked = BTreeMap::new();
    for line in cases.lines().filter(|l| !l.trim().is_empty()) {
        let f: Vec<&str> = line.split_whitespace().collect();
        let (case, qname, qtype, zone, expected) = (
            f[0],
            name(f[1]),
            f[2].parse::<Rtype>().unwrap(),
            name(f[3]),
            Verdict::parse(f[4]),
        );
        let answer = exchange(&format!("unbound/{case}/answer")).unwrap();
        let unbound = Verdict::of_unbound(&answer.response());
        let ours = dnsbox_verdict(case, &qname, qtype, &zone);
        assert_eq!(
            (ours, unbound),
            (expected, expected),
            "{case}: dnsbox {ours:?}, unbound {unbound:?}, expected {expected:?}"
        );
        *checked.entry(format!("{expected:?}")).or_insert(0) += 1;
    }
    println!("{checked:?}");
    assert_eq!(checked.len(), 3, "{checked:?}");
}

/// kdig's RFC 8427 JSON (`+json`) of knotd's AXFRs: for every record, the
/// presentation text (`rdata<TYPE>`) read by dnsbox gives the wire RDATA
/// (`RDATAHEX`), the wire RDATA is what dnsbox decoded from the message,
/// and dnsbox's own presentation of it reads back to the same bytes. Where
/// dnsbox's text differs from Knot's, the difference is listed in
/// [`KNOT_STYLE`].
#[test]
fn kdig_json_text_and_hex_agree() {
    let mut checked = 0;
    let mut differences: BTreeSet<(String, String, String)> = BTreeSet::new();
    for ex in exchanges("knot") {
        let Some(output) = &ex.output else { continue };
        if !output.trim_start().starts_with(['{', '[']) {
            continue;
        }
        // One JSON object per message.
        let wires: Vec<Vec<RrWire>> = ex
            .responses()
            .map(|r| {
                let msg = Message::parse_validated(&r.wire).unwrap();
                msg.records()
                    .map(Result::unwrap)
                    .filter(|(_, rr)| !matches!(rr.rtype(), Rtype::OPT | Rtype::TSIG))
                    .map(|(_, rr)| RrWire::of(&rr))
                    .collect()
            })
            .collect();
        // One object per message; an array of them for a transfer.
        let objects: Vec<serde_json::Value> = serde_json::Deserializer::from_str(output)
            .into_iter()
            .map(Result::unwrap)
            .flat_map(|v| match v {
                serde_json::Value::Array(a) => a,
                v => vec![v],
            })
            .collect();
        assert_eq!(objects.len(), wires.len(), "{}", ex.label);
        for (obj, wire) in objects.iter().zip(&wires) {
            let mut json_rrs = Vec::new();
            for section in ["answerRRs", "authorityRRs", "additionalRRs"] {
                if let Some(rrs) = obj.get(section).and_then(|v| v.as_array()) {
                    json_rrs.extend(rrs.iter().filter(|rr| rr["TYPE"] != 250));
                }
            }
            assert_eq!(json_rrs.len(), wire.len(), "{}", ex.label);
            for (j, w) in json_rrs.iter().zip(wire) {
                let rtype = Rtype::new(j["TYPE"].as_u64().unwrap() as u16);
                assert_eq!(rtype, w.rtype, "{}", ex.label);
                // (Empty RDATA has no RDATAHEX.)
                let hex = j.get("RDATAHEX").and_then(|h| h.as_str()).unwrap_or("");
                assert_eq!(hex, hex_upper(&w.rdata), "{} {rtype}", ex.label);
                let key = format!("rdata{}", j["TYPEname"].as_str().unwrap());
                let Some(text) = j.get(&key).and_then(|t| t.as_str()) else {
                    continue; // types kdig gives as hex only
                };
                // Knot's text reads to the same RDATA.
                let ours = RData::text_to_wire(rtype, w.class, text)
                    .unwrap_or_else(|e| panic!("{} {rtype} {text:?}: {e}", ex.label));
                assert_eq!(ours, w.rdata, "{} {rtype} {text}", ex.label);
                // And dnsbox's text does too.
                let shown = w.display();
                let back = RData::text_to_wire(rtype, w.class, &shown).unwrap();
                assert_eq!(back, w.rdata, "{rtype} {shown}");
                // Up to spacing and the case of hex and base32 digits.
                let norm = |t: &str| t.split_whitespace().collect::<Vec<_>>().join(" ");
                if !norm(&shown).eq_ignore_ascii_case(&norm(text)) {
                    let expected = KNOT_STYLE.iter().any(|&(t, _)| t == rtype.to_string());
                    if !expected {
                        differences.insert((rtype.to_string(), text.to_owned(), shown));
                    }
                }
                checked += 1;
            }
        }
    }
    let list: String = differences
        .iter()
        .map(|(t, k, d)| format!("\n  {t}\n    knot:   {k}\n    dnsbox: {d}"))
        .collect();
    assert!(
        differences.is_empty(),
        "{} differences:{list}",
        differences.len()
    );
    assert!(checked >= if live() { 1000 } else { 100 }, "{checked}");
}

/// Types whose presentation differs between Knot 3.5 and dnsbox (beyond
/// spacing and the case of hex and base32 digits), each side reading the
/// other's to the same RDATA: (type, how).
const KNOT_STYLE: &[(&str, &str)] = &[
    (
        "CERT",
        "Knot writes the certificate type and algorithm as numbers \
         (`1 12345 8`), dnsbox the mnemonics BIND and dnspython also \
         write (`PKIX 12345 RSASHA256`); RFC 4398 §2.2 allows both",
    ),
    (
        "LOC",
        "Knot writes whole seconds and meters without decimals \
         (`52 22 23 N ... -2m 0m`), dnsbox as BIND does \
         (`52 22 23.000 N ... -2.00m 0.00m`)",
    ),
];

/// A record's type, class and uncompressed RDATA.
struct RrWire {
    rtype: Rtype,
    class: Class,
    rdata: Vec<u8>,
}

impl RrWire {
    fn of(rr: &dnsbox::Record<'_>) -> RrWire {
        let o = dnsbox::OwnedRecord::from_record(rr).unwrap();
        RrWire {
            rtype: o.rtype(),
            class: o.class,
            rdata: o.rdata.as_wire().to_vec(),
        }
    }

    /// dnsbox's presentation of the RDATA.
    fn display(&self) -> String {
        RData::parse(self.rtype, self.class, dnsbox::WireReader::new(&self.rdata))
            .unwrap()
            .to_string()
    }
}

fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

/// knotd loaded dnsbox's presentation of every type BIND reads
/// (`tests/corpus/bind9/alltypes.dnsbox`, written by
/// `tests/interop_zones.rs`), but for the types Knot does not know, and
/// transfers exactly the records of BIND's own AXFR of the zone
/// (`tests/corpus/named-alltypes-axfr.hex`) but those: Knot reads
/// dnsbox's text of every other type to BIND's wire form.
#[test]
fn knot_reads_dnsbox_text_of_every_type() {
    let Some(ex) = exchange("knot/alltypes/axfr") else {
        assert!(!live());
        return;
    };
    let t = transfer(&ex, XfrProcessor::axfr(name("alltypes.example")));
    assert!(t.done);
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/named-alltypes-axfr.hex");
    let wire = hex_file(&path);
    let msg = Message::parse_validated(&wire).unwrap();
    let mut bind: Vec<Rr> = msg.answers().map(|r| rr_of(&r.unwrap())).collect();
    bind.pop(); // the closing SOA
    // What Knot 3.5 cannot read: types it has no mnemonic for (it would
    // read them in the RFC 3597 form), and a KEY without key data.
    let omitted = read_zone(&text("alltypes-omitted.txt"));
    let unknown: BTreeSet<String> = omitted.iter().map(|r| r.rtype.to_string()).collect();
    let expected: BTreeSet<&str> = [
        "A6", "ATMA", "AVC", "DLV", "EID", "GID", "GPOS", "HIP", "ISDN", "KEY", "MB", "MG", "MR",
        "NIMLOC", "NINFO", "NSAP", "NSAP-PTR", "NULL", "NXT", "PX", "RKEY", "SIG", "SINK", "TA",
        "TALINK", "UID", "UINFO", "UNSPEC", "WKS", "X25",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        unknown.iter().map(String::as_str).collect::<BTreeSet<_>>(),
        expected
    );
    for r in &omitted {
        let i = bind
            .iter()
            .position(|b| *b == rr(r))
            .expect("omitted record");
        bind.remove(i);
    }
    assert!(bind.len() >= 100, "{}", bind.len());
    // Knot keeps no TTL of its own for an RRSIG: it serves the RRSIG's
    // original TTL field (RFC 4034 §3 wants the covered RRset's TTL; here
    // the RRSIG covers nothing in the zone).
    for r in bind.iter_mut().filter(|r| r.1 == Rtype::RRSIG) {
        r.3 = u32::from_be_bytes(r.4[4..8].try_into().unwrap());
    }
    assert_same_records(t.full, bind, "knotd (-) and BIND (+)");
}
