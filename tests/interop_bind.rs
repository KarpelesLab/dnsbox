//! Interoperability with BIND 9 (9.18, Ubuntu's), whose tools ran on a
//! GitHub Actions runner (`.github/workflows/interop.yml`, driven by
//! `tests/corpus/bind/run.sh`; see `tests/corpus/README.md`).
//!
//! The tests read the output directory of such a run: the one named by
//! `DNSBOX_INTEROP_DIR` (the workflow points it at its fresh captures), or
//! else the subset of a run kept in `tests/corpus/bind/`.
//!
//! - Zones signed by `dnssec-signzone` with keys from `dnssec-keygen`, for
//!   every algorithm BIND still supports (RSASHA1, NSEC3RSASHA1, RSASHA256,
//!   RSASHA512, ECDSAP256SHA256, ECDSAP384SHA384, ED25519, ED448), each
//!   with NSEC, NSEC3 and NSEC3 Opt-Out (RSASHA1: NSEC only): dnsbox reads
//!   BIND's presentation format, authenticates the keys from
//!   `dnssec-dsfromkey`'s DS records, verifies every RRSIG, finds the
//!   NSEC/NSEC3 chains it predicts, re-signs every RRset with BIND's
//!   private keys (to BIND's exact bytes with the deterministic
//!   algorithms) and, with `DNSBOX_INTEROP_WRITE` set, writes the zones
//!   re-signed by dnsbox into `<dir>/dnsbox/`, for `named-checkzone`,
//!   `named-compilezone` and `dnssec-verify` to check.
//! - `named-compilezone`'s output of the zones in its two text styles
//!   (`-s full`, `-s relative`) reads back to the same records, and
//!   `named-compilezone`'s output of the zones dnsbox wrote reads back to
//!   dnsbox's records.
//! - `named` serving them, queried by `dig` and `nsupdate` (and by
//!   dnsbox's `bind_probe` example) through a recording proxy: every
//!   message parses and rebuilds, the zone file text and the AXFR wire
//!   hold the same records, dig's text of each response reads back to its
//!   wire records, the positive and denial-of-existence answers verify
//!   and prove what they should, every TSIG MAC (six HMACs; requests,
//!   responses, multi-message transfers, UPDATE) and every SIG(0) of
//!   `nsupdate -k` verifies, and the IXFR after the dynamic updates turns
//!   the AXFR before them into the AXFR after them. `named` serves
//!   dnsbox's presentation of every type it knows (AMTRELAY, DSYNC and DOA
//!   included) as BIND's own wire form.
//! - `named` as a validating resolver with `interop.`'s trust anchor: for
//!   every case (secure answers, NSEC/NSEC3 denials, wildcards, Opt-Out
//!   and unsigned delegations, and three tampered zones), dnsbox
//!   validates the chain the resolver fetched (with CD set) and reaches
//!   its verdict: AD for secure, neither AD nor SERVFAIL for insecure,
//!   SERVFAIL for bogus.

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
    SigningKey, TrustedKeys, ValidationBudget, ZoneKey, nsec3_hash, sign_rrset, verify_ds,
};
use dnsbox::rdata::{Dnskey, Ds, Nsec, Nsec3, RData, Rrsig};
use dnsbox::tsig::{self, HmacKey, TsigAlgorithm, TsigRcode, TsigVerifier};
use dnsbox::xfr::{XfrEvent, XfrProcessor, XfrStyle};
use dnsbox::zone::{ZoneReader, ZoneRecordBuf};
use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rcode, Rtype, Section};

// ---------------------------------------------------------------------
// The run's output directory.
// ---------------------------------------------------------------------

/// The directory the tests read: `DNSBOX_INTEROP_DIR`, or the subset in
/// `tests/corpus/bind/`.
fn dir() -> PathBuf {
    match std::env::var_os("DNSBOX_INTEROP_DIR") {
        Some(d) => PathBuf::from(d),
        None => Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/bind"),
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
/// responses in order, and the client's text output (dig, nsupdate).
struct Exchange {
    label: String,
    messages: Vec<Recorded>,
    output: Option<String>,
    /// `dig.txt` or `nsupdate.txt`.
    tool: &'static str,
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

    /// The last response (the only one, but for transfers and retries).
    fn response(&self) -> Message<'_> {
        let r = self
            .responses()
            .last()
            .unwrap_or_else(|| panic!("{}: no response", self.label));
        Message::parse_validated(&r.wire).unwrap()
    }

    /// Every message, parsed.
    fn messages(&self) -> Vec<Message<'_>> {
        self.messages
            .iter()
            .map(|m| Message::parse_validated(&m.wire).unwrap())
            .collect()
    }
}

/// The exchange recorded under `label` (e.g. `named/edns/nsid`), if the
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
    let (tool, output) = ["dig.txt", "nsupdate.txt"]
        .iter()
        .find_map(|f| Some((*f, fs::read_to_string(path.join(f)).ok()?)))
        .map_or(("", None), |(t, o)| (t, Some(o)));
    Some(Exchange {
        label: label.to_owned(),
        messages,
        output,
        tool,
    })
}

/// Every exchange under `sub` (`named` or `resolver`), recursively.
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

/// The records of a zone as BIND loads them: every record of an RRset
/// takes the TTL of the first one (RFC 2181 §5.2; dnsbox's streaming
/// reader keeps each record's own; RRSIGs form one set per type covered),
/// and duplicates are dropped.
fn as_loaded(records: &[Rr]) -> Vec<Rr> {
    let mut first: BTreeMap<(NameBuf, Rtype, Class, u16), u32> = BTreeMap::new();
    let mut out: BTreeSet<Rr> = BTreeSet::new();
    for r in records {
        let covered = match r.1 {
            Rtype::RRSIG | Rtype::SIG if r.4.len() >= 2 => u16::from_be_bytes([r.4[0], r.4[1]]),
            _ => 0,
        };
        let ttl = *first.entry((r.0.clone(), r.1, r.2, covered)).or_insert(r.3);
        out.insert((r.0.clone(), r.1, r.2, ttl, r.4.clone()));
    }
    out.into_iter().collect()
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
    /// A zone of `../knot/child.zone`, as BIND signed it.
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

/// `run.sh`'s names of the algorithms dnssec-keygen supports.
const ALGORITHMS: &[(&str, Algorithm)] = &[
    ("rsasha1", Algorithm::RSASHA1),
    ("nsec3rsasha1", Algorithm::RSASHA1_NSEC3_SHA1),
    ("rsasha256", Algorithm::RSASHA256),
    ("rsasha512", Algorithm::RSASHA512),
    ("ecdsap256", Algorithm::ECDSAP256SHA256),
    ("ecdsap384", Algorithm::ECDSAP384SHA384),
    ("ed25519", Algorithm::ED25519),
    ("ed448", Algorithm::ED448),
];

fn manifest() -> Vec<Spec> {
    text("manifest.txt")
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let algorithm = ALGORITHMS
                .iter()
                .find(|(n, _)| *n == f[1])
                .unwrap_or_else(|| panic!("algorithm {}", f[1]))
                .1;
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

    /// The zone's keys from dnssec-keygen's `K*.private` files (private
    /// key format v1.3: base64 fields), by key tag.
    fn signing_keys(&self) -> Vec<(u16, SigningKey)> {
        let keys = dir().join(format!("keys/{}", self.file));
        let mut files: Vec<PathBuf> = fs::read_dir(&keys)
            .unwrap_or_else(|e| panic!("{}: {e}", keys.display()))
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "private"))
            .collect();
        files.sort();
        files
            .iter()
            .map(|path| {
                // K<zone>.+<alg>+<tag>.private
                let stem = path.file_stem().unwrap().to_str().unwrap();
                let tag: u16 = stem.rsplit('+').next().unwrap().parse().unwrap();
                (
                    tag,
                    private_key(self.spec.algorithm, &fs::read_to_string(path).unwrap()),
                )
            })
            .collect()
    }
}

/// A BIND private key file (`Private-key-format: v1.3`) as a dnsbox
/// signing key.
fn private_key(algorithm: Algorithm, text: &str) -> SigningKey {
    let fields: BTreeMap<&str, Vec<u8>> = text
        .lines()
        .filter_map(|l| l.split_once(": "))
        .filter_map(|(k, v)| Some((k, base64(v)?)))
        .collect();
    let f = |k: &str| fields.get(k).map_or(&[][..], Vec::as_slice);
    if algorithm.is_rsa() {
        SigningKey::from_rsa_components(
            algorithm,
            f("Modulus"),
            f("PublicExponent"),
            f("PrivateExponent"),
            f("Prime1"),
            f("Prime2"),
        )
    } else {
        SigningKey::from_private_bytes(algorithm, f("PrivateKey"))
    }
    .unwrap()
}

fn data_of<'a, T: dnsbox::rdata::ParseRdata<'a>>(r: &'a ZoneRecordBuf) -> T {
    T::parse_rdata(&mut dnsbox::WireReader::new(&r.rdata)).unwrap()
}

fn zones() -> Vec<Zone> {
    let zones: Vec<Zone> = manifest().iter().map(Zone::load).collect();
    let children = zones.iter().filter(|z| z.spec.kind == Kind::Child).count();
    // Every algorithm with every chain it allows in a fresh run (RSASHA1:
    // NSEC only); the kept subset has every algorithm and every chain.
    assert!(children >= if live() { 22 } else { 8 }, "{children} zones");
    for (_, alg) in ALGORITHMS {
        assert!(zones.iter().any(|z| z.spec.algorithm == *alg), "{alg}");
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

/// dnssec-keygen supports exactly the algorithms dnsbox signs and
/// verifies (RFC 8624 §3.1 "MUST" and "MAY" ones), and none of the
/// algorithms RFC 8624 forbids or dnsbox does not implement (RSAMD5, DSA,
/// DSA-NSEC3-SHA1, ECC-GOST): `run.sh` tried them all.
#[test]
fn bind_supports_the_algorithms_dnsbox_does() {
    let mut ok = BTreeSet::new();
    let mut unsupported = BTreeSet::new();
    for line in text("algorithms.txt").lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        let number: u8 = f[1].parse().unwrap();
        if f[2] == "ok" {
            ok.insert(number);
        } else {
            unsupported.insert(number);
        }
    }
    let ours: BTreeSet<u8> = ALGORITHMS.iter().map(|(_, a)| a.get()).collect();
    assert_eq!(ok, ours);
    assert_eq!(unsupported, [1, 3, 6, 12].into());
}

#[test]
fn keys_authenticate_from_dsfromkey() {
    for z in zones() {
        let keys = z.dnskeys();
        assert_eq!(keys.len(), 2, "{}", z.apex());
        let ksk = keys.iter().find(|k| k.is_sep()).unwrap();
        // dnssec-dsfromkey -1, -2 and -a SHA-384.
        let ds = z.ds();
        let digests: Vec<DigestType> = ds.iter().map(|d| d.digest_type).collect();
        assert_eq!(
            digests,
            [DigestType::SHA1, DigestType::SHA256, DigestType::SHA384]
        );
        for d in &ds {
            verify_ds(d, z.apex().as_name(), ksk).unwrap();
            assert_eq!((d.key_tag, d.algorithm), (ksk.key_tag(), z.spec.algorithm));
        }
        assert_eq!(z.trusted().zone(), z.apex().as_name());
        // The NSEC3 zones' KSKs have a "sync" time (dnssec-keygen -P sync
        // now): dnssec-signzone -S publishes their CDS (SHA-256) and
        // CDNSKEY records (RFC 7344).
        let cds: Vec<Ds<'_>> = z.of_type(z.apex(), Rtype::CDS).map(data_of).collect();
        let cdnskey: Vec<Dnskey<'_>> = z.of_type(z.apex(), Rtype::CDNSKEY).map(data_of).collect();
        let synced = z.spec.chain == Chain::Nsec3 && z.spec.kind == Kind::Child;
        assert_eq!(!cds.is_empty(), synced, "{}", z.apex());
        assert_eq!(cdnskey.len(), usize::from(synced), "{}", z.apex());
        for c in &cds {
            verify_ds(c, z.apex().as_name(), ksk).unwrap();
        }
        for c in &cdnskey {
            assert_eq!(c, ksk);
        }
    }
}

/// Every RRSIG BIND made verifies (but the tampered ones), and BIND
/// signed exactly the RRsets RFC 4035 §2.2 wants signed.
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
        total >= if live() { 800 } else { 250 },
        "{total} signatures"
    );
}

/// The parent holds the children's DS records (SHA-256 and SHA-384), and
/// they authenticate the children's keys, but those of `bogus-ds.`.
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
            assert_eq!(ds, z.ds()[1..]);
        }
        checked += 1;
    }
    assert!(checked >= 8);
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
    assert!(checked >= 3);
}

#[test]
fn nsec3_chains_match_dnsbox_hashes() {
    let mut checked = 0;
    for z in zones().iter().filter(|z| z.spec.chain != Chain::Nsec) {
        let param = z.of_type(z.apex(), Rtype::NSEC3PARAM).next().unwrap();
        let param: dnsbox::rdata::Nsec3param<'_> = data_of(param);
        // dnssec-signzone -A leaves unsigned delegations (NS without DS)
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
        // run.sh: a salt and 5 iterations for NSEC3, neither for Opt-Out.
        let (iterations, salt) = match z.spec.chain {
            Chain::Nsec3 => (5, &[0xaa, 0xbb, 0xcc, 0xdd][..]),
            _ => (0, &[][..]),
        };
        assert_eq!((param.iterations, param.salt), (iterations, salt));
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

/// The DNSKEYs dnsbox derives from dnssec-keygen's private keys are
/// BIND's, and with the deterministic algorithms (RSA PKCS #1 v1.5,
/// Ed25519, Ed448) dnsbox reproduces every signature of dnssec-signzone
/// byte for byte, which pins down the signed data (RFC 4034 §3.1.8.1) of
/// every RRset.
///
/// With `DNSBOX_INTEROP_WRITE` set, also writes every zone, displayed by
/// dnsbox and with every RRSIG replaced by one dnsbox made (new validity
/// period, same keys), to `<dir>/dnsbox/<zone>.zone`, for
/// `named-checkzone`, `named-compilezone` and `dnssec-verify` (`run.sh
/// check-dnsbox`; [`bind_reads_dnsbox_zones`]).
#[test]
fn dnsbox_resigns_bind_zones() {
    let write = std::env::var_os("DNSBOX_INTEROP_WRITE").is_some();
    if write {
        fs::create_dir_all(dir().join("dnsbox")).unwrap();
    }
    let mut identical = 0;
    for z in zones() {
        if matches!(z.spec.kind, Kind::BogusRdata | Kind::BogusNsec) {
            continue;
        }
        let signers = z.signing_keys();
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
            "; {} re-signed by dnsbox (tests/interop_bind.rs)\n",
            z.apex()
        );
        let mut scratch = Vec::new();
        for (owner, rtype) in z.rrsets() {
            let rdata = z.rdata(&owner, rtype);
            for r in z.of_type(&owner, rtype) {
                out += &format!("{}\n", r.as_record());
            }
            for sig in z.rrsigs(&owner, rtype) {
                let (_, signer) = signers.iter().find(|(t, _)| *t == sig.key_tag).unwrap();
                let rrset = Rrset::new(owner.as_name(), Class::IN, &rdata);
                let mut buf = [0u8; 1024];
                if deterministic {
                    let len = sign_rrset(signer, &sig, rrset, &mut scratch, &mut buf).unwrap();
                    assert_eq!(&buf[..len], sig.signature, "{owner} {rtype}");
                    identical += 1;
                }
                let template = Rrsig {
                    inception,
                    expiration,
                    signature: &[],
                    ..sig
                };
                let len = sign_rrset(signer, &template, rrset, &mut scratch, &mut buf).unwrap();
                let ours = template.with_signature(&buf[..len]);
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
                let ttl = z.of_type(&owner, rtype).next().unwrap().ttl;
                out += &format!("{owner} {ttl} IN RRSIG {ours}\n");
            }
        }
        if write {
            fs::write(dir().join(format!("dnsbox/{}.zone", z.file)), &out).unwrap();
        }
        // What dnsbox wrote reads back to the same records, signatures
        // aside.
        let back = read_zone(&out);
        let strip = |v: &[ZoneRecordBuf]| {
            sorted(
                v.iter()
                    .filter(|r| r.rtype != Rtype::RRSIG)
                    .map(rr)
                    .collect(),
            )
        };
        assert_eq!(strip(&back), strip(&z.records), "{}", z.apex());
    }
    assert!(identical >= if live() { 500 } else { 150 }, "{identical}");
}

// ---------------------------------------------------------------------
// Every captured message.
// ---------------------------------------------------------------------

/// Every message that went through the proxies (dig's, nsupdate's, the
/// resolver's and the probe's queries, both named's responses) validates,
/// passes the shared fuzz checks (typed RDATA, canonical forms, parse →
/// build → parse) and rebuilds to the same message, of about the same
/// size (BIND's and dnsbox's compression differ in details).
#[test]
fn every_captured_message_parses_and_rebuilds() {
    let mut count = 0;
    let mut identical = 0;
    let mut differ: BTreeMap<String, usize> = BTreeMap::new();
    let mut smaller = 0;
    let mut larger = 0;
    for sub in ["named", "resolver"] {
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
                // dnsbox's compression table holds 128 labels (BIND's grows
                // with the message), and dnsbox never points into names
                // it may not compress (RRSIG signers, NSEC next names,
                // DNAME targets), where BIND does: within 5%, but where a
                // DNAME target serves a whole other name.
                let dname = msg
                    .records()
                    .any(|r| r.is_ok_and(|(_, r)| r.rtype() == Rtype::DNAME));
                if out.len() * 20 > m.wire.len() * 21 && !dname {
                    *differ.entry(ex.label.clone()).or_default() += 1;
                }
                larger += usize::from(out.len() > m.wire.len());
                smaller += usize::from(out.len() < m.wire.len());
                count += 1;
            }
        }
    }
    println!(
        "{identical} of {count} messages rebuilt byte for byte, {smaller} smaller, {larger} larger"
    );
    assert!(count >= if live() { 2000 } else { 200 }, "{count} messages");
    assert!(differ.is_empty(), "rebuilt over 5% larger: {differ:?}");
    assert!(identical * 2 >= count, "{identical} of {count}");
}

// ---------------------------------------------------------------------
// TSIG and SIG(0).
// ---------------------------------------------------------------------

/// The secret of every TSIG key of the run: 00 01 .. 1f.
const SECRET: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

/// named's keys: `hmac-<hash>.key.` with algorithm `hmac-<hash>`.
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

/// Every TSIG-signed exchange with named: dnsbox verifies the request
/// (dig's, nsupdate's, the probe's) as a server would and every response
/// message (named's) as the client would; those signed with a wrong
/// secret or an unknown key are rejected with the error named gave, and
/// named's NOTAUTH answer carries that error with an empty MAC (RFC 8945
/// §5.3.2).
#[test]
fn tsig_exchanges_verify() {
    let keys = tsig_keys();
    let mut by_alg: BTreeMap<String, usize> = BTreeMap::new();
    let mut rejected = 0;
    for ex in exchanges("named") {
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
            let r = ex.response();
            assert_eq!(r.flags().rcode(), Rcode::NOTAUTH, "{}", ex.label);
            let theirs = tsig::find(&r).unwrap().expect("a TSIG record");
            assert_eq!(theirs.data.error, want, "{}", ex.label);
            assert!(theirs.data.mac.is_empty(), "{}", ex.label);
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
    let least = if live() { 3 } else { 2 };
    assert!(by_alg.values().all(|&n| n >= least), "{by_alg:?}");
    assert!(rejected >= 4, "{rejected}");
}

/// The SIG(0) keys of `dyn.interop.` (`dnssec-keygen -T KEY`), from
/// `sig0/K*.key`.
fn sig0_keys() -> Vec<ZoneRecordBuf> {
    let mut out = Vec::new();
    for e in fs::read_dir(dir().join("sig0")).unwrap() {
        let path = e.unwrap().path();
        if path.extension().is_some_and(|e| e == "key") {
            out.extend(read_zone(&fs::read_to_string(&path).unwrap()));
        }
    }
    assert!(out.iter().all(|r| r.rtype == Rtype::KEY));
    out
}

/// `nsupdate -k` signs its UPDATEs with SIG(0) (RFC 2931) with each of
/// the zone's KEYs (Ed25519, ECDSA P-256, RSA/SHA-256), and the probe
/// with the Ed25519 one: dnsbox verifies every signature with the KEY
/// record, and reproduces the deterministic ones (Ed25519, RSA) byte for
/// byte from the private key. named 9.18 (since 9.18.28, CVE-2024-1975)
/// no longer verifies SIG(0): it treats the updates as unsigned and its
/// update policy refuses them, unsigned.
#[test]
fn sig0_updates_verify() {
    use dnsbox::sig0::{self, DnssecSig0Verifier, SignedData};
    let keys = sig0_keys();
    let mut checked = BTreeSet::new();
    let mut labels: Vec<String> = ["ed25519", "ecdsap256", "rsasha256"]
        .iter()
        .map(|s| format!("named/dyn/sig0-{s}"))
        .collect();
    labels.push("named/probe/sig0/update".to_owned());
    for label in &labels {
        let Some(ex) = exchange(label) else {
            assert!(!live(), "{label}");
            continue;
        };
        let q = ex.query();
        assert_eq!(q.flags().opcode(), dnsbox::Opcode::UPDATE);
        let rec = sig0::find(&q).unwrap().expect("a SIG(0)");
        let key = keys
            .iter()
            .find(|k| k.name.as_name() == rec.data.signer_name)
            .unwrap_or_else(|| panic!("{label}: no KEY {}", rec.data.signer_name));
        let key_rdata: dnsbox::rdata::Key<'_> = data_of(key);
        assert_eq!(key_rdata.key_tag(), rec.data.key_tag, "{label}");
        let verifier = DnssecSig0Verifier::new(PurecryptoVerifier, key.name.as_name(), key_rdata);
        let mid = rec
            .data
            .inception
            .wrapping_add(rec.data.expiration.wrapping_sub(rec.data.inception) / 2);
        sig0::verify(&q, &verifier, mid, None).unwrap_or_else(|e| panic!("{label}: {e}"));
        // The private key, from dnssec-keygen's file.
        let stem = format!(
            "K{}+{:03}+{:05}",
            key.name,
            key_rdata.algorithm.get(),
            key_rdata.key_tag()
        );
        let signer = private_key(key_rdata.algorithm, &text(&format!("sig0/{stem}.private")));
        assert_eq!(signer.public_key(), key_rdata.public_key, "{label}");
        if key_rdata.algorithm != Algorithm::ECDSAP256SHA256 {
            let data = SignedData::new(&rec.data, q.as_bytes(), Some(rec.start), None).unwrap();
            let mut buf = [0u8; 512];
            let len = signer.sign(&data.parts().concat(), &mut buf).unwrap();
            assert_eq!(&buf[..len], rec.data.signature, "{label}");
        }
        // named refuses the update, as unsigned.
        let r = ex.response();
        assert_eq!(r.flags().opcode(), dnsbox::Opcode::UPDATE, "{label}");
        assert_eq!(r.flags().rcode(), Rcode::REFUSED, "{label}");
        assert!(sig0::find(&r).unwrap().is_none(), "{label}");
        checked.insert(key_rdata.algorithm);
    }
    assert_eq!(checked.len(), if live() { 3 } else { 1 }, "{checked:?}");
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

/// The records of a zone file, as named loads them.
fn zone_file(file: &str) -> Vec<Rr> {
    let records: Vec<Rr> = read_zone(&text(&format!("zones/{file}.zone")))
        .iter()
        .map(rr)
        .collect();
    as_loaded(&records)
}

/// named's AXFR of every signed zone holds exactly the records of the
/// zone file dnssec-signzone wrote: BIND's text and BIND's wire agree, as
/// dnsbox reads them.
#[test]
fn zone_files_match_axfr() {
    let mut checked = 0;
    for spec in manifest() {
        let file = spec.apex.to_string();
        let file = file.trim_end_matches('.');
        let ex = exchange(&format!("named/{file}/axfr")).unwrap_or_else(|| panic!("{file}"));
        let t = transfer(&ex, XfrProcessor::axfr(&spec.apex));
        assert!(t.done && t.style == Some(XfrStyle::Full), "{file}");
        assert_same_records(t.full, zone_file(file), file);
        checked += 1;
    }
    assert!(checked >= if live() { 26 } else { 12 }, "{checked}");
}

/// The transfers of `bulk.interop.` span several messages, each signed
/// (with every HMAC in turn): they hold the zone file's records. Without
/// a key, named refuses the transfer.
#[test]
fn multi_message_transfers() {
    let bulk = zone_file("bulk.interop");
    let mut checked = 0;
    for ex in exchanges("named/tsig") {
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
    assert!(checked >= if live() { 6 } else { 1 }, "{checked}");
    if let Some(ex) = exchange("named/tsig/axfr-unsigned") {
        assert_eq!(ex.response().flags().rcode(), Rcode::REFUSED);
    }
}

/// The SOA serial in a full transfer.
fn serial_of(rrs: &[Rr]) -> u32 {
    let soa = rrs.iter().find(|r| r.1 == Rtype::SOA).unwrap();
    u32::from_be_bytes(
        soa.4[soa.4.len() - 20..soa.4.len() - 16]
            .try_into()
            .unwrap(),
    )
}

/// `dyn.interop.` before and after the TSIG-signed UPDATEs of nsupdate
/// (six over UDP, one over TCP; the YXDOMAIN, unsigned and SIG(0) ones
/// were not applied): each IXFR from the old serial (RFC 1995), applied
/// to the AXFR before, gives the AXFR after; an IXFR from the current
/// serial is up to date, and over UDP named sends only its SOA (retry
/// over TCP).
#[test]
fn ixfr_turns_old_axfr_into_new() {
    let zone = name("dyn.interop");
    let before_ex = exchange("named/dyn/axfr-before").expect("axfr-before");
    let before = transfer(&before_ex, XfrProcessor::axfr(&zone));
    let after = transfer(
        &exchange("named/dyn/axfr-after").expect("axfr-after"),
        XfrProcessor::axfr(&zone),
    );
    assert!(before.done && after.done);
    // The records the refused updates would have added are absent.
    for (n, _, _, _, _) in &after.full {
        let n = n.to_string();
        assert!(!n.starts_with("sig0-") || !n.contains("-added."), "{n}");
        assert!(!n.starts_with("unsigned."), "{n}");
    }
    let old_serial = serial_of(&before.full);
    let mut checked = 0;
    for ex in exchanges("named/dyn") {
        if !ex.label.contains("/ixfr-")
            || ex.label.ends_with("uptodate")
            || ex.label.ends_with("udp")
        {
            continue;
        }
        let t = transfer(&ex, XfrProcessor::ixfr(&zone, old_serial));
        assert!(t.done, "{}", ex.label);
        assert_eq!(t.style, Some(XfrStyle::Incremental), "{}", ex.label);
        // One difference sequence per UPDATE applied, in order.
        let sequences = t
            .changes
            .iter()
            .filter(|(add, r)| !add && r.1 == Rtype::SOA);
        assert_eq!(sequences.count(), 7, "{}", ex.label);
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
    let new_serial = serial_of(&after.full);
    let t = transfer(
        &exchange("named/dyn/ixfr-uptodate").unwrap(),
        XfrProcessor::ixfr(&zone, new_serial),
    );
    assert!(t.done);
    assert_eq!(t.style, Some(XfrStyle::UpToDate));
    let t = transfer(
        &exchange("named/dyn/ixfr-udp").unwrap(),
        XfrProcessor::ixfr(&zone, old_serial),
    );
    assert!(!t.done, "a newer SOA alone over UDP: retry over TCP");
}

/// nsupdate's UPDATE requests (RFC 2136) as dnsbox reads them, and named's
/// answers: NOERROR, YXDOMAIN for the failed prerequisite, REFUSED for
/// the unsigned update.
#[test]
fn nsupdate_requests() {
    use dnsbox::update::{Prerequisite, UpdateMessage, UpdateOp};
    let mut checked = 0;
    for ex in exchanges("named/dyn") {
        if ex.tool != "nsupdate.txt" {
            continue;
        }
        let up = UpdateMessage::new(ex.query()).unwrap();
        up.validate().unwrap();
        assert_eq!(up.zone_name(), name("dyn.interop").as_name());
        let pre: Vec<Prerequisite<'_>> = up.prerequisites().map(Result::unwrap).collect();
        let ops: Vec<UpdateOp<'_>> = up.updates().map(Result::unwrap).collect();
        let r = ex.response();
        assert_eq!(r.flags().opcode(), dnsbox::Opcode::UPDATE);
        let label = ex.label.rsplit('/').next().unwrap();
        match label {
            "update-yxdomain" => {
                assert!(matches!(pre[..], [Prerequisite::NameAbsent(_)]), "{pre:?}");
                assert_eq!(r.flags().rcode(), Rcode::YXDOMAIN);
            }
            "update-unsigned" => {
                assert!(matches!(ops[..], [UpdateOp::Add(_)]), "{ops:?}");
                assert_eq!(r.flags().rcode(), Rcode::REFUSED);
            }
            "update-tcp" => {
                assert!(ex.queries().all(|q| q.tcp));
                assert!(
                    matches!(&ops[..], [UpdateOp::Add(a)] if a.rtype() == Rtype::AAAA),
                    "{ops:?}"
                );
                assert_eq!(r.flags().rcode(), Rcode::NOERROR);
            }
            l if l.starts_with("sig0-") => {
                assert_eq!(r.flags().rcode(), Rcode::REFUSED);
            }
            _ => {
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
        }
    }
    assert_eq!(checked, if live() { 6 } else { 1 });
}

// ---------------------------------------------------------------------
// dig's text.
// ---------------------------------------------------------------------

/// The records dig printed: its whole output (`;` lines are comments),
/// read by dnsbox's zone-file reader, TSIG pseudo-records included (dig
/// writes them as BIND's presentation of TSIG, an empty MAC as nothing).
fn dig_records(label: &str, output: &str) -> Vec<Rr> {
    let records = ZoneReader::new(output)
        .records()
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|e| panic!("{label}: {e}"));
    sorted(records.iter().map(rr).collect())
}

/// dig's presentation of every response (every record type of the
/// zones, DNSSEC records, CHAOS TXT, TSIG, in both its one-line and its
/// `+multiline` layout) reads back, with dnsbox's zone reader, to the
/// records of the wire messages.
#[test]
fn dig_text_reads_back_to_the_wire() {
    let mut checked = 0;
    let mut bad: BTreeSet<String> = BTreeSet::new();
    let mut multiline = 0;
    for sub in ["named", "resolver"] {
        for ex in exchanges(sub) {
            let Some(output) = &ex.output else { continue };
            if ex.tool != "dig.txt" {
                continue; // nsupdate prints only the answer's header
            }
            if output.contains(";; Got bad packet") {
                // dig could not parse named's answer: dnsbox did
                // (every_captured_message_parses_and_rebuilds).
                let q = ex.query();
                let q = q.questions().next().unwrap().unwrap();
                bad.insert(format!("{} {}", q.name(), q.qtype()));
                continue;
            }
            // dig shows every message of a transfer, else the last
            // response (after a TCP or EDNS version retry).
            let q = ex.query();
            let qtype = q.questions().next().unwrap().unwrap().qtype();
            let responses: Vec<&Recorded> = if matches!(qtype, Rtype::AXFR | Rtype::IXFR) {
                ex.responses().collect()
            } else {
                ex.responses().last().into_iter().collect()
            };
            let mut wire = Vec::new();
            for r in responses {
                let msg = Message::parse_validated(&r.wire).unwrap();
                for rr in msg.records() {
                    let (_, rr) = rr.unwrap();
                    if rr.rtype() != Rtype::OPT {
                        wire.push(rr_of(&rr));
                    }
                }
            }
            assert_same_records(dig_records(&ex.label, output), wire, &ex.label);
            multiline += usize::from(ex.label.ends_with("-multiline"));
            checked += 1;
        }
    }
    // BIND 9.18.39 takes the key of a KEY, DNSKEY or RKEY of algorithm 253
    // (PRIVATEDNS) to start with a domain name (RFC 4034 Appendix A.1.1):
    // `named` loads and serves alltypes.example.'s RKEY, whose key does
    // not, and dig rejects the answer ("bad label type"); dnsbox reads it
    // as opaque key data.
    assert_eq!(
        bad,
        ["alltypes.example. AXFR", "rkey.alltypes.example. RKEY"]
            .map(str::to_owned)
            .into(),
    );
    assert!(checked >= if live() { 1000 } else { 150 }, "{checked}");
    assert!(multiline >= if live() { 3 } else { 1 }, "{multiline}");
}

// ---------------------------------------------------------------------
// named's answers.
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

/// The cases `run.sh` asks named for in every zone of `child.zone`:
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
    // A DS query at an unsigned delegation: with Opt-Out, BIND leaves the
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

/// named's answers in every zone signed by dnssec-signzone (positive,
/// NXDOMAIN, NODATA, empty non-terminal, wildcard, CNAME, DNAME,
/// referrals): every signed RRset verifies from the zone's DS, and the
/// denial-of-existence proofs give the expected status.
#[test]
fn named_answers_verify_and_prove() {
    let mut checked = 0;
    for z in zones().iter().filter(|z| z.spec.kind == Kind::Child) {
        let keys = z.trusted();
        let apex = z.apex().as_name();
        for (case, rel, qtype, expect) in expectations(z.spec.chain) {
            let label = format!("named/{}/{case}", z.file);
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
        checked >= if live() { 22 * 12 } else { 8 * 12 },
        "{checked}"
    );
}

/// named's EDNS (RFC 6891) and its options, as dnsbox decodes them in
/// dig's and the probe's queries and named's responses: NSID (RFC 5001),
/// cookies (RFC 7873; named's are RFC 9018 server cookies, which dnsbox
/// recomputes from the configured secret), Client Subnet (RFC 7871:
/// named echoes it with scope 0), EXPIRE (RFC 7314), Padding (RFC 7830,
/// RFC 8467: named pads over TCP, or over UDP when the client has a valid
/// server cookie), TCP keepalive (RFC 7828), unknown options and flags,
/// BADVERS, and no EDNS at all.
#[test]
fn named_edns_options() {
    use dnsbox::edns::{ClientSubnet, Cookie, Expire, Nsid, Padding, TcpKeepalive};

    fn edns<'m>(m: &Message<'m>) -> dnsbox::edns::Edns<'m> {
        m.edns().unwrap().expect("an OPT record")
    }
    fn get<'m, T: dnsbox::edns::ParseOption<'m>>(m: &Message<'m>) -> Option<T> {
        edns(m).get::<T>().map(Result::unwrap)
    }
    let Some(ex) = exchange("named/edns/nsid") else {
        assert!(!live());
        return;
    };
    // NSID.
    assert_eq!(get::<Nsid<'_>>(&ex.query()), Some(Nsid::REQUEST));
    assert_eq!(
        get::<Nsid<'_>>(&ex.response()).unwrap().as_str(),
        Some("named.dnsbox-interop")
    );

    // Cookies: a client cookie alone, or with a server cookie named did
    // not make, gets a fresh server cookie (no BADCOOKIE: named does not
    // require them), which verifies with named's secret (00 01 .. 0f; the
    // client is the proxy).
    let mut cookies = 0;
    for ex in exchanges("named/edns") {
        let (q, r) = (ex.query(), ex.response());
        if q.edns().unwrap().is_none() || edns(&q).version() != 0 {
            continue;
        }
        let (Some(qc), Some(rc)) = (get::<Cookie<'_>>(&q), get::<Cookie<'_>>(&r)) else {
            continue;
        };
        assert_eq!(rc.client(), qc.client(), "{}", ex.label);
        let server = rc.server_cookie_v1().expect("an RFC 9018 cookie");
        assert!(server.is_fresh(now()) || !live(), "{}", ex.label);
        #[cfg(feature = "cookie-siphash")]
        {
            let secret: [u8; 16] = core::array::from_fn(|i| i as u8);
            let ip = std::net::IpAddr::from([127, 0, 0, 1]);
            assert!(server.verify(&secret, &qc.client(), ip), "{}", ex.label);
        }
        assert_eq!(r.effective_rcode().unwrap(), Rcode::NOERROR, "{}", ex.label);
        cookies += 1;
    }
    assert!(cookies >= 10, "{cookies}");
    let ex = exchange("named/edns/cookie-server").unwrap();
    let qc = get::<Cookie<'_>>(&ex.query()).unwrap();
    assert_eq!(qc.server().unwrap().len(), 16);
    assert_ne!(
        get::<Cookie<'_>>(&ex.response()).unwrap().server(),
        qc.server()
    );
    let ex = exchange("named/edns/nocookie").unwrap();
    assert!(get::<Cookie<'_>>(&ex.query()).is_none());
    assert!(get::<Cookie<'_>>(&ex.response()).is_none());

    // Client Subnet: echoed with scope 0 (RFC 7871 §7.2.1).
    for (label, prefix) in [
        ("named/edns/subnet4", 24),
        ("named/edns/subnet6", 56),
        ("named/edns/subnet0", 0),
    ] {
        let ex = exchange(label).unwrap();
        let q = get::<ClientSubnet>(&ex.query()).unwrap();
        let r = get::<ClientSubnet>(&ex.response()).unwrap();
        assert_eq!(q.source_prefix(), prefix);
        assert_eq!(r, q.with_scope_prefix(0).unwrap(), "{label}");
    }

    // EXPIRE: the SOA expire of a primary.
    let ex = exchange("named/edns/expire").unwrap();
    assert_eq!(get::<Expire>(&ex.query()), Some(Expire::REQUEST));
    assert_eq!(get::<Expire>(&ex.response()), Some(Expire::new(1_209_600)));

    // Padding: dig pads its queries to 128-byte blocks; named pads its
    // response over TCP (to 128-byte blocks too), not over UDP to a
    // client without a valid server cookie (RFC 8467 §4.1 leaves that to
    // the server).
    for (label, padded) in [
        ("named/edns/padding", false),
        ("named/edns/padding-tcp", true),
    ] {
        let ex = exchange(label).unwrap();
        let q = ex.queries().next().unwrap();
        assert!(get::<Padding<'_>>(&ex.query()).is_some(), "{label}");
        assert_eq!(q.wire.len() % 128, 0, "{label}");
        let r = ex.responses().last().unwrap();
        assert_eq!(
            get::<Padding<'_>>(&ex.response()).is_some(),
            padded,
            "{label}"
        );
        if padded {
            assert_eq!(r.wire.len() % 128, 0, "{label}");
        }
    }

    // TCP keepalive: requested over TCP, named gives its idle timeout
    // (tcp-advertised-timeout 300: 30 seconds).
    let ex = exchange("named/edns/keepalive").unwrap();
    assert!(ex.queries().all(|q| q.tcp));
    assert_eq!(
        get::<TcpKeepalive>(&ex.query()),
        Some(TcpKeepalive::REQUEST)
    );
    assert_eq!(
        get::<TcpKeepalive>(&ex.response()),
        Some(TcpKeepalive::new(300))
    );

    // An unknown option is ignored, and so are unknown EDNS flags.
    let ex = exchange("named/edns/unknown-option").unwrap();
    let q = ex.query();
    let raw = edns(&q)
        .raw_options()
        .find(|o| o.code.get() == 65001)
        .expect("option 65001");
    assert_eq!(raw.data, [0xc0, 0xff, 0xee]);
    assert!(
        edns(&ex.response())
            .raw_options()
            .all(|o| o.code.get() != 65001)
    );
    assert_eq!(ex.response().flags().rcode(), Rcode::NOERROR);
    let ex = exchange("named/edns/flags").unwrap();
    assert_eq!(edns(&ex.query()).flags().bits() & 0x7fff, 0x40);
    assert_eq!(edns(&ex.response()).flags().bits() & 0x7fff, 0);

    // EDNS version 1: BADVERS, answered with version 0 (RFC 6891 §6.1.3);
    // dig then retries with version 0.
    let ex = exchange("named/edns/version1-nonegotiation").unwrap();
    assert_eq!(edns(&ex.query()).version(), 1);
    assert_eq!(ex.response().effective_rcode().unwrap(), Rcode::BADVERS);
    assert_eq!(edns(&ex.response()).version(), 0);
    let ex = exchange("named/edns/version1").unwrap();
    let m = ex.messages();
    assert_eq!(m.len(), 4);
    assert_eq!(edns(&m[0]).version(), 1);
    assert_eq!(m[1].effective_rcode().unwrap(), Rcode::BADVERS);
    assert_eq!(edns(&m[2]).version(), 0);
    assert_eq!(m[3].effective_rcode().unwrap(), Rcode::NOERROR);

    // No EDNS in the query, none in the response.
    let ex = exchange("named/edns/none").unwrap();
    assert!(ex.query().edns().unwrap().is_none());
    assert!(ex.response().edns().unwrap().is_none());

    // CHAOS TXT: named's configured identity and version.
    for (label, want) in [
        ("named/chaos/id.server", "named.dnsbox-interop"),
        ("named/chaos/hostname.bind", "named.dnsbox-interop"),
        ("named/chaos/version.bind", "dnsbox-interop"),
    ] {
        let ex = exchange(label).unwrap();
        let r = ex.response();
        let rr = r.answers().next().unwrap().unwrap();
        assert_eq!(rr.class(), Class::CH);
        assert!(rr.to_string().ends_with(&format!("\"{want}\"")), "{rr}");
    }
    // An opcode named does not implement, and a name it does not serve.
    let ex = exchange("named/notimp").unwrap();
    assert_eq!(ex.query().flags().opcode(), dnsbox::Opcode::STATUS);
    assert_eq!(ex.response().flags().rcode(), Rcode::NOTIMP);
    let ex = exchange("named/refused").unwrap();
    assert_eq!(ex.response().flags().rcode(), Rcode::REFUSED);

    // The probe's queries: with the server cookie of the first answer,
    // the second is padded (over UDP) to 128-byte blocks; Client Subnet
    // comes back with scope 0 both times.
    if let Some(ex) = exchange("named/probe/edns") {
        let m = ex.messages();
        assert_eq!(m.len(), 4);
        assert!(get::<Padding<'_>>(&m[1]).is_none());
        assert!(get::<Padding<'_>>(&m[3]).is_some());
        assert_eq!(ex.responses().last().unwrap().wire.len() % 128, 0);
        let q = get::<ClientSubnet>(&m[0]).unwrap();
        for r in [&m[1], &m[3]] {
            assert_eq!(
                get::<ClientSubnet>(r),
                Some(q.with_scope_prefix(0).unwrap())
            );
        }
    }
}

/// A truncated UDP answer (TC, RFC 2181 §9) and dig's retry over TCP,
/// whose DNSKEY RRset verifies.
#[test]
fn named_truncation() {
    let Some(ex) = exchange("named/transport/truncated") else {
        assert!(!live());
        return;
    };
    let r = ex.response();
    assert!(r.flags().tc());
    let ex = exchange("named/transport/fallback").unwrap();
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

/// The probe's TKEY query (RFC 2930 §4.2, deleting the key that signs
/// it, built by `dnsbox::tkey::build_query`): dnsbox reads it back and
/// verifies its TSIG as a server would. named only deletes keys TKEY
/// made: it answers NOERROR with a TKEY record of the same mode carrying
/// the error BADNAME (RFC 2930 §4.2), signed with the request's key.
#[test]
fn named_answers_tkey() {
    let Some(ex) = exchange("named/probe/tkey") else {
        assert!(!live());
        return;
    };
    let q = ex.query();
    let question = q.questions().next().unwrap().unwrap();
    assert_eq!(
        (question.qtype(), question.qclass()),
        (Rtype::TKEY, Class::ANY)
    );
    let rec = dnsbox::tkey::find(&q).unwrap().expect("TKEY record");
    assert_eq!(rec.section, Section::Additional);
    assert_eq!(rec.key_name, question.name());
    assert_eq!(rec.data.mode, dnsbox::rdata::TkeyMode::KEY_DELETION);
    let tsig = tsig::find(&q).unwrap().expect("TSIG record");
    let keys = tsig_keys();
    let status = tsig::verify_request(&q, &keys[..], tsig.data.time_signed);
    let verified = status.verified().expect("TKEY query rejected");

    let r = ex.response();
    assert_eq!(r.id(), q.id());
    assert_eq!(r.flags().rcode(), Rcode::NOERROR);
    let answer = dnsbox::tkey::find(&r).unwrap().expect("a TKEY answer");
    assert_eq!(answer.key_name, question.name());
    assert_eq!(answer.data.mode, dnsbox::rdata::TkeyMode::KEY_DELETION);
    assert_eq!(answer.data.error, TsigRcode::BADNAME);
    assert!(answer.data.key.is_empty() && answer.data.other.is_empty());
    let mut v = TsigVerifier::new(verified.key, verified.request_mac()).unwrap();
    let t = tsig::find(&r).unwrap().expect("signed").data.time_signed;
    assert!(v.verify(&r, t).unwrap().is_some());
    v.finish().unwrap();
}

// ---------------------------------------------------------------------
// named as a validating resolver.
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

    /// The resolver's verdict from its answer: SERVFAIL for bogus data, AD
    /// for secure data (RFC 4035 §3.2.3).
    fn of_resolver(msg: &Message<'_>) -> Verdict {
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

/// The trust anchor: `interop.`'s DS records (dnssec-dsfromkey's).
fn anchor() -> Vec<ZoneRecordBuf> {
    read_zone(&text("anchor.ds"))
}

/// Validates the answer to `qname`/`qtype` the way a resolver does, from
/// the trust anchor down (RFC 4035 §5): for every zone from `interop.` to
/// `zone`, the DS RRset (verified by the parent's keys) authenticates the
/// DNSKEY RRset, or a verified denial proves the delegation unsigned
/// (insecure); then the answer, or its denial proof, must verify with the
/// zone's keys. The data is what the resolver fetched (`case/<step>`,
/// asked with CD set, RFC 4035 §3.2.2). Each response is validated within
/// one default [`ValidationBudget`]: a legitimate chain must never run
/// out of it.
fn dnsbox_verdict(case: &str, qname: &NameBuf, qtype: Rtype, zone: &NameBuf) -> Verdict {
    // The last response of every step of the case.
    let mut wires: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for ex in exchanges(&format!("resolver/{case}")) {
        let step = ex.label.rsplit('/').next().unwrap().to_owned();
        if let Some(r) = ex.responses().last() {
            wires.insert(step, r.wire.clone());
        }
    }
    let fetch = |step: &str| -> Message<'_> {
        let wire = wires
            .get(step)
            .unwrap_or_else(|| panic!("resolver/{case}/{step}: no response"));
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
    let (k, s) = dnskeys(&fetch("dnskey-interop"), &root);
    let Ok(mut keys) = TrustedKeys::from_ds_with_budget(
        &PurecryptoVerifier,
        Rrset::new(root.as_name(), Class::IN, k),
        anchor_ds.iter().copied(),
        s,
        now(),
        &mut scratch,
        &ValidationBudget::new(),
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
        let ds_msg = fetch(&format!("ds-{}", child.to_string().trim_end_matches('.')));
        let budget = ValidationBudget::new();
        let (ds, ds_sigs) = rrset_in(&ds_msg, Section::Answer, child, Rtype::DS);
        if ds.is_empty() {
            // No DS: the parent must prove the delegation unsigned.
            let (nsec, nsec3) = denial_records(&ds_msg);
            for (owner, rtype) in rrsets_of(&ds_msg, Section::Authority) {
                if !matches!(rtype, Rtype::NSEC | Rtype::NSEC3) {
                    continue;
                }
                let (rdata, sigs) = rrset_in(&ds_msg, Section::Authority, &owner, rtype);
                if keys
                    .verify_rrset_with_budget(
                        &PurecryptoVerifier,
                        Rrset::new(owner.as_name(), Class::IN, &rdata),
                        sigs,
                        now(),
                        &mut scratch,
                        &budget,
                    )
                    .is_err()
                {
                    return Verdict::Bogus;
                }
            }
            let status = if nsec3.is_empty() {
                NsecProof::new(cut.as_name(), &nsec).unsigned_delegation(child.as_name())
            } else {
                Nsec3Proof::new(
                    cut.as_name(),
                    &nsec3,
                    budget.nsec3_hasher(PurecryptoNsec3Hasher),
                )
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
            .verify_rrset_with_budget(
                &PurecryptoVerifier,
                Rrset::new(child.as_name(), Class::IN, &ds),
                ds_sigs,
                now(),
                &mut scratch,
                &budget,
            )
            .is_err()
        {
            return Verdict::Bogus;
        }
        let (k, s) = dnskeys(
            &fetch(&format!(
                "dnskey-{}",
                child.to_string().trim_end_matches('.')
            )),
            child,
        );
        let Ok(child_keys) = TrustedKeys::from_ds_with_budget(
            &PurecryptoVerifier,
            Rrset::new(child.as_name(), Class::IN, k),
            ds.iter().copied(),
            s,
            now(),
            &mut scratch,
            &ValidationBudget::new(),
        ) else {
            return Verdict::Bogus;
        };
        keys = child_keys;
        cut = child.clone();
    }

    // The answer itself, from the zone's keys.
    let msg = fetch("cd");
    let budget = ValidationBudget::new();
    let verify_section = |section: Section, scratch: &mut Vec<u8>| -> Result<bool, ()> {
        let mut wildcard = false;
        for (owner, rtype) in rrsets_of(&msg, section) {
            let (rdata, sigs) = rrset_in(&msg, section, &owner, rtype);
            let v = keys
                .verify_rrset_with_budget(
                    &PurecryptoVerifier,
                    Rrset::new(owner.as_name(), Class::IN, &rdata),
                    sigs,
                    now(),
                    scratch,
                    &budget,
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
                budget.nsec3_hasher(PurecryptoNsec3Hasher),
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
    let answer = prove(&|p| match keys.verify_answer_with_budget(
        &PurecryptoVerifier,
        Rrset::new(qn, Class::IN, &rdata),
        sigs.iter().copied(),
        p,
        now(),
        &mut Vec::new(),
        &budget,
    ) {
        Ok(dnsbox::dnssec::Answer::Wildcard { proof, .. }) => proof,
        Ok(_) => DenialStatus::Secure(Denial::WildcardAnswer),
        Err(_) => DenialStatus::Bogus(dnsbox::dnssec::BogusReason::MissingProof),
    });
    Verdict::of_status(answer)
}

/// For every case of `resolver/cases.txt` (secure answers and denials in
/// every zone, wildcards, Opt-Out, unsigned delegations, a changed record,
/// changed NSEC records, a DS that matches no key), dnsbox, validating
/// what named fetched, reaches named's own verdict (AD, no AD, SERVFAIL),
/// which is also the one the case was made for.
#[test]
fn dnsbox_agrees_with_named_resolver() {
    let cases = text("resolver/cases.txt");
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
        let answer = exchange(&format!("resolver/{case}/answer")).unwrap();
        let named = Verdict::of_resolver(&answer.response());
        let ours = dnsbox_verdict(case, &qname, qtype, &zone);
        assert_eq!(
            (ours, named),
            (expected, expected),
            "{case}: dnsbox {ours:?}, named {named:?}, expected {expected:?}"
        );
        *checked.entry(format!("{expected:?}")).or_insert(0) += 1;
    }
    println!("{checked:?}");
    assert_eq!(checked.len(), 3, "{checked:?}");
}

// ---------------------------------------------------------------------
// BIND's zone writers and readers.
// ---------------------------------------------------------------------

/// `named-compilezone -s full` (one record per line, absolute names) and
/// `-s relative` (BIND's default: `$ORIGIN` and `$TTL` directives,
/// relative names, omitted owners, classes and TTLs, multi-line records
/// with comments) of every signed zone, of the bulk zone, of
/// `../bind9/alltypes.zone` (every type BIND reads) and of dnsbox's
/// `newtypes.zone`: dnsbox reads each to the records BIND loaded. BIND
/// 9.18.39 aborts writing one record of `alltypes.zone` in the relative
/// style (an assertion in `dns_name_fromregion`: an RKEY of algorithm
/// 253 whose key does not start with a domain name); `run.sh` lists it in
/// `compiled/alltypes.relative.omitted` and compiles the others.
#[test]
fn dnsbox_reads_compilezone_styles() {
    let mut checked = 0;
    let compiled = dir().join("compiled");
    let mut files: Vec<PathBuf> = fs::read_dir(&compiled)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.extension()
                .is_some_and(|e| e == "full" || e == "relative")
        })
        .collect();
    files.sort();
    let axfr = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/named-alltypes-axfr.hex");
    for path in &files {
        let stem = path.file_stem().unwrap().to_str().unwrap();
        let style = path.extension().unwrap().to_str().unwrap();
        let ours: Vec<Rr> = ZoneReader::new(&fs::read_to_string(path).unwrap())
            .records()
            .map(|r| rr(&r.unwrap_or_else(|e| panic!("{}: {e}", path.display()))))
            .collect();
        let mut theirs = match stem {
            "alltypes" => {
                // BIND's own AXFR of the zone (named 9.18, the corpus).
                let wire = hex_file(&axfr);
                let msg = Message::parse_validated(&wire).unwrap();
                let mut v: Vec<Rr> = msg.answers().map(|r| rr_of(&r.unwrap())).collect();
                v.pop(); // the closing SOA
                v
            }
            "newtypes" => zone_file("newtypes.example"),
            z => zone_file(z),
        };
        let omitted = path.with_extension(format!("{style}.omitted"));
        if let Ok(text) = fs::read_to_string(&omitted) {
            // named-compilezone -s relative aborts on the RKEY of
            // algorithm 253 whose key does not start with a domain name
            // (see dig_text_reads_back_to_the_wire), and only on it.
            let records = read_zone(&text);
            assert_eq!((stem, style), ("alltypes", "relative"));
            assert!(
                matches!(&records[..], [r] if r.rtype == Rtype::RKEY && r.rdata[3] == 253),
                "{text}"
            );
            for r in records {
                let i = theirs
                    .iter()
                    .position(|x| *x == rr(&r))
                    .unwrap_or_else(|| panic!("{}: {r}", omitted.display()));
                theirs.remove(i);
            }
        }
        assert_same_records(
            as_loaded(&ours),
            as_loaded(&theirs),
            &path.display().to_string(),
        );
        checked += 1;
    }
    // Both styles of every child, the parent, a bogus zone, bulk, alltypes
    // and newtypes.
    assert!(checked >= if live() { 2 * 27 } else { 10 }, "{checked}");
}

/// named loaded dnsbox's presentation of every type BIND reads
/// (`tests/corpus/bind9/alltypes.dnsbox`, written by
/// `tests/interop_zones.rs`) and transfers exactly the records of BIND's
/// own AXFR of the hand-written zone
/// (`tests/corpus/named-alltypes-axfr.hex`).
#[test]
fn bind_reads_dnsbox_text_of_every_type() {
    assert_eq!(text("alltypes-omitted.txt"), "");
    let Some(ex) = exchange("named/alltypes/axfr") else {
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
    assert!(bind.len() >= 150, "{}", bind.len());
    assert_same_records(t.full, bind, "named (-) and named 9.18.49's AXFR (+)");
}

/// named loaded dnsbox's presentation of the types BIND 9.18's alltypes
/// zone lacks (`../knot/newtypes.zone`: AMTRELAY, DSYNC, HHIT, BRID,
/// DOA), but for the records BIND 9.18.39 cannot read: HHIT and BRID
/// (types it does not know) and an AMTRELAY of relay type 0, which it
/// reads only without the `.` RFC 8777 §4.3.1 requires (`run.sh` serves
/// it in BIND's form too). named transfers exactly dnsbox's records but
/// HHIT and BRID: BIND reads dnsbox's text of AMTRELAY, DSYNC and DOA to
/// dnsbox's wire form, and dig's text of them reads back to it.
#[test]
fn bind_reads_dnsbox_text_of_new_types() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/knot/newtypes.zone");
    let records = read_zone(&fs::read_to_string(&path).unwrap());
    let omitted: Vec<Rr> = read_zone(&text("newtypes-omitted.txt"))
        .iter()
        .map(rr)
        .collect();
    let unknown: BTreeSet<Rtype> = [Rtype::HHIT, Rtype::BRID].into();
    let mut amtrelay0 = 0;
    for r in &omitted {
        if r.1 == Rtype::AMTRELAY {
            assert_eq!(r.4, [0, 0], "{}", show(r));
            amtrelay0 += 1;
        } else {
            assert!(unknown.contains(&r.1), "{}", show(r));
        }
    }
    assert_eq!((omitted.len(), amtrelay0), (3, 1));
    let Some(ex) = exchange("named/newtypes/axfr") else {
        assert!(!live());
        return;
    };
    let t = transfer(&ex, XfrProcessor::axfr(name("newtypes.example")));
    assert!(t.done);
    let served: Vec<Rr> = records
        .iter()
        .map(rr)
        .filter(|r| !unknown.contains(&r.1))
        .collect();
    assert_same_records(t.full, served, "named (-) and dnsbox (+)");
    // dig's text of named's type-0 AMTRELAY: no relay.
    let output = ex.output.as_deref().unwrap();
    assert!(
        output
            .lines()
            .any(|l| l.contains("AMTRELAY") && l.trim_end().ends_with("AMTRELAY 0 0 0")),
        "{output}"
    );
}

/// named-checkzone and dnssec-verify accepted every zone dnsbox wrote
/// (`run.sh check-dnsbox`, logs in `checks/dnsbox-*`), and
/// `named-compilezone`'s output of each, in both styles, reads back to
/// dnsbox's records: BIND reads dnsbox's presentation of the zones and
/// their signatures.
#[test]
fn bind_reads_dnsbox_zones() {
    let compiled = dir().join("dnsbox-compiled");
    if !compiled.exists() {
        // Before run.sh check-dnsbox (the workflow runs this test again
        // after it, with DNSBOX_INTEROP_COMPILED set).
        assert!(std::env::var_os("DNSBOX_INTEROP_COMPILED").is_none());
        return;
    }
    let mut checked = 0;
    for e in fs::read_dir(dir().join("dnsbox")).unwrap() {
        let path = e.unwrap().path();
        let stem = path.file_stem().unwrap().to_str().unwrap().to_owned();
        let ours: Vec<Rr> = read_zone(&fs::read_to_string(&path).unwrap())
            .iter()
            .map(rr)
            .collect();
        for style in ["full", "relative"] {
            let back = compiled.join(format!("{stem}.{style}"));
            let theirs: Vec<Rr> = read_zone(&fs::read_to_string(&back).unwrap())
                .iter()
                .map(rr)
                .collect();
            assert_same_records(theirs, as_loaded(&ours), &back.display().to_string());
        }
        let log = text(&format!("checks/dnsbox-{stem}.dnssec-verify"));
        assert!(log.contains("Zone fully signed"), "{stem}: {log}");
        checked += 1;
    }
    assert!(checked >= if live() { 24 } else { 2 }, "{checked}");
}
