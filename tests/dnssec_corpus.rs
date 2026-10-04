//! DNSSEC validation of real responses from the interop corpus
//! (`tests/corpus/*.hex`, captured on 2026-10-04 from the root servers,
//! TLD and domain servers running NSD, BIND, Knot and PowerDNS, Cloudflare's
//! authoritative servers and the public resolvers).
//!
//! The root DNSKEY RRset is authenticated from the IANA root trust anchors,
//! `com` from the root's DS RRset, and the other zones from their own
//! key-signing keys. Then every signed RRset of the responses verifies with
//! the purecrypto backend, and the denial-of-existence proofs in them —
//! NSEC (root, isc.org, powerdns.com, nlnetlabs.nl), NSEC3 (example.com),
//! NSEC3 with Opt-Out (com, de) and Cloudflare's compact denial
//! (RFC 9824) — give the status their zones' signing modes call for.

#![cfg(feature = "dnssec")]

use std::collections::BTreeMap;
use std::fs;

use dnsbox::dnssec::{
    Denial, DenialProof, DenialStatus, InsecureReason, Nsec3Proof, Nsec3Record, NsecProof,
    NsecRecord, PurecryptoNsec3Hasher, PurecryptoVerifier, Rrset, TrustedKeys,
};
use dnsbox::rdata::{Dnskey, Ds, RData, Rrsig};
use dnsbox::{Class, Message, Name, NameBuf, Rtype, Section};

/// 2026-10-04T14:15:00Z, just after the last capture: inside the validity
/// of every signature captured.
const NOW: u32 = 1_791_123_300;

/// The IANA root trust anchors (KSK-2017 and KSK-2024), as DS RDATA text.
const ROOT_ANCHORS: [&str; 2] = [
    "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
    "38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
];

/// A corpus message, leaked so that views of it live for the whole test.
fn message(label: &str) -> Message<'static> {
    let path = format!("{}/tests/corpus/{label}.hex", env!("CARGO_MANIFEST_DIR"));
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let digits: Vec<u8> = text
        .lines()
        .filter(|l| !l.starts_with('#'))
        .flat_map(str::bytes)
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| (b as char).to_digit(16).expect("hex digit") as u8)
        .collect();
    let wire: Vec<u8> = digits.chunks(2).map(|p| (p[0] << 4) | p[1]).collect();
    Message::parse_validated(Box::leak(wire.into_boxed_slice())).unwrap()
}

type Keys = TrustedKeys<'static, Vec<Dnskey<'static>>>;

/// The records of `rtype` at `owner` in a section, and the RRSIGs over
/// them.
fn rrset(
    msg: &Message<'static>,
    section: Section,
    owner: Name<'_>,
    rtype: Rtype,
) -> (Vec<RData<'static>>, Vec<Rrsig<'static>>) {
    let records: Vec<_> = msg
        .records()
        .map(Result::unwrap)
        .filter(|(s, r)| *s == section && r.name() == owner)
        .map(|(_, r)| r)
        .collect();
    let data = records
        .iter()
        .filter(|r| r.rtype() == rtype)
        .map(|r| r.data().unwrap())
        .collect();
    let sigs = records
        .iter()
        .filter_map(|r| r.data_as::<Rrsig<'static>>().ok())
        .filter(|s| s.type_covered == rtype)
        .collect();
    (data, sigs)
}

/// The DNSKEY RRset of a DNSKEY response: (zone, keys, RRSIGs).
fn dnskeys(msg: &Message<'static>) -> (Name<'static>, Vec<Dnskey<'static>>, Vec<Rrsig<'static>>) {
    let zone = msg.questions().next().unwrap().unwrap().name();
    let (data, sigs) = rrset(msg, Section::Answer, zone, Rtype::DNSKEY);
    let keys = data
        .into_iter()
        .map(|d| match d {
            RData::Dnskey(k) => k,
            other => panic!("{other:?}"),
        })
        .collect();
    (zone, keys, sigs)
}

/// The keys of a DNSKEY response, authenticated by DS records.
fn from_ds(label: &str, ds: &[Ds<'_>]) -> Keys {
    let (zone, keys, sigs) = dnskeys(&message(label));
    TrustedKeys::from_ds(
        &PurecryptoVerifier,
        Rrset::new(zone, Class::IN, keys),
        ds.iter().copied(),
        sigs,
        NOW,
        &mut Vec::new(),
    )
    .unwrap_or_else(|e| panic!("{label}: {e}"))
}

/// The keys of a DNSKEY response, anchored at its own key-signing keys:
/// the RRset must be signed by one of them.
fn self_anchored(label: &str) -> Keys {
    let (zone, keys, sigs) = dnskeys(&message(label));
    let anchors: Vec<Dnskey<'_>> = keys.iter().copied().filter(|k| k.is_sep()).collect();
    assert!(!anchors.is_empty(), "{label}");
    TrustedKeys::from_anchors(
        &PurecryptoVerifier,
        Rrset::new(zone, Class::IN, keys),
        anchors,
        sigs,
        NOW,
        &mut Vec::new(),
    )
    .unwrap_or_else(|e| panic!("{label}: {e}"))
}

fn root_keys() -> Keys {
    let anchors: Vec<Vec<u8>> = ROOT_ANCHORS
        .iter()
        .map(|t| RData::text_to_wire(Rtype::DS, Class::IN, t).unwrap())
        .collect();
    let ds: Vec<Ds<'_>> = anchors
        .iter()
        .map(
            |w| match RData::parse(Rtype::DS, Class::IN, dnsbox::WireReader::new(w)) {
                Ok(RData::Ds(d)) => d,
                other => panic!("{other:?}"),
            },
        )
        .collect();
    from_ds("nsd-kroot-dnskey", &ds)
}

/// The keys of every zone the corpus can authenticate, by zone name.
fn all_keys() -> BTreeMap<NameBuf, Keys> {
    let mut out = BTreeMap::new();
    let root = root_keys();
    // com: the root's referral carries the DS RRset, signed by the root.
    let referral = message("nsd-kroot-referral-com");
    let com: NameBuf = "com.".parse().unwrap();
    let (ds, sigs) = rrset(&referral, Section::Authority, com.as_name(), Rtype::DS);
    root.verify_rrset(
        &PurecryptoVerifier,
        Rrset::new(com.as_name(), Class::IN, &ds),
        sigs,
        NOW,
        &mut Vec::new(),
    )
    .unwrap();
    let ds: Vec<Ds<'_>> = ds
        .iter()
        .map(|d| match d {
            RData::Ds(d) => *d,
            other => panic!("{other:?}"),
        })
        .collect();
    out.insert(com, from_ds("quad9-dnskey-com", &ds));
    out.insert(NameBuf::root(), root);
    for label in [
        "bind-isc-dnskey",
        "knot-iana-example-dnskey",
        "pdns-auth-dnskey",
        "quad9-dnskey-de",
        "quad9-dnskey-nlnetlabs",
        "cloudflare-auth-dnskey",
        "knot-resolver-nic-dnskey",
    ] {
        let keys = self_anchored(label);
        out.insert(keys.zone().to_buf(), keys);
    }
    out
}

/// Verifies every RRset of the answer and authority sections signed by a
/// zone in `keys`; returns how many verified.
fn verify_sections(label: &str, msg: &Message<'static>, keys: &BTreeMap<NameBuf, Keys>) -> usize {
    let mut verified = 0;
    for section in [Section::Answer, Section::Authority] {
        let mut seen: Vec<(NameBuf, Rtype)> = Vec::new();
        for (s, rr) in msg.records().map(Result::unwrap) {
            if s != section || matches!(rr.rtype(), Rtype::RRSIG | Rtype::OPT) {
                continue;
            }
            let key = (rr.name().to_buf(), rr.rtype());
            if seen.contains(&key) {
                continue;
            }
            seen.push(key);
            let (data, sigs) = rrset(msg, section, rr.name(), rr.rtype());
            let Some(signer) = sigs.first().map(|s| s.signer_name.to_buf()) else {
                continue;
            };
            let Some(zone) = keys.get(&signer) else {
                continue;
            };
            zone.verify_rrset(
                &PurecryptoVerifier,
                Rrset::new(rr.name(), Class::IN, &data),
                sigs,
                NOW,
                &mut Vec::new(),
            )
            .unwrap_or_else(|e| panic!("{label}: {} {}: {e}", rr.name(), rr.rtype()));
            verified += 1;
        }
    }
    verified
}

#[test]
fn chain_of_trust_from_the_root_anchor() {
    let keys = all_keys();
    // Both root KSKs are in the RRset and the anchors match them.
    let root = &keys[&NameBuf::root()];
    let tags: Vec<u16> = root
        .keys()
        .iter()
        .filter(|k| k.is_sep())
        .map(Dnskey::key_tag)
        .collect();
    assert!(tags.contains(&20326) && tags.contains(&38696), "{tags:?}");
    assert!(keys.contains_key(&"com.".parse::<NameBuf>().unwrap()));
    assert_eq!(keys.len(), 9);
}

#[test]
fn signed_answers_verify() {
    let keys = all_keys();
    // (label, signed RRsets in the answer and authority sections)
    for (label, expected) in [
        ("nsd-kroot-dnskey", 1),
        ("nsd-kroot-zonemd", 1),
        ("google-zonemd-root", 1),
        ("nsd-kroot-referral-com", 1),
        ("quad9-ds-com", 1),
        ("quad9-dnskey-com", 1),
        ("cloudflare-nsec3param-com", 1),
        ("bind-isc-soa-dnssec", 2),
        ("bind-isc-mx", 2),
        ("bind-isc-nodata", 2),
        ("unbound-isc-mx-dnssec", 1),
        ("google-cds", 1),
        ("google-cdnskey", 1),
        ("quad9-rrsig", 1),
        ("knot-iana-example-soa", 1),
        ("knot-denic-referral", 1),
        ("pdns-auth-soa", 1),
        ("nsd-nlnetlabs-soa", 2),
        ("knot-resolver-tlsa", 1),
        ("cloudflare-caa", 1),
    ] {
        let msg = message(label);
        let n = verify_sections(label, &msg, &keys);
        assert_eq!(n, expected, "{label}: RRsets verified");
    }
}

/// The NSEC/NSEC3 records of the authority section.
fn proofs(msg: &Message<'static>) -> (Vec<NsecRecord<'static>>, Vec<Nsec3Record<'static>>) {
    let auth: Vec<_> = msg.authority().map(Result::unwrap).collect();
    (
        auth.iter().filter_map(NsecRecord::from_record).collect(),
        auth.iter().filter_map(Nsec3Record::from_record).collect(),
    )
}

#[test]
fn real_denials_of_existence() {
    let keys = all_keys();
    let secure = DenialStatus::Secure;
    let opt_out = DenialStatus::Insecure(InsecureReason::OptOut);
    // (label, zone, NXDOMAIN?, expected status)
    for (label, zone, nxdomain, want) in [
        ("nsd-kroot-nxdomain", ".", true, secure(Denial::NameError)),
        (
            "bind-isc-nxdomain",
            "isc.org.",
            true,
            secure(Denial::NameError),
        ),
        (
            "pdns-auth-nxdomain",
            "powerdns.com.",
            true,
            secure(Denial::NameError),
        ),
        (
            "nsd-nlnetlabs-nxdomain",
            "nlnetlabs.nl.",
            true,
            secure(Denial::NameError),
        ),
        (
            "knot-iana-example-nxdomain",
            "example.com.",
            true,
            secure(Denial::NameError),
        ),
        // com and de sign with NSEC3 Opt-Out: an unsigned delegation could
        // hide in the span covering the name (RFC 5155 §9.2).
        ("cloudflare-nxdomain-com-optout", "com.", true, opt_out),
        ("knot-denic-nxdomain-nsec3", "de.", true, opt_out),
        // Compact denial (RFC 9824): NOERROR, and an NSEC at the name
        // itself with only RRSIG, NSEC and NXNAME.
        (
            "cloudflare-auth-compact-denial",
            "cloudflare.com.",
            false,
            secure(Denial::NoData),
        ),
    ] {
        let msg = message(label);
        let n = verify_sections(label, &msg, &keys);
        assert!(n >= 2, "{label}: {n} RRsets verified");
        let q = msg.questions().next().unwrap().unwrap();
        let zone: NameBuf = zone.parse().unwrap();
        let zone = keys[&zone].zone();
        let (nsec, nsec3) = proofs(&msg);
        let check = |p: &dyn DenialProof| {
            if nxdomain {
                assert_eq!(msg.flags().rcode(), dnsbox::Rcode::NXDOMAIN, "{label}");
                p.name_error(q.name())
            } else {
                p.no_data(q.name(), q.qtype())
            }
        };
        let got = if nsec3.is_empty() {
            check(&NsecProof::new(zone, &nsec))
        } else {
            check(&Nsec3Proof::new(zone, &nsec3, PurecryptoNsec3Hasher))
        };
        assert_eq!(got, want, "{label}");
    }
}

#[test]
fn compact_denial_is_not_a_name_error() {
    // The NSEC of a compact denial matches the name, so it proves the
    // name exists (as an NXNAME owner) rather than an NXDOMAIN.
    let msg = message("cloudflare-auth-compact-denial");
    let (nsec, _) = proofs(&msg);
    let zone: NameBuf = "cloudflare.com.".parse().unwrap();
    let proof = NsecProof::new(zone.as_name(), &nsec);
    let q = msg.questions().next().unwrap().unwrap();
    assert!(nsec[0].nsec.types.contains(Rtype::NXNAME));
    assert!(proof.name_error(q.name()).is_bogus());
}

/// The whole root zone (too big for the repository): run with
/// `DNSBOX_ROOT_ZONE=path/to/root.zone cargo test --release --all-features
/// --test dnssec_corpus -- --ignored`, the file being a fresh copy of
/// <https://www.internic.net/domain/root.zone>. Its DNSKEY RRset must
/// match the IANA trust anchors, its ZONEMD (RFC 8976) must verify, and
/// so must every RRSIG in it (at the time `DNSBOX_ROOT_ZONE_TIME`, in
/// seconds since the epoch, by default the SOA serial's day).
#[test]
#[ignore = "needs a copy of the root zone in DNSBOX_ROOT_ZONE"]
fn root_zone() {
    use dnsbox::dnssec::{ZonemdRecord, verify_zonemd};
    use dnsbox::zone::ZoneReader;
    let path = std::env::var("DNSBOX_ROOT_ZONE").expect("DNSBOX_ROOT_ZONE");
    let text = fs::read_to_string(path).unwrap();
    let zone: Vec<_> = ZoneReader::new(&text)
        .records()
        .collect::<Result<_, _>>()
        .unwrap_or_else(|e| panic!("{e}"));
    let root = NameBuf::root();
    let verified = verify_zonemd(
        root.as_name(),
        zone.iter()
            .map(|r| ZonemdRecord::new(r.name.as_name(), r.class, r.ttl, r.data().unwrap())),
    )
    .unwrap_or_else(|e| panic!("ZONEMD: {e}"));
    println!("ZONEMD verified: {verified:?}");

    // RRsets and their RRSIGs.
    let mut sets: BTreeMap<(NameBuf, Rtype), (Vec<RData<'_>>, Vec<Rrsig<'_>>)> = BTreeMap::new();
    for r in &zone {
        match r.data().unwrap() {
            RData::Rrsig(s) => sets
                .entry((r.name.clone(), s.type_covered))
                .or_default()
                .1
                .push(s),
            d => sets.entry((r.name.clone(), r.rtype)).or_default().0.push(d),
        }
    }
    let now = std::env::var("DNSBOX_ROOT_ZONE_TIME").map_or_else(
        |_| {
            let soa = &sets[&(root.clone(), Rtype::SOA)].0[0];
            let RData::Soa(soa) = soa else { unreachable!() };
            // YYYYMMDDnn: noon UTC of that day.
            let day = format!("{}120000", soa.serial / 100);
            day.parse::<dnsbox::dnssec::Timestamp>().unwrap().get()
        },
        |t| t.parse().unwrap(),
    );
    let (keys, key_sigs) = &sets[&(root.clone(), Rtype::DNSKEY)];
    let keys: Vec<Dnskey<'_>> = keys
        .iter()
        .map(|k| match k {
            RData::Dnskey(k) => *k,
            _ => unreachable!(),
        })
        .collect();
    let anchors: Vec<Vec<u8>> = ROOT_ANCHORS
        .iter()
        .map(|t| RData::text_to_wire(Rtype::DS, Class::IN, t).unwrap())
        .collect();
    let ds: Vec<Ds<'_>> = anchors
        .iter()
        .map(
            |w| match RData::parse(Rtype::DS, Class::IN, dnsbox::WireReader::new(w)) {
                Ok(RData::Ds(d)) => d,
                other => panic!("{other:?}"),
            },
        )
        .collect();
    let trusted = TrustedKeys::from_ds(
        &PurecryptoVerifier,
        Rrset::new(root.as_name(), Class::IN, keys),
        ds,
        key_sigs.iter().copied(),
        now,
        &mut Vec::new(),
    )
    .unwrap();
    let mut verified = 0;
    for ((owner, rtype), (data, sigs)) in &sets {
        if sigs.is_empty() {
            continue;
        }
        trusted
            .verify_rrset(
                &PurecryptoVerifier,
                Rrset::new(owner.as_name(), Class::IN, data),
                sigs.iter().copied(),
                now,
                &mut Vec::new(),
            )
            .unwrap_or_else(|e| panic!("{owner} {rtype}: {e}"));
        verified += 1;
    }
    println!("{verified} RRsets verified");
    assert!(verified > 1000);
}
