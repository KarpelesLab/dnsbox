//! Interoperability with the zone files and DNSSEC signers of BIND 9.18
//! and ldns 1.8 (`tests/corpus/bind9/` and `tests/corpus/ldns/`, made by
//! their `gen.sh`; see `tests/corpus/README.md`).
//!
//! - `alltypes.zone` (every type BIND reads, in hand-written master-file
//!   syntax), BIND's canonical dump of it (`named-checkzone -D`), its AXFR
//!   from `named` and ldns's rewrite of it (`ldns-read-zone`) must hold the
//!   same records, dnsbox must read all the texts, and display every
//!   record as BIND does.
//! - `signed.zone` signed by `dnssec-signzone` with every DNSSEC algorithm
//!   and by `ldns-signzone` (with ZONEMD) with three, using NSEC, NSEC3
//!   and NSEC3 Opt-Out chains: every signature verifies with the
//!   purecrypto backend, the keys authenticate from their DS records
//!   (SHA-1, SHA-256, SHA-384), dnsbox re-signs every RRset to the
//!   signer's exact bytes with the deterministic algorithms (RSA, EdDSA),
//!   the NSEC / NSEC3 chains are exactly what dnsbox's canonical order and
//!   NSEC3 hashing predict, and ldns's ZONEMD digests are dnsbox's.
//! - `named` serving BIND's zones: its positive, NXDOMAIN, NODATA,
//!   wildcard, CNAME/DNAME and referral responses (`tests/corpus/named-*`)
//!   verify, and their denial-of-existence proofs give the expected status.

#![cfg(feature = "alloc")]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use dnsbox::rdata::RData;
use dnsbox::zone::{ZoneReader, ZoneRecordBuf};
use dnsbox::{Class, Message, NameBuf, OwnedRecord, Rtype};

fn bind9(file: &str) -> String {
    read("bind9", file)
}

/// A file of `tests/corpus/<dir>/`.
fn read(dir: &str, file: &str) -> String {
    let path = format!("{}/tests/corpus/{dir}/{file}", env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// A `tests/corpus/*.hex` message.
fn corpus(label: &str) -> Vec<u8> {
    let path = format!("{}/tests/corpus/{label}.hex", env!("CARGO_MANIFEST_DIR"));
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let digits: Vec<u8> = text
        .lines()
        .filter(|l| !l.starts_with('#'))
        .flat_map(str::bytes)
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| (b as char).to_digit(16).expect("hex digit") as u8)
        .collect();
    digits.chunks(2).map(|p| (p[0] << 4) | p[1]).collect()
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

/// The records as a sorted list (a multiset).
fn sorted(mut v: Vec<Rr>) -> Vec<Rr> {
    v.sort();
    v
}

// ---------------------------------------------------------------------
// alltypes.zone: master-file text, BIND's canonical text, AXFR wire.
// ---------------------------------------------------------------------

#[test]
fn alltypes_text_canonical_and_axfr_agree() {
    let source = read_zone(&bind9("alltypes.zone"));
    let canonical_text = bind9("alltypes.canonical");
    let canonical = read_zone(&canonical_text);
    assert!(source.len() >= 150, "{} records", source.len());

    // The hand-written zone and BIND's dump hold the same records. BIND
    // gives every record of an RRset the TTL of the first one when it
    // loads a zone (RFC 2181 §5.2; it warns "TTL set to prior TTL"), while
    // dnsbox's streaming reader returns each record as written: apply the
    // same rule here.
    let mut first_ttl: BTreeMap<(NameBuf, Rtype), u32> = BTreeMap::new();
    let a = sorted(
        source
            .iter()
            .map(|r| {
                let ttl = *first_ttl.entry((r.name.clone(), r.rtype)).or_insert(r.ttl);
                (r.name.clone(), r.rtype, r.class, ttl, r.rdata.clone())
            })
            .collect(),
    );
    assert!(
        source
            .iter()
            .any(|r| r.ttl != first_ttl[&(r.name.clone(), r.rtype)])
    );
    let b = sorted(canonical.iter().map(rr).collect());
    for (x, y) in a.iter().zip(&b) {
        assert_eq!(x, y);
    }
    assert_eq!(a.len(), b.len());

    // And so does the AXFR stream (minus the closing SOA), whose RDATA is
    // BIND's own wire encoding of every type.
    let wire = corpus("named-alltypes-axfr");
    let msg = Message::parse_validated(&wire).unwrap();
    let mut axfr: Vec<Rr> = msg
        .answers()
        .map(|r| {
            let r = OwnedRecord::from_record(&r.unwrap()).unwrap();
            (
                r.name.clone(),
                r.rtype(),
                r.class,
                r.ttl,
                r.rdata.as_wire().to_vec(),
            )
        })
        .collect();
    let last = axfr.pop().unwrap();
    assert_eq!((last.1, &last.0), (Rtype::SOA, &axfr[0].0));
    assert_eq!(sorted(axfr), a);

    // BIND's dump lists names in DNSSEC canonical order (RFC 4034 §6.1),
    // NSEC3-type owners aside (BIND keeps those in a separate tree).
    let owners: Vec<&NameBuf> = canonical
        .iter()
        .filter(|r| r.rtype != Rtype::NSEC3)
        .map(|r| &r.name)
        .collect();
    assert!(owners.windows(2).all(|w| w[0] <= w[1]), "canonical order");
}

/// dnsbox displays every record of BIND's canonical dump as BIND does.
/// BIND splits long base64/hex fields into 56-character chunks, so lines
/// may differ in spacing inside the RDATA; [`BIND_STYLE`] lists the few
/// other differences.
#[test]
fn alltypes_display_matches_bind() {
    let text = bind9("alltypes.canonical");
    let records = read_zone(&text);
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| !l.starts_with(';') && !l.trim().is_empty())
        .collect();
    assert_eq!(lines.len(), records.len());
    let mut failures = String::new();
    let mut chunked = 0;
    for (line, rec) in lines.iter().zip(&records) {
        let theirs: Vec<&str> = line.split_whitespace().collect();
        let ours = rec.as_record().to_string();
        let ours_fields: Vec<&str> = ours.split_whitespace().collect();
        // Owner, TTL, class and type.
        assert_eq!(theirs[..4], ours_fields[..4], "{line}");
        let rdata_theirs = rdata_of(line);
        let rdata_ours = rdata_of(&ours);
        let expected = BIND_STYLE
            .iter()
            .find(|(t, _)| *t == rdata_theirs)
            .map_or(rdata_theirs, |(_, o)| o);
        if rdata_ours == expected {
            continue;
        }
        if rdata_ours.replace(' ', "") == expected.replace(' ', "") {
            chunked += 1;
            continue;
        }
        failures += &format!("\n  bind:   {line}\n  dnsbox: {ours}");
    }
    assert!(failures.is_empty(), "{failures}");
    assert!(chunked < 20, "{chunked} lines differ in spacing");
}

/// BIND reads dnsbox's presentation of every record back to the same
/// zone: `alltypes.dnsbox` is dnsbox's display of BIND's dump (this test
/// rewrites it when `DNSBOX_WRITE_ALLTYPES` is set, and otherwise checks
/// it is current), and `alltypes.dnsbox.canonical` is what
/// `named-checkzone -D` made of it (`gen.sh`): BIND's own dump again.
#[test]
fn bind_reads_dnsbox_text() {
    let records = read_zone(&bind9("alltypes.canonical"));
    let mut ours = String::from(
        "; dnsbox's display of alltypes.canonical (tests/interop_zones.rs).\n$TTL 3600\n",
    );
    for r in &records {
        ours += &format!("{}\n", r.as_record());
    }
    let path = format!(
        "{}/tests/corpus/bind9/alltypes.dnsbox",
        env!("CARGO_MANIFEST_DIR")
    );
    if std::env::var_os("DNSBOX_WRITE_ALLTYPES").is_some() {
        fs::write(&path, &ours).unwrap();
    }
    assert_eq!(
        bind9("alltypes.dnsbox"),
        ours,
        "rerun with DNSBOX_WRITE_ALLTYPES=1, then gen.sh"
    );
    assert_eq!(
        bind9("alltypes.dnsbox.canonical"),
        bind9("alltypes.canonical")
    );
}

/// The RDATA part of a record line: what follows owner, TTL, class and
/// type.
fn rdata_of(line: &str) -> &str {
    let mut rest = line.trim_start();
    for _ in 0..4 {
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        rest = rest[end..].trim_start();
    }
    rest.trim_end()
}

/// ldns 1.8 (`ldns-read-zone`) rewrote BIND's dump of alltypes.zone in its
/// own presentation style (`tests/corpus/ldns/alltypes.ldns`: unquoted
/// SvcParam values, uncompressed IPv6 in APL, service names in WKS, raw
/// tabs in strings, trailing blanks, `;{id = ...}` comments): dnsbox reads
/// every record back to BIND's data.
#[test]
fn ldns_text_reads_as_bind_data() {
    // What ldns-read-zone was not given (see ldns/gen.sh) or writes
    // wrongly: UINFO, UID, GID and UNSPEC come out as "TYPE0", and the
    // NSAP-PTR name as a quoted string (which neither BIND nor dnsbox
    // reads as a name).
    let skipped = |line: &str| {
        let ty = line.split_whitespace().nth(3).unwrap_or("");
        matches!(
            ty,
            "A6" | "ATMA"
                | "AVC"
                | "NINFO"
                | "NXT"
                | "RKEY"
                | "SINK"
                | "TA"
                | "UINFO"
                | "UID"
                | "GID"
                | "UNSPEC"
                | "NSAP-PTR"
        ) || line.contains("NSEC3RSASHA1")
            || line.contains("NSEC3DSA")
            || line.trim_end().ends_with("CSYNC\t0 0")
            || line.trim_end().ends_with("KEY\t49664 3 5")
    };
    let bind = bind9("alltypes.canonical");
    let bind: String = bind
        .lines()
        .filter(|l| !skipped(l))
        .map(|l| format!("{l}\n"))
        .collect();
    let bind = read_zone(&bind);
    let ldns = read("ldns", "alltypes.ldns");
    let ty = |l: &str| l.split_whitespace().nth(3).unwrap_or("").to_owned();
    assert_eq!(ldns.lines().filter(|l| ty(l) == "TYPE0").count(), 4);
    let ldns: String = ldns
        .lines()
        .filter(|l| !matches!(ty(l).as_str(), "TYPE0" | "NSAP-PTR"))
        .map(|l| format!("{l}\n"))
        .collect();
    let ldns = read_zone(&ldns);
    assert!(ldns.len() >= 130, "{} records", ldns.len());
    assert_eq!(
        sorted(ldns.iter().map(rr).collect()),
        sorted(bind.iter().map(rr).collect())
    );
}

/// RDATA that dnsbox writes differently from BIND 9.18 (BIND, dnsbox),
/// each still read by both.
const BIND_STYLE: &[(&str, &str)] = &[
    // CERT algorithms 6 and 7 have three different mnemonics (IANA, BIND,
    // dnspython); dnsbox writes the number (RFC 4398 §2.2).
    ("IPGP 1 NSEC3RSASHA1 AQID", "IPGP 1 7 AQID"),
    ("OID 1 NSEC3DSA AQID", "OID 1 6 AQID"),
    // ILNP values: dnsbox keeps the four hex digits of every group, as in
    // the RFC 6742 examples; BIND drops leading zeros.
    ("10 2001:db8:1140:1000", "10 2001:0db8:1140:1000"),
    ("10 14:4fff:ff20:ee64", "10 0014:4fff:ff20:ee64"),
    // A type without mnemonic is TYPE0 in RFC 3597 §5 form; BIND writes a
    // bare number in SIG records.
    (
        "0 15 0 0 20261004090347 20261004085347 43160 sig0.alltypes.example. AAAA",
        "TYPE0 15 0 0 20261004090347 20261004085347 43160 sig0.alltypes.example. AAAA",
    ),
    // BIND 9.18 predates the dohpath key (RFC 9461).
    (
        "1 doh.example. alpn=\"h2\" key7=\"/dns-query{?dns}\"",
        "1 doh.example. alpn=\"h2\" dohpath=\"/dns-query{?dns}\"",
    ),
];

// ---------------------------------------------------------------------
// Signed zones.
// ---------------------------------------------------------------------

#[cfg(feature = "dnssec")]
mod signed {
    use super::*;
    use dnsbox::dnssec::{
        Algorithm, Answer, Denial, DenialProof, DenialStatus, DigestType, InsecureReason,
        Nsec3Proof, Nsec3Record, NsecProof, NsecRecord, PurecryptoNsec3Hasher, PurecryptoVerifier,
        Rrset, Signer, SigningKey, TrustedKeys, ZoneKey, nsec3_hash, sign_rrset, verify_ds,
        verify_rrsig,
    };
    use dnsbox::rdata::{Dnskey, Ds, Nsec, Nsec3, Rrsig};
    use dnsbox::{Name, Section};

    /// Inside the signatures' validity (2026-01-01 to 2036-01-01).
    const NOW: u32 = 1_791_105_383;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Chain {
        Nsec,
        Nsec3,
        OptOut,
    }

    /// The signer of a zone.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Tool {
        /// BIND 9.18 `dnssec-signzone` (`tests/corpus/bind9/`, zone
        /// `<name>.example.`).
        Bind,
        /// ldns 1.8 `ldns-signzone`, with ZONEMD (`tests/corpus/ldns/`,
        /// zone `ldns-<name>.example.`).
        Ldns,
    }

    /// (signer, file name, algorithm, denial chain), as in the gen.sh
    /// scripts.
    const ZONES: &[(Tool, &str, Algorithm, Chain)] = &[
        (Tool::Bind, "rsasha1", Algorithm::RSASHA1, Chain::Nsec),
        (
            Tool::Bind,
            "nsec3rsasha1",
            Algorithm::RSASHA1_NSEC3_SHA1,
            Chain::Nsec3,
        ),
        (Tool::Bind, "rsasha256", Algorithm::RSASHA256, Chain::OptOut),
        (Tool::Bind, "rsasha512", Algorithm::RSASHA512, Chain::Nsec),
        (
            Tool::Bind,
            "ecdsap256",
            Algorithm::ECDSAP256SHA256,
            Chain::Nsec3,
        ),
        (
            Tool::Bind,
            "ecdsap384",
            Algorithm::ECDSAP384SHA384,
            Chain::Nsec,
        ),
        (Tool::Bind, "ed25519", Algorithm::ED25519, Chain::OptOut),
        (Tool::Bind, "ed448", Algorithm::ED448, Chain::Nsec),
        (Tool::Ldns, "ed25519", Algorithm::ED25519, Chain::Nsec3),
        (Tool::Ldns, "rsasha256", Algorithm::RSASHA256, Chain::OptOut),
        (
            Tool::Ldns,
            "ecdsap256",
            Algorithm::ECDSAP256SHA256,
            Chain::Nsec,
        ),
    ];

    /// A signed zone as dnsbox read it.
    struct Zone {
        tool: Tool,
        dir: &'static str,
        name: &'static str,
        algorithm: Algorithm,
        chain: Chain,
        apex: NameBuf,
        records: Vec<ZoneRecordBuf>,
        ds: Vec<ZoneRecordBuf>,
    }

    impl Zone {
        fn load(&(tool, name, algorithm, chain): &(Tool, &'static str, Algorithm, Chain)) -> Zone {
            let (dir, apex) = match tool {
                Tool::Bind => ("bind9", format!("{name}.example.")),
                Tool::Ldns => ("ldns", format!("ldns-{name}.example.")),
            };
            let records = read_zone(&read(dir, &format!("{name}.signed")));
            let ds = read_zone(&read(dir, &format!("{name}.ds")));
            Zone {
                tool,
                dir,
                name,
                algorithm,
                chain,
                apex: apex.parse().unwrap(),
                records,
                ds,
            }
        }

        fn dnskeys(&self) -> Vec<Dnskey<'_>> {
            self.of_type(&self.apex, Rtype::DNSKEY)
                .map(|r| match r.data().unwrap() {
                    RData::Dnskey(k) => k,
                    _ => unreachable!(),
                })
                .collect()
        }

        fn ds(&self) -> Vec<Ds<'_>> {
            self.ds
                .iter()
                .map(|r| match r.data().unwrap() {
                    RData::Ds(d) => d,
                    _ => unreachable!(),
                })
                .collect()
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

        /// The RRSIGs over `rtype` at `owner`.
        fn rrsigs<'s>(&'s self, owner: &'s NameBuf, rtype: Rtype) -> Vec<Rrsig<'s>> {
            self.of_type(owner, Rtype::RRSIG)
                .map(|r| match r.data().unwrap() {
                    RData::Rrsig(s) => s,
                    _ => unreachable!(),
                })
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
                .filter(|r| r.rtype == Rtype::NS && r.name != self.apex)
                .map(|r| r.name.clone())
                .collect()
        }

        /// Whether `name` is glue / occluded (strictly below a cut).
        fn below_cut(&self, name: &NameBuf) -> bool {
            self.cuts()
                .iter()
                .any(|c| name != c && name.as_name().is_subdomain_of(&c.as_name()))
        }

        fn trusted(&self) -> TrustedKeys<'_, Vec<Dnskey<'_>>> {
            let mut scratch = Vec::new();
            TrustedKeys::from_ds(
                &PurecryptoVerifier,
                Rrset::new(self.apex.as_name(), Class::IN, self.dnskeys()),
                self.ds(),
                self.rrsigs(&self.apex, Rtype::DNSKEY),
                NOW,
                &mut scratch,
            )
            .unwrap_or_else(|e| panic!("{}: DNSKEY from DS: {e}", self.apex))
        }

        /// The zone's signing keys from the `.keys` file, by key tag.
        fn signing_keys(&self) -> Vec<(u16, SigningKey)> {
            let text = read(self.dir, &format!("{}.keys", self.name));
            let mut out = Vec::new();
            let mut fields: BTreeMap<String, Vec<u8>> = BTreeMap::new();
            let mut tag = 0;
            let mut flush = |tag: u16, fields: &mut BTreeMap<String, Vec<u8>>| {
                if fields.is_empty() {
                    return;
                }
                let f = |k: &str| fields.get(k).map_or(&[][..], Vec::as_slice);
                let key = if self.algorithm.is_rsa() {
                    SigningKey::from_rsa_components(
                        self.algorithm,
                        f("Modulus"),
                        f("PublicExponent"),
                        f("PrivateExponent"),
                        f("Prime1"),
                        f("Prime2"),
                    )
                } else {
                    SigningKey::from_private_bytes(self.algorithm, f("PrivateKey"))
                };
                out.push((tag, key.unwrap()));
                fields.clear();
            };
            for line in text.lines() {
                if let Some(file) = line.strip_prefix("; K").filter(|l| l.ends_with(".private")) {
                    flush(tag, &mut fields);
                    // K<zone>.+<alg>+<tag>.private
                    let t = file.rsplit('+').next().unwrap();
                    tag = t.trim_end_matches(".private").parse().unwrap();
                } else if let Some(field) = line.strip_prefix(";! ") {
                    // The key material of the private-key format (BIND's
                    // v1.3, ldns's v1.2): base64 fields.
                    let (k, v) = field.split_once(": ").unwrap();
                    if matches!(
                        k,
                        "Modulus"
                            | "PublicExponent"
                            | "PrivateExponent"
                            | "Prime1"
                            | "Prime2"
                            | "PrivateKey"
                    ) {
                        fields.insert(k.to_owned(), base64(v).unwrap());
                    }
                }
            }
            flush(tag, &mut fields);
            out
        }
    }

    /// Decodes standard base64 (`None` if it is not).
    fn base64(s: &str) -> Option<Vec<u8>> {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let s = s.trim();
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

    fn data_of<'a, T: dnsbox::rdata::ParseRdata<'a>>(r: &'a ZoneRecordBuf) -> T {
        T::parse_rdata(&mut dnsbox::WireReader::new(&r.rdata)).unwrap()
    }

    #[test]
    fn keys_authenticate_from_every_ds_digest() {
        for z in ZONES.iter().map(Zone::load) {
            let keys = z.dnskeys();
            assert_eq!(keys.len(), 2, "{}", z.apex);
            let ds = z.ds();
            let digests: Vec<DigestType> = ds.iter().map(|d| d.digest_type).collect();
            assert_eq!(
                digests,
                [DigestType::SHA1, DigestType::SHA256, DigestType::SHA384],
                "{}",
                z.apex
            );
            let ksk = keys.iter().find(|k| k.is_sep()).unwrap();
            for d in &ds {
                verify_ds(d, z.apex.as_name(), ksk).unwrap();
                assert_eq!(d.key_tag, ksk.key_tag());
                assert_eq!(d.algorithm, z.algorithm);
                // Each digest alone authenticates the DNSKEY RRset.
                TrustedKeys::from_ds(
                    &PurecryptoVerifier,
                    Rrset::new(z.apex.as_name(), Class::IN, keys.clone()),
                    [*d],
                    z.rrsigs(&z.apex, Rtype::DNSKEY),
                    NOW,
                    &mut Vec::new(),
                )
                .unwrap_or_else(|e| panic!("{} {:?}: {e}", z.apex, d.digest_type));
            }
            // And the DS set as a whole.
            assert_eq!(z.trusted().zone(), z.apex.as_name());
        }
    }

    /// Every RRSIG BIND made verifies, and BIND signed exactly the
    /// RRsets dnsbox expects: everything but delegation NS and glue, the
    /// DNSKEY RRset with the KSK only (`-x`), the rest with the ZSK.
    #[test]
    fn every_signature_verifies() {
        let mut total = 0;
        for z in ZONES.iter().map(Zone::load) {
            let keys = z.dnskeys();
            let ksk = *keys.iter().find(|k| k.is_sep()).unwrap();
            let zsk = *keys.iter().find(|k| !k.is_sep()).unwrap();
            let mut scratch = Vec::new();
            for (owner, rtype) in z.rrsets() {
                let rdata: Vec<RData<'_>> = z
                    .of_type(&owner, rtype)
                    .map(|r| r.data().unwrap())
                    .collect();
                let sigs = z.rrsigs(&owner, rtype);
                let unsigned = z.below_cut(&owner) || (rtype == Rtype::NS && owner != z.apex);
                assert_eq!(sigs.is_empty(), unsigned, "{} {owner} {rtype}", z.apex);
                for sig in &sigs {
                    let key = if rtype == Rtype::DNSKEY { ksk } else { zsk };
                    assert_eq!(sig.key_tag, key.key_tag(), "{} {owner} {rtype}", z.apex);
                    assert_eq!(
                        sig.original_ttl,
                        z.of_type(&owner, rtype).next().unwrap().ttl
                    );
                    verify_rrsig(
                        &PurecryptoVerifier,
                        &ZoneKey::new(z.apex.as_name(), key),
                        sig,
                        Rrset::new(owner.as_name(), Class::IN, &rdata),
                        NOW,
                        &mut scratch,
                    )
                    .unwrap_or_else(|e| panic!("{} {owner} {rtype}: {e}", z.apex));
                    total += 1;
                }
                // Through the chain of trust as well.
                if !sigs.is_empty() {
                    z.trusted()
                        .verify_rrset(
                            &PurecryptoVerifier,
                            Rrset::new(owner.as_name(), Class::IN, &rdata),
                            sigs.iter().copied(),
                            NOW,
                            &mut scratch,
                        )
                        .unwrap();
                }
            }
        }
        assert!(total >= 150, "{total} signatures");
    }

    /// With the deterministic algorithms (RSA PKCS#1 v1.5, Ed25519, Ed448)
    /// dnsbox's signer reproduces BIND's signatures byte for byte, which
    /// pins down the signed data (RFC 4034 §3.1.8.1, canonical RRset order
    /// and RDATA forms) for every type in the zone.
    #[test]
    fn dnsbox_resigns_to_signer_bytes() {
        let mut total = 0;
        for z in ZONES.iter().map(Zone::load) {
            if matches!(
                z.algorithm,
                Algorithm::ECDSAP256SHA256 | Algorithm::ECDSAP384SHA384
            ) {
                continue; // BIND (OpenSSL) signs ECDSA with random nonces.
            }
            let signers = z.signing_keys();
            assert_eq!(signers.len(), 2, "{}", z.apex);
            let mut scratch = Vec::new();
            for (owner, rtype) in z.rrsets() {
                let rdata: Vec<RData<'_>> = z
                    .of_type(&owner, rtype)
                    .map(|r| r.data().unwrap())
                    .collect();
                for sig in z.rrsigs(&owner, rtype) {
                    let (_, signer) = signers.iter().find(|(t, _)| *t == sig.key_tag).unwrap();
                    let mut out = [0u8; 512];
                    let len = sign_rrset(
                        signer,
                        &sig,
                        Rrset::new(owner.as_name(), Class::IN, &rdata),
                        &mut scratch,
                        &mut out,
                    )
                    .unwrap();
                    assert_eq!(&out[..len], sig.signature, "{} {owner} {rtype}", z.apex);
                    total += 1;
                }
            }
            // The DNSKEYs dnsbox derives from the private keys are BIND's.
            for (tag, signer) in &signers {
                let k = z
                    .dnskeys()
                    .into_iter()
                    .find(|k| k.key_tag() == *tag)
                    .unwrap();
                assert_eq!(signer.public_key(), k.public_key, "{}", z.apex);
            }
        }
        assert!(total >= 90, "{total} signatures");
    }

    /// ldns-signzone adds ZONEMD records (RFC 8976) with SHA-384 and
    /// SHA-512 and signs them (their RRSIGs are checked with the others):
    /// dnsbox computes the same digests over the signed zone.
    #[test]
    fn ldns_zonemd_digests() {
        use dnsbox::dnssec::{ZonemdRecord, verify_zonemd, zonemd_digest};
        use dnsbox::rdata::Zonemd;
        for z in ZONES
            .iter()
            .map(Zone::load)
            .filter(|z| z.tool == Tool::Ldns)
        {
            let records = || {
                z.records
                    .iter()
                    .map(|r| ZonemdRecord::new(r.name.as_name(), r.class, r.ttl, r.data().unwrap()))
            };
            let verified = verify_zonemd(z.apex.as_name(), records())
                .unwrap_or_else(|e| panic!("{}: {e}", z.apex));
            assert_eq!(verified.serial, 2026100401);
            let zonemds: Vec<Zonemd<'_>> = z.of_type(&z.apex, Rtype::ZONEMD).map(data_of).collect();
            assert_eq!(zonemds.len(), 2, "{}", z.apex);
            for zm in zonemds {
                let ours = zonemd_digest(z.apex.as_name(), records(), zm.hash_alg).unwrap();
                assert_eq!(ours.as_bytes(), zm.digest, "{} {}", z.apex, zm.hash_alg);
            }
            assert_eq!(z.rrsigs(&z.apex, Rtype::ZONEMD).len(), 1, "{}", z.apex);
        }
    }

    /// The names of the zone that NSEC/NSEC3 chains cover, with their
    /// types: authoritative owners (not below a cut) and, for NSEC3, the
    /// empty non-terminals; NSEC/NSEC3 records themselves excluded.
    fn names(z: &Zone) -> BTreeMap<NameBuf, BTreeSet<Rtype>> {
        let mut names: BTreeMap<NameBuf, BTreeSet<Rtype>> = BTreeMap::new();
        for r in &z.records {
            if z.below_cut(&r.name) || matches!(r.rtype, Rtype::NSEC | Rtype::NSEC3) {
                continue;
            }
            if r.name.as_name().label_count() == z.apex.as_name().label_count() + 1
                && r.rtype == Rtype::RRSIG
                && data_of::<Rrsig<'_>>(r).type_covered == Rtype::NSEC3
            {
                continue; // The signature of an NSEC3 record.
            }
            names.entry(r.name.clone()).or_default().insert(r.rtype);
            let mut n = r.name.as_name();
            while let Some(p) = n.parent() {
                if !p.is_subdomain_of(&z.apex.as_name()) {
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
        for z in ZONES
            .iter()
            .map(Zone::load)
            .filter(|z| z.chain == Chain::Nsec)
        {
            let names = names(&z);
            // Only names with records own an NSEC (no NSEC at empty
            // non-terminals), in canonical order, each pointing at the
            // next and the last back to the apex.
            let owners: Vec<&NameBuf> = names
                .iter()
                .filter(|(_, t)| !t.is_empty())
                .map(|(n, _)| n)
                .collect();
            // (dnssec-signzone writes names in its own order, not canonical.)
            let mut nsecs: Vec<&ZoneRecordBuf> = z
                .records
                .iter()
                .filter(|r| r.rtype == Rtype::NSEC)
                .collect();
            nsecs.sort_by(|a, b| a.name.cmp(&b.name));
            let nsec_owners: Vec<&NameBuf> = nsecs.iter().map(|r| &r.name).collect();
            assert_eq!(nsec_owners, owners, "{}", z.apex);
            for (i, r) in nsecs.iter().enumerate() {
                let nsec: Nsec<'_> = data_of(r);
                let next = owners[(i + 1) % owners.len()];
                assert_eq!(
                    nsec.next_domain_name,
                    next.as_name(),
                    "{} {}",
                    z.apex,
                    r.name
                );
                let mut types: BTreeSet<Rtype> = names[&r.name].clone();
                types.insert(Rtype::NSEC);
                assert_eq!(
                    nsec.types.iter().collect::<BTreeSet<_>>(),
                    types,
                    "{} {}",
                    z.apex,
                    r.name
                );
            }
        }
    }

    #[test]
    fn nsec3_chains_match_dnsbox_hashes() {
        for z in ZONES
            .iter()
            .map(Zone::load)
            .filter(|z| z.chain != Chain::Nsec)
        {
            let param = z.of_type(&z.apex, Rtype::NSEC3PARAM).next().unwrap();
            let param: dnsbox::rdata::Nsec3param<'_> = data_of(param);
            // With Opt-Out, BIND leaves unsigned delegations (NS without
            // DS) out of the chain (RFC 5155 §7.1 allows it); ldns only
            // sets the flag and keeps them.
            let unsigned = |n: &NameBuf, t: &BTreeSet<Rtype>| {
                *n != z.apex && t.contains(&Rtype::NS) && !t.contains(&Rtype::DS)
            };
            let omits_unsigned = z.chain == Chain::OptOut && z.tool == Tool::Bind;
            let mut expected: BTreeMap<NameBuf, BTreeSet<Rtype>> = BTreeMap::new();
            for (name, types) in names(&z) {
                if omits_unsigned && unsigned(&name, &types) {
                    continue;
                }
                let h = nsec3_hash(
                    name.as_name(),
                    param.hash_algorithm,
                    param.iterations,
                    param.salt,
                )
                .unwrap();
                expected.insert(h.owner_name(z.apex.as_name()).unwrap(), types);
            }
            let mut nsec3s: Vec<&ZoneRecordBuf> = z
                .records
                .iter()
                .filter(|r| r.rtype == Rtype::NSEC3)
                .collect();
            nsec3s.sort_by(|a, b| a.name.cmp(&b.name));
            let owners: Vec<&NameBuf> = nsec3s.iter().map(|r| &r.name).collect();
            assert_eq!(owners, expected.keys().collect::<Vec<_>>(), "{}", z.apex);
            for (i, r) in nsec3s.iter().enumerate() {
                let n: Nsec3<'_> = data_of(r);
                assert_eq!(
                    (n.hash_algorithm, n.iterations, n.salt),
                    (param.hash_algorithm, param.iterations, param.salt)
                );
                assert_eq!(n.flags, u8::from(z.chain == Chain::OptOut), "{}", z.apex);
                let next = owners[(i + 1) % owners.len()];
                let next = dnsbox::dnssec::Nsec3Hash::from_owner(next.as_name()).unwrap();
                assert_eq!(
                    n.next_hashed_owner,
                    next.as_bytes(),
                    "{} {}",
                    z.apex,
                    r.name
                );
                assert_eq!(
                    n.types.iter().collect::<BTreeSet<_>>(),
                    expected[&r.name],
                    "{} {}",
                    z.apex,
                    r.name
                );
            }
        }
    }

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
        /// A referral: the denial proof for an unsigned delegation, or
        /// none (signed delegation, DS in the authority section).
        Referral(Option<DenialStatus>),
    }

    fn expectations(chain: Chain) -> Vec<(&'static str, &'static str, Rtype, Expect)> {
        use Expect::*;
        // With Opt-Out (`dnssec-signzone -A` sets it on every NSEC3), a
        // proof that relies on a record covering a name, rather than
        // matching it, leaves the response insecure (RFC 5155 §9.2):
        // an unsigned delegation may hide in the span.
        let secure = |d| {
            if chain == Chain::OptOut {
                DenialStatus::Insecure(InsecureReason::OptOut)
            } else {
                DenialStatus::Secure(d)
            }
        };
        let matched = DenialStatus::Secure;
        // A DS query at an unsigned delegation: NODATA at a delegation is
        // the proof that it is unsigned (and with Opt-Out the delegation
        // has no NSEC3 record of its own).
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

    #[test]
    fn named_responses_verify_and_prove() {
        let mut checked = 0;
        for z in ZONES
            .iter()
            .map(Zone::load)
            .filter(|z| z.tool == Tool::Bind)
        {
            let keys = z.trusted();
            for (case, rel, qtype, expect) in expectations(z.chain) {
                let label = format!("named-{}-{case}", z.name);
                let wire = corpus(&label);
                let msg = Message::parse_validated(&wire).unwrap();
                let q = msg.questions().next().unwrap().unwrap();
                let qname: NameBuf = if rel.is_empty() {
                    z.apex.clone()
                } else {
                    format!("{rel}.{}", z.apex).parse().unwrap()
                };
                assert_eq!(
                    (q.name().to_buf(), q.qtype()),
                    (qname.clone(), qtype),
                    "{label}"
                );
                let mut scratch = Vec::new();

                // Every signed RRset in the answer and authority sections
                // verifies; the unsigned ones are what RFC 4035 leaves
                // unsigned (referral NS, the CNAME a DNAME synthesizes).
                let mut wildcard = None;
                for section in [Section::Answer, Section::Authority] {
                    for (owner, rtype) in rrsets_of(&msg, section) {
                        let records: Vec<_> = msg
                            .records()
                            .map(Result::unwrap)
                            .filter(|(s, r)| *s == section && r.name() == owner.as_name())
                            .map(|(_, r)| r)
                            .collect();
                        let rdata: Vec<RData<'_>> = records
                            .iter()
                            .filter(|r| r.rtype() == rtype)
                            .map(|r| r.data().unwrap())
                            .collect();
                        let sigs: Vec<Rrsig<'_>> = records
                            .iter()
                            .filter_map(|r| r.data_as::<Rrsig<'_>>().ok())
                            .filter(|s| s.type_covered == rtype)
                            .collect();
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
                                NOW,
                                &mut scratch,
                            )
                            .unwrap_or_else(|e| panic!("{label}: {owner} {rtype}: {e}"));
                        if v.wildcard.is_some() {
                            wildcard = Some((owner.clone(), rtype));
                        }
                    }
                }

                let authority = || {
                    msg.authority()
                        .map(Result::unwrap)
                        .filter(|r| matches!(r.rtype(), Rtype::NSEC | Rtype::NSEC3))
                };
                let nsec: Vec<NsecRecord<'_>> = authority()
                    .filter_map(|r| NsecRecord::from_record(&r))
                    .collect();
                let nsec3: Vec<Nsec3Record<'_>> = authority()
                    .filter_map(|r| Nsec3Record::from_record(&r))
                    .collect();
                let apex = z.apex.as_name();
                let status = |f: &dyn Fn(&dyn DenialProof) -> DenialStatus| match z.chain {
                    Chain::Nsec => f(&NsecProof::new(apex, &nsec)),
                    _ => f(&Nsec3Proof::new(apex, &nsec3, PurecryptoNsec3Hasher)),
                };
                let qn: Name<'_> = qname.as_name();
                match expect {
                    Expect::Positive => {
                        assert!(msg.header().ancount > 0, "{label}");
                        assert!(wildcard.is_none(), "{label}");
                    }
                    Expect::Wildcard(want) => {
                        let (owner, rtype) = wildcard.expect("a wildcard expansion");
                        assert_eq!((owner, rtype), (qname.clone(), qtype));
                        let rdata: Vec<RData<'_>> = msg
                            .answers()
                            .map(Result::unwrap)
                            .filter(|r| r.rtype() == qtype)
                            .map(|r| r.data().unwrap())
                            .collect();
                        let sigs: Vec<Rrsig<'_>> = msg
                            .answers()
                            .map(Result::unwrap)
                            .filter_map(|r| r.data_as::<Rrsig<'_>>().ok())
                            .collect();
                        let run = |proof: &dyn DenialProof| {
                            keys.verify_answer(
                                &PurecryptoVerifier,
                                Rrset::new(qn, Class::IN, &rdata),
                                sigs.iter().copied(),
                                proof,
                                NOW,
                                &mut Vec::new(),
                            )
                            .unwrap()
                        };
                        let answer = match z.chain {
                            Chain::Nsec => run(&NsecProof::new(apex, &nsec)),
                            _ => run(&Nsec3Proof::new(apex, &nsec3, PurecryptoNsec3Hasher)),
                        };
                        let Answer::Wildcard { proof, .. } = answer else {
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
                        let cut: NameBuf = format!("{}.{}", rel.split('.').nth(1).unwrap(), z.apex)
                            .parse()
                            .unwrap();
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
        assert_eq!(checked, 8 * 12);
    }
}
