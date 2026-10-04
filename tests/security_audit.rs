//! Regression tests for the findings of the Milestone 9 security audit
//! (see `SECURITY.md`): each test reproduces one issue as an attacker
//! would trigger it and checks the hardened behaviour.

#![allow(clippy::unwrap_used)]

use dnsbox::{Class, Error, Message, MessageBuilder, NameBuf, Rtype};

fn name(s: &str) -> NameBuf {
    s.parse().unwrap()
}

// ---------------------------------------------------------------------------
// TSIG / SIG(0): bytes after the signature record are not authenticated.
// ---------------------------------------------------------------------------

/// A signed request with `extra` appended after its last record.
#[cfg(feature = "tsig")]
fn tsig_request(key: &dnsbox::tsig::HmacKey<'_>, now: u64, extra: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use dnsbox::tsig::TsigSigner;
    let mut buf = vec![0u8; 512];
    let mut b =
        MessageBuilder::query(&mut buf, 0x1234, name("example."), Rtype::SOA, Class::IN).unwrap();
    let mac = TsigSigner::request(key).sign(&mut b, now).unwrap();
    let mut wire = b.finish().to_vec();
    wire.extend_from_slice(extra);
    (wire, mac.as_slice().to_vec())
}

/// RFC 8945 §4.2/§5.1: the TSIG is the last record of the message and its
/// MAC covers everything before it. Octets after it are covered by nothing:
/// a server that accepted them as part of a verified request would act on
/// (or forward) unauthenticated bytes.
#[cfg(feature = "tsig")]
#[test]
fn tsig_rejects_trailing_bytes() {
    use dnsbox::tsig::{HmacKey, RequestStatus, TsigAlgorithm, verify_request};
    let now = 1_800_000_000;
    let key = HmacKey::new(name("key."), TsigAlgorithm::HmacSha256, b"secret");
    let (wire, _) = tsig_request(&key, now, &[]);
    let msg = Message::parse(&wire).unwrap();
    assert!(matches!(
        verify_request(&msg, &key, now),
        RequestStatus::Verified(_)
    ));

    let (wire, _) = tsig_request(&key, now, b"\x00injected");
    let msg = Message::parse(&wire).unwrap();
    let status = verify_request(&msg, &key, now);
    assert_eq!(status.error(), Some(Error::TrailingData), "{status:?}");
    assert_eq!(
        dnsbox::tsig::response_codes(Error::TrailingData).0,
        dnsbox::Rcode::FORMERR
    );
}

/// The same for a client verifying a signed response.
#[cfg(feature = "tsig")]
#[test]
fn tsig_response_rejects_trailing_bytes() {
    use dnsbox::tsig::{HmacKey, TsigAlgorithm, TsigVerifier, verify_request};
    let now = 1_800_000_000;
    let key = HmacKey::new(name("key."), TsigAlgorithm::HmacSha256, b"secret");
    let (request, request_mac) = tsig_request(&key, now, &[]);
    let verified = verify_request(&Message::parse(&request).unwrap(), &key, now)
        .verified()
        .unwrap();
    let mut buf = vec![0u8; 512];
    let mut b = MessageBuilder::response(&mut buf, &Message::parse(&request).unwrap()).unwrap();
    verified.signer().sign(&mut b, now).unwrap();
    let mut response = b.finish().to_vec();

    let mut v = TsigVerifier::new(&key, &request_mac).unwrap();
    assert!(v.verify(&Message::parse(&response).unwrap(), now).is_ok());

    response.push(0);
    let mut v = TsigVerifier::new(&key, &request_mac).unwrap();
    assert_eq!(
        v.verify(&Message::parse(&response).unwrap(), now),
        Err(Error::TrailingData)
    );
}

/// RFC 2931 §3.1: a SIG(0) signs the message up to the SIG record, which
/// must be the last thing in it.
#[cfg(feature = "dnssec")]
#[test]
fn sig0_rejects_trailing_bytes() {
    use dnsbox::dnssec::{Algorithm, PurecryptoVerifier, SigningKey};
    use dnsbox::sig0::{self, DnssecSig0Signer, DnssecSig0Verifier, Validity};
    let now = 1_800_000_000;
    let key = SigningKey::from_private_bytes(Algorithm::ED25519, &[7; 32]).unwrap();
    let owner = name("client.example.");
    let signer = DnssecSig0Signer::new(&key, owner.as_name(), 512);
    let mut buf = vec![0u8; 512];
    let mut b = MessageBuilder::query(&mut buf, 7, &owner, Rtype::A, Class::IN).unwrap();
    sig0::sign(&mut b, &signer, Validity::around(now, 300), None).unwrap();
    let mut wire = b.finish().to_vec();
    let verifier = DnssecSig0Verifier::new(PurecryptoVerifier, owner.as_name(), signer.key());
    assert!(sig0::verify(&Message::parse(&wire).unwrap(), &verifier, now, None).is_ok());

    wire.extend_from_slice(b"\x00\x01");
    assert_eq!(
        sig0::verify(&Message::parse(&wire).unwrap(), &verifier, now, None),
        Err(Error::TrailingData)
    );
}

// ---------------------------------------------------------------------------
// RRSIG: the labels field may not put the source of synthesis above the
// signer's zone.
// ---------------------------------------------------------------------------

/// An RRSIG made by the zone's key over `owner`'s A RRset with the labels
/// field forced to `labels`, signed directly (as a hostile or buggy signer
/// would; `sign_rrset` refuses such a template).
#[cfg(feature = "dnssec")]
fn forged_labels_rrsig(
    key: &dnsbox::dnssec::SigningKey,
    zone_key: &dnsbox::dnssec::ZoneKey<'_>,
    owner: dnsbox::Name<'_>,
    labels: u8,
    class: Class,
    sig: &mut [u8; 64],
) -> usize {
    use dnsbox::dnssec::{Rrset, Signer, signed_data};
    use dnsbox::rdata::A;
    let mut template = zone_key.rrsig_template(owner, Rtype::A, 300, 1_000, 3_000);
    template.labels = labels;
    let rdata = [A::new([192, 0, 2, 1].into())];
    let mut scratch = Vec::new();
    signed_data(&mut scratch, &template, Rrset::new(owner, class, &rdata)).unwrap();
    key.sign(&scratch, sig).unwrap()
}

/// RFC 4035 §5.3.1: the RRSIG's signer must be the zone containing the
/// RRset, so a labels field smaller than the signer's own label count
/// (which would make the RRset an expansion of a wildcard *above* the zone,
/// here `*.`) is never valid.
#[cfg(feature = "dnssec")]
#[test]
fn rrsig_labels_below_signer_are_rejected() {
    use dnsbox::dnssec::{
        PurecryptoVerifier, Rrset, Signer, SigningKey, TrustedKeys, ZoneKey, verify_rrsig,
    };
    use dnsbox::rdata::{A, Dnskey};
    let key = SigningKey::from_private_bytes(dnsbox::dnssec::Algorithm::ED25519, &[9; 32]).unwrap();
    let zone = name("example.");
    let www = name("www.example.");
    let dnskey = key.dnskey(Dnskey::ZONE);
    let zone_key = ZoneKey::new(zone.as_name(), dnskey);
    let rdata = [A::new([192, 0, 2, 1].into())];
    let rrset = Rrset::new(www.as_name(), Class::IN, &rdata);
    let mut scratch = Vec::new();

    // The legitimate wildcard expansion from `*.example.` still verifies.
    let mut sig = [0u8; 64];
    let len = forged_labels_rrsig(&key, &zone_key, www.as_name(), 1, Class::IN, &mut sig);
    let template = zone_key.rrsig_template(www.as_name(), Rtype::A, 300, 1_000, 3_000);
    let ok = dnsbox::rdata::Rrsig {
        labels: 1,
        ..template
    }
    .with_signature(&sig[..len]);
    assert_eq!(
        verify_rrsig(
            &PurecryptoVerifier,
            &zone_key,
            &ok,
            rrset,
            2_000,
            &mut scratch
        ),
        Ok(())
    );

    // Labels 0: the signature covers `*.`, outside the zone.
    let len = forged_labels_rrsig(&key, &zone_key, www.as_name(), 0, Class::IN, &mut sig);
    let bad = dnsbox::rdata::Rrsig {
        labels: 0,
        ..template
    }
    .with_signature(&sig[..len]);
    assert_eq!(
        verify_rrsig(
            &PurecryptoVerifier,
            &zone_key,
            &bad,
            rrset,
            2_000,
            &mut scratch
        ),
        Err(Error::RrsetMismatch)
    );
    let keys = TrustedKeys::assume_trusted(zone.as_name(), Class::IN, [dnskey]);
    assert_eq!(
        keys.verify_rrset(&PurecryptoVerifier, rrset, [bad], 2_000, &mut scratch),
        Err(Error::RrsetMismatch)
    );
    // And no such template can be signed.
    let mut out = [0u8; 64];
    assert_eq!(
        dnsbox::dnssec::sign_rrset(
            &key,
            &dnsbox::rdata::Rrsig {
                labels: 0,
                ..template
            },
            rrset,
            &mut scratch,
            &mut out
        ),
        Err(Error::RrsetMismatch)
    );
    let _ = key.algorithm();
}

/// RFC 4035 §5.3.1: the RRSIG and the RRset must have the same class, and
/// keys of one class do not vouch for data of another.
#[cfg(feature = "dnssec")]
#[test]
fn trusted_keys_reject_other_class() {
    use dnsbox::dnssec::{PurecryptoVerifier, Rrset, Signer, SigningKey, TrustedKeys, ZoneKey};
    use dnsbox::rdata::{A, Dnskey};
    let key = SigningKey::from_private_bytes(dnsbox::dnssec::Algorithm::ED25519, &[9; 32]).unwrap();
    let zone = name("example.");
    let www = name("www.example.");
    let dnskey = key.dnskey(Dnskey::ZONE);
    let zone_key = ZoneKey::new(zone.as_name(), dnskey);
    let mut sig = [0u8; 64];
    let len = forged_labels_rrsig(&key, &zone_key, www.as_name(), 2, Class::CH, &mut sig);
    let rrsig = zone_key
        .rrsig_template(www.as_name(), Rtype::A, 300, 1_000, 3_000)
        .with_signature(&sig[..len]);
    let rdata = [A::new([192, 0, 2, 1].into())];
    let mut scratch = Vec::new();
    let keys = TrustedKeys::assume_trusted(zone.as_name(), Class::IN, [dnskey]);
    let ch = Rrset::new(www.as_name(), Class::CH, &rdata);
    assert_eq!(
        keys.verify_rrset(&PurecryptoVerifier, ch, [rrsig], 2_000, &mut scratch),
        Err(Error::RrsetMismatch)
    );
    let keys_ch = TrustedKeys::assume_trusted(zone.as_name(), Class::CH, [dnskey]);
    assert!(
        keys_ch
            .verify_rrset(&PurecryptoVerifier, ch, [rrsig], 2_000, &mut scratch)
            .is_ok()
    );
}

// ---------------------------------------------------------------------------
// NSEC3: a record whose hashes are shorter than the hash function's output
// must not cover anything.
// ---------------------------------------------------------------------------

/// RFC 5155 §3.1.7, §8.3: hashes compare as fixed-length octet strings. A
/// record whose owner and next hashes are a single octet (`00` to `ff`)
/// would otherwise "cover" almost every real 20-octet hash, denying any
/// name of the zone. (Unbound ignores such a record too.)
#[cfg(feature = "dnssec-digest")]
#[test]
fn nsec3_short_hash_covers_nothing() {
    use dnsbox::dnssec::{
        BogusReason, DenialStatus, Nsec3Hash, Nsec3HashAlgorithm, Nsec3Proof, Nsec3Record,
        PurecryptoNsec3Hasher, nsec3_hash,
    };
    use dnsbox::rdata::{Nsec3, TypeBitmap};
    use dnsbox::{Name, WireWriter};

    let zone = name("example.");
    let apex_hash = nsec3_hash(zone.as_name(), Nsec3HashAlgorithm::SHA1, 0, &[]).unwrap();
    let apex_owner = apex_hash.owner_name(zone.as_name()).unwrap();
    // The apex record's span ends right after it.
    let mut next = apex_hash.as_bytes().to_vec();
    *next.last_mut().unwrap() = next.last().unwrap().wrapping_add(1);
    let mut bits = [0u8; 32];
    let mut w = WireWriter::new(&mut bits);
    TypeBitmap::compose(&[Rtype::NS, Rtype::SOA], &mut w).unwrap();
    let apex_types = TypeBitmap::new(w.as_bytes()).unwrap();
    let nsec3 = |next: &'static [u8], types| Nsec3 {
        hash_algorithm: Nsec3HashAlgorithm::SHA1,
        flags: 0,
        iterations: 0,
        salt: &[],
        next_hashed_owner: next,
        types,
    };
    let next: &'static [u8] = Box::leak(next.into_boxed_slice());
    let short_owner = Nsec3Hash::new(&[0x00])
        .unwrap()
        .owner_name(zone.as_name())
        .unwrap();
    let records = [
        Nsec3Record::new(apex_owner.as_name(), nsec3(next, apex_types)),
        Nsec3Record::new(short_owner.as_name(), nsec3(&[0xff], TypeBitmap::default())),
    ];
    let proof = Nsec3Proof::new(zone.as_name(), &records, PurecryptoNsec3Hasher);
    let qname = name("www.example.");
    let h: Nsec3Hash = nsec3_hash(qname.as_name(), Nsec3HashAlgorithm::SHA1, 0, &[]).unwrap();
    assert_ne!(h.as_bytes()[0], 0xff);
    assert_eq!(
        proof.name_error(qname.as_name()),
        DenialStatus::Bogus(BogusReason::MissingProof)
    );
    let _: Name<'_> = qname.as_name();
}

// ---------------------------------------------------------------------------
// Denial proofs: a zone's apex is not its own delegation.
// ---------------------------------------------------------------------------

/// RFC 4035 §5.2, RFC 6840 §4.4: an unsigned delegation is proven by the
/// *parent's* record for a name strictly below the parent's apex, and the
/// DS RRset at a zone's apex lives in the parent. A zone's own apex record
/// that lacks SOA (only a hostile or broken signer produces one) must not
/// prove that the zone itself is an unsigned delegation.
#[test]
fn apex_is_not_its_own_delegation() {
    use dnsbox::dnssec::{BogusReason, DenialStatus, NsecProof, NsecRecord};
    use dnsbox::rdata::{Nsec, TypeBitmap};
    let zone = name("example.");
    let next = name("a.example.");
    let mut bits = [0u8; 32];
    let mut w = dnsbox::WireWriter::new(&mut bits);
    TypeBitmap::compose(&[Rtype::NS, Rtype::RRSIG, Rtype::NSEC], &mut w).unwrap();
    let types = TypeBitmap::new(w.as_bytes()).unwrap();
    let records = [NsecRecord::new(
        zone.as_name(),
        Nsec::new(next.as_name(), types),
    )];
    let proof = NsecProof::new(zone.as_name(), &records);
    let cut = DenialStatus::Bogus(BogusReason::ZoneCut);
    assert_eq!(proof.unsigned_delegation(zone.as_name()), cut);
    assert_eq!(proof.no_data(zone.as_name(), Rtype::DS), cut);
    // A real delegation below the apex still is one.
    let sub = name("sub.example.");
    let records = [NsecRecord::new(
        sub.as_name(),
        Nsec::new(next.as_name(), types),
    )];
    let proof = NsecProof::new(zone.as_name(), &records);
    assert!(proof.unsigned_delegation(sub.as_name()).is_secure());
    assert!(proof.no_data(sub.as_name(), Rtype::DS).is_secure());
}

// ---------------------------------------------------------------------------
// ZONEMD: many apex ZONEMD records must not cost quadratic time.
// ---------------------------------------------------------------------------

/// RFC 8976 §4 step 4 checks that (scheme, hash algorithm) tuples are
/// unique, and duplicate RRs are dropped while collating. Both used to
/// compare every apex ZONEMD RR with every other: a zone file (or transfer)
/// with 40 000 of them took minutes to reject. Now it is a sort.
#[cfg(all(feature = "alloc", feature = "dnssec-digest"))]
#[test]
fn zonemd_many_apex_records_are_not_quadratic() {
    use dnsbox::dnssec::{ZoneCollation, ZonemdFailure, ZonemdRecord};
    use dnsbox::rdata::{RData, Soa, Zonemd, ZonemdHashAlg, ZonemdScheme};
    use std::time::{Duration, Instant};

    const N: usize = 40_000;
    let apex = name("example.");
    let soa = Soa {
        mname: apex.as_name(),
        rname: apex.as_name(),
        serial: 1,
        refresh: 0,
        retry: 0,
        expire: 0,
        minimum: 0,
    };
    let digests: Vec<[u8; 48]> = (0..N)
        .map(|i| {
            let mut d = [0u8; 48];
            d[..8].copy_from_slice(&(i as u64).to_be_bytes());
            d
        })
        .collect();
    let mut records = vec![ZonemdRecord::new(
        apex.as_name(),
        Class::IN,
        0,
        RData::Soa(soa),
    )];
    for (i, d) in digests.iter().enumerate() {
        records.push(ZonemdRecord::new(
            apex.as_name(),
            Class::IN,
            0,
            RData::Zonemd(Zonemd {
                serial: 1,
                scheme: ZonemdScheme::SIMPLE,
                // Half SHA-384 with a 48-octet digest, half unknown.
                hash_alg: ZonemdHashAlg::new(if i % 2 == 0 { 1 } else { 200 }),
                digest: d,
            }),
        ));
    }
    // A duplicate of every tenth record, dropped while collating.
    let dups: Vec<_> = records.iter().skip(1).step_by(10).copied().collect();
    records.extend(dups);

    let start = Instant::now();
    let collation = ZoneCollation::new(apex.as_name(), records).unwrap();
    assert_eq!(collation.zonemd_rdata().count(), N);
    assert_eq!(collation.verify(), Err(ZonemdFailure::DuplicateTuple));
    let elapsed = start.elapsed();
    assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}");
}

// ---------------------------------------------------------------------------
// Buffers larger than a DNS message.
// ---------------------------------------------------------------------------

/// Nothing caps the slice handed to `Message::parse` at 65535 octets (a
/// caller may pass a whole read buffer). Records past offset 0xffff, and
/// owner names there that point back into the first 16 KiB, parse and
/// display like any other; the fuzzers (inputs of at most 4 KiB) never get
/// there.
#[test]
fn oversized_buffer_is_handled() {
    const N: u16 = 8000;
    let mut wire = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
    wire[6..8].copy_from_slice(&N.to_be_bytes());
    wire.extend_from_slice(b"\x07example\x00\x00\x01\x00\x01");
    for i in 0..N {
        // Owner: a label, then a pointer to the question name.
        wire.extend_from_slice(b"\x01a\xc0\x0c");
        wire.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        wire.extend_from_slice(&u32::from(i).to_be_bytes());
    }
    assert!(wire.len() > 100_000);
    let msg = Message::parse(&wire).unwrap();
    assert_eq!(msg.validate(), Ok(()));
    let mut n = 0;
    for rr in msg.answers() {
        let rr = rr.unwrap();
        assert_eq!(rr.name().to_string(), "a.example.");
        rr.data().unwrap();
        n += 1;
    }
    assert_eq!(n, N);
    assert!(msg.to_string().contains("a.example."));
    assert_eq!(dnsbox::tsig::find(&msg), Ok(None));
    assert_eq!(msg.edns().map(|e| e.is_some()), Ok(false));
    // Re-encoding cannot exceed 65535 octets.
    let mut out = vec![0u8; 200_000];
    let mut b = MessageBuilder::new(&mut out).unwrap();
    let mut copied = 0;
    for rr in msg.answers() {
        match b.copy_record(dnsbox::Section::Answer, &rr.unwrap()) {
            Ok(()) => copied += 1,
            Err(e) => {
                assert_eq!(e, Error::BufferTooSmall);
                break;
            }
        }
    }
    assert!(copied < N && b.finish().len() <= 65535);
}

// ---------------------------------------------------------------------------
// Presentation format: arithmetic on hostile numbers.
// ---------------------------------------------------------------------------

/// Parses `text` as the RDATA of `rtype` in class IN.
fn parse_text(rtype: Rtype, text: &str) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0u8; 65535];
    let mut w = dnsbox::WireWriter::new(&mut buf);
    let mut s = dnsbox::zone::Scanner::new(text);
    dnsbox::RData::parse_text(rtype, Class::IN, &mut s, &mut w)?;
    Ok(w.as_bytes().to_vec())
}

/// RFC 1876 §3: an altitude just below 2^63 centimetres overflowed the
/// signed addition of the 100 000 m base (a panic with overflow checks,
/// as in debug builds).
#[test]
fn loc_huge_altitude_is_an_error() {
    assert_eq!(
        parse_text(Rtype::LOC, "0 N 0 E 92233720368547758.00m"),
        Err(Error::InvalidText)
    );
    assert_eq!(
        parse_text(Rtype::LOC, "0 N 0 E -92233720368547758.07m"),
        Err(Error::InvalidText)
    );
    assert!(parse_text(Rtype::LOC, "0 N 0 E 42849672.95m").is_ok());
}
