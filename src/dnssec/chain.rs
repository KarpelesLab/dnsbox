//! The chain of trust (RFC 4035 §5): authenticating a zone's DNSKEY RRset
//! from the parent's DS RRset (or from trust anchors), then the zone's
//! RRsets with those keys, including wildcard expansions (RFC 4035
//! §5.3.4).

use super::{Algorithm, DenialProof, DenialStatus, Rrset, Verifier, ZoneKey, verify_rrsig};
use crate::name::Name;
use crate::rdata::{ComposeRdata, Dnskey, Rrsig};
use crate::wire::OutBuf;
use crate::{Class, Error, Result};
#[cfg(feature = "dnssec-digest")]
use {super::DigestType, crate::rdata::Ds};

/// The most cryptographic operations (signature verifications and DS
/// digests) one [`TrustedKeys`] call performs before giving up.
///
/// Legitimate RRsets need one or two; the cap keeps a response with many
/// colliding key tags and signatures from costing quadratic work (the
/// "KeyTrap" attack, CVE-2023-50387).
pub const MAX_CRYPTO_OPERATIONS: usize = 16;

/// A zone's DNSKEY RRset, authenticated through the chain of trust
/// (RFC 4035 §5.2) or configured as trusted: the keys that validate the
/// zone's other RRsets (RFC 4035 §5.3).
///
/// `K` is anything that can be iterated more than once yielding the
/// DNSKEY record data (a slice iterator, `Copied`, a cloneable iterator
/// over a message section, ...).
///
/// A typical walk down from a trust anchor:
///
/// 1. the root's keys from [`from_ds`](Self::from_ds) with the root
///    trust anchor's DS records (or [`from_anchors`](Self::from_anchors));
/// 2. the child's DS RRset authenticated with
///    [`verify_rrset`](Self::verify_rrset) of the parent's keys;
/// 3. the child's keys from [`from_ds`](Self::from_ds) with that DS RRset;
///    a proven absence of DS ([`Denial::UnsignedDelegation`]) or a DS
///    RRset without supported algorithms
///    ([`Error::UnsupportedAlgorithm`]) makes the child insecure instead;
/// 4. answers with [`verify_answer`](Self::verify_answer), negative
///    responses by verifying the NSEC/NSEC3 RRsets and checking them with
///    a [`DenialProof`].
///
/// Revoked keys (RFC 5011 §2.1) are never used. Work is bounded by
/// [`MAX_CRYPTO_OPERATIONS`] per call: once it is spent, the call fails
/// with [`Error::BadSignature`] (if it had not failed otherwise).
///
/// [`Denial::UnsignedDelegation`]: super::Denial::UnsignedDelegation
#[derive(Clone, Copy, Debug)]
pub struct TrustedKeys<'a, K> {
    zone: Name<'a>,
    class: Class,
    keys: K,
}

/// What a successful RRset verification established.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Verified {
    /// The key tag of the DNSKEY that verified the signature.
    pub key_tag: u16,
    /// The signature algorithm.
    pub algorithm: Algorithm,
    /// The RRSIG labels field (RFC 4034 §3.1.3).
    pub labels: u8,
    /// The RRSIG original TTL: the RRset's TTL must be capped to it
    /// (RFC 4035 §5.3.3).
    pub original_ttl: u32,
    /// The RRSIG signature expiration (seconds since 1970, modulo 2^32):
    /// the RRset must not be cached beyond it (RFC 4035 §5.3.3).
    pub expiration: u32,
    /// The closest encloser's label count if the RRset was synthesized
    /// from a wildcard (the labels field is smaller than the owner's label
    /// count, and the owner is not the wildcard itself; RFC 4035 §5.3.4).
    pub wildcard: Option<u8>,
}

impl Verified {
    /// Whether the RRset was synthesized from a wildcard: its existence
    /// is only proven together with a proof that no closer match exists
    /// ([`DenialProof::wildcard_answer`], RFC 4035 §5.3.4).
    #[inline]
    pub const fn is_wildcard_expansion(&self) -> bool {
        self.wildcard.is_some()
    }
}

/// The result of [`TrustedKeys::verify_answer`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Answer {
    /// The RRset is signed by the zone and was not synthesized from a
    /// wildcard: secure.
    Exact(Verified),
    /// The RRset was synthesized from a wildcard and its signature
    /// verifies; `proof` is the outcome of checking that no closer match
    /// exists (RFC 4035 §5.3.4, RFC 5155 §8.8). Only a secure proof makes
    /// the answer secure; an insecure one (NSEC3 Opt-Out) makes it
    /// insecure, a bogus one bogus.
    Wildcard {
        /// The signature check.
        verified: Verified,
        /// The wildcard proof.
        proof: DenialStatus,
    },
}

impl Answer {
    /// The signature check.
    #[inline]
    pub const fn verified(&self) -> &Verified {
        match self {
            Answer::Exact(v) | Answer::Wildcard { verified: v, .. } => v,
        }
    }

    /// Whether the answer is secure: exact, or a wildcard expansion with a
    /// secure proof.
    #[inline]
    pub const fn is_secure(&self) -> bool {
        match self {
            Answer::Exact(_) => true,
            Answer::Wildcard { proof, .. } => proof.is_secure(),
        }
    }
}

/// Keeps the more informative of two failures: signature and validity
/// failures over key mismatches over missing signatures.
fn worse(current: Error, new: Error) -> Error {
    let rank = |e: Error| match e {
        Error::Unsigned => 0,
        Error::KeyMismatch => 1,
        Error::UnsupportedAlgorithm => 2,
        _ => 3,
    };
    if rank(new) >= rank(current) {
        new
    } else {
        current
    }
}

/// A budget of cryptographic operations.
struct Budget(usize);

impl Budget {
    fn spend(&mut self) -> Result<()> {
        self.0 = self.0.checked_sub(1).ok_or(Error::BadSignature)?;
        Ok(())
    }
}

impl<'a, K> TrustedKeys<'a, K>
where
    K: IntoIterator<Item = Dnskey<'a>> + Clone,
{
    /// Trusts `keys`, the DNSKEY RRset of `zone` in `class`, without
    /// checking anything: for keys authenticated by other means (local
    /// configuration, a previous validation).
    #[inline]
    pub const fn assume_trusted(zone: Name<'a>, class: Class, keys: K) -> Self {
        TrustedKeys { zone, class, keys }
    }

    /// The zone (owner of the keys and signer name of its RRSIGs).
    #[inline]
    pub const fn zone(&self) -> Name<'a> {
        self.zone
    }

    /// The class.
    #[inline]
    pub const fn class(&self) -> Class {
        self.class
    }

    /// The keys.
    #[inline]
    pub fn keys(&self) -> K {
        self.keys.clone()
    }

    /// The keys that may verify signatures: zone keys, protocol 3, not
    /// revoked (RFC 4034 §2.1.1, RFC 5011 §2.1).
    fn usable(&self) -> impl Iterator<Item = Dnskey<'a>> {
        self.keys
            .clone()
            .into_iter()
            .filter(|k| k.is_zone_key() && k.protocol == 3 && !k.is_revoked())
    }

    /// Authenticates the DNSKEY RRset `dnskeys` (owner: the zone) with the
    /// zone's DS RRset `ds`, already authenticated in the parent zone (or
    /// configured as a trust anchor), and the RRSIGs over the DNSKEY RRset
    /// (RFC 4035 §5.2): some DS must match a key of the set (key tag,
    /// algorithm, digest; [`verify_ds`](super::verify_ds)) and that key
    /// must have signed the set.
    ///
    /// DS records with digest types the crate cannot compute or algorithms
    /// `verifier` does not support are disregarded, as are SHA-1 DS records
    /// when a stronger digest is present (RFC 6840 §5.2, RFC 4509 §3). If
    /// none is left, fails with [`Error::UnsupportedAlgorithm`]: the zone
    /// is then **insecure**, not bogus (RFC 4035 §5.2). Any other error
    /// means the keys are bogus: [`Error::Unsigned`] (no RRSIG over the
    /// DNSKEY RRset by the zone), [`Error::KeyMismatch`] (no RRSIG by a
    /// usable key that a DS matches), or the error of the last signature
    /// check ([`Error::BadSignature`], [`Error::SignatureExpired`], ...).
    ///
    /// `now` is the current time in seconds since 1970 (modulo 2^32); the
    /// signed data is built at the end of `scratch` and removed again.
    #[cfg(feature = "dnssec-digest")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec-digest")))]
    pub fn from_ds<'d, 's, V, B, D, S>(
        verifier: &V,
        dnskeys: Rrset<'a, K>,
        ds: D,
        rrsigs: S,
        now: u32,
        scratch: &mut B,
    ) -> Result<Self>
    where
        V: Verifier + ?Sized,
        B: OutBuf,
        D: IntoIterator<Item = Ds<'d>> + Clone,
        S: IntoIterator<Item = Rrsig<'s>>,
    {
        let usable_ds = |d: &Ds<'_>| {
            d.digest_type.digest_len().is_some()
                && d.digest_type != DigestType::GOST
                && verifier.supports(d.algorithm)
        };
        if !ds.clone().into_iter().any(|d| usable_ds(&d)) {
            return Err(Error::UnsupportedAlgorithm);
        }
        let strong = ds
            .clone()
            .into_iter()
            .any(|d| usable_ds(&d) && d.digest_type != DigestType::SHA1);
        let candidate =
            move |d: &Ds<'_>| usable_ds(d) && !(strong && d.digest_type == DigestType::SHA1);
        let keys = Self::assume_trusted(dnskeys.owner, dnskeys.class, dnskeys.rdata);
        let mut budget = Budget(MAX_CRYPTO_OPERATIONS);
        // Whether a DS authenticates `key` (RFC 4035 §5.2).
        let mut authenticated = |key: &Dnskey<'_>, budget: &mut Budget| -> Result<bool> {
            let tag = key.key_tag();
            for d in ds.clone().into_iter().filter(|d| candidate(d)) {
                if d.key_tag != tag || d.algorithm != key.algorithm {
                    continue;
                }
                budget.spend()?;
                match super::verify_ds(&d, keys.zone, key) {
                    Ok(()) => return Ok(true),
                    Err(Error::BadSignature | Error::KeyMismatch) => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(false)
        };
        keys.verify_with(
            verifier,
            Rrset::new(keys.zone, keys.class, keys.keys.clone()),
            rrsigs,
            now,
            scratch,
            &mut budget,
            &mut authenticated,
        )
        .map(|_| keys)
    }

    /// Authenticates the DNSKEY RRset `dnskeys` (owner: the zone) with
    /// trust anchors given as DNSKEY records (RFC 4035 §4.4, RFC 5011): a
    /// key of the set with the algorithm and public key of an anchor must
    /// have signed the set.
    ///
    /// Fails with [`Error::KeyMismatch`] if no anchor is in the set, and
    /// otherwise as [`from_ds`](Self::from_ds).
    pub fn from_anchors<'t, 's, V, B, T, S>(
        verifier: &V,
        dnskeys: Rrset<'a, K>,
        anchors: T,
        rrsigs: S,
        now: u32,
        scratch: &mut B,
    ) -> Result<Self>
    where
        V: Verifier + ?Sized,
        B: OutBuf,
        T: IntoIterator<Item = Dnskey<'t>> + Clone,
        S: IntoIterator<Item = Rrsig<'s>>,
    {
        let keys = Self::assume_trusted(dnskeys.owner, dnskeys.class, dnskeys.rdata);
        let mut budget = Budget(MAX_CRYPTO_OPERATIONS);
        let mut anchored = |key: &Dnskey<'_>, _: &mut Budget| -> Result<bool> {
            Ok(anchors
                .clone()
                .into_iter()
                .any(|a| a.algorithm == key.algorithm && a.public_key == key.public_key))
        };
        keys.verify_with(
            verifier,
            Rrset::new(keys.zone, keys.class, keys.keys.clone()),
            rrsigs,
            now,
            scratch,
            &mut budget,
            &mut anchored,
        )
        .map(|_| keys)
    }

    /// Verifies `rrset` with the zone's keys (RFC 4035 §5.3): some RRSIG
    /// in `rrsigs` covering the RRset's type, with the zone as signer,
    /// must verify with a usable key ([`verify_rrsig`]). RRSIGs of other
    /// types, signers, or without a matching key are disregarded
    /// (RFC 6840 §5.12); one valid signature suffices (RFC 6840 §5.11).
    ///
    /// Fails with [`Error::RrsetMismatch`] for an empty RRset or one
    /// outside the zone, [`Error::Unsigned`] if no RRSIG is by the zone,
    /// [`Error::KeyMismatch`] if no key matches one, and otherwise with
    /// the error of the last signature check. The result says whether the
    /// RRset was synthesized from a wildcard, which then still needs a
    /// proof (see [`verify_answer`](Self::verify_answer)).
    pub fn verify_rrset<'s, V, B, I, S>(
        &self,
        verifier: &V,
        rrset: Rrset<'_, I>,
        rrsigs: S,
        now: u32,
        scratch: &mut B,
    ) -> Result<Verified>
    where
        V: Verifier + ?Sized,
        B: OutBuf,
        I: IntoIterator + Clone,
        I::Item: ComposeRdata,
        S: IntoIterator<Item = Rrsig<'s>>,
    {
        let mut budget = Budget(MAX_CRYPTO_OPERATIONS);
        self.verify_with(
            verifier,
            rrset,
            rrsigs,
            now,
            scratch,
            &mut budget,
            &mut |_, _| Ok(true),
        )
    }

    /// Verifies `rrset` like [`verify_rrset`](Self::verify_rrset), then,
    /// if it was synthesized from a wildcard, checks with `proof` (the
    /// authenticated NSEC or NSEC3 records of the response) that no closer
    /// match exists (RFC 4035 §5.3.4, RFC 5155 §8.8).
    ///
    /// ```
    /// # #[cfg(feature = "dnssec")] {
    /// use dnsbox::dnssec::{Algorithm, Answer, NsecProof, NsecRecord, PurecryptoVerifier, Rrset, SigningKey, TrustedKeys, sign_rrset, Signer, ZoneKey};
    /// use dnsbox::rdata::{A, Dnskey};
    /// use dnsbox::{Class, NameBuf, Rtype};
    ///
    /// let signer = SigningKey::from_private_bytes(Algorithm::ED25519, &[7; 32])?;
    /// let zone: NameBuf = "example.".parse()?;
    /// let dnskey = signer.dnskey(Dnskey::ZONE);
    /// let keys = TrustedKeys::assume_trusted(zone.as_name(), Class::IN, [dnskey]);
    ///
    /// let www: NameBuf = "www.example.".parse()?;
    /// let rdata = [A::new([192, 0, 2, 1].into())];
    /// let rrset = Rrset::new(www.as_name(), Class::IN, &rdata);
    /// let key = ZoneKey::new(zone.as_name(), dnskey);
    /// let template = key.rrsig_template(www.as_name(), Rtype::A, 3600, 1_000, 2_000);
    /// let mut scratch = Vec::new();
    /// let mut sig = [0u8; 64];
    /// let len = sign_rrset(&signer, &template, rrset, &mut scratch, &mut sig)?;
    /// let rrsig = template.with_signature(&sig[..len]);
    ///
    /// let no_nsec: [NsecRecord<'_>; 0] = [];
    /// let proof = NsecProof::new(zone.as_name(), &no_nsec);
    /// let answer = keys.verify_answer(&PurecryptoVerifier, rrset, [rrsig], &proof, 1_500, &mut scratch)?;
    /// assert!(matches!(answer, Answer::Exact(v) if v.key_tag == dnskey.key_tag()));
    /// assert!(answer.is_secure());
    /// # }
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub fn verify_answer<'s, V, B, I, S, P>(
        &self,
        verifier: &V,
        rrset: Rrset<'_, I>,
        rrsigs: S,
        proof: &P,
        now: u32,
        scratch: &mut B,
    ) -> Result<Answer>
    where
        V: Verifier + ?Sized,
        B: OutBuf,
        I: IntoIterator + Clone,
        I::Item: ComposeRdata,
        S: IntoIterator<Item = Rrsig<'s>>,
        P: DenialProof + ?Sized,
    {
        let owner = rrset.owner;
        let verified = self.verify_rrset(verifier, rrset, rrsigs, now, scratch)?;
        Ok(match verified.wildcard {
            None => Answer::Exact(verified),
            Some(labels) => Answer::Wildcard {
                verified,
                proof: proof.wildcard_answer(owner, labels),
            },
        })
    }

    /// The common verification loop: tries every RRSIG of the zone over
    /// the RRset's type with every usable key it designates that `accept`
    /// approves, within `budget`.
    #[allow(clippy::too_many_arguments)]
    fn verify_with<'s, V, B, I, S, F>(
        &self,
        verifier: &V,
        rrset: Rrset<'_, I>,
        rrsigs: S,
        now: u32,
        scratch: &mut B,
        budget: &mut Budget,
        accept: &mut F,
    ) -> Result<Verified>
    where
        V: Verifier + ?Sized,
        B: OutBuf,
        I: IntoIterator + Clone,
        I::Item: ComposeRdata,
        S: IntoIterator<Item = Rrsig<'s>>,
        F: FnMut(&Dnskey<'a>, &mut Budget) -> Result<bool>,
    {
        let rtype = rrset
            .rdata
            .clone()
            .into_iter()
            .next()
            .map(|d| d.rtype())
            .ok_or(Error::RrsetMismatch)?;
        if !rrset.owner.is_subdomain_of(&self.zone) {
            return Err(Error::RrsetMismatch);
        }
        let mut err = Error::Unsigned;
        for rrsig in rrsigs {
            if rrsig.type_covered != rtype || rrsig.signer_name != self.zone {
                continue;
            }
            err = worse(err, Error::KeyMismatch);
            for dnskey in self.usable() {
                if dnskey.algorithm != rrsig.algorithm || dnskey.key_tag() != rrsig.key_tag {
                    continue;
                }
                match accept(&dnskey, budget) {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(e) => return Err(worse(err, e)),
                }
                budget.spend().map_err(|e| worse(err, e))?;
                let key = ZoneKey::new(self.zone, dnskey);
                let set = Rrset::new(rrset.owner, rrset.class, rrset.rdata.clone());
                match verify_rrsig(verifier, &key, &rrsig, set, now, scratch) {
                    Ok(()) => return Ok(verified(&rrsig, rrset.owner)),
                    Err(e) => err = worse(err, e),
                }
            }
        }
        Err(err)
    }
}

/// The [`Verified`] summary of a valid `rrsig` over an RRset at `owner`.
fn verified(rrsig: &Rrsig<'_>, owner: Name<'_>) -> Verified {
    let count = owner.label_count();
    let labels = usize::from(rrsig.labels);
    // `*.<encloser>` queried by its own name is not an expansion.
    let literal = owner.is_wildcard() && labels + 1 == count;
    Verified {
        key_tag: rrsig.key_tag,
        algorithm: rrsig.algorithm,
        labels: rrsig.labels,
        original_ttl: rrsig.original_ttl,
        expiration: rrsig.expiration,
        wildcard: (labels < count && !literal).then_some(rrsig.labels),
    }
}

#[cfg(test)]
mod tests;
