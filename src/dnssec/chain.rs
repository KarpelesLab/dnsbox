//! The chain of trust (RFC 4035 §5): authenticating a zone's DNSKEY RRset
//! from the parent's DS RRset (or from trust anchors), then the zone's
//! RRsets with those keys, including wildcard expansions (RFC 4035
//! §5.3.4).

use super::budget::CallBudget;
use super::{
    Algorithm, DenialProof, DenialStatus, Rrset, ValidationBudget, Verifier, ZoneKey, verify_rrsig,
};
use crate::name::Name;
use crate::rdata::{ComposeRdata, Dnskey, Rrsig};
use crate::wire::OutBuf;
use crate::{Class, Error, Result};
#[cfg(feature = "dnssec-digest")]
use {super::DigestType, crate::rdata::Ds};

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
/// 1. the root's keys from [`from_ds`] with the root
///    trust anchor's DS records (or [`from_anchors`](Self::from_anchors));
/// 2. the child's DS RRset authenticated with
///    [`verify_rrset`](Self::verify_rrset) of the parent's keys;
/// 3. the child's keys from [`from_ds`] with that DS RRset;
///    a proven absence of DS ([`Denial::UnsignedDelegation`]) or a DS
///    RRset without supported algorithms
///    ([`Error::UnsupportedAlgorithm`]) makes the child insecure instead;
/// 4. answers with [`verify_answer`](Self::verify_answer), negative
///    responses by verifying the NSEC/NSEC3 RRsets and checking them with
///    a [`DenialProof`].
///
/// Revoked keys (RFC 5011 §2.1) are never used.
///
/// # Bounded work
///
/// Every method spends from a [`ValidationBudget`]: the `*_with_budget`
/// methods from one the caller passes (use one per response, so that the
/// whole response is bounded), the others from a fresh default budget per
/// call. A call tries at most
/// [`max_rrsigs_per_rrset`](super::ValidationLimits::max_rrsigs_per_rrset)
/// RRSIGs by the zone over the RRset's type, for each at most
/// [`max_keys_per_rrsig`](super::ValidationLimits::max_keys_per_rrsig) keys
/// with its algorithm and key tag among the first
/// [`max_dnskeys`](super::ValidationLimits::max_dnskeys) keys of the set,
/// and performs at most
/// [`max_verifications_per_rrset`](super::ValidationLimits::max_verifications_per_rrset)
/// signature verifications and DS digests, which also count against the
/// budget's total. Besides those, it computes one key tag per (RRSIG, key)
/// pair it looks at. When a limit stops the search before a signature
/// verifies, the call fails with [`Error::LimitExceeded`] (the KeyTrap
/// case, CVE-2023-50387: see the [`ValidationBudget`] example).
///
/// # Examples
///
/// A zone signed with a key-signing key (KSK) and a zone-signing key
/// (ZSK), validated from the DS record its parent publishes:
///
/// ```
/// # #[cfg(feature = "dnssec")] {
/// use dnsbox::dnssec::{Algorithm, DigestType, PurecryptoVerifier, Rrset, Signer, SigningKey};
/// use dnsbox::dnssec::{TrustedKeys, ZoneKey, sign_rrset};
/// use dnsbox::rdata::{A, Dnskey};
/// use dnsbox::{Class, NameBuf, Rtype};
///
/// let zone: NameBuf = "example.".parse()?;
/// let ksk = SigningKey::from_private_bytes(Algorithm::ED25519, &[1; 32])?;
/// let zsk = SigningKey::from_private_bytes(Algorithm::ED25519, &[2; 32])?;
/// let dnskeys = [ksk.dnskey(Dnskey::ZONE | Dnskey::SEP), zsk.dnskey(Dnskey::ZONE)];
/// let (inception, expiration, now) = (1_000, 2_000, 1_500);
/// let mut scratch = Vec::new();
///
/// // Signer side: the KSK signs the DNSKEY RRset, the ZSK the data; the
/// // parent publishes the KSK's DS.
/// let ksk_key = ZoneKey::new(zone.as_name(), dnskeys[0]);
/// let template = ksk_key.rrsig_template(zone.as_name(), Rtype::DNSKEY, 3600, inception, expiration);
/// let mut ksk_sig = [0u8; 64];
/// let dnskey_rrset = Rrset::new(zone.as_name(), Class::IN, &dnskeys);
/// let n = sign_rrset(&ksk, &template, dnskey_rrset, &mut scratch, &mut ksk_sig)?;
/// let dnskey_rrsig = template.with_signature(&ksk_sig[..n]);
///
/// let www: NameBuf = "www.example.".parse()?;
/// let addrs = [A::new([192, 0, 2, 1].into())];
/// let zsk_key = ZoneKey::new(zone.as_name(), dnskeys[1]);
/// let template = zsk_key.rrsig_template(www.as_name(), Rtype::A, 3600, inception, expiration);
/// let mut zsk_sig = [0u8; 64];
/// let n = sign_rrset(&zsk, &template, Rrset::new(www.as_name(), Class::IN, &addrs), &mut scratch, &mut zsk_sig)?;
/// let a_rrsig = template.with_signature(&zsk_sig[..n]);
/// let ds = ksk_key.ds(DigestType::SHA256)?;
///
/// // Validator side: DS -> DNSKEY RRset -> A RRset.
/// let keys = TrustedKeys::from_ds(
///     &PurecryptoVerifier,
///     Rrset::new(zone.as_name(), Class::IN, dnskeys),
///     [ds.to_ds()],
///     [dnskey_rrsig],
///     now,
///     &mut scratch,
/// )?;
/// let verified = keys.verify_rrset(
///     &PurecryptoVerifier,
///     Rrset::new(www.as_name(), Class::IN, &addrs),
///     [a_rrsig],
///     now,
///     &mut scratch,
/// )?;
/// assert_eq!(verified.key_tag, dnskeys[1].key_tag());
/// assert!(!verified.is_wildcard_expansion());
/// # }
/// # Ok::<(), dnsbox::Error>(())
/// ```
///
/// [`Denial::UnsignedDelegation`]: super::Denial::UnsignedDelegation
#[cfg_attr(feature = "dnssec-digest", doc = "[`from_ds`]: Self::from_ds")]
#[cfg_attr(
    not(feature = "dnssec-digest"),
    doc = "[`from_ds`]: crate#cargo-features"
)]
#[derive(Clone, Copy, Debug)]
pub struct TrustedKeys<'a, K> {
    zone: Name<'a>,
    class: Class,
    keys: K,
}

/// What a successful RRset verification established.
///
/// Returned by [`TrustedKeys::verify_rrset`] (see the example there) and
/// inside an [`Answer`]. Cap the TTLs of the RRset to `original_ttl` and
/// the cache lifetime to `expiration` (RFC 4035 §5.3.3):
///
/// ```
/// use dnsbox::dnssec::Verified;
///
/// fn cache_ttl(verified: &Verified, rrset_ttl: u32, now: u32) -> u32 {
///     let until_expiry = verified.expiration.wrapping_sub(now);
///     rrset_ttl.min(verified.original_ttl).min(until_expiry)
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
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
    #[must_use]
    pub const fn is_wildcard_expansion(&self) -> bool {
        self.wildcard.is_some()
    }
}

/// The result of [`TrustedKeys::verify_answer`] (see the example there).
///
/// ```
/// use dnsbox::dnssec::{Answer, DenialStatus};
///
/// fn describe(answer: &Answer) -> &'static str {
///     match answer {
///         Answer::Exact(_) => "secure",
///         Answer::Wildcard { proof: DenialStatus::Secure(_), .. } => "secure wildcard expansion",
///         Answer::Wildcard { proof, .. } if proof.is_insecure() => "insecure (opt-out)",
///         _ => "bogus",
///     }
/// }
/// ```
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
    #[must_use]
    pub const fn verified(&self) -> &Verified {
        match self {
            Answer::Exact(v) | Answer::Wildcard { verified: v, .. } => v,
        }
    }

    /// Whether the answer is secure: exact, or a wildcard expansion with a
    /// secure proof.
    #[inline]
    #[must_use]
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
        Error::LimitExceeded => 4,
        _ => 3,
    };
    if rank(new) >= rank(current) {
        new
    } else {
        current
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

    /// The keys among the first `max` that may verify signatures: zone
    /// keys, protocol 3, not revoked (RFC 4034 §2.1.1, RFC 5011 §2.1).
    fn usable(&self, max: usize) -> impl Iterator<Item = Dnskey<'a>> {
        self.keys
            .clone()
            .into_iter()
            .take(max)
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
    /// Work is bounded by a fresh default [`ValidationBudget`]
    /// ([`from_ds_with_budget`](Self::from_ds_with_budget) takes one).
    ///
    /// # Errors
    ///
    /// As described above: [`Error::UnsupportedAlgorithm`] (insecure),
    /// or [`Error::Unsigned`], [`Error::KeyMismatch`],
    /// [`Error::BadSignature`], [`Error::SignatureExpired`], ... (bogus),
    /// and [`Error::LimitExceeded`] when the budget ran out first.
    /// See the [type-level example](TrustedKeys#examples).
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
        let budget = ValidationBudget::new();
        Self::from_ds_with_budget(verifier, dnskeys, ds, rrsigs, now, scratch, &budget)
    }

    /// [`from_ds`](Self::from_ds), spending from `budget`: DS digests and
    /// signature verifications both count.
    ///
    /// # Errors
    ///
    /// As [`from_ds`](Self::from_ds).
    #[cfg(feature = "dnssec-digest")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec-digest")))]
    #[allow(clippy::too_many_arguments)]
    pub fn from_ds_with_budget<'d, 's, V, B, D, S>(
        verifier: &V,
        dnskeys: Rrset<'a, K>,
        ds: D,
        rrsigs: S,
        now: u32,
        scratch: &mut B,
        budget: &ValidationBudget,
    ) -> Result<Self>
    where
        V: Verifier + ?Sized,
        B: OutBuf,
        D: IntoIterator<Item = Ds<'d>> + Clone,
        S: IntoIterator<Item = Rrsig<'s>>,
    {
        // Only digest types we can compute count (RFC 4035 §5.2): any other
        // (GOST, GOST12, SM3, unassigned) is disregarded, so it neither
        // displaces SHA-1 (RFC 4509 §3) nor fails the check.
        let usable_ds =
            |d: &Ds<'_>| super::DsDigest::supports(d.digest_type) && verifier.supports(d.algorithm);
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
        // Whether a DS authenticates `key` (RFC 4035 §5.2).
        let mut authenticated = |key: &Dnskey<'_>, budget: &mut CallBudget<'_>| -> Result<bool> {
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
            budget,
            &mut authenticated,
        )
        .map(|_| keys)
    }

    /// Authenticates the DNSKEY RRset `dnskeys` (owner: the zone) with
    /// trust anchors given as DNSKEY records (RFC 4035 §4.4, RFC 5011): a
    /// key of the set with the algorithm and public key of an anchor must
    /// have signed the set.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::KeyMismatch`] if no anchor is in the set, and
    /// otherwise as [`from_ds`].
    ///
    #[cfg_attr(feature = "dnssec-digest", doc = "[`from_ds`]: Self::from_ds")]
    #[cfg_attr(
        not(feature = "dnssec-digest"),
        doc = "[`from_ds`]: crate#cargo-features"
    )]
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
        let budget = ValidationBudget::new();
        Self::from_anchors_with_budget(verifier, dnskeys, anchors, rrsigs, now, scratch, &budget)
    }

    /// [`from_anchors`](Self::from_anchors), spending from `budget`.
    ///
    /// # Errors
    ///
    /// As [`from_anchors`](Self::from_anchors).
    #[allow(clippy::too_many_arguments)]
    pub fn from_anchors_with_budget<'t, 's, V, B, T, S>(
        verifier: &V,
        dnskeys: Rrset<'a, K>,
        anchors: T,
        rrsigs: S,
        now: u32,
        scratch: &mut B,
        budget: &ValidationBudget,
    ) -> Result<Self>
    where
        V: Verifier + ?Sized,
        B: OutBuf,
        T: IntoIterator<Item = Dnskey<'t>> + Clone,
        S: IntoIterator<Item = Rrsig<'s>>,
    {
        let keys = Self::assume_trusted(dnskeys.owner, dnskeys.class, dnskeys.rdata);
        let mut anchored = |key: &Dnskey<'_>, _: &mut CallBudget<'_>| -> Result<bool> {
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
            budget,
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
    /// Work is bounded by a fresh default [`ValidationBudget`]
    /// ([`verify_rrset_with_budget`](Self::verify_rrset_with_budget) takes
    /// one).
    ///
    /// # Errors
    ///
    /// Fails with [`Error::RrsetMismatch`] for an empty RRset or one
    /// outside the zone or of another class (RFC 4035 §5.3.1),
    /// [`Error::Unsigned`] if no RRSIG is by the zone,
    /// [`Error::KeyMismatch`] if no key matches one,
    /// [`Error::LimitExceeded`] if the budget ran out before a signature
    /// verified, and otherwise with the error of the last signature check.
    /// The result says whether the RRset was synthesized from a wildcard,
    /// which then still needs a proof (see
    /// [`verify_answer`](Self::verify_answer)).
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
        self.verify_rrset_with_budget(
            verifier,
            rrset,
            rrsigs,
            now,
            scratch,
            &ValidationBudget::new(),
        )
    }

    /// [`verify_rrset`](Self::verify_rrset), spending from `budget` (see
    /// the [`ValidationBudget`] example).
    ///
    /// # Errors
    ///
    /// As [`verify_rrset`](Self::verify_rrset).
    pub fn verify_rrset_with_budget<'s, V, B, I, S>(
        &self,
        verifier: &V,
        rrset: Rrset<'_, I>,
        rrsigs: S,
        now: u32,
        scratch: &mut B,
        budget: &ValidationBudget,
    ) -> Result<Verified>
    where
        V: Verifier + ?Sized,
        B: OutBuf,
        I: IntoIterator + Clone,
        I::Item: ComposeRdata,
        S: IntoIterator<Item = Rrsig<'s>>,
    {
        self.verify_with(
            verifier,
            rrset,
            rrsigs,
            now,
            scratch,
            budget,
            &mut |_, _| Ok(true),
        )
    }

    /// Verifies `rrset` like [`verify_rrset`](Self::verify_rrset), then,
    /// if it was synthesized from a wildcard, checks with `proof` (the
    /// authenticated NSEC or NSEC3 records of the response) that no closer
    /// match exists (RFC 4035 §5.3.4, RFC 5155 §8.8).
    ///
    /// # Errors
    ///
    /// As [`verify_rrset`](Self::verify_rrset). A failed wildcard proof
    /// is not an error: it is reported in [`Answer::Wildcard`].
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
        let budget = ValidationBudget::new();
        self.verify_answer_with_budget(verifier, rrset, rrsigs, proof, now, scratch, &budget)
    }

    /// [`verify_answer`](Self::verify_answer), spending from `budget`. To
    /// bound the proof's NSEC3 hashes too, build it with the budget's
    /// [`nsec3_hasher`](ValidationBudget::nsec3_hasher).
    ///
    /// # Errors
    ///
    /// As [`verify_rrset`](Self::verify_rrset).
    #[allow(clippy::too_many_arguments)]
    pub fn verify_answer_with_budget<'s, V, B, I, S, P>(
        &self,
        verifier: &V,
        rrset: Rrset<'_, I>,
        rrsigs: S,
        proof: &P,
        now: u32,
        scratch: &mut B,
        budget: &ValidationBudget,
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
        let verified =
            self.verify_rrset_with_budget(verifier, rrset, rrsigs, now, scratch, budget)?;
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
    /// approves, within the limits of `budget`.
    #[allow(clippy::too_many_arguments)]
    fn verify_with<'s, V, B, I, S, F>(
        &self,
        verifier: &V,
        rrset: Rrset<'_, I>,
        rrsigs: S,
        now: u32,
        scratch: &mut B,
        budget: &ValidationBudget,
        accept: &mut F,
    ) -> Result<Verified>
    where
        V: Verifier + ?Sized,
        B: OutBuf,
        I: IntoIterator + Clone,
        I::Item: ComposeRdata,
        S: IntoIterator<Item = Rrsig<'s>>,
        F: FnMut(&Dnskey<'a>, &mut CallBudget<'_>) -> Result<bool>,
    {
        let rtype = rrset
            .rdata
            .clone()
            .into_iter()
            .next()
            .map(|d| d.rtype())
            .ok_or(Error::RrsetMismatch)?;
        if !rrset.owner.is_subdomain_of(&self.zone) || rrset.class != self.class {
            return Err(Error::RrsetMismatch);
        }
        let mut call = CallBudget::new(budget);
        let limits = *call.limits();
        let max_keys = usize::try_from(limits.max_dnskeys).unwrap_or(usize::MAX);
        // Keys beyond the limit are never looked at.
        let keys_cut = self.keys.clone().into_iter().nth(max_keys).is_some();
        let mut err = Error::Unsigned;
        // Whether a limit left something untried.
        let mut cut = false;
        let mut rrsigs_tried = 0u32;
        for rrsig in rrsigs {
            if rrsig.type_covered != rtype || rrsig.signer_name != self.zone {
                continue;
            }
            if rrsigs_tried >= limits.max_rrsigs_per_rrset {
                cut = true;
                break;
            }
            rrsigs_tried += 1;
            cut |= keys_cut;
            err = worse(err, Error::KeyMismatch);
            let mut keys_tried = 0u32;
            for dnskey in self.usable(max_keys) {
                if dnskey.algorithm != rrsig.algorithm || dnskey.key_tag() != rrsig.key_tag {
                    continue;
                }
                // A key tag collision beyond the limit (KeyTrap).
                if keys_tried >= limits.max_keys_per_rrsig {
                    cut = true;
                    break;
                }
                keys_tried += 1;
                match accept(&dnskey, &mut call) {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(e) => return Err(worse(err, e)),
                }
                call.spend()?;
                let key = ZoneKey::new(self.zone, dnskey);
                let set = Rrset::new(rrset.owner, rrset.class, rrset.rdata.clone());
                match verify_rrsig(verifier, &key, &rrsig, set, now, scratch) {
                    Ok(()) => return Ok(verified(&rrsig, rrset.owner)),
                    Err(e) => err = worse(err, e),
                }
            }
        }
        Err(if cut { Error::LimitExceeded } else { err })
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
