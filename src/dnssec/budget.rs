//! [`ValidationBudget`]: bounded work for DNSSEC validation (the KeyTrap
//! class of attacks, CVE-2023-50387 and CVE-2023-50868).

use core::cell::Cell;

use super::{Nsec3Hash, Nsec3HashAlgorithm, Nsec3Hasher};
use crate::name::Name;
use crate::{Error, Result};

/// The default number of signature verifications and DS digests one
/// [`TrustedKeys`](super::TrustedKeys) call may perform
/// ([`ValidationLimits::max_verifications_per_rrset`]).
///
/// Legitimate RRsets need one or two; the cap keeps a response with many
/// colliding key tags and signatures from costing quadratic work (the
/// "KeyTrap" attack, CVE-2023-50387).
pub const MAX_CRYPTO_OPERATIONS: usize = 16;

/// Limits on the work of DNSSEC validation, the configuration of a
/// [`ValidationBudget`].
///
/// A validator facing a hostile zone must not let one response cost
/// unbounded CPU: many DNSKEYs sharing a key tag and many RRSIGs
/// (KeyTrap, CVE-2023-50387) multiply signature verifications, and NSEC3
/// closest-encloser proofs for names with many labels multiply hash
/// computations (CVE-2023-50868). The defaults are of the order of the
/// caps validating resolvers adopted after KeyTrap (on signature
/// validations per RRset and per response, on key tag collisions and on
/// NSEC3 hash computations), with room for every legitimate configuration
/// (algorithm and key rollovers, multi-signer zones, deep `ip6.arpa`
/// names):
///
/// | Limit | Default | Per |
/// |-------|---------|-----|
/// | [`max_verifications`](Self::max_verifications) | 32 | budget (response) |
/// | [`max_verifications_per_rrset`](Self::max_verifications_per_rrset) | 16 ([`MAX_CRYPTO_OPERATIONS`]) | `TrustedKeys` call |
/// | [`max_rrsigs_per_rrset`](Self::max_rrsigs_per_rrset) | 8 | `TrustedKeys` call |
/// | [`max_keys_per_rrsig`](Self::max_keys_per_rrsig) | 4 | RRSIG |
/// | [`max_dnskeys`](Self::max_dnskeys) | 32 | `TrustedKeys` call |
/// | [`max_nsec3_hashes`](Self::max_nsec3_hashes) | 64 | budget (response) |
///
/// NSEC3 iteration counts are capped separately, before anything is
/// hashed, by [`Nsec3Limits`](super::Nsec3Limits) (insecure above 100
/// iterations, bogus above 500, RFC 9276 §3.2); with both, an NSEC3 check
/// costs at most `max_nsec3_hashes × 101` SHA-1 computations.
///
/// ```
/// use dnsbox::dnssec::{ValidationBudget, ValidationLimits};
///
/// let mut limits = ValidationLimits::DEFAULT;
/// limits.max_verifications = 8;
/// let budget = ValidationBudget::with_limits(limits);
/// assert_eq!(budget.limits().max_rrsigs_per_rrset, 8);
/// assert_eq!(ValidationLimits::default(), ValidationLimits::DEFAULT);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ValidationLimits {
    /// The most signature verifications and DS digests in total, over
    /// every call sharing the budget.
    pub max_verifications: u32,
    /// The most signature verifications and DS digests in one
    /// [`TrustedKeys`](super::TrustedKeys) call (one RRset).
    pub max_verifications_per_rrset: u32,
    /// The most RRSIGs over the RRset's type by the zone tried in one
    /// call; others are not looked at.
    pub max_rrsigs_per_rrset: u32,
    /// The most keys tried for one RRSIG: keys of its algorithm and key
    /// tag, so this caps key tag collisions (RFC 4034 Appendix B allows
    /// them; a hostile zone makes many).
    pub max_keys_per_rrsig: u32,
    /// The most DNSKEY records looked at in one call: further keys of the
    /// trusted set are ignored.
    pub max_dnskeys: u32,
    /// The most NSEC3 hashes computed in total through
    /// [`ValidationBudget::nsec3_hasher`].
    pub max_nsec3_hashes: u32,
}

impl ValidationLimits {
    /// The defaults: see the table in the [type documentation](Self).
    pub const DEFAULT: ValidationLimits = ValidationLimits {
        max_verifications: 32,
        max_verifications_per_rrset: MAX_CRYPTO_OPERATIONS as u32,
        max_rrsigs_per_rrset: 8,
        max_keys_per_rrsig: 4,
        max_dnskeys: 32,
        max_nsec3_hashes: 64,
    };
}

impl Default for ValidationLimits {
    #[inline]
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A budget of DNSSEC validation work, spent by the
/// [`TrustedKeys`](super::TrustedKeys) `*_with_budget` methods and by the
/// NSEC3 hasher of [`nsec3_hasher`](Self::nsec3_hasher); use one budget per
/// response (or per resolution) so that the total work a response causes
/// is bounded, whatever the number of RRsets, RRSIGs, keys and labels it
/// carries. See [`ValidationLimits`] for the limits and their defaults.
///
/// When a limit stops the work before a valid signature was found, the
/// `TrustedKeys` methods fail with [`Error::LimitExceeded`], and NSEC3
/// proofs return [`BogusReason::LimitExceeded`](super::BogusReason::LimitExceeded):
/// the response could not be validated, which a validator treats like
/// bogus (SERVFAIL, Extended DNS Error 6 or 0), never as insecure. A
/// valid signature found within the limits is accepted.
///
/// The counters are in [`Cell`]s, so a budget is shared by reference
/// between the calls of one validation, including the NSEC3 hasher that
/// a proof holds while `TrustedKeys` verifies an answer; it is `Send` but
/// not `Sync`.
///
/// The `TrustedKeys` methods without a budget use a fresh default budget
/// per call: each call is bounded, but not the number of calls.
///
/// # Examples
///
/// KeyTrap: a zone publishes 40 keys sharing one key tag and signs an
/// RRset 40 times, so that a naive validator tries 1600 verifications;
/// here at most 16 happen (4 keys for each of the first 4 RRSIGs), and the
/// outcome is `LimitExceeded`.
///
/// ```
/// use core::cell::Cell;
/// use dnsbox::dnssec::{Algorithm, Rrset, TrustedKeys, ValidationBudget, Verifier, ZoneKey};
/// use dnsbox::rdata::{A, Dnskey};
/// use dnsbox::{Class, Error, NameBuf, Rtype, WireWriter};
///
/// /// Counts verifications; every signature is bad.
/// struct Counting(Cell<u32>);
/// impl Verifier for Counting {
///     fn supports(&self, _: Algorithm) -> bool { true }
///     fn verify(&self, _: Algorithm, _: &[u8], _: &[u8], _: &[u8]) -> dnsbox::Result<()> {
///         self.0.set(self.0.get() + 1);
///         Err(Error::BadSignature)
///     }
/// }
///
/// // 40 distinct keys with the same key tag: the key tag is a checksum,
/// // so moving one unit between two 16-bit words keeps it.
/// let material: Vec<[u8; 32]> = (0..40u8).map(|i| {
///     let mut k = [100u8; 32];
///     k[0] += i;
///     k[2] -= i;
///     k
/// }).collect();
/// let keys: Vec<Dnskey<'_>> = material.iter()
///     .map(|k| Dnskey::new(Dnskey::ZONE, 3, Algorithm::ED25519, k))
///     .collect();
/// assert!(keys.iter().all(|k| k.key_tag() == keys[0].key_tag()));
///
/// let zone: NameBuf = "example.".parse()?;
/// let www: NameBuf = "www.example.".parse()?;
/// let trusted = TrustedKeys::assume_trusted(zone.as_name(), Class::IN, keys.iter().copied());
/// let rrsig = ZoneKey::new(zone.as_name(), keys[0])
///     .rrsig_template(www.as_name(), Rtype::A, 300, 1_000, 2_000)
///     .with_signature(&[0; 64]);
/// let addrs = [A::new([192, 0, 2, 1].into())];
/// let rrset = Rrset::new(www.as_name(), Class::IN, &addrs);
///
/// let budget = ValidationBudget::new();
/// let verifier = Counting(Cell::new(0));
/// let mut buf = [0u8; 512];
/// let mut scratch = WireWriter::new(&mut buf);
/// let result = trusted.verify_rrset_with_budget(
///     &verifier, rrset, [rrsig; 40], 1_500, &mut scratch, &budget,
/// );
/// assert_eq!(result, Err(Error::LimitExceeded));
/// assert_eq!(verifier.0.get(), 16);
/// assert_eq!(budget.verifications(), 16);
///
/// // The budget is shared: one more such RRset exhausts it.
/// let again = trusted.verify_rrset_with_budget(
///     &verifier, rrset, [rrsig; 40], 1_500, &mut scratch, &budget,
/// );
/// assert_eq!(again, Err(Error::LimitExceeded));
/// assert_eq!(budget.verifications(), 32);
/// assert!(budget.is_exhausted());
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Debug, Default)]
pub struct ValidationBudget {
    limits: ValidationLimits,
    verifications: Cell<u32>,
    nsec3_hashes: Cell<u32>,
}

impl ValidationBudget {
    /// A budget with the [default limits](ValidationLimits::DEFAULT).
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self::with_limits(ValidationLimits::DEFAULT)
    }

    /// A budget with `limits`.
    #[inline]
    #[must_use]
    pub const fn with_limits(limits: ValidationLimits) -> Self {
        ValidationBudget {
            limits,
            verifications: Cell::new(0),
            nsec3_hashes: Cell::new(0),
        }
    }

    /// The limits.
    #[inline]
    #[must_use]
    pub const fn limits(&self) -> &ValidationLimits {
        &self.limits
    }

    /// The signature verifications and DS digests spent so far.
    #[inline]
    #[must_use]
    pub fn verifications(&self) -> u32 {
        self.verifications.get()
    }

    /// The NSEC3 hashes spent so far.
    #[inline]
    #[must_use]
    pub fn nsec3_hashes(&self) -> u32 {
        self.nsec3_hashes.get()
    }

    /// Whether the verifications or the NSEC3 hashes are all spent.
    #[inline]
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.verifications.get() >= self.limits.max_verifications
            || self.nsec3_hashes.get() >= self.limits.max_nsec3_hashes
    }

    /// Starts afresh (for the next response), keeping the limits.
    #[inline]
    pub fn reset(&mut self) {
        self.verifications.set(0);
        self.nsec3_hashes.set(0);
    }

    /// Wraps an NSEC3 hasher so that its hashes are spent from this
    /// budget: give it to [`Nsec3Proof::new`](super::Nsec3Proof::new).
    /// Once [`max_nsec3_hashes`](ValidationLimits::max_nsec3_hashes) are
    /// spent, the hasher fails with [`Error::LimitExceeded`] and the proof
    /// is [`BogusReason::LimitExceeded`](super::BogusReason::LimitExceeded).
    ///
    /// ```
    /// # #[cfg(feature = "dnssec-digest")] {
    /// use dnsbox::dnssec::{Nsec3HashAlgorithm, Nsec3Hasher, PurecryptoNsec3Hasher};
    /// use dnsbox::dnssec::{ValidationBudget, ValidationLimits};
    /// use dnsbox::{Error, NameBuf};
    ///
    /// let mut limits = ValidationLimits::DEFAULT;
    /// limits.max_nsec3_hashes = 2;
    /// let budget = ValidationBudget::with_limits(limits);
    /// let hasher = budget.nsec3_hasher(PurecryptoNsec3Hasher);
    /// let name: NameBuf = "example.".parse()?;
    /// for _ in 0..2 {
    ///     hasher.hash(name.as_name(), Nsec3HashAlgorithm::SHA1, 0, &[])?;
    /// }
    /// let third = hasher.hash(name.as_name(), Nsec3HashAlgorithm::SHA1, 0, &[]);
    /// assert_eq!(third, Err(Error::LimitExceeded));
    /// assert_eq!(budget.nsec3_hashes(), 2);
    /// # }
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub const fn nsec3_hasher<H: Nsec3Hasher>(&self, hasher: H) -> BudgetedNsec3Hasher<'_, H> {
        BudgetedNsec3Hasher {
            budget: self,
            hasher,
        }
    }

    /// Spends one verification (or DS digest) from the total.
    pub(super) fn spend_verification(&self) -> Result<()> {
        spend(&self.verifications, self.limits.max_verifications)
    }
}

/// Takes one unit from `counter` if it is below `max`.
fn spend(counter: &Cell<u32>, max: u32) -> Result<()> {
    let n = counter.get();
    if n >= max {
        return Err(Error::LimitExceeded);
    }
    counter.set(n + 1);
    Ok(())
}

/// An [`Nsec3Hasher`] whose hashes are spent from a [`ValidationBudget`];
/// made by [`ValidationBudget::nsec3_hasher`] (see the example there).
#[derive(Clone, Copy, Debug)]
pub struct BudgetedNsec3Hasher<'b, H> {
    budget: &'b ValidationBudget,
    hasher: H,
}

impl<H: Nsec3Hasher> Nsec3Hasher for BudgetedNsec3Hasher<'_, H> {
    #[inline]
    fn supports(&self, algorithm: Nsec3HashAlgorithm) -> bool {
        self.hasher.supports(algorithm)
    }

    /// Hashes with the wrapped hasher, if the budget allows one more hash.
    ///
    /// # Errors
    ///
    /// [`Error::LimitExceeded`] once the budget's NSEC3 hashes are spent,
    /// and the wrapped hasher's errors.
    fn hash(
        &self,
        name: Name<'_>,
        algorithm: Nsec3HashAlgorithm,
        iterations: u16,
        salt: &[u8],
    ) -> Result<Nsec3Hash> {
        spend(
            &self.budget.nsec3_hashes,
            self.budget.limits.max_nsec3_hashes,
        )?;
        self.hasher.hash(name, algorithm, iterations, salt)
    }
}

/// The work allowed in one [`TrustedKeys`](super::TrustedKeys) call.
pub(super) struct CallBudget<'b> {
    budget: &'b ValidationBudget,
    /// Verifications left for this call.
    left: u32,
}

impl<'b> CallBudget<'b> {
    /// The allowance of one call.
    pub(super) const fn new(budget: &'b ValidationBudget) -> Self {
        CallBudget {
            budget,
            left: budget.limits.max_verifications_per_rrset,
        }
    }

    /// The limits.
    pub(super) const fn limits(&self) -> &ValidationLimits {
        &self.budget.limits
    }

    /// Spends one verification (or DS digest).
    pub(super) fn spend(&mut self) -> Result<()> {
        self.left = self.left.checked_sub(1).ok_or(Error::LimitExceeded)?;
        self.budget.spend_verification()
    }
}
