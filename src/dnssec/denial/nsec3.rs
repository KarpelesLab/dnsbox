//! NSEC3 proofs (RFC 5155 §8, RFC 7129 §5, RFC 6840 §4, RFC 9276 §3.2).

use super::nsec::wildcard_encloser;
use super::{
    BogusReason, ClosestEncloser, Denial, DenialProof, DenialStatus, InsecureReason, cuts_below,
    delegation_bitmap, nodata_bitmap,
};
use crate::dnssec::{Nsec3Hash, Nsec3HashAlgorithm};
use crate::message::Record;
use crate::name::Name;
use crate::rdata::Nsec3;
use crate::{Result, Rtype};

/// An authenticated NSEC3 record: its hashed owner name and data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nsec3Record<'a> {
    /// The hashed owner name: the base32hex hash label followed by the
    /// zone name (RFC 5155 §3).
    pub owner: Name<'a>,
    /// The record data.
    pub nsec3: Nsec3<'a>,
}

impl<'a> Nsec3Record<'a> {
    /// Pairs an owner name with NSEC3 data.
    #[inline]
    pub const fn new(owner: Name<'a>, nsec3: Nsec3<'a>) -> Self {
        Nsec3Record { owner, nsec3 }
    }

    /// The NSEC3 record `rr`, or `None` if it is of another type or its
    /// data is malformed.
    pub fn from_record(rr: &Record<'a>) -> Option<Self> {
        if rr.rtype() != Rtype::NSEC3 {
            return None;
        }
        Some(Nsec3Record {
            owner: rr.name(),
            nsec3: rr.data_as::<Nsec3<'a>>().ok()?,
        })
    }
}

impl<'a> From<&Nsec3Record<'a>> for Nsec3Record<'a> {
    #[inline]
    fn from(r: &Nsec3Record<'a>) -> Self {
        *r
    }
}

/// Computes NSEC3 hashes (RFC 5155 §5) for [`Nsec3Proof`]: the pluggable
/// crypto of NSEC3 validation.
///
/// [`PurecryptoNsec3Hasher`] (feature `dnssec-digest`) implements it with
/// SHA-1 from `purecrypto`. Any function or closure with the signature of
/// [`nsec3_hash`](crate::dnssec::nsec3_hash) is a hasher too.
pub trait Nsec3Hasher {
    /// Whether names can be hashed with `algorithm`. NSEC3 records of other
    /// algorithms are ignored (RFC 5155 §8.1). The default accepts SHA-1,
    /// the only algorithm defined.
    fn supports(&self, algorithm: Nsec3HashAlgorithm) -> bool {
        algorithm == Nsec3HashAlgorithm::SHA1
    }

    /// Hashes `name` with `algorithm`, `iterations` additional iterations
    /// and `salt` (RFC 5155 §5).
    fn hash(
        &self,
        name: Name<'_>,
        algorithm: Nsec3HashAlgorithm,
        iterations: u16,
        salt: &[u8],
    ) -> Result<Nsec3Hash>;
}

impl<F> Nsec3Hasher for F
where
    F: Fn(Name<'_>, Nsec3HashAlgorithm, u16, &[u8]) -> Result<Nsec3Hash>,
{
    #[inline]
    fn hash(
        &self,
        name: Name<'_>,
        algorithm: Nsec3HashAlgorithm,
        iterations: u16,
        salt: &[u8],
    ) -> Result<Nsec3Hash> {
        self(name, algorithm, iterations, salt)
    }
}

/// The `purecrypto` NSEC3 hasher: SHA-1 through
/// [`nsec3_hash`](crate::dnssec::nsec3_hash).
#[cfg(feature = "dnssec-digest")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec-digest")))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PurecryptoNsec3Hasher;

#[cfg(feature = "dnssec-digest")]
impl Nsec3Hasher for PurecryptoNsec3Hasher {
    #[inline]
    fn hash(
        &self,
        name: Name<'_>,
        algorithm: Nsec3HashAlgorithm,
        iterations: u16,
        salt: &[u8],
    ) -> Result<Nsec3Hash> {
        crate::dnssec::nsec3_hash(name, algorithm, iterations, salt)
    }
}

/// Iteration-count policy for NSEC3 validation (RFC 9276 §3.2,
/// RFC 5155 §10.3).
///
/// Every NSEC3 hash costs `iterations + 1` digest computations, and a
/// proof may hash one name per label of the query name, so validators cap
/// the count: above `insecure_above` the response is treated as insecure,
/// above `bogus_above` as bogus, in both cases without hashing anything.
/// The records' signatures must still have been verified, so that the
/// iteration count is authentic (RFC 9276 §3.2); resolvers should then
/// add Extended DNS Error 27, "Unsupported NSEC3 Iterations Value".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Nsec3Limits {
    /// Iteration counts above this make the response insecure.
    pub insecure_above: u16,
    /// Iteration counts above this make the response bogus (checked
    /// first).
    pub bogus_above: u16,
}

impl Nsec3Limits {
    /// The defaults, the interoperable starting points of RFC 9276
    /// Appendix A: insecure above 100 iterations, bogus above 500.
    pub const DEFAULT: Nsec3Limits = Nsec3Limits::new(100, 500);

    /// A policy: insecure above `insecure_above` iterations, bogus above
    /// `bogus_above`. RFC 9276 §3.2 allows both limits to be as low as 0,
    /// the only value zones should use (RFC 9276 §3.1).
    #[inline]
    pub const fn new(insecure_above: u16, bogus_above: u16) -> Self {
        Nsec3Limits {
            insecure_above,
            bogus_above,
        }
    }

    /// The status for `iterations`, if it is over a limit.
    pub const fn check(&self, iterations: u16) -> Option<DenialStatus> {
        if iterations > self.bogus_above {
            Some(DenialStatus::Bogus(BogusReason::Iterations))
        } else if iterations > self.insecure_above {
            Some(DenialStatus::Insecure(InsecureReason::Iterations))
        } else {
            None
        }
    }
}

impl Default for Nsec3Limits {
    #[inline]
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// An NSEC3 denial-of-existence proof: authenticated NSEC3 records of one
/// zone (RFC 5155 §8). See [`DenialProof`] for the checks and their
/// results.
///
/// `records` is anything that can be iterated more than once (a slice, a
/// `Vec`, a cloneable iterator over a message section) yielding
/// [`Nsec3Record`]s or references to them. Following RFC 5155 §8.1 and
/// §8.2, records are ignored when their flags are not 0 or 1, their hash
/// algorithm is not supported by the hasher, their owner is not a single
/// base32hex label directly below `zone`, or their next hashed owner name
/// is not as long as their own hash. The remaining records must agree on
/// algorithm, iterations and salt ([`BogusReason::InconsistentParameters`]
/// otherwise), and the iteration count is checked against the
/// [`Nsec3Limits`] before anything is hashed.
///
/// RFC 6840 §4.1 and RFC 5155 §8.3 are enforced: the closest encloser's
/// record must have neither DNAME nor NS without SOA, and a parent-side
/// record (NS without SOA) denies nothing at its owner but DS.
///
/// A check hashes at most one name per label of the query name plus one
/// wildcard, and makes one pass over the records per hash.
///
/// ```
/// # #[cfg(feature = "dnssec-digest")] {
/// use dnsbox::dnssec::{Denial, DenialStatus, Nsec3Hash, Nsec3HashAlgorithm, Nsec3Proof, Nsec3Record, PurecryptoNsec3Hasher};
/// use dnsbox::rdata::{Nsec3, TypeBitmap};
/// use dnsbox::{NameBuf, Rtype, WireWriter};
///
/// // RFC 5155 Appendix B.2: ns1.example. exists, without MX.
/// //   2t7b4g4vsa5smi47k61mv5bv1a22bojr.example. NSEC3 1 1 12 aabbccdd (
/// //       2vptu5timamqttgl4luu9kg21e0aor3s A RRSIG )
/// let owner: NameBuf = "2t7b4g4vsa5smi47k61mv5bv1a22bojr.example".parse()?;
/// let next: NameBuf = "2vptu5timamqttgl4luu9kg21e0aor3s.example".parse()?;
/// let next = Nsec3Hash::from_owner(next.as_name())?;
/// let mut buf = [0u8; 16];
/// let mut w = WireWriter::new(&mut buf);
/// TypeBitmap::compose(&[Rtype::A, Rtype::RRSIG], &mut w)?;
/// let nsec3 = Nsec3 {
///     hash_algorithm: Nsec3HashAlgorithm::SHA1,
///     flags: 1,
///     iterations: 12,
///     salt: &[0xaa, 0xbb, 0xcc, 0xdd],
///     next_hashed_owner: next.as_bytes(),
///     types: TypeBitmap::new(w.as_bytes())?,
/// };
/// let records = [Nsec3Record::new(owner.as_name(), nsec3)];
/// let zone: NameBuf = "example".parse()?;
/// let proof = Nsec3Proof::new(zone.as_name(), &records, PurecryptoNsec3Hasher);
/// let qname: NameBuf = "ns1.example".parse()?;
/// assert_eq!(proof.no_data(qname.as_name(), Rtype::MX), DenialStatus::Secure(Denial::NoData));
/// # }
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Nsec3Proof<'a, I, H> {
    zone: Name<'a>,
    records: I,
    hasher: H,
    limits: Nsec3Limits,
}

/// The hash parameters shared by the usable records.
#[derive(Clone, Copy)]
struct Params<'s> {
    algorithm: Nsec3HashAlgorithm,
    iterations: u16,
    salt: &'s [u8],
}

/// A usable record with its decoded owner hash.
struct Usable<'a> {
    hash: Nsec3Hash,
    record: Nsec3Record<'a>,
}

/// An early exit of a check.
type Check<T> = core::result::Result<T, BogusReason>;

impl<'a, I, H> Nsec3Proof<'a, I, H>
where
    I: IntoIterator + Clone,
    I::Item: Into<Nsec3Record<'a>>,
    H: Nsec3Hasher,
{
    /// A proof from `records` of `zone` (the signer name of their RRSIGs),
    /// hashing with `hasher`, under [`Nsec3Limits::DEFAULT`].
    #[inline]
    pub const fn new(zone: Name<'a>, records: I, hasher: H) -> Self {
        Nsec3Proof {
            zone,
            records,
            hasher,
            limits: Nsec3Limits::DEFAULT,
        }
    }

    /// Replaces the iteration-count policy.
    #[inline]
    #[must_use]
    pub const fn with_limits(mut self, limits: Nsec3Limits) -> Self {
        self.limits = limits;
        self
    }

    /// The zone the records belong to.
    #[inline]
    pub const fn zone(&self) -> Name<'a> {
        self.zone
    }

    /// The iteration-count policy.
    #[inline]
    pub const fn limits(&self) -> Nsec3Limits {
        self.limits
    }

    /// Decodes `record` if it is usable (RFC 5155 §8.1, §8.2).
    fn usable(&self, record: Nsec3Record<'a>) -> Option<Usable<'a>> {
        let n = &record.nsec3;
        if n.flags & !Nsec3::OPT_OUT != 0
            || !self.hasher.supports(n.hash_algorithm)
            || record.owner.label_count() != self.zone.label_count() + 1
            || !record.owner.is_subdomain_of(&self.zone)
        {
            return None;
        }
        let hash = Nsec3Hash::from_owner(record.owner).ok()?;
        if hash.as_bytes().len() != n.next_hashed_owner.len() {
            return None;
        }
        Some(Usable { hash, record })
    }

    /// The usable records.
    fn iter(&self) -> impl Iterator<Item = Usable<'a>> + '_ {
        self.records
            .clone()
            .into_iter()
            .filter_map(|r| self.usable(r.into()))
    }

    /// The shared parameters, or the status to return right away: bogus
    /// without usable records or with inconsistent ones, or the limit
    /// status of the iteration count.
    fn params(&self) -> core::result::Result<Params<'a>, DenialStatus> {
        let mut iter = self.iter();
        let Some(first) = iter.next() else {
            let any = self.records.clone().into_iter().next().is_some();
            return Err(DenialStatus::Bogus(if any {
                BogusReason::UnusableRecords
            } else {
                BogusReason::MissingProof
            }));
        };
        let n = first.record.nsec3;
        let params = Params {
            algorithm: n.hash_algorithm,
            iterations: n.iterations,
            salt: n.salt,
        };
        if iter.any(|u| {
            let m = &u.record.nsec3;
            m.hash_algorithm != params.algorithm
                || m.iterations != params.iterations
                || m.salt != params.salt
        }) {
            return Err(DenialStatus::Bogus(BogusReason::InconsistentParameters));
        }
        if let Some(status) = self.limits.check(params.iterations) {
            return Err(status);
        }
        Ok(params)
    }

    /// Hashes `name` with the shared parameters.
    fn hash(&self, p: &Params<'_>, name: Name<'_>) -> Check<Nsec3Hash> {
        self.hasher
            .hash(name, p.algorithm, p.iterations, p.salt)
            .map_err(|_| BogusReason::UnusableRecords)
    }

    /// The record whose owner hash is `hash`.
    fn find_match(&self, hash: &Nsec3Hash) -> Option<Nsec3Record<'a>> {
        self.iter().find(|u| u.hash == *hash).map(|u| u.record)
    }

    /// A record covering `hash` (RFC 5155 §8.3).
    fn find_cover(&self, hash: &Nsec3Hash) -> Option<Nsec3Record<'a>> {
        self.iter()
            .find(|u| u.record.nsec3.covers(u.hash.as_bytes(), hash.as_bytes()))
            .map(|u| u.record)
    }

    /// The closest encloser proof for `qname`, which must not exist
    /// (RFC 5155 §8.3): the longest ancestor of `qname` matched by a
    /// record, whose child towards `qname` (the next closer name) is
    /// covered by a record. `qhash` is the hash of `qname`.
    fn encloser<'q>(
        &self,
        p: &Params<'_>,
        qname: Name<'q>,
        qhash: Nsec3Hash,
    ) -> Check<ClosestEncloser<'q>> {
        if self.find_match(&qhash).is_some() {
            return Err(BogusReason::NameExists);
        }
        let extra = qname.label_count().saturating_sub(self.zone.label_count());
        let mut next_closer = (qname, qhash);
        for strip in 1..=extra {
            let candidate = qname.strip_labels(strip).ok_or(BogusReason::OutOfZone)?;
            let hash = self.hash(p, candidate)?;
            if let Some(m) = self.find_match(&hash) {
                // RFC 5155 §8.3, RFC 6840 §4.1: the encloser's record must
                // be from this zone and not hide a DNAME's subtree.
                if cuts_below(&m.nsec3.types) {
                    return Err(BogusReason::ZoneCut);
                }
                let cover = self
                    .find_cover(&next_closer.1)
                    .ok_or(BogusReason::MissingProof)?;
                return Ok(ClosestEncloser {
                    encloser: candidate,
                    next_closer: next_closer.0,
                    opt_out: cover.nsec3.is_opt_out(),
                });
            }
            next_closer = (candidate, hash);
        }
        Err(BogusReason::MissingProof)
    }

    /// Runs `f` with the shared parameters for a check about `name` (in
    /// the zone), turning early exits into statuses.
    fn checked<T>(
        &self,
        name: Name<'_>,
        f: impl FnOnce(&Params<'a>) -> Check<T>,
    ) -> core::result::Result<T, DenialStatus> {
        if !name.is_subdomain_of(&self.zone) {
            return Err(DenialStatus::Bogus(BogusReason::OutOfZone));
        }
        let p = self.params()?;
        f(&p).map_err(DenialStatus::Bogus)
    }

    /// The closest (provable) encloser proof for `qname` (RFC 5155 §8.3):
    /// no record matches `qname`, and the longest ancestor of `qname` that
    /// a record matches has its next closer name covered by a record. The
    /// encloser's record must be from this zone: no DNAME, and no NS
    /// without SOA ([`BogusReason::ZoneCut`]).
    ///
    /// [`ClosestEncloser::opt_out`] tells whether the next closer name is
    /// in an Opt-Out span. Fails with the status the other checks would
    /// return for unusable records, iteration limits or a missing proof.
    pub fn closest_encloser<'q>(
        &self,
        qname: Name<'q>,
    ) -> core::result::Result<ClosestEncloser<'q>, DenialStatus> {
        self.checked(qname, |p| {
            let qhash = self.hash(p, qname)?;
            self.encloser(p, qname, qhash)
        })
    }

    /// Checks an NXDOMAIN response (RFC 5155 §8.4): a closest encloser
    /// proof for `qname` and a record covering the wildcard at the closest
    /// encloser. An Opt-Out record covering the next closer name makes the
    /// response insecure (RFC 5155 §9.2).
    pub fn name_error(&self, qname: Name<'_>) -> DenialStatus {
        status(self.checked(qname, |p| {
            let qhash = self.hash(p, qname)?;
            let ce = self.encloser(p, qname, qhash)?;
            if let Some(wildcard) = ce.wildcard() {
                let h = self.hash(p, wildcard.as_name())?;
                if self.find_match(&h).is_some() {
                    return Err(BogusReason::WildcardExists);
                }
                self.find_cover(&h).ok_or(BogusReason::MissingProof)?;
            }
            Ok(secure_unless_opt_out(ce.opt_out, Denial::NameError))
        }))
    }

    /// Checks a NOERROR/NODATA response (RFC 5155 §8.5–§8.7, RFC 6840
    /// §4.1, §4.3, §4.4).
    ///
    /// With a record matching `qname`: neither `qtype` nor CNAME may be in
    /// its bitmap ([`Denial::NoData`]); for DS it must not be from the
    /// child apex (SOA), and an NS bit gives
    /// [`Denial::UnsignedDelegation`]. Otherwise a closest encloser proof
    /// is needed, plus either a record matching the wildcard at the
    /// closest encloser without `qtype` or CNAME
    /// ([`Denial::WildcardNoData`]) or an Opt-Out record covering the next
    /// closer name ([`InsecureReason::OptOut`]: for DS an unsigned
    /// delegation, RFC 5155 §8.6, otherwise an empty non-terminal without
    /// NSEC3 record, RFC 5155 Errata 3441; [`BogusReason::NoOptOut`] for
    /// DS without Opt-Out).
    pub fn no_data(&self, qname: Name<'_>, qtype: Rtype) -> DenialStatus {
        status(self.checked(qname, |p| {
            let qhash = self.hash(p, qname)?;
            if let Some(m) = self.find_match(&qhash) {
                return Ok(nodata_bitmap(&m.nsec3.types, qname, qtype));
            }
            let ce = self.encloser(p, qname, qhash)?;
            if let Some(wildcard) = ce.wildcard() {
                let h = self.hash(p, wildcard.as_name())?;
                if let Some(m) = self.find_match(&h) {
                    return Ok(
                        match nodata_bitmap(&m.nsec3.types, wildcard.as_name(), qtype) {
                            DenialStatus::Secure(_) => {
                                secure_unless_opt_out(ce.opt_out, Denial::WildcardNoData)
                            }
                            other => other,
                        },
                    );
                }
            }
            if ce.opt_out {
                Ok(DenialStatus::Insecure(InsecureReason::OptOut))
            } else if qtype == Rtype::DS {
                Err(BogusReason::NoOptOut)
            } else {
                Err(BogusReason::MissingProof)
            }
        }))
    }

    /// Checks an answer synthesized from a wildcard (RFC 5155 §8.8):
    /// `labels` is the RRSIG labels field, so the closest encloser is
    /// `qname` reduced to `labels` labels, and a record must cover the
    /// next closer name. An Opt-Out cover makes the answer insecure
    /// (RFC 5155 §9.2).
    pub fn wildcard_answer(&self, qname: Name<'_>, labels: u8) -> DenialStatus {
        status(self.checked(qname, |p| {
            let encloser = wildcard_encloser(qname, labels).ok_or(BogusReason::WrongWildcard)?;
            if !encloser.is_subdomain_of(&self.zone) {
                return Err(BogusReason::OutOfZone);
            }
            let extra = qname.label_count() - encloser.label_count();
            let next_closer = qname
                .strip_labels(extra - 1)
                .ok_or(BogusReason::WrongWildcard)?;
            let h = self.hash(p, next_closer)?;
            if self.find_match(&h).is_some() {
                return Err(BogusReason::WrongWildcard);
            }
            let cover = self.find_cover(&h).ok_or(BogusReason::MissingProof)?;
            Ok(secure_unless_opt_out(
                cover.nsec3.is_opt_out(),
                Denial::WildcardAnswer,
            ))
        }))
    }

    /// Checks a referral to an unsigned zone (RFC 5155 §8.9, RFC 6840
    /// §4.4): the record matching `delegation` has NS but neither DS nor
    /// SOA, or, with no such record, a closest provable encloser proof
    /// whose next closer record has Opt-Out
    /// ([`InsecureReason::OptOut`]).
    pub fn unsigned_delegation(&self, delegation: Name<'_>) -> DenialStatus {
        status(self.checked(delegation, |p| {
            let hash = self.hash(p, delegation)?;
            if let Some(m) = self.find_match(&hash) {
                return Ok(delegation_bitmap(&m.nsec3.types));
            }
            let ce = self.encloser(p, delegation, hash)?;
            if ce.opt_out {
                Ok(DenialStatus::Insecure(InsecureReason::OptOut))
            } else {
                Err(BogusReason::NoOptOut)
            }
        }))
    }
}

/// Flattens the result of a check.
fn status(r: core::result::Result<DenialStatus, DenialStatus>) -> DenialStatus {
    r.unwrap_or_else(|s| s)
}

/// `Secure(denial)`, or insecure if the next closer name is in an Opt-Out
/// span (RFC 5155 §9.2).
fn secure_unless_opt_out(opt_out: bool, denial: Denial) -> DenialStatus {
    if opt_out {
        DenialStatus::Insecure(InsecureReason::OptOut)
    } else {
        DenialStatus::Secure(denial)
    }
}

impl<'a, I, H> DenialProof for Nsec3Proof<'a, I, H>
where
    I: IntoIterator + Clone,
    I::Item: Into<Nsec3Record<'a>>,
    H: Nsec3Hasher,
{
    #[inline]
    fn name_error(&self, qname: Name<'_>) -> DenialStatus {
        Nsec3Proof::name_error(self, qname)
    }

    #[inline]
    fn no_data(&self, qname: Name<'_>, qtype: Rtype) -> DenialStatus {
        Nsec3Proof::no_data(self, qname, qtype)
    }

    #[inline]
    fn wildcard_answer(&self, qname: Name<'_>, labels: u8) -> DenialStatus {
        Nsec3Proof::wildcard_answer(self, qname, labels)
    }

    #[inline]
    fn unsigned_delegation(&self, delegation: Name<'_>) -> DenialStatus {
        Nsec3Proof::unsigned_delegation(self, delegation)
    }
}
