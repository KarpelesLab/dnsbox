//! Authenticated denial of existence: checking NSEC (RFC 4035 §5.4,
//! RFC 7129 §3–§5) and NSEC3 (RFC 5155 §8, RFC 7129 §5, RFC 9276) proofs,
//! with the RFC 6840 §4 corrections.
//!
//! See [`DenialProof`] for the overview.

use core::fmt;

use crate::name::{Name, NameBuf};
use crate::rdata::TypeBitmap;
use crate::{Rtype, name};

mod nsec;
mod nsec3;

pub use nsec::{NsecProof, NsecRecord};
#[cfg(feature = "dnssec-digest")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec-digest")))]
pub use nsec3::PurecryptoNsec3Hasher;
pub use nsec3::{Nsec3Hasher, Nsec3Limits, Nsec3Proof, Nsec3Record};

/// What a denial-of-existence proof establishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Denial {
    /// The name does not exist and no wildcard could have produced it
    /// (NXDOMAIN; RFC 4035 §5.4, RFC 5155 §8.4).
    NameError,
    /// The name exists (possibly as an empty non-terminal) but has no
    /// RRset of the type, nor a CNAME (RFC 4035 §5.4, RFC 5155 §8.5,
    /// §8.6, RFC 6840 §4.3).
    NoData,
    /// The name does not exist; the wildcard at its closest encloser
    /// exists but has no RRset of the type, nor a CNAME (RFC 4035 §3.1.3.4,
    /// RFC 5155 §8.7).
    WildcardNoData,
    /// The name does not exist and the wildcard the answer was synthesized
    /// from is the right one: no closer match exists (RFC 4035 §5.3.4,
    /// RFC 5155 §8.8).
    WildcardAnswer,
    /// The delegation exists and has no DS RRset: the child zone is
    /// unsigned (RFC 4035 §5.2, RFC 5155 §8.6, §8.9, RFC 6840 §4.4).
    UnsignedDelegation,
}

impl fmt::Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Denial::NameError => "name does not exist",
            Denial::NoData => "no RRset of that type",
            Denial::WildcardNoData => "wildcard has no RRset of that type",
            Denial::WildcardAnswer => "wildcard expansion is valid",
            Denial::UnsignedDelegation => "delegation has no DS",
        })
    }
}

/// Why a proof leaves the response insecure rather than secure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InsecureReason {
    /// The NSEC3 record covering the next closer name has the Opt-Out flag
    /// set: unsigned delegations may exist in its span, so the response
    /// must not be marked authenticated (RFC 5155 §6, §9.2, §12.2).
    OptOut,
    /// The NSEC3 iteration count is above the configured insecure limit
    /// (RFC 9276 §3.2; resolvers should add Extended DNS Error 27). The
    /// records' signatures must still have been verified.
    Iterations,
}

impl fmt::Display for InsecureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            InsecureReason::OptOut => "NSEC3 opt-out span",
            InsecureReason::Iterations => "NSEC3 iteration count above limit",
        })
    }
}

/// Why a proof is bogus.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BogusReason {
    /// The name is not in the zone the records belong to.
    OutOfZone,
    /// A record the proof needs (a match for the name or its closest
    /// encloser, a cover for it, its next closer name or the wildcard) is
    /// missing (RFC 4035 §5.4, RFC 5155 §8.3–§8.8).
    MissingProof,
    /// The name exists — a record matches it, or it is an empty
    /// non-terminal — where its absence was to be proven.
    NameExists,
    /// The type, or a CNAME, is present in the matching type bitmap
    /// (RFC 4035 §5.4, RFC 6840 §4.3); for a referral, a DS RRset exists.
    TypeExists,
    /// The wildcard at the closest encloser exists, so the name could have
    /// been synthesized (RFC 4035 §5.4, RFC 5155 §8.4).
    WildcardExists,
    /// The answer was synthesized from the wrong wildcard: a closer name
    /// exists (RFC 4035 §5.3.4, RFC 5155 §8.8), or the labels field does
    /// not denote an expansion.
    WrongWildcard,
    /// The proof relies on a record from the wrong side of a zone cut: an
    /// ancestor delegation (NS without SOA) or a DNAME owner used to deny
    /// names below it (RFC 6840 §4.1, RFC 5155 §8.3), a parent-side record
    /// used for anything but DS, or a child-apex record (SOA set) used for
    /// DS (RFC 4035 §5.2, RFC 6840 §4.4).
    ZoneCut,
    /// The record matching a referral's delegation name has no NS bit
    /// (RFC 6840 §4.4).
    NotDelegation,
    /// No record matches the delegation, and the NSEC3 record covering the
    /// next closer name does not have Opt-Out set (RFC 5155 §8.6, §8.9).
    NoOptOut,
    /// The NSEC3 records use different hash algorithms, iterations or
    /// salts (RFC 5155 §7.2, §8.2).
    InconsistentParameters,
    /// No record is usable: unknown NSEC3 hash algorithm or flags, or a
    /// malformed hashed owner name (RFC 5155 §8.1, §8.2).
    UnusableRecords,
    /// The NSEC3 iteration count is above the configured bogus limit
    /// (RFC 9276 §3.2).
    Iterations,
}

impl fmt::Display for BogusReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            BogusReason::OutOfZone => "name outside the zone of the proof",
            BogusReason::MissingProof => "denial-of-existence record missing",
            BogusReason::NameExists => "name exists",
            BogusReason::TypeExists => "type exists",
            BogusReason::WildcardExists => "matching wildcard exists",
            BogusReason::WrongWildcard => "closer match than the wildcard exists",
            BogusReason::ZoneCut => "record from the wrong side of a zone cut",
            BogusReason::NotDelegation => "not a delegation",
            BogusReason::NoOptOut => "next closer name not in an opt-out span",
            BogusReason::InconsistentParameters => "inconsistent NSEC3 parameters",
            BogusReason::UnusableRecords => "no usable denial-of-existence record",
            BogusReason::Iterations => "NSEC3 iteration count above limit",
        })
    }
}

/// The outcome of checking a denial-of-existence proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DenialStatus {
    /// The proof holds (RFC 4035 §4.3 "Secure").
    Secure(Denial),
    /// The records are authentic but do not authenticate the response
    /// (RFC 4035 §4.3 "Insecure"): it must not be marked authenticated.
    Insecure(InsecureReason),
    /// The proof fails (RFC 4035 §4.3 "Bogus").
    Bogus(BogusReason),
}

impl DenialStatus {
    /// Whether the proof holds.
    #[inline]
    pub const fn is_secure(&self) -> bool {
        matches!(self, DenialStatus::Secure(_))
    }

    /// Whether the response is insecure.
    #[inline]
    pub const fn is_insecure(&self) -> bool {
        matches!(self, DenialStatus::Insecure(_))
    }

    /// Whether the proof fails.
    #[inline]
    pub const fn is_bogus(&self) -> bool {
        matches!(self, DenialStatus::Bogus(_))
    }

    /// What was proven, for a secure proof.
    #[inline]
    pub const fn denial(&self) -> Option<Denial> {
        match self {
            DenialStatus::Secure(d) => Some(*d),
            _ => None,
        }
    }
}

impl fmt::Display for DenialStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DenialStatus::Secure(d) => write!(f, "secure: {d}"),
            DenialStatus::Insecure(r) => write!(f, "insecure: {r}"),
            DenialStatus::Bogus(r) => write!(f, "bogus: {r}"),
        }
    }
}

/// A closest encloser proof (RFC 5155 §8.3, RFC 7129 §5.5): the longest
/// existing ancestor of a name that does not exist, and the name one label
/// longer (the "next closer" name), which is proven not to exist.
///
/// Both are views of the name the proof was made for. Returned by
/// [`NsecProof::closest_encloser`] and [`Nsec3Proof::closest_encloser`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ClosestEncloser<'q> {
    /// The closest encloser: an ancestor of the name that exists.
    pub encloser: Name<'q>,
    /// The next closer name: the ancestor of (or the) name one label
    /// longer than the closest encloser, covered by a denial record.
    pub next_closer: Name<'q>,
    /// Whether the NSEC3 record covering the next closer name has the
    /// Opt-Out flag set (RFC 5155 §6): unsigned delegations may exist in
    /// its span, so responses relying on it must not be marked
    /// authenticated (RFC 5155 §9.2). Always `false` for NSEC.
    pub opt_out: bool,
}

impl ClosestEncloser<'_> {
    /// The wildcard at the closest encloser, `*.<encloser>`, the source of
    /// synthesis for the name (RFC 4592 §3.3.1), or `None` if it would be
    /// longer than 255 octets (and so cannot exist).
    #[inline]
    pub fn wildcard(&self) -> Option<NameBuf> {
        wildcard_of(self.encloser)
    }
}

/// The checks a validator makes with an NSEC ([`NsecProof`]) or NSEC3
/// ([`Nsec3Proof`]) denial-of-existence proof (RFC 4035 §5.4, RFC 5155 §8,
/// RFC 7129, RFC 6840 §4).
///
/// A proof is a set of NSEC or NSEC3 records **already authenticated** by
/// the caller (each RRset verified with [`verify_rrsig`](super::verify_rrsig)
/// or [`TrustedKeys::verify_rrset`](super::TrustedKeys::verify_rrset), with
/// an RRSIG labels field equal to the owner's label count: an NSEC record
/// is never itself a wildcard expansion, RFC 4035 §5.4), all from one zone.
/// [`NsecProof`] and [`Nsec3Proof`] (which implement this trait) then answer the questions a validator
/// asks of a negative or wildcard response:
///
/// | Response | Method | Proves |
/// |----------|--------|--------|
/// | NXDOMAIN | [`name_error`](DenialProof::name_error) | the name and every wildcard that could match it are absent |
/// | NOERROR, empty answer | [`no_data`](DenialProof::no_data) | the name (or the wildcard matching it) exists without the type, or for DS: the delegation is unsigned |
/// | answer synthesized from a wildcard | [`wildcard_answer`](DenialProof::wildcard_answer) | no closer match exists (RFC 4035 §5.3.4) |
/// | referral | [`unsigned_delegation`](DenialProof::unsigned_delegation) | the delegation has no DS RRset |
///
/// Every check returns a [`DenialStatus`]: `Secure` with the [`Denial`]
/// proven, `Insecure` (an NSEC3 Opt-Out span, RFC 5155 §9.2, or an
/// iteration count above policy, RFC 9276 §3.2) or `Bogus` with the
/// [`BogusReason`].
///
/// Work is bounded: NSEC checks are a constant number of passes over the
/// records; NSEC3 checks hash at most one name per label of the query name
/// plus one wildcard (each hash costing `iterations + 1` digest
/// computations, capped by [`Nsec3Limits`]), and make one pass over the
/// records per hashed name.
///
/// ```
/// use dnsbox::dnssec::{Denial, DenialStatus, NsecProof, NsecRecord};
/// use dnsbox::rdata::{Nsec, TypeBitmap};
/// use dnsbox::{NameBuf, Rtype, WireWriter};
///
/// // RFC 4035 Appendix B.2: "ml.example." does not exist.
/// //   b.example. NSEC ns1.example. NS RRSIG NSEC
/// //   example.   NSEC a.example. NS SOA MX RRSIG NSEC DNSKEY
/// let bitmap = |types: &[Rtype], buf: &mut [u8; 32]| -> dnsbox::Result<usize> {
///     let mut w = WireWriter::new(buf);
///     TypeBitmap::compose(types, &mut w)?;
///     Ok(w.len())
/// };
/// let (mut b1, mut b2) = ([0u8; 32], [0u8; 32]);
/// let n1 = bitmap(&[Rtype::NS, Rtype::RRSIG, Rtype::NSEC], &mut b1)?;
/// let apex_types = [Rtype::NS, Rtype::SOA, Rtype::MX, Rtype::RRSIG, Rtype::NSEC, Rtype::DNSKEY];
/// let n2 = bitmap(&apex_types, &mut b2)?;
/// let zone: NameBuf = "example".parse()?;
/// let (b, ns1, a) = ("b.example".parse::<NameBuf>()?, "ns1.example".parse::<NameBuf>()?, "a.example".parse::<NameBuf>()?);
/// let records = [
///     NsecRecord::new(b.as_name(), Nsec::new(ns1.as_name(), TypeBitmap::new(&b1[..n1])?)),
///     NsecRecord::new(zone.as_name(), Nsec::new(a.as_name(), TypeBitmap::new(&b2[..n2])?)),
/// ];
/// let proof = NsecProof::new(zone.as_name(), &records);
/// let qname: NameBuf = "ml.example".parse()?;
/// assert_eq!(proof.name_error(qname.as_name()), DenialStatus::Secure(Denial::NameError));
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub trait DenialProof {
    /// Checks an NXDOMAIN response for `qname`: the name does not exist and
    /// neither does the wildcard at its closest encloser (RFC 4035 §5.4,
    /// RFC 5155 §8.4).
    fn name_error(&self, qname: Name<'_>) -> DenialStatus;

    /// Checks a NOERROR response with no answer for `qname`/`qtype`
    /// (RFC 4035 §5.4, RFC 5155 §8.5–§8.7, RFC 6840 §4.1, §4.3): the name
    /// exists without the type or a CNAME ([`Denial::NoData`]), or the
    /// wildcard matching it does ([`Denial::WildcardNoData`]). For
    /// `qtype` DS, a delegation without DS gives
    /// [`Denial::UnsignedDelegation`] (or, inside an NSEC3 Opt-Out span,
    /// [`InsecureReason::OptOut`]).
    fn no_data(&self, qname: Name<'_>, qtype: Rtype) -> DenialStatus;

    /// Checks an answer for `qname` synthesized from a wildcard, `labels`
    /// being the RRSIG labels field (the number of labels of the
    /// wildcard's closest encloser, RFC 4035 §5.3.4, RFC 5155 §8.8): no
    /// name closer to `qname` exists.
    ///
    /// The wildcard's existence is proven by its verified RRSIG, not by
    /// this check: call it only for an RRset verified as a wildcard
    /// expansion ([`TrustedKeys::verify_answer`](super::TrustedKeys::verify_answer)
    /// does both).
    fn wildcard_answer(&self, qname: Name<'_>, labels: u8) -> DenialStatus;

    /// Checks a referral to `delegation` (the owner of the authority NS
    /// RRset) without DS records: the delegation exists and has no DS
    /// (RFC 4035 §5.2, RFC 5155 §8.9, RFC 6840 §4.4).
    fn unsigned_delegation(&self, delegation: Name<'_>) -> DenialStatus;
}

impl<P: DenialProof + ?Sized> DenialProof for &P {
    #[inline]
    fn name_error(&self, qname: Name<'_>) -> DenialStatus {
        (**self).name_error(qname)
    }

    #[inline]
    fn no_data(&self, qname: Name<'_>, qtype: Rtype) -> DenialStatus {
        (**self).no_data(qname, qtype)
    }

    #[inline]
    fn wildcard_answer(&self, qname: Name<'_>, labels: u8) -> DenialStatus {
        (**self).wildcard_answer(qname, labels)
    }

    #[inline]
    fn unsigned_delegation(&self, delegation: Name<'_>) -> DenialStatus {
        (**self).unsigned_delegation(delegation)
    }
}

/// Whether a record with `types` at a proper ancestor of a name may not be
/// used to deny that name: an ancestor delegation (NS without SOA) or a
/// DNAME (RFC 6840 §4.1, RFC 5155 §8.3).
fn cuts_below(types: &TypeBitmap<'_>) -> bool {
    (types.contains(Rtype::NS) && !types.contains(Rtype::SOA)) || types.contains(Rtype::DNAME)
}

/// The NODATA check on the bitmap of a record matching `qname` (RFC 4035
/// §5.4, RFC 5155 §8.5, §8.6, RFC 6840 §4.1, §4.3, §4.4).
fn nodata_bitmap(types: &TypeBitmap<'_>, qname: Name<'_>, qtype: Rtype) -> DenialStatus {
    let ns = types.contains(Rtype::NS);
    let soa = types.contains(Rtype::SOA);
    if qtype == Rtype::DS {
        // The DS RRset lives on the parent side; a record from the child
        // apex cannot deny it (the root has no parent).
        if soa && !qname.is_root() {
            return DenialStatus::Bogus(BogusReason::ZoneCut);
        }
        if types.contains(Rtype::DS) || types.contains(Rtype::CNAME) {
            return DenialStatus::Bogus(BogusReason::TypeExists);
        }
        return DenialStatus::Secure(if ns && !soa {
            Denial::UnsignedDelegation
        } else {
            Denial::NoData
        });
    }
    // A parent-side record at a delegation proves nothing about the
    // child's data.
    if ns && !soa {
        return DenialStatus::Bogus(BogusReason::ZoneCut);
    }
    if types.contains(qtype) || types.contains(Rtype::CNAME) {
        return DenialStatus::Bogus(BogusReason::TypeExists);
    }
    DenialStatus::Secure(Denial::NoData)
}

/// The referral check on the bitmap of a record matching the delegation
/// name (RFC 5155 §8.9, RFC 6840 §4.4).
fn delegation_bitmap(types: &TypeBitmap<'_>) -> DenialStatus {
    if types.contains(Rtype::SOA) {
        DenialStatus::Bogus(BogusReason::ZoneCut)
    } else if !types.contains(Rtype::NS) {
        DenialStatus::Bogus(BogusReason::NotDelegation)
    } else if types.contains(Rtype::DS) {
        DenialStatus::Bogus(BogusReason::TypeExists)
    } else {
        DenialStatus::Secure(Denial::UnsignedDelegation)
    }
}

/// The longest common ancestor of `a` and `b` (as a view of `a`).
fn shared_ancestor<'a>(a: Name<'a>, b: Name<'_>) -> Name<'a> {
    let common = a.label_count().min(b.label_count());
    let mut x = a
        .strip_labels(a.label_count() - common)
        .unwrap_or(Name::ROOT);
    let mut y = b
        .strip_labels(b.label_count() - common)
        .unwrap_or(Name::ROOT);
    while x != y {
        match (x.parent(), y.parent()) {
            (Some(px), Some(py)) => {
                x = px;
                y = py;
            }
            _ => return Name::ROOT,
        }
    }
    x
}

/// The wildcard `*.<encloser>`, or `None` if it would exceed
/// [`MAX_NAME_LEN`](name::MAX_NAME_LEN) (such a wildcard cannot exist).
fn wildcard_of(encloser: Name<'_>) -> Option<NameBuf> {
    if encloser.wire_len() + 2 > name::MAX_NAME_LEN {
        return None;
    }
    let mut w = NameBuf::from_name(encloser);
    w.prepend_label(b"*").ok()?;
    Some(w)
}

#[cfg(test)]
pub(in crate::dnssec) mod tests;
