//! NSEC proofs (RFC 4035 §5.4, RFC 7129 §3–§5, RFC 6840 §4.1, §4.3,
//! §4.4).

use super::{
    BogusReason, ClosestEncloser, Denial, DenialProof, DenialStatus, cuts_below, delegation_bitmap,
    nodata_bitmap, shared_ancestor,
};
use crate::Rtype;
use crate::message::Record;
use crate::name::Name;
use crate::rdata::Nsec;

/// An authenticated NSEC record: its owner name and data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NsecRecord<'a> {
    /// The owner name (an existing name of the zone).
    pub owner: Name<'a>,
    /// The record data: the next owner name and the types at `owner`.
    pub nsec: Nsec<'a>,
}

impl<'a> NsecRecord<'a> {
    /// Pairs an owner name with NSEC data.
    #[inline]
    pub const fn new(owner: Name<'a>, nsec: Nsec<'a>) -> Self {
        NsecRecord { owner, nsec }
    }

    /// The NSEC record `rr`, or `None` if it is of another type or its
    /// data is malformed.
    pub fn from_record(rr: &Record<'a>) -> Option<Self> {
        if rr.rtype() != Rtype::NSEC {
            return None;
        }
        Some(NsecRecord {
            owner: rr.name(),
            nsec: rr.data_as::<Nsec<'a>>().ok()?,
        })
    }

    /// Whether `name` falls strictly between the owner and the next name
    /// (RFC 4035 §5.4).
    #[inline]
    fn covers(&self, name: Name<'_>) -> bool {
        self.nsec.covers(&self.owner, &name)
    }

    /// Whether `name`, which this record covers, is an empty non-terminal:
    /// the next name is below it (RFC 4592 §2.2.2, RFC 7129 §5.5).
    fn is_empty_non_terminal(&self, name: Name<'_>) -> bool {
        let next = self.nsec.next_domain_name;
        next != name && next.is_subdomain_of(&name)
    }

    /// The closest encloser of a `name` this record covers (RFC 7129
    /// §5.5): the longer of the names it shares with the owner and with
    /// the next name, both of which exist.
    fn closest_encloser<'n>(&self, name: Name<'n>) -> Name<'n> {
        let a = shared_ancestor(name, self.owner);
        let b = shared_ancestor(name, self.nsec.next_domain_name);
        if a.label_count() >= b.label_count() {
            a
        } else {
            b
        }
    }
}

impl<'a> From<&NsecRecord<'a>> for NsecRecord<'a> {
    #[inline]
    fn from(r: &NsecRecord<'a>) -> Self {
        *r
    }
}

/// An NSEC denial-of-existence proof: authenticated NSEC records of one
/// zone (RFC 4035 §5.4). See [`DenialProof`] for the checks and their
/// results.
///
/// `records` is anything that can be iterated more than once (a slice, a
/// `Vec`, a cloneable iterator over a message section) yielding
/// [`NsecRecord`]s or references to them; records whose owner is outside
/// `zone` are ignored. The records must have been authenticated against
/// `zone`'s keys (their RRSIG signer name is `zone`).
///
/// RFC 6840 §4.1 is enforced: a record with NS but not SOA (the parent
/// side of a zone cut) or with DNAME never denies names below its owner,
/// and a parent-side record denies nothing at its owner but DS.
///
/// Every check is a constant number of passes over the records.
#[derive(Clone, Copy, Debug)]
pub struct NsecProof<'a, I> {
    zone: Name<'a>,
    records: I,
}

impl<'a, I> NsecProof<'a, I>
where
    I: IntoIterator + Clone,
    I::Item: Into<NsecRecord<'a>>,
{
    /// A proof from `records` of `zone` (the signer name of their RRSIGs).
    #[inline]
    pub const fn new(zone: Name<'a>, records: I) -> Self {
        NsecProof { zone, records }
    }

    /// The zone the records belong to.
    #[inline]
    pub const fn zone(&self) -> Name<'a> {
        self.zone
    }

    /// The records inside the zone.
    fn iter(&self) -> impl Iterator<Item = NsecRecord<'a>> + '_ {
        self.records
            .clone()
            .into_iter()
            .map(Into::into)
            .filter(|r| r.owner.is_subdomain_of(&self.zone))
    }

    /// The record whose owner is `name`.
    fn find_match(&self, name: Name<'_>) -> Option<NsecRecord<'a>> {
        self.iter().find(|r| r.owner == name)
    }

    /// A record covering `name` that may deny it. Fails with
    /// [`BogusReason::ZoneCut`] if only records from above a zone cut (or
    /// at a DNAME) cover it, [`BogusReason::MissingProof`] if none does.
    fn find_cover(&self, name: Name<'_>) -> Result<NsecRecord<'a>, BogusReason> {
        let mut reason = BogusReason::MissingProof;
        for r in self.iter().filter(|r| r.covers(name)) {
            if name.is_subdomain_of(&r.owner) && cuts_below(&r.nsec.types) {
                reason = BogusReason::ZoneCut;
                continue;
            }
            return Ok(r);
        }
        Err(reason)
    }

    /// The closest encloser of `qname` derived from `cover`, the record
    /// covering it (RFC 7129 §5.5).
    fn encloser<'q>(
        &self,
        qname: Name<'q>,
        cover: &NsecRecord<'_>,
    ) -> Result<ClosestEncloser<'q>, BogusReason> {
        let encloser = cover.closest_encloser(qname);
        let extra = qname.label_count().saturating_sub(encloser.label_count());
        if extra == 0 || !encloser.is_subdomain_of(&self.zone) {
            return Err(BogusReason::MissingProof);
        }
        let next_closer = qname
            .strip_labels(extra - 1)
            .ok_or(BogusReason::MissingProof)?;
        Ok(ClosestEncloser {
            encloser,
            next_closer,
            opt_out: false,
        })
    }

    /// The closest encloser proof for `qname` (RFC 4035 §5.4, RFC 7129
    /// §5.5): no record matches `qname`, a record covers it, `qname` is
    /// not an empty non-terminal, and the closest encloser is the longest
    /// ancestor `qname` shares with the covering record's owner or next
    /// name (both of which exist).
    ///
    /// Fails with the status the other checks would return:
    /// [`BogusReason::OutOfZone`], [`BogusReason::NameExists`],
    /// [`BogusReason::ZoneCut`] or [`BogusReason::MissingProof`].
    pub fn closest_encloser<'q>(
        &self,
        qname: Name<'q>,
    ) -> Result<ClosestEncloser<'q>, DenialStatus> {
        if !qname.is_subdomain_of(&self.zone) {
            return Err(DenialStatus::Bogus(BogusReason::OutOfZone));
        }
        if self.find_match(qname).is_some() {
            return Err(DenialStatus::Bogus(BogusReason::NameExists));
        }
        let cover = self.find_cover(qname).map_err(DenialStatus::Bogus)?;
        if cover.is_empty_non_terminal(qname) {
            return Err(DenialStatus::Bogus(BogusReason::NameExists));
        }
        self.encloser(qname, &cover).map_err(DenialStatus::Bogus)
    }

    /// Checks an NXDOMAIN response (RFC 4035 §5.4): one record covers
    /// `qname` and one (possibly the same) covers the wildcard at its
    /// closest encloser.
    pub fn name_error(&self, qname: Name<'_>) -> DenialStatus {
        let ce = match self.closest_encloser(qname) {
            Ok(ce) => ce,
            Err(status) => return status,
        };
        let Some(wildcard) = ce.wildcard() else {
            // `*.<ce>` would be too long to exist.
            return DenialStatus::Secure(Denial::NameError);
        };
        let wildcard = wildcard.as_name();
        if self.find_match(wildcard).is_some() {
            return DenialStatus::Bogus(BogusReason::WildcardExists);
        }
        match self.find_cover(wildcard) {
            Ok(_) => DenialStatus::Secure(Denial::NameError),
            Err(r) => DenialStatus::Bogus(r),
        }
    }

    /// Checks a NOERROR/NODATA response (RFC 4035 §5.4, RFC 6840 §4.1,
    /// §4.3, §4.4): a record matching `qname` without `qtype` or CNAME,
    /// a record proving `qname` is an empty non-terminal, or a record
    /// covering `qname` plus a record matching the wildcard at its closest
    /// encloser, without `qtype` or CNAME.
    ///
    /// A matching record proves nothing about the NSEC and RRSIG types,
    /// which always exist at its owner (RFC 4035 §5.4).
    pub fn no_data(&self, qname: Name<'_>, qtype: Rtype) -> DenialStatus {
        if !qname.is_subdomain_of(&self.zone) {
            return DenialStatus::Bogus(BogusReason::OutOfZone);
        }
        if let Some(m) = self.find_match(qname) {
            if qtype == Rtype::NSEC || qtype == Rtype::RRSIG {
                return DenialStatus::Bogus(BogusReason::TypeExists);
            }
            return nodata_bitmap(&m.nsec.types, qname, qtype);
        }
        let cover = match self.find_cover(qname) {
            Ok(c) => c,
            Err(r) => return DenialStatus::Bogus(r),
        };
        // An empty non-terminal exists, with no data at all.
        if cover.is_empty_non_terminal(qname) {
            return DenialStatus::Secure(Denial::NoData);
        }
        // Wildcard NODATA (RFC 4035 §3.1.3.4).
        let ce = match self.encloser(qname, &cover) {
            Ok(ce) => ce,
            Err(r) => return DenialStatus::Bogus(r),
        };
        let Some(wildcard) = ce.wildcard() else {
            return DenialStatus::Bogus(BogusReason::MissingProof);
        };
        let Some(m) = self.find_match(wildcard.as_name()) else {
            return DenialStatus::Bogus(BogusReason::MissingProof);
        };
        if qtype == Rtype::NSEC || qtype == Rtype::RRSIG {
            return DenialStatus::Bogus(BogusReason::TypeExists);
        }
        match nodata_bitmap(&m.nsec.types, wildcard.as_name(), qtype) {
            DenialStatus::Secure(_) => DenialStatus::Secure(Denial::WildcardNoData),
            other => other,
        }
    }

    /// Checks an answer synthesized from a wildcard (RFC 4035 §5.3.4):
    /// `labels` is the RRSIG labels field, so the wildcard's closest
    /// encloser is `qname` reduced to `labels` labels; a record must cover
    /// `qname` and show that this is its closest encloser.
    pub fn wildcard_answer(&self, qname: Name<'_>, labels: u8) -> DenialStatus {
        if !qname.is_subdomain_of(&self.zone) {
            return DenialStatus::Bogus(BogusReason::OutOfZone);
        }
        let Some(encloser) = wildcard_encloser(qname, labels) else {
            return DenialStatus::Bogus(BogusReason::WrongWildcard);
        };
        if !encloser.is_subdomain_of(&self.zone) {
            return DenialStatus::Bogus(BogusReason::OutOfZone);
        }
        match self.closest_encloser(qname) {
            Ok(ce) if ce.encloser == encloser => DenialStatus::Secure(Denial::WildcardAnswer),
            Ok(_) => DenialStatus::Bogus(BogusReason::WrongWildcard),
            Err(status) => status,
        }
    }

    /// Checks a referral to an unsigned zone (RFC 4035 §5.2, RFC 6840
    /// §4.4): the record matching `delegation` has NS, but neither DS nor
    /// SOA.
    pub fn unsigned_delegation(&self, delegation: Name<'_>) -> DenialStatus {
        if !delegation.is_subdomain_of(&self.zone) {
            return DenialStatus::Bogus(BogusReason::OutOfZone);
        }
        match self.find_match(delegation) {
            Some(m) => delegation_bitmap(&m.nsec.types),
            None => DenialStatus::Bogus(BogusReason::MissingProof),
        }
    }
}

/// The closest encloser of a wildcard expansion of `qname` whose RRSIG
/// labels field is `labels` (RFC 4035 §5.3.4): `qname` reduced to
/// `labels` labels, or `None` if that is not a proper ancestor.
pub(super) fn wildcard_encloser(qname: Name<'_>, labels: u8) -> Option<Name<'_>> {
    let extra = qname
        .label_count()
        .checked_sub(usize::from(labels))
        .filter(|&e| e > 0)?;
    qname.strip_labels(extra)
}

impl<'a, I> DenialProof for NsecProof<'a, I>
where
    I: IntoIterator + Clone,
    I::Item: Into<NsecRecord<'a>>,
{
    #[inline]
    fn name_error(&self, qname: Name<'_>) -> DenialStatus {
        NsecProof::name_error(self, qname)
    }

    #[inline]
    fn no_data(&self, qname: Name<'_>, qtype: Rtype) -> DenialStatus {
        NsecProof::no_data(self, qname, qtype)
    }

    #[inline]
    fn wildcard_answer(&self, qname: Name<'_>, labels: u8) -> DenialStatus {
        NsecProof::wildcard_answer(self, qname, labels)
    }

    #[inline]
    fn unsigned_delegation(&self, delegation: Name<'_>) -> DenialStatus {
        NsecProof::unsigned_delegation(self, delegation)
    }
}
