//! RRset-level pushes and truncation (RFC 1035 §4.1.1, RFC 2181 §9).
//!
//! The record-level pushes of [`MessageBuilder`] are atomic but know
//! nothing about RRsets. The methods here treat a group of records as one
//! unit: either the whole unit fits, or none of it is left in the message.
//! What happens then is the builder's [`Truncation`] policy:
//!
//! - [`Truncation::Error`] (the default) fails with
//!   [`Error::BufferTooSmall`], leaving the message as it was before the
//!   call;
//! - [`Truncation::SetTc`] sets the TC bit and stops: later RRset-level
//!   pushes are skipped. As RFC 2181 §9 asks, TC is only set when a
//!   *required* RRset is cut. Data for the additional section is optional
//!   ("TC should not be set merely because some extra information could
//!   have been included"): an additional RRset that does not fit is just
//!   dropped, and later ones are still tried. Callers that consider some
//!   additional data required (e.g. in-domain glue, RFC 9471) call
//!   [`MessageBuilder::truncate`] when they get [`Outcome::Dropped`].
//!
//! Records that must still be added after truncation — the OPT record
//! (RFC 6891 §7), TSIG (RFC 8945 §5.3) — are written with the ordinary
//! record-level pushes, which keep working; reserve their room up front with
//! [`MessageBuilder::set_reserve`].

use super::MessageBuilder;
use crate::message::{Message, Record, Section};
use crate::name::{Name, ToName};
use crate::rdata::ComposeRdata;
use crate::wire::OutBuf;
use crate::{Class, Error, Header, Result, Rtype};

/// What the RRset-level pushes ([`MessageBuilder::push_rrset`],
/// [`MessageBuilder::copy_section`], ...) do when an RRset does not fit
/// within the size limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Truncation {
    /// Remove the partial RRset and fail with [`Error::BufferTooSmall`]
    /// (the message is left exactly as it was before the call).
    #[default]
    Error,
    /// Remove the partial RRset (RFC 2181 §9), set the TC bit
    /// (RFC 1035 §4.1.1) and skip every later RRset-level push. Optional
    /// additional-section data is dropped without setting TC.
    SetTc,
}

/// The result of an RRset-level push.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[must_use]
pub enum Outcome {
    /// Everything was written.
    Added,
    /// Something did not fit: the partial RRset was removed, the TC bit is
    /// set, and later RRset-level pushes are skipped. Also returned,
    /// without writing anything, by RRset-level pushes made after the
    /// message was truncated.
    Truncated,
    /// Some optional (additional-section) data did not fit and was left
    /// out, without setting TC (RFC 2181 §9).
    Dropped,
}

impl Outcome {
    /// Whether everything was written.
    #[inline]
    pub const fn is_added(self) -> bool {
        matches!(self, Outcome::Added)
    }

    /// Whether the message is now truncated (TC set).
    #[inline]
    pub const fn is_truncated(self) -> bool {
        matches!(self, Outcome::Truncated)
    }

    /// Combines the outcomes of two successive pushes (the worst wins).
    #[inline]
    const fn and(self, other: Outcome) -> Outcome {
        match (self, other) {
            (Outcome::Truncated, _) | (_, Outcome::Truncated) => Outcome::Truncated,
            (Outcome::Dropped, _) | (_, Outcome::Dropped) => Outcome::Dropped,
            _ => Outcome::Added,
        }
    }
}

/// The type an RRSIG record covers (RFC 4034 §3.1: the first two RDATA
/// octets), used to keep signatures together with their RRset.
fn rrsig_covers(rr: &Record<'_>) -> Option<Rtype> {
    if rr.rtype() != Rtype::RRSIG {
        return None;
    }
    match *rr.rdata() {
        [a, b, ..] => Some(Rtype::new(u16::from_be_bytes([a, b]))),
        _ => None,
    }
}

/// The identity of the RRset a parsed record belongs to: owner name
/// (compared case-insensitively, RFC 4343), type and class. An RRSIG joins
/// the RRset it covers when it directly follows it.
struct RrsetKey<'a> {
    name: Name<'a>,
    rtype: Rtype,
    class: Class,
}

impl<'a> RrsetKey<'a> {
    fn of(rr: &Record<'a>) -> Self {
        RrsetKey {
            name: rr.name(),
            rtype: rr.rtype(),
            class: rr.class(),
        }
    }

    fn contains(&self, rr: &Record<'_>) -> bool {
        rr.class() == self.class
            && (rr.rtype() == self.rtype || rrsig_covers(rr) == Some(self.rtype))
            && rr.name() == self.name
    }
}

impl<B: OutBuf> MessageBuilder<B> {
    /// Sets what RRset-level pushes do when an RRset does not fit; see
    /// [`Truncation`]. The default is [`Truncation::Error`].
    #[inline]
    pub fn set_truncation(&mut self, policy: Truncation) {
        self.policy = policy;
    }

    /// The current truncation policy.
    #[inline]
    pub const fn truncation(&self) -> Truncation {
        self.policy
    }

    /// Whether the message was truncated by an RRset-level push or
    /// [`truncate`](Self::truncate). (Setting TC through
    /// [`set_flags`](Self::set_flags) does not count.)
    #[inline]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Marks the message as truncated: sets the TC bit (RFC 1035 §4.1.1)
    /// and makes later RRset-level pushes no-ops returning
    /// [`Outcome::Truncated`]. Record-level pushes keep working (for OPT,
    /// TSIG, ...). Not undone by [`rollback`](Self::rollback).
    pub fn truncate(&mut self) {
        self.truncated = true;
        self.header.flags = self.header.flags.with_tc(true);
        self.sync_header();
    }

    /// Applies the truncation policy after a unit of `section` did not
    /// fit (and was rolled back).
    fn overflow(&mut self, section: Section) -> Result<Outcome> {
        match self.policy {
            Truncation::Error => Err(Error::BufferTooSmall),
            Truncation::SetTc if section == Section::Additional => Ok(Outcome::Dropped),
            Truncation::SetTc => {
                self.truncate();
                Ok(Outcome::Truncated)
            }
        }
    }

    /// Runs `f` as one all-or-nothing unit belonging to `section` (an
    /// RRset, possibly with its RRSIGs, written with the record-level
    /// pushes).
    ///
    /// If `f` fails with [`Error::BufferTooSmall`], everything it wrote is
    /// removed and the [`Truncation`] policy applies. Any other error
    /// removes everything `f` wrote and is returned. If the message is
    /// already truncated, `f` is not called and [`Outcome::Truncated`] is
    /// returned. `section` must not be [`Section::Question`].
    ///
    /// ```
    /// use dnsbox::{Class, MessageBuilder, NameBuf, Rtype, Section};
    /// use dnsbox::builder::{Outcome, Truncation};
    /// use dnsbox::rdata::A;
    ///
    /// let name: NameBuf = "example.com".parse()?;
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.set_limit(60);
    /// b.set_truncation(Truncation::SetTc);
    /// b.push_question(&name, Rtype::A, Class::IN)?;
    /// let outcome = b.push_rrset_with(Section::Answer, |b| {
    ///     for i in 0..4 {
    ///         b.push_answer(&name, Class::IN, 300, &A::new([192, 0, 2, i].into()))?;
    ///     }
    ///     Ok(())
    /// })?;
    /// // 29 + 4 × 16 bytes do not fit in 60: the whole RRset is left out.
    /// assert_eq!(outcome, Outcome::Truncated);
    /// assert_eq!(b.header().ancount, 0);
    /// assert!(b.header().flags.tc());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn push_rrset_with<F>(&mut self, section: Section, f: F) -> Result<Outcome>
    where
        F: FnOnce(&mut Self) -> Result<()>,
    {
        if section == Section::Question {
            return Err(Error::SectionOrder);
        }
        if self.truncated {
            return Ok(Outcome::Truncated);
        }
        let cp = self.checkpoint();
        match f(self) {
            Ok(()) => Ok(Outcome::Added),
            Err(Error::BufferTooSmall) => {
                self.rollback(cp);
                self.overflow(section)
            }
            Err(e) => {
                self.rollback(cp);
                Err(e)
            }
        }
    }

    /// Appends an RRset — the records `name class ttl rdata` for every
    /// item of `rdata` — to `section` as one unit: if it does not fit, none
    /// of it is kept and the [`Truncation`] policy applies (see
    /// [`push_rrset_with`](Self::push_rrset_with)).
    ///
    /// ```
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype, Section};
    /// use dnsbox::builder::Outcome;
    /// use dnsbox::rdata::A;
    ///
    /// let name: NameBuf = "example.com".parse()?;
    /// let addrs = [A::new([192, 0, 2, 1].into()), A::new([192, 0, 2, 2].into())];
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.push_question(&name, Rtype::A, Class::IN)?;
    /// assert_eq!(b.push_rrset(Section::Answer, &name, Class::IN, 300, &addrs)?, Outcome::Added);
    /// assert_eq!(Message::parse_validated(b.finish())?.header().ancount, 2);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn push_rrset<I>(
        &mut self,
        section: Section,
        name: impl ToName,
        class: Class,
        ttl: u32,
        rdata: I,
    ) -> Result<Outcome>
    where
        I: IntoIterator,
        I::Item: ComposeRdata,
    {
        let name = name.to_name();
        self.push_rrset_with(section, |b| {
            for data in rdata {
                b.push_record(section, name, class, ttl, &data)?;
            }
            Ok(())
        })
    }

    /// Copies one section of a parsed message into the same section of
    /// this one, RRset by RRset, re-encoding RDATA (names are decompressed
    /// and recompressed against this message, as with
    /// [`copy_record`](Self::copy_record)).
    ///
    /// Consecutive records with the same owner, type and class form an
    /// RRset, together with the RRSIG records that directly follow them
    /// and cover their type (RFC 4035 §3.1.1 asks that signatures travel
    /// with their RRset). Each RRset is one unit for the [`Truncation`]
    /// policy. For [`Section::Question`] the questions are copied, and a
    /// question that does not fit is always an error.
    ///
    /// On an error (malformed source message, or a unit that does not fit
    /// under [`Truncation::Error`]), everything this call wrote is removed.
    pub fn copy_section(&mut self, msg: &Message<'_>, section: Section) -> Result<Outcome> {
        let mut opt = None;
        self.copy_section_inner(msg, section, &mut opt, 0)
    }

    /// The body of [`copy_section`](Self::copy_section). If `opt` holds a
    /// record offset, the record starting there (the OPT record of
    /// [`copy_message`](Self::copy_message)) is copied on its own after
    /// releasing the reserve down to `base_reserve`, and `opt` is cleared.
    fn copy_section_inner(
        &mut self,
        msg: &Message<'_>,
        section: Section,
        opt: &mut Option<usize>,
        base_reserve: usize,
    ) -> Result<Outcome> {
        let start = self.checkpoint();
        if section == Section::Question {
            for q in msg.questions() {
                if let Err(e) = q.and_then(|q| self.copy_question(&q)) {
                    self.rollback(start);
                    return Err(e);
                }
            }
            return Ok(Outcome::Added);
        }
        if self.truncated {
            return Ok(Outcome::Truncated);
        }
        let mut outcome = Outcome::Added;
        let mut group: Option<RrsetKey<'_>> = None;
        let mut group_start = start;
        let mut skipping = false;
        for rr in msg.section(section) {
            let rr = match rr {
                Ok(rr) => rr,
                Err(e) => {
                    self.rollback(start);
                    return Err(e);
                }
            };
            if *opt == Some(rr.start()) {
                *opt = None;
                self.reserve = base_reserve;
                if let Err(e) = self.copy_record(section, &rr) {
                    self.rollback(start);
                    return Err(e);
                }
                group = None;
                continue;
            }
            if !group.as_ref().is_some_and(|g| g.contains(&rr)) {
                group = Some(RrsetKey::of(&rr));
                group_start = self.checkpoint();
                skipping = false;
            }
            if skipping {
                continue;
            }
            match self.copy_record(section, &rr) {
                Ok(()) => {}
                Err(Error::BufferTooSmall) => {
                    self.rollback(group_start);
                    match self.overflow(section) {
                        Ok(Outcome::Truncated) => return Ok(Outcome::Truncated),
                        Ok(o) => {
                            outcome = outcome.and(o);
                            skipping = true;
                        }
                        Err(e) => {
                            self.rollback(start);
                            return Err(e);
                        }
                    }
                }
                Err(e) => {
                    self.rollback(start);
                    return Err(e);
                }
            }
        }
        Ok(outcome)
    }

    /// Copies a whole parsed message into this (empty) builder: ID, flags,
    /// questions and every section, RRset by RRset with the [`Truncation`]
    /// policy — e.g. to fit a response received over TCP into a 512-byte
    /// UDP reply. Records are re-encoded with this builder's compression.
    ///
    /// The source's OPT record (RFC 6891), if any, is always kept: its
    /// size is [reserved](Self::set_reserve) while the other records are
    /// copied, and when truncation stops the copy before it is reached it
    /// is appended at the end. Other records are copied as they are;
    /// signatures over the message (TSIG, SIG(0)) cover the original bytes
    /// and must be recomputed by the caller if needed.
    ///
    /// Fails with [`Error::SectionOrder`] if anything was written to the
    /// builder already. On error the builder is left as it was.
    ///
    /// ```
    /// use dnsbox::{Message, MessageBuilder};
    /// use dnsbox::builder::{Outcome, Truncation};
    /// # use dnsbox::{Class, NameBuf, Rtype, Section, rdata::A};
    /// # let name: NameBuf = "example.com".parse()?;
    /// # let mut big_buf = [0u8; 1024];
    /// # let mut big = MessageBuilder::new(&mut big_buf)?;
    /// # big.push_question(&name, Rtype::A, Class::IN)?;
    /// # let addrs = [A::new([192, 0, 2, 1].into()); 40];
    /// # let _ = big.push_rrset(Section::Answer, &name, Class::IN, 60, &addrs)?;
    /// # let tcp_response = big.finish();
    /// // `tcp_response`: a 669-byte response with a 40-record RRset.
    /// let full = Message::parse_validated(tcp_response)?;
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.set_truncation(Truncation::SetTc);
    /// assert_eq!(b.copy_message(&full)?, Outcome::Truncated);
    /// let small = Message::parse_validated(b.finish())?;
    /// assert!(small.flags().tc());
    /// assert_eq!(small.header().ancount, 0); // the RRset was cut whole
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn copy_message(&mut self, msg: &Message<'_>) -> Result<Outcome> {
        self.ensure_fresh()?;
        let saved_header = self.header;
        let saved_reserve = self.reserve;
        let saved_truncated = self.truncated;
        self.header.id = msg.id();
        self.header.flags = msg.flags();
        self.sync_header();
        let res = self.copy_message_inner(msg, saved_reserve);
        self.reserve = saved_reserve;
        if res.is_err() {
            self.rollback(self.fresh_checkpoint());
            self.header = saved_header;
            self.truncated = saved_truncated;
            self.sync_header();
        }
        res
    }

    fn copy_message_inner(&mut self, msg: &Message<'_>, base_reserve: usize) -> Result<Outcome> {
        let mut none = None;
        let _ = self.copy_section_inner(msg, Section::Question, &mut none, base_reserve)?;
        // Locate the OPT record (the first one; RFC 6891 §6.1.1 forbids
        // more) and reserve its room.
        let mut opt = None;
        let mut opt_len = 0;
        for rr in msg.additional().flatten() {
            if rr.rtype() == Rtype::OPT {
                opt = Some(rr.start());
                opt_len = rr.name().wire_len() + 10 + rr.rdata().len();
                break;
            }
        }
        self.reserve = base_reserve.saturating_add(opt_len);
        let mut outcome = Outcome::Added;
        for section in [Section::Answer, Section::Authority, Section::Additional] {
            let o = self.copy_section_inner(msg, section, &mut opt, base_reserve)?;
            outcome = outcome.and(o);
        }
        if let Some(at) = opt {
            // Not reached (the copy was truncated before it): append it.
            self.reserve = base_reserve;
            for rr in msg.additional() {
                let rr = rr?;
                if rr.start() == at {
                    self.copy_record(Section::Additional, &rr)?;
                    break;
                }
            }
        }
        Ok(outcome)
    }

    /// Fails with [`Error::SectionOrder`] unless nothing was written yet.
    pub(super) fn ensure_fresh(&self) -> Result<()> {
        let h = &self.header;
        if self.len() != Header::LEN
            || self.section != Section::Question
            || (h.qdcount, h.ancount, h.nscount, h.arcount) != (0, 0, 0, 0)
        {
            return Err(Error::SectionOrder);
        }
        Ok(())
    }

    /// A checkpoint of the empty message.
    pub(super) fn fresh_checkpoint(&self) -> super::Checkpoint {
        super::Checkpoint {
            len: Header::LEN,
            counts: [0; 4],
            section: Section::Question,
            table_len: 0,
        }
    }
}

#[cfg(test)]
mod tests;
