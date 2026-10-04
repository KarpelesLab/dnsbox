//! Dynamic UPDATE messages (RFC 2136).
//!
//! An UPDATE message reuses the four sections under new names (RFC 2136
//! §2): **Zone** (the question section: one entry, the zone's SOA),
//! **Prerequisite** (answer section), **Update** (authority section) and
//! **Additional**. Prerequisites and updates are encoded as resource
//! records whose CLASS, TYPE and RDATA select the meaning (§2.4, §2.5):
//!
//! | CLASS | TYPE | RDATA | Prerequisite (§2.4) | Update (§2.5) |
//! |---|---|---|---|---|
//! | zone | rrset | RR | RRset exists, value-dependent | add RR |
//! | ANY | rrset | empty | RRset exists | delete RRset |
//! | ANY | ANY | empty | name is in use | delete all RRsets of the name |
//! | NONE | rrset | empty / RR | RRset does not exist | delete RR |
//! | NONE | ANY | empty | name is not in use | — |
//!
//! [`UpdateBuilder`] writes these forms; [`UpdateMessage`] classifies them
//! when parsing, applying the FORMERR rules of §3.2 and §3.4.1.3 (reported
//! as [`Error::MalformedUpdate`]).
//!
//! ```
//! use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
//! use dnsbox::rdata::A;
//! use dnsbox::update::{Prerequisite, UpdateBuilder, UpdateMessage, UpdateOp};
//!
//! let zone: NameBuf = "example.com".parse()?;
//! let host: NameBuf = "www.example.com".parse()?;
//! let mut buf = [0u8; 512];
//! let mut u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
//! u.require_name_absent(&host)?;
//! u.add(&host, 300, &A::new([192, 0, 2, 1].into()))?;
//! let wire = u.finish();
//!
//! let update = UpdateMessage::new(Message::parse_validated(wire)?)?;
//! assert_eq!(update.zone_name(), zone.as_name());
//! assert!(matches!(update.prerequisites().next(), Some(Ok(Prerequisite::NameAbsent(_)))));
//! assert!(matches!(update.updates().next(), Some(Ok(UpdateOp::Add(_)))));
//! # Ok::<(), dnsbox::Error>(())
//! ```

use crate::builder::MessageBuilder;
use crate::message::{Message, Question, Record, Records, Section};
use crate::name::{Name, ToName};
use crate::rdata::{ComposeRdata, UnknownRdata};
use crate::wire::OutBuf;
use crate::{Class, Error, Opcode, Result, Rtype};

/// Builds an UPDATE message (RFC 2136 §2) on top of a [`MessageBuilder`].
///
/// Prerequisites must be added before updates, and updates before
/// additional data (section order); each method is atomic like the
/// builder's pushes. Use [`builder`](Self::builder) for the ID, TSIG or
/// SIG(0) signing, and checkpoints.
#[derive(Debug)]
pub struct UpdateBuilder<B: OutBuf> {
    inner: MessageBuilder<B>,
    class: Class,
}

/// Empty RDATA of a given type, for the RDLENGTH-0 forms.
const fn empty(rtype: Rtype) -> UnknownRdata<'static> {
    UnknownRdata::new(rtype, &[])
}

/// Whether `rtype` may name an RRset in an update or prerequisite: not a
/// meta-type or QTYPE (RFC 2136 §3.4.1.3).
const fn is_rrset_type(rtype: Rtype) -> bool {
    !rtype.is_meta() && rtype.get() != 0
}

impl<B: OutBuf> UpdateBuilder<B> {
    /// Starts an UPDATE for `zone` in `class` (§2.3): sets the opcode and
    /// writes the zone section (`zone SOA class`). `builder` must not hold
    /// any question or record yet ([`Error::SectionOrder`]).
    pub fn new(mut builder: MessageBuilder<B>, zone: impl ToName, class: Class) -> Result<Self> {
        if !builder.is_empty() {
            return Err(Error::SectionOrder);
        }
        let flags = builder.header().flags.with_opcode(Opcode::UPDATE);
        builder.set_flags(flags);
        builder.push_question(zone, Rtype::SOA, class)?;
        Ok(UpdateBuilder {
            inner: builder,
            class,
        })
    }

    /// The zone class.
    #[inline]
    pub const fn zone_class(&self) -> Class {
        self.class
    }

    /// The underlying builder (ID, flags, checkpoints, signing).
    #[inline]
    pub fn builder(&mut self) -> &mut MessageBuilder<B> {
        &mut self.inner
    }

    /// Returns the underlying builder.
    #[inline]
    pub fn into_builder(self) -> MessageBuilder<B> {
        self.inner
    }

    /// Finishes the message.
    #[inline]
    pub fn finish(self) -> B::Output {
        self.inner.finish()
    }

    fn rrset_type(rtype: Rtype) -> Result<()> {
        if is_rrset_type(rtype) {
            Ok(())
        } else {
            Err(Error::MalformedUpdate)
        }
    }

    /// Prerequisite: an RRset of `rtype` exists at `name`, whatever its
    /// value (§2.4.1: CLASS ANY, TTL 0, empty RDATA).
    pub fn require_rrset_exists(&mut self, name: impl ToName, rtype: Rtype) -> Result<()> {
        Self::rrset_type(rtype)?;
        self.inner
            .push_record(Section::Answer, name, Class::ANY, 0, &empty(rtype))
    }

    /// Prerequisite: the RRset at `name` contains this RR (§2.4.2: zone
    /// class, TTL 0). A value-dependent prerequisite on a whole RRset is
    /// one such record per RR of the set; the server compares the full
    /// set.
    pub fn require_rr<D: ComposeRdata + ?Sized>(
        &mut self,
        name: impl ToName,
        data: &D,
    ) -> Result<()> {
        Self::rrset_type(data.rtype())?;
        self.inner
            .push_record(Section::Answer, name, self.class, 0, data)
    }

    /// Prerequisite: no RRset of `rtype` exists at `name` (§2.4.3: CLASS
    /// NONE, TTL 0, empty RDATA).
    pub fn require_rrset_absent(&mut self, name: impl ToName, rtype: Rtype) -> Result<()> {
        Self::rrset_type(rtype)?;
        self.inner
            .push_record(Section::Answer, name, Class::NONE, 0, &empty(rtype))
    }

    /// Prerequisite: `name` owns at least one RR (§2.4.4: CLASS ANY, TYPE
    /// ANY).
    pub fn require_name_in_use(&mut self, name: impl ToName) -> Result<()> {
        self.inner
            .push_record(Section::Answer, name, Class::ANY, 0, &empty(Rtype::ANY))
    }

    /// Prerequisite: `name` owns no RR (§2.4.5: CLASS NONE, TYPE ANY).
    pub fn require_name_absent(&mut self, name: impl ToName) -> Result<()> {
        self.inner
            .push_record(Section::Answer, name, Class::NONE, 0, &empty(Rtype::ANY))
    }

    /// Update: add an RR to an RRset (§2.5.1: zone class).
    pub fn add<D: ComposeRdata + ?Sized>(
        &mut self,
        name: impl ToName,
        ttl: u32,
        data: &D,
    ) -> Result<()> {
        Self::rrset_type(data.rtype())?;
        self.inner
            .push_record(Section::Authority, name, self.class, ttl, data)
    }

    /// Update: delete the RRset of `rtype` at `name` (§2.5.2: CLASS ANY,
    /// TTL 0, empty RDATA).
    pub fn delete_rrset(&mut self, name: impl ToName, rtype: Rtype) -> Result<()> {
        Self::rrset_type(rtype)?;
        self.inner
            .push_record(Section::Authority, name, Class::ANY, 0, &empty(rtype))
    }

    /// Update: delete every RRset at `name` (§2.5.3: CLASS ANY, TYPE ANY).
    pub fn delete_name(&mut self, name: impl ToName) -> Result<()> {
        self.inner
            .push_record(Section::Authority, name, Class::ANY, 0, &empty(Rtype::ANY))
    }

    /// Update: delete one RR from an RRset (§2.5.4: CLASS NONE, TTL 0).
    pub fn delete_rr<D: ComposeRdata + ?Sized>(
        &mut self,
        name: impl ToName,
        data: &D,
    ) -> Result<()> {
        Self::rrset_type(data.rtype())?;
        self.inner
            .push_record(Section::Authority, name, Class::NONE, 0, data)
    }

    /// Additional data (§2.6), e.g. glue for added NS records.
    pub fn push_additional<D: ComposeRdata + ?Sized>(
        &mut self,
        name: impl ToName,
        class: Class,
        ttl: u32,
        data: &D,
    ) -> Result<()> {
        self.inner.push_additional(name, class, ttl, data)
    }
}

/// A prerequisite of an UPDATE (RFC 2136 §2.4, classified per §3.2).
#[derive(Clone, Copy, Debug)]
pub enum Prerequisite<'a> {
    /// An RRset of this type exists, value-independent (§2.4.1).
    RrsetExists {
        /// Owner name.
        name: Name<'a>,
        /// RRset type.
        rtype: Rtype,
    },
    /// This RR is part of an RRset that must exist with exactly the RRs
    /// listed (value-dependent, §2.4.2). The record's TTL is 0.
    RrExists(Record<'a>),
    /// No RRset of this type exists (§2.4.3).
    RrsetAbsent {
        /// Owner name.
        name: Name<'a>,
        /// RRset type.
        rtype: Rtype,
    },
    /// The name owns at least one RR (§2.4.4).
    NameInUse(Name<'a>),
    /// The name owns no RR (§2.4.5).
    NameAbsent(Name<'a>),
}

impl<'a> Prerequisite<'a> {
    /// The owner name the prerequisite is about.
    pub fn name(&self) -> Name<'a> {
        match *self {
            Prerequisite::RrsetExists { name, .. }
            | Prerequisite::RrsetAbsent { name, .. }
            | Prerequisite::NameInUse(name)
            | Prerequisite::NameAbsent(name) => name,
            Prerequisite::RrExists(rr) => rr.name(),
        }
    }

    /// Classifies a prerequisite RR (§3.2), failing with
    /// [`Error::MalformedUpdate`] (FORMERR) on an invalid combination.
    pub fn classify(rr: Record<'a>, zone_class: Class) -> Result<Self> {
        if rr.ttl() != 0 {
            return Err(Error::MalformedUpdate);
        }
        let (name, rtype, empty) = (rr.name(), rr.rtype(), rr.rdata().is_empty());
        let class = rr.class();
        Ok(if class == Class::ANY {
            if !empty {
                return Err(Error::MalformedUpdate);
            }
            if rtype == Rtype::ANY {
                Prerequisite::NameInUse(name)
            } else if is_rrset_type(rtype) {
                Prerequisite::RrsetExists { name, rtype }
            } else {
                return Err(Error::MalformedUpdate);
            }
        } else if class == Class::NONE {
            if !empty {
                return Err(Error::MalformedUpdate);
            }
            if rtype == Rtype::ANY {
                Prerequisite::NameAbsent(name)
            } else if is_rrset_type(rtype) {
                Prerequisite::RrsetAbsent { name, rtype }
            } else {
                return Err(Error::MalformedUpdate);
            }
        } else if class == zone_class && is_rrset_type(rtype) {
            Prerequisite::RrExists(rr)
        } else {
            return Err(Error::MalformedUpdate);
        })
    }
}

/// An update operation (RFC 2136 §2.5, classified per §3.4.1.3).
#[derive(Clone, Copy, Debug)]
pub enum UpdateOp<'a> {
    /// Add this RR (§2.5.1).
    Add(Record<'a>),
    /// Delete the RRset of this type (§2.5.2).
    DeleteRrset {
        /// Owner name.
        name: Name<'a>,
        /// RRset type.
        rtype: Rtype,
    },
    /// Delete every RRset of the name (§2.5.3).
    DeleteName(Name<'a>),
    /// Delete this RR (§2.5.4; the record's class is NONE and TTL 0, its
    /// RDATA identifies the RR).
    DeleteRr(Record<'a>),
}

impl<'a> UpdateOp<'a> {
    /// The owner name the operation applies to.
    pub fn name(&self) -> Name<'a> {
        match *self {
            UpdateOp::Add(rr) | UpdateOp::DeleteRr(rr) => rr.name(),
            UpdateOp::DeleteRrset { name, .. } | UpdateOp::DeleteName(name) => name,
        }
    }

    /// Classifies an update RR (§3.4.1.3 prescan), failing with
    /// [`Error::MalformedUpdate`] (FORMERR) on an invalid combination.
    pub fn classify(rr: Record<'a>, zone_class: Class) -> Result<Self> {
        let (class, rtype) = (rr.class(), rr.rtype());
        Ok(if class == Class::ANY {
            if rr.ttl() != 0 || !rr.rdata().is_empty() {
                return Err(Error::MalformedUpdate);
            }
            if rtype == Rtype::ANY {
                UpdateOp::DeleteName(rr.name())
            } else if is_rrset_type(rtype) {
                UpdateOp::DeleteRrset {
                    name: rr.name(),
                    rtype,
                }
            } else {
                return Err(Error::MalformedUpdate);
            }
        } else if class == Class::NONE {
            if rr.ttl() != 0 || !is_rrset_type(rtype) {
                return Err(Error::MalformedUpdate);
            }
            UpdateOp::DeleteRr(rr)
        } else if class == zone_class && is_rrset_type(rtype) {
            UpdateOp::Add(rr)
        } else {
            return Err(Error::MalformedUpdate);
        })
    }
}

/// A parsed UPDATE message (RFC 2136 §2): a view over a [`Message`].
#[derive(Clone, Copy, Debug)]
pub struct UpdateMessage<'a> {
    msg: Message<'a>,
    zone: Question<'a>,
}

impl<'a> UpdateMessage<'a> {
    /// Wraps a message, checking that it is an UPDATE (opcode 5) with
    /// exactly one zone entry of type SOA (§3.1.1); fails with
    /// [`Error::MalformedUpdate`] otherwise.
    pub fn new(msg: Message<'a>) -> Result<Self> {
        if msg.flags().opcode() != Opcode::UPDATE || msg.header().qdcount != 1 {
            return Err(Error::MalformedUpdate);
        }
        let zone = msg.questions().next().ok_or(Error::UnexpectedEof)??;
        if zone.qtype() != Rtype::SOA {
            return Err(Error::MalformedUpdate);
        }
        Ok(UpdateMessage { msg, zone })
    }

    /// The underlying message.
    #[inline]
    pub const fn message(&self) -> Message<'a> {
        self.msg
    }

    /// The zone section entry.
    #[inline]
    pub const fn zone(&self) -> Question<'a> {
        self.zone
    }

    /// The zone name (ZNAME).
    #[inline]
    pub const fn zone_name(&self) -> Name<'a> {
        self.zone.name()
    }

    /// The zone class (ZCLASS).
    #[inline]
    pub const fn zone_class(&self) -> Class {
        self.zone.qclass()
    }

    /// Whether `name` is at or below the zone name: servers answer NOTZONE
    /// for prerequisites or updates outside the zone (§3.2, §3.4.1.3).
    pub fn in_zone(&self, name: &Name<'_>) -> bool {
        name.is_subdomain_of(&self.zone.name())
    }

    /// The prerequisite section (answer section), classified.
    pub fn prerequisites(&self) -> Prerequisites<'a> {
        Prerequisites {
            inner: self.msg.answers(),
            class: self.zone_class(),
            failed: false,
        }
    }

    /// The update section (authority section), classified.
    pub fn updates(&self) -> Updates<'a> {
        Updates {
            inner: self.msg.authority(),
            class: self.zone_class(),
            failed: false,
        }
    }

    /// The additional data section.
    #[inline]
    pub fn additional(&self) -> Records<'a> {
        self.msg.additional()
    }

    /// Checks every prerequisite and update once (FORMERR conditions only;
    /// zone membership is left to [`in_zone`](Self::in_zone)).
    pub fn validate(&self) -> Result<()> {
        for p in self.prerequisites() {
            p?;
        }
        for u in self.updates() {
            u?;
        }
        Ok(())
    }
}

/// Iterator over the prerequisites of an UPDATE; see
/// [`UpdateMessage::prerequisites`]. Stops after the first error.
#[derive(Clone, Debug)]
pub struct Prerequisites<'a> {
    inner: Records<'a>,
    class: Class,
    failed: bool,
}

impl<'a> Iterator for Prerequisites<'a> {
    type Item = Result<Prerequisite<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let item = self
            .inner
            .next()?
            .and_then(|rr| Prerequisite::classify(rr, self.class));
        self.failed = item.is_err();
        Some(item)
    }
}

impl core::iter::FusedIterator for Prerequisites<'_> {}

/// Iterator over the update operations of an UPDATE; see
/// [`UpdateMessage::updates`]. Stops after the first error.
#[derive(Clone, Debug)]
pub struct Updates<'a> {
    inner: Records<'a>,
    class: Class,
    failed: bool,
}

impl<'a> Iterator for Updates<'a> {
    type Item = Result<UpdateOp<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let item = self
            .inner
            .next()?
            .and_then(|rr| UpdateOp::classify(rr, self.class));
        self.failed = item.is_err();
        Some(item)
    }
}

impl core::iter::FusedIterator for Updates<'_> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NameBuf;
    use crate::rdata::{A, Txt};
    use std::string::ToString;
    use std::vec::Vec;

    fn n(s: &str) -> NameBuf {
        s.parse().unwrap()
    }

    fn build(f: impl FnOnce(&mut UpdateBuilder<crate::WireWriter<'_>>) -> Result<()>) -> Vec<u8> {
        let mut buf = [0u8; 1024];
        let mut u = UpdateBuilder::new(
            MessageBuilder::new(&mut buf).unwrap(),
            n("example.com"),
            Class::IN,
        )
        .unwrap();
        f(&mut u).unwrap();
        u.finish().to_vec()
    }

    #[test]
    fn every_form_round_trips() {
        let a = A::new([192, 0, 2, 1].into());
        let wire = build(|u| {
            u.require_rrset_exists(n("a.example.com"), Rtype::A)?;
            u.require_rr(n("b.example.com"), &a)?;
            u.require_rrset_absent(n("c.example.com"), Rtype::TXT)?;
            u.require_name_in_use(n("d.example.com"))?;
            u.require_name_absent(n("e.example.com"))?;
            u.add(n("f.example.com"), 300, &a)?;
            u.delete_rrset(n("g.example.com"), Rtype::MX)?;
            u.delete_name(n("h.example.com"))?;
            u.delete_rr(n("i.example.com"), &a)?;
            u.push_additional(n("ns.example.com"), Class::IN, 60, &a)
        });
        let msg = Message::parse_validated(&wire).unwrap();
        assert_eq!(msg.flags().opcode(), Opcode::UPDATE);
        let up = UpdateMessage::new(msg).unwrap();
        up.validate().unwrap();
        assert_eq!(up.zone_class(), Class::IN);
        assert_eq!(up.zone().qtype(), Rtype::SOA);
        let pre: Vec<_> = up.prerequisites().map(|p| p.unwrap()).collect();
        assert!(matches!(
            pre[0],
            Prerequisite::RrsetExists {
                rtype: Rtype::A,
                ..
            }
        ));
        assert!(
            matches!(pre[1], Prerequisite::RrExists(rr) if rr.data().unwrap().to_string() == "192.0.2.1")
        );
        assert!(matches!(
            pre[2],
            Prerequisite::RrsetAbsent {
                rtype: Rtype::TXT,
                ..
            }
        ));
        assert!(matches!(pre[3], Prerequisite::NameInUse(_)));
        assert!(matches!(pre[4], Prerequisite::NameAbsent(_)));
        let names: Vec<_> = pre.iter().map(|p| p.name().to_string()).collect();
        assert_eq!(
            names,
            [
                "a.example.com.",
                "b.example.com.",
                "c.example.com.",
                "d.example.com.",
                "e.example.com."
            ]
        );
        let ups: Vec<_> = up.updates().map(|u| u.unwrap()).collect();
        assert!(matches!(ups[0], UpdateOp::Add(rr) if rr.ttl() == 300));
        assert!(matches!(
            ups[1],
            UpdateOp::DeleteRrset {
                rtype: Rtype::MX,
                ..
            }
        ));
        assert!(matches!(ups[2], UpdateOp::DeleteName(_)));
        assert!(matches!(ups[3], UpdateOp::DeleteRr(rr) if rr.class() == Class::NONE));
        assert_eq!(ups[3].name().to_string(), "i.example.com.");
        assert_eq!(up.additional().count(), 1);
        assert!(up.in_zone(&ups[0].name()));
        assert!(!up.in_zone(&n("example.org").as_name()));
    }

    #[test]
    fn builder_rejects_meta_types() {
        let mut buf = [0u8; 512];
        let mut u = UpdateBuilder::new(
            MessageBuilder::new(&mut buf).unwrap(),
            n("example.com"),
            Class::IN,
        )
        .unwrap();
        for t in [
            Rtype::ANY,
            Rtype::AXFR,
            Rtype::OPT,
            Rtype::TSIG,
            Rtype::new(0),
        ] {
            assert_eq!(
                u.require_rrset_exists(n("x"), t),
                Err(Error::MalformedUpdate)
            );
            assert_eq!(u.delete_rrset(n("x"), t), Err(Error::MalformedUpdate));
            assert_eq!(
                u.add(n("x"), 0, &UnknownRdata::new(t, &[])),
                Err(Error::MalformedUpdate)
            );
        }
        // Section order: no prerequisites after updates.
        u.delete_name(n("x.example.com")).unwrap();
        assert_eq!(u.require_name_in_use(n("x")), Err(Error::SectionOrder));
        assert_eq!(u.builder().header().nscount, 1);
        // The builder must be empty.
        let mut buf = [0u8; 512];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.push_question(n("x"), Rtype::A, Class::IN).unwrap();
        assert_eq!(
            UpdateBuilder::new(b, n("x"), Class::IN).err(),
            Some(Error::SectionOrder)
        );
    }

    /// Builds a raw UPDATE with one record in `section`.
    fn raw(section: Section, class: Class, rtype: Rtype, ttl: u32, rdata: &[u8]) -> Vec<u8> {
        let mut buf = [0u8; 512];
        let mut u = UpdateBuilder::new(
            MessageBuilder::new(&mut buf).unwrap(),
            n("example.com"),
            Class::IN,
        )
        .unwrap();
        u.builder()
            .push_record(
                section,
                n("x.example.com"),
                class,
                ttl,
                &UnknownRdata::new(rtype, rdata),
            )
            .unwrap();
        u.finish().to_vec()
    }

    #[test]
    fn formerr_rules() {
        let bad_pre = [
            (Class::ANY, Rtype::A, 1, &[][..]),           // TTL != 0
            (Class::ANY, Rtype::A, 0, &[1, 2, 3, 4][..]), // RDATA with ANY
            (Class::NONE, Rtype::A, 0, &[1, 2, 3, 4][..]),
            (Class::CH, Rtype::A, 0, &[1, 2, 3, 4][..]), // other class
            (Class::ANY, Rtype::AXFR, 0, &[][..]),
            (Class::IN, Rtype::ANY, 0, &[][..]),
        ];
        for (class, rtype, ttl, rdata) in bad_pre {
            let wire = raw(Section::Answer, class, rtype, ttl, rdata);
            let up = UpdateMessage::new(Message::parse(&wire).unwrap()).unwrap();
            let mut it = up.prerequisites();
            assert_eq!(
                it.next().unwrap().err(),
                Some(Error::MalformedUpdate),
                "{class} {rtype} {ttl}"
            );
            assert!(it.next().is_none());
            assert_eq!(up.validate(), Err(Error::MalformedUpdate));
        }
        let bad_up = [
            (Class::ANY, Rtype::A, 1, &[][..]),
            (Class::ANY, Rtype::A, 0, &[1, 2, 3, 4][..]),
            (Class::ANY, Rtype::MAILA, 0, &[][..]),
            (Class::NONE, Rtype::A, 5, &[1, 2, 3, 4][..]),
            (Class::NONE, Rtype::ANY, 0, &[][..]),
            (Class::IN, Rtype::ANY, 0, &[][..]),
            (Class::IN, Rtype::AXFR, 0, &[][..]),
            (Class::HS, Rtype::A, 0, &[1, 2, 3, 4][..]),
        ];
        for (class, rtype, ttl, rdata) in bad_up {
            let wire = raw(Section::Authority, class, rtype, ttl, rdata);
            let up = UpdateMessage::new(Message::parse(&wire).unwrap()).unwrap();
            assert_eq!(
                up.updates().next().unwrap().err(),
                Some(Error::MalformedUpdate),
                "{class} {rtype} {ttl}"
            );
        }
        // NONE with an empty RDATA is a (degenerate) delete-RR.
        let wire = raw(Section::Authority, Class::NONE, Rtype::A, 0, &[]);
        let up = UpdateMessage::new(Message::parse(&wire).unwrap()).unwrap();
        assert!(matches!(
            up.updates().next(),
            Some(Ok(UpdateOp::DeleteRr(_)))
        ));
    }

    #[test]
    fn zone_section_rules() {
        // Not an UPDATE.
        let mut buf = [0u8; 512];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.push_question(n("example.com"), Rtype::SOA, Class::IN)
            .unwrap();
        let q = b.finish().to_vec();
        assert_eq!(
            UpdateMessage::new(Message::parse(&q).unwrap()).err(),
            Some(Error::MalformedUpdate)
        );
        // Zone type must be SOA, and exactly one zone.
        for (count, qtype) in [(1, Rtype::A), (2, Rtype::SOA), (0, Rtype::SOA)] {
            let mut buf = [0u8; 512];
            let mut b = MessageBuilder::new(&mut buf).unwrap();
            b.set_flags(crate::Flags::default().with_opcode(Opcode::UPDATE));
            for _ in 0..count {
                b.push_question(n("example.com"), qtype, Class::IN).unwrap();
            }
            let m = b.finish().to_vec();
            assert_eq!(
                UpdateMessage::new(Message::parse(&m).unwrap()).err(),
                Some(Error::MalformedUpdate)
            );
        }
        // Truncated zone entry.
        let wire = build(|_| Ok(()));
        for end in 12..wire.len() {
            if let Ok(m) = Message::parse(&wire[..end]) {
                assert!(UpdateMessage::new(m).is_err());
            }
        }
    }

    #[test]
    fn txt_add_and_delete() {
        let txt = Txt::from_wire(b"\x05hello").unwrap();
        let wire = build(|u| {
            u.add(n("t.example.com"), 60, &txt)?;
            u.delete_rr(n("t.example.com"), &txt)
        });
        let up = UpdateMessage::new(Message::parse_validated(&wire).unwrap()).unwrap();
        let ops: Vec<_> = up.updates().collect::<Result<_>>().unwrap();
        assert_eq!(ops.len(), 2);
        for op in ops {
            match op {
                UpdateOp::Add(rr) | UpdateOp::DeleteRr(rr) => {
                    assert_eq!(rr.data().unwrap().to_string(), "\"hello\"");
                }
                _ => panic!("{op:?}"),
            }
        }
    }
}
