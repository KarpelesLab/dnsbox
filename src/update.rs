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
//! as [`Error::InvalidUpdate`]).
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

/// The Zone section of an UPDATE: the question section (RFC 2136 §2.3).
pub const ZONE: Section = Section::Question;
/// The Prerequisite section of an UPDATE: the answer section (RFC 2136
/// §2.4).
pub const PREREQUISITE: Section = Section::Answer;
/// The Update section of an UPDATE: the authority section (RFC 2136 §2.5).
pub const UPDATE: Section = Section::Authority;
/// The Additional Data section of an UPDATE (RFC 2136 §2.6).
pub const ADDITIONAL: Section = Section::Additional;

/// Builds an UPDATE message (RFC 2136 §2) on top of a [`MessageBuilder`].
///
/// Prerequisites must be added before updates, and updates before
/// additional data (section order); each method is atomic like the
/// builder's pushes. Use [`builder`](Self::builder) for the ID, TSIG or
/// SIG(0) signing, and checkpoints.
///
/// Every prerequisite and update method fails with
/// [`Error::InvalidUpdate`] for a meta-type or QTYPE where an RRset type
/// is required (RFC 2136 §3.4.1.3), and otherwise like
/// [`MessageBuilder::push_record`] ([`Error::SectionOrder`] when called
/// out of section order, [`Error::BufferTooSmall`], ...).
///
/// ```
/// use dnsbox::rdata::{A, Aaaa};
/// use dnsbox::update::UpdateBuilder;
/// use dnsbox::{Class, Error, MessageBuilder, NameBuf, Rtype};
///
/// // Replace host's addresses, but only if it already has an A RRset.
/// let zone: NameBuf = "example.com".parse()?;
/// let host: NameBuf = "host.example.com".parse()?;
/// let mut buf = [0u8; 512];
/// let mut u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
/// u.builder().set_id(0x2136);
/// u.require_rrset_exists(&host, Rtype::A)?;
/// u.delete_rrset(&host, Rtype::A)?;
/// u.delete_rrset(&host, Rtype::AAAA)?;
/// u.add(&host, 300, &A::new([192, 0, 2, 10].into()))?;
/// u.add(&host, 300, &Aaaa::new("2001:db8::10".parse().unwrap()))?;
/// // Prerequisites come first: the section order is enforced.
/// assert_eq!(u.require_name_in_use(&host), Err(Error::SectionOrder));
/// let wire = u.finish();
/// assert_eq!(dnsbox::Message::parse_validated(wire)?.header().nscount, 4);
/// # Ok::<(), Error>(())
/// ```
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
    /// writes the zone section (`zone SOA class`).
    ///
    /// # Errors
    ///
    /// [`Error::SectionOrder`] if `builder` already holds a question or
    /// record, [`Error::BufferTooSmall`] if the zone section does not fit.
    ///
    /// ```
    /// use dnsbox::update::UpdateBuilder;
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Opcode, Rtype};
    ///
    /// let zone: NameBuf = "example.com".parse()?;
    /// let mut buf = [0u8; 512];
    /// let u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
    /// let msg = Message::parse_validated(u.finish())?;
    /// assert_eq!(msg.flags().opcode(), Opcode::UPDATE);
    /// assert_eq!(msg.questions().next().unwrap()?.qtype(), Rtype::SOA); // the zone section
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
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
    ///
    /// ```
    /// use dnsbox::update::UpdateBuilder;
    /// use dnsbox::{Class, MessageBuilder, NameBuf};
    ///
    /// let zone: NameBuf = "example.com".parse()?;
    /// let mut buf = [0u8; 512];
    /// let u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
    /// assert_eq!(u.zone_class(), Class::IN); // the class of added records
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub const fn zone_class(&self) -> Class {
        self.class
    }

    /// The underlying builder (ID, flags, checkpoints, signing).
    ///
    /// ```
    /// use dnsbox::rdata::A;
    /// use dnsbox::update::UpdateBuilder;
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf};
    ///
    /// let zone: NameBuf = "example.com".parse()?;
    /// let host: NameBuf = "host.example.com".parse()?;
    /// let mut buf = [0u8; 512];
    /// let mut u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
    /// u.builder().set_id(0x2136);
    /// // Undo a tentative change with a checkpoint.
    /// let cp = u.builder().checkpoint();
    /// u.add(&host, 300, &A::new([192, 0, 2, 9].into()))?;
    /// u.builder().rollback(cp);
    /// let msg = Message::parse(u.finish())?;
    /// assert_eq!((msg.id(), msg.header().nscount), (0x2136, 0));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub fn builder(&mut self) -> &mut MessageBuilder<B> {
        &mut self.inner
    }

    /// Returns the underlying builder.
    ///
    /// ```
    /// use dnsbox::rdata::A;
    /// use dnsbox::update::UpdateBuilder;
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf};
    ///
    /// let zone: NameBuf = "example.com".parse()?;
    /// let host: NameBuf = "host.example.com".parse()?;
    /// let mut buf = [0u8; 512];
    /// let mut u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
    /// u.add(&host, 300, &A::new([192, 0, 2, 9].into()))?;
    /// // Back to the plain builder, e.g. to sign with TSIG or SIG(0).
    /// let b = u.into_builder();
    /// assert_eq!(Message::parse(b.finish())?.header().nscount, 1);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub fn into_builder(self) -> MessageBuilder<B> {
        self.inner
    }

    /// Finishes the message.
    ///
    /// ```
    /// use dnsbox::update::{UpdateBuilder, UpdateMessage};
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf};
    ///
    /// let zone: NameBuf = "example.com".parse()?;
    /// let gone: NameBuf = "old.example.com".parse()?;
    /// let mut buf = [0u8; 512];
    /// let mut u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
    /// u.delete_name(&gone)?;
    /// let wire = u.finish();
    /// assert!(UpdateMessage::new(Message::parse(wire)?)?.validate().is_ok());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub fn finish(self) -> B::Output {
        self.inner.finish()
    }

    fn rrset_type(rtype: Rtype) -> Result<()> {
        if is_rrset_type(rtype) {
            Ok(())
        } else {
            Err(Error::InvalidUpdate)
        }
    }

    /// Prerequisite: an RRset of `rtype` exists at `name`, whatever its
    /// value (§2.4.1: CLASS ANY, TTL 0, empty RDATA).
    ///
    /// # Errors
    ///
    /// See the [type documentation](UpdateBuilder).
    ///
    /// ```
    /// use dnsbox::update::{Prerequisite, UpdateBuilder, UpdateMessage};
    /// use dnsbox::{Class, Error, Message, MessageBuilder, NameBuf, Rtype};
    ///
    /// let zone: NameBuf = "example.com".parse()?;
    /// let host: NameBuf = "mail.example.com".parse()?;
    /// let mut buf = [0u8; 512];
    /// let mut u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
    /// u.require_rrset_exists(&host, Rtype::MX)?;
    /// assert_eq!(u.require_rrset_exists(&host, Rtype::OPT), Err(Error::InvalidUpdate)); // not an RRset type
    /// let update = UpdateMessage::new(Message::parse(u.finish())?)?;
    /// assert!(matches!(update.prerequisites().next(), Some(Ok(Prerequisite::RrsetExists { rtype: Rtype::MX, .. }))));
    /// # Ok::<(), Error>(())
    /// ```
    pub fn require_rrset_exists(&mut self, name: impl ToName, rtype: Rtype) -> Result<()> {
        Self::rrset_type(rtype)?;
        self.inner
            .push_record(PREREQUISITE, name, Class::ANY, 0, &empty(rtype))
    }

    /// Prerequisite: the RRset at `name` contains this RR (§2.4.2: zone
    /// class, TTL 0). A value-dependent prerequisite on a whole RRset is
    /// one such record per RR of the set; the server compares the full
    /// set.
    ///
    /// # Errors
    ///
    /// See the [type documentation](UpdateBuilder).
    ///
    /// ```
    /// use dnsbox::rdata::A;
    /// use dnsbox::update::{Prerequisite, UpdateBuilder, UpdateMessage};
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf};
    ///
    /// // Compare-and-swap: only if host's A RRset is exactly { 192.0.2.1 }.
    /// let zone: NameBuf = "example.com".parse()?;
    /// let host: NameBuf = "host.example.com".parse()?;
    /// let (old, new) = (A::new([192, 0, 2, 1].into()), A::new([192, 0, 2, 2].into()));
    /// let mut buf = [0u8; 512];
    /// let mut u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
    /// u.require_rr(&host, &old)?;
    /// u.delete_rr(&host, &old)?;
    /// u.add(&host, 300, &new)?;
    /// let update = UpdateMessage::new(Message::parse(u.finish())?)?;
    /// let Some(Ok(Prerequisite::RrExists(rr))) = update.prerequisites().next() else { panic!() };
    /// assert_eq!(rr.to_string(), "host.example.com. 0 IN A 192.0.2.1");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn require_rr<D: ComposeRdata + ?Sized>(
        &mut self,
        name: impl ToName,
        data: &D,
    ) -> Result<()> {
        Self::rrset_type(data.rtype())?;
        self.inner
            .push_record(PREREQUISITE, name, self.class, 0, data)
    }

    /// Prerequisite: no RRset of `rtype` exists at `name` (§2.4.3: CLASS
    /// NONE, TTL 0, empty RDATA).
    ///
    /// # Errors
    ///
    /// See the [type documentation](UpdateBuilder).
    ///
    /// ```
    /// use dnsbox::rdata::Cname;
    /// use dnsbox::update::UpdateBuilder;
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
    ///
    /// // Add a CNAME only if the name has no A RRset yet.
    /// let zone: NameBuf = "example.com".parse()?;
    /// let (alias, target): (NameBuf, NameBuf) = ("www.example.com".parse()?, "web.example.com".parse()?);
    /// let mut buf = [0u8; 512];
    /// let mut u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
    /// u.require_rrset_absent(&alias, Rtype::A)?;
    /// u.add(&alias, 300, &Cname::new(target.as_name()))?;
    /// let msg = Message::parse_validated(u.finish())?;
    /// let prereq = msg.answers().next().unwrap()?;
    /// assert_eq!((prereq.class(), prereq.rtype(), prereq.rdata().len()), (Class::NONE, Rtype::A, 0));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn require_rrset_absent(&mut self, name: impl ToName, rtype: Rtype) -> Result<()> {
        Self::rrset_type(rtype)?;
        self.inner
            .push_record(PREREQUISITE, name, Class::NONE, 0, &empty(rtype))
    }

    /// Prerequisite: `name` owns at least one RR (§2.4.4: CLASS ANY, TYPE
    /// ANY).
    ///
    /// # Errors
    ///
    /// See the [type documentation](UpdateBuilder).
    ///
    /// ```
    /// use dnsbox::update::{Prerequisite, UpdateBuilder, UpdateMessage};
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf};
    ///
    /// let zone: NameBuf = "example.com".parse()?;
    /// let host: NameBuf = "host.example.com".parse()?;
    /// let mut buf = [0u8; 512];
    /// let mut u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
    /// u.require_name_in_use(&host)?; // only touch existing hosts
    /// let update = UpdateMessage::new(Message::parse(u.finish())?)?;
    /// assert!(matches!(update.prerequisites().next(), Some(Ok(Prerequisite::NameInUse(n))) if n == host.as_name()));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn require_name_in_use(&mut self, name: impl ToName) -> Result<()> {
        self.inner
            .push_record(PREREQUISITE, name, Class::ANY, 0, &empty(Rtype::ANY))
    }

    /// Prerequisite: `name` owns no RR (§2.4.5: CLASS NONE, TYPE ANY).
    ///
    /// # Errors
    ///
    /// See the [type documentation](UpdateBuilder).
    ///
    /// ```
    /// use dnsbox::rdata::A;
    /// use dnsbox::update::UpdateBuilder;
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
    ///
    /// // Claim a fresh name: fails with YXDOMAIN on the server if it exists.
    /// let zone: NameBuf = "example.com".parse()?;
    /// let host: NameBuf = "new-host.example.com".parse()?;
    /// let mut buf = [0u8; 512];
    /// let mut u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
    /// u.require_name_absent(&host)?;
    /// u.add(&host, 300, &A::new([192, 0, 2, 77].into()))?;
    /// let msg = Message::parse_validated(u.finish())?;
    /// let prereq = msg.answers().next().unwrap()?;
    /// assert_eq!((prereq.class(), prereq.rtype()), (Class::NONE, Rtype::ANY));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn require_name_absent(&mut self, name: impl ToName) -> Result<()> {
        self.inner
            .push_record(PREREQUISITE, name, Class::NONE, 0, &empty(Rtype::ANY))
    }

    /// Update: add an RR to an RRset (§2.5.1: zone class).
    ///
    /// # Errors
    ///
    /// See the [type documentation](UpdateBuilder).
    ///
    /// ```
    /// use dnsbox::rdata::Txt;
    /// use dnsbox::update::UpdateBuilder;
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf};
    ///
    /// // An ACME DNS-01 challenge record.
    /// let zone: NameBuf = "example.com".parse()?;
    /// let name: NameBuf = "_acme-challenge.example.com".parse()?;
    /// let mut buf = [0u8; 512];
    /// let mut u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
    /// u.add(&name, 60, &Txt::from_wire(b"\x0fgfj9Xq...Rg85nM")?)?;
    /// let msg = Message::parse_validated(u.finish())?;
    /// let rr = msg.authority().next().unwrap()?;
    /// assert_eq!((rr.class(), rr.ttl()), (Class::IN, 60));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn add<D: ComposeRdata + ?Sized>(
        &mut self,
        name: impl ToName,
        ttl: u32,
        data: &D,
    ) -> Result<()> {
        Self::rrset_type(data.rtype())?;
        self.inner.push_record(UPDATE, name, self.class, ttl, data)
    }

    /// Update: delete the RRset of `rtype` at `name` (§2.5.2: CLASS ANY,
    /// TTL 0, empty RDATA).
    ///
    /// # Errors
    ///
    /// See the [type documentation](UpdateBuilder).
    ///
    /// ```
    /// use dnsbox::update::{UpdateBuilder, UpdateMessage, UpdateOp};
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
    ///
    /// // Remove the challenge record once the certificate is issued.
    /// let zone: NameBuf = "example.com".parse()?;
    /// let name: NameBuf = "_acme-challenge.example.com".parse()?;
    /// let mut buf = [0u8; 512];
    /// let mut u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
    /// u.delete_rrset(&name, Rtype::TXT)?;
    /// let update = UpdateMessage::new(Message::parse(u.finish())?)?;
    /// assert!(matches!(update.updates().next(), Some(Ok(UpdateOp::DeleteRrset { rtype: Rtype::TXT, .. }))));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn delete_rrset(&mut self, name: impl ToName, rtype: Rtype) -> Result<()> {
        Self::rrset_type(rtype)?;
        self.inner
            .push_record(UPDATE, name, Class::ANY, 0, &empty(rtype))
    }

    /// Update: delete every RRset at `name` (§2.5.3: CLASS ANY, TYPE ANY).
    ///
    /// # Errors
    ///
    /// See the [type documentation](UpdateBuilder).
    ///
    /// ```
    /// use dnsbox::update::UpdateBuilder;
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
    ///
    /// let zone: NameBuf = "example.com".parse()?;
    /// let host: NameBuf = "decommissioned.example.com".parse()?;
    /// let mut buf = [0u8; 512];
    /// let mut u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
    /// u.delete_name(&host)?;
    /// let msg = Message::parse_validated(u.finish())?;
    /// let rr = msg.authority().next().unwrap()?;
    /// assert_eq!((rr.class(), rr.rtype(), rr.ttl()), (Class::ANY, Rtype::ANY, 0));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn delete_name(&mut self, name: impl ToName) -> Result<()> {
        self.inner
            .push_record(UPDATE, name, Class::ANY, 0, &empty(Rtype::ANY))
    }

    /// Update: delete one RR from an RRset (§2.5.4: CLASS NONE, TTL 0).
    ///
    /// # Errors
    ///
    /// See the [type documentation](UpdateBuilder).
    ///
    /// ```
    /// use dnsbox::rdata::A;
    /// use dnsbox::update::{UpdateBuilder, UpdateMessage, UpdateOp};
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf};
    ///
    /// // Take one address out of a round-robin set.
    /// let zone: NameBuf = "example.com".parse()?;
    /// let pool: NameBuf = "pool.example.com".parse()?;
    /// let mut buf = [0u8; 512];
    /// let mut u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
    /// u.delete_rr(&pool, &A::new([192, 0, 2, 3].into()))?;
    /// let update = UpdateMessage::new(Message::parse(u.finish())?)?;
    /// let Some(Ok(UpdateOp::DeleteRr(rr))) = update.updates().next() else { panic!() };
    /// assert_eq!(rr.to_string(), "pool.example.com. 0 NONE A 192.0.2.3");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn delete_rr<D: ComposeRdata + ?Sized>(
        &mut self,
        name: impl ToName,
        data: &D,
    ) -> Result<()> {
        Self::rrset_type(data.rtype())?;
        self.inner.push_record(UPDATE, name, Class::NONE, 0, data)
    }

    /// Additional data (§2.6), e.g. glue for added NS records.
    ///
    /// # Errors
    ///
    /// As [`MessageBuilder::push_additional`].
    ///
    /// ```
    /// use dnsbox::rdata::{A, Ns};
    /// use dnsbox::update::UpdateBuilder;
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf};
    ///
    /// // Delegate a subzone, with glue for its name server.
    /// let zone: NameBuf = "example.com".parse()?;
    /// let (sub, ns): (NameBuf, NameBuf) = ("lab.example.com".parse()?, "ns.lab.example.com".parse()?);
    /// let mut buf = [0u8; 512];
    /// let mut u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
    /// u.add(&sub, 3600, &Ns::new(ns.as_name()))?;
    /// u.push_additional(&ns, Class::IN, 3600, &A::new([192, 0, 2, 53].into()))?;
    /// let msg = Message::parse_validated(u.finish())?;
    /// assert_eq!((msg.header().nscount, msg.header().arcount), (1, 1));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
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
///
/// A server checks each one against the zone (see the [module
/// example](self) for building and parsing):
///
/// ```
/// use dnsbox::update::Prerequisite;
/// use dnsbox::{Name, Rcode, Rtype};
///
/// // `exists(name, rtype)` stands in for a lookup in the zone.
/// fn check(p: &Prerequisite<'_>, exists: impl Fn(Name<'_>, Rtype) -> bool) -> Rcode {
///     match p {
///         Prerequisite::RrsetExists { name, rtype } if !exists(*name, *rtype) => Rcode::NXRRSET,
///         Prerequisite::RrsetAbsent { name, rtype } if exists(*name, *rtype) => Rcode::YXRRSET,
///         Prerequisite::NameInUse(name) if !exists(*name, Rtype::ANY) => Rcode::NXDOMAIN,
///         Prerequisite::NameAbsent(name) if exists(*name, Rtype::ANY) => Rcode::YXDOMAIN,
///         _ => Rcode::NOERROR, // value-dependent RrExists: compare whole RRsets
///     }
/// }
/// ```
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
    ///
    /// ```
    /// use dnsbox::update::{UpdateBuilder, UpdateMessage};
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
    ///
    /// let zone: NameBuf = "example.com".parse()?;
    /// let host: NameBuf = "host.example.com".parse()?;
    /// let mut buf = [0u8; 512];
    /// let mut u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
    /// u.require_rrset_exists(&host, Rtype::A)?;
    /// u.require_name_in_use(&host)?;
    /// let update = UpdateMessage::new(Message::parse(u.finish())?)?;
    /// for p in update.prerequisites() {
    ///     assert_eq!(p?.name(), host.as_name());
    /// }
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn name(&self) -> Name<'a> {
        match *self {
            Prerequisite::RrsetExists { name, .. }
            | Prerequisite::RrsetAbsent { name, .. }
            | Prerequisite::NameInUse(name)
            | Prerequisite::NameAbsent(name) => name,
            Prerequisite::RrExists(rr) => rr.name(),
        }
    }

    /// Classifies a prerequisite RR (§3.2).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUpdate`] (FORMERR) on an invalid combination of
    /// class, type, TTL and RDATA.
    ///
    /// ```
    /// use dnsbox::rdata::UnknownRdata;
    /// use dnsbox::update::Prerequisite;
    /// use dnsbox::{Class, Error, Message, MessageBuilder, NameBuf, Rtype};
    ///
    /// let host: NameBuf = "host.example.com".parse()?;
    /// let mut buf = [0u8; 256];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// // CLASS NONE, empty RDATA: "no A RRset" (RFC 2136 §2.4.3) ...
    /// b.push_answer(&host, Class::NONE, 0, &UnknownRdata::new(Rtype::A, &[]))?;
    /// // ... but a non-zero TTL is a FORMERR.
    /// b.push_answer(&host, Class::NONE, 60, &UnknownRdata::new(Rtype::A, &[]))?;
    /// let msg = Message::parse(b.finish())?;
    /// let mut rrs = msg.answers();
    /// let p = Prerequisite::classify(rrs.next().unwrap()?, Class::IN)?;
    /// assert!(matches!(p, Prerequisite::RrsetAbsent { rtype: Rtype::A, .. }));
    /// assert_eq!(Prerequisite::classify(rrs.next().unwrap()?, Class::IN).unwrap_err(), Error::InvalidUpdate);
    /// # Ok::<(), Error>(())
    /// ```
    pub fn classify(rr: Record<'a>, zone_class: Class) -> Result<Self> {
        if rr.ttl() != 0 {
            return Err(Error::InvalidUpdate);
        }
        let (name, rtype, empty) = (rr.name(), rr.rtype(), rr.rdata().is_empty());
        let class = rr.class();
        Ok(if class == Class::ANY {
            if !empty {
                return Err(Error::InvalidUpdate);
            }
            if rtype == Rtype::ANY {
                Prerequisite::NameInUse(name)
            } else if is_rrset_type(rtype) {
                Prerequisite::RrsetExists { name, rtype }
            } else {
                return Err(Error::InvalidUpdate);
            }
        } else if class == Class::NONE {
            if !empty {
                return Err(Error::InvalidUpdate);
            }
            if rtype == Rtype::ANY {
                Prerequisite::NameAbsent(name)
            } else if is_rrset_type(rtype) {
                Prerequisite::RrsetAbsent { name, rtype }
            } else {
                return Err(Error::InvalidUpdate);
            }
        } else if class == zone_class && is_rrset_type(rtype) {
            Prerequisite::RrExists(rr)
        } else {
            return Err(Error::InvalidUpdate);
        })
    }
}

/// An update operation (RFC 2136 §2.5, classified per §3.4.1.3).
///
/// ```
/// use dnsbox::update::{UpdateBuilder, UpdateMessage, UpdateOp};
/// use dnsbox::{Class, Message, MessageBuilder, NameBuf};
///
/// let zone: NameBuf = "example.com".parse()?;
/// let old: NameBuf = "old.example.com".parse()?;
/// let mut buf = [0u8; 256];
/// let mut u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
/// u.delete_name(&old)?;
/// let update = UpdateMessage::new(Message::parse(u.finish())?)?;
/// let op = update.updates().next().unwrap()?;
/// assert!(matches!(op, UpdateOp::DeleteName(n) if n == old.as_name()));
/// assert_eq!(op.name(), old.as_name());
/// # Ok::<(), dnsbox::Error>(())
/// ```
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
    ///
    /// ```
    /// use dnsbox::rdata::A;
    /// use dnsbox::update::{UpdateBuilder, UpdateMessage};
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
    ///
    /// let zone: NameBuf = "example.com".parse()?;
    /// let host: NameBuf = "host.example.com".parse()?;
    /// let mut buf = [0u8; 512];
    /// let mut u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
    /// u.delete_rrset(&host, Rtype::A)?;
    /// u.add(&host, 300, &A::new([192, 0, 2, 5].into()))?;
    /// let update = UpdateMessage::new(Message::parse(u.finish())?)?;
    /// let names: Vec<String> = update.updates().map(|op| op.map(|op| op.name().to_string())).collect::<Result<_, _>>()?;
    /// assert_eq!(names, ["host.example.com.", "host.example.com."]);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn name(&self) -> Name<'a> {
        match *self {
            UpdateOp::Add(rr) | UpdateOp::DeleteRr(rr) => rr.name(),
            UpdateOp::DeleteRrset { name, .. } | UpdateOp::DeleteName(name) => name,
        }
    }

    /// Classifies an update RR (§3.4.1.3 prescan).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUpdate`] (FORMERR) on an invalid combination of
    /// class, type, TTL and RDATA.
    ///
    /// ```
    /// use dnsbox::rdata::A;
    /// use dnsbox::update::UpdateOp;
    /// use dnsbox::{Class, Error, Message, MessageBuilder, NameBuf};
    ///
    /// let host: NameBuf = "host.example.com".parse()?;
    /// let a = A::new([192, 0, 2, 5].into());
    /// let mut buf = [0u8; 256];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.push_authority(&host, Class::IN, 300, &a)?; // zone class: add
    /// b.push_authority(&host, Class::CH, 300, &a)?; // another class: FORMERR
    /// let msg = Message::parse(b.finish())?;
    /// let mut rrs = msg.authority();
    /// assert!(matches!(UpdateOp::classify(rrs.next().unwrap()?, Class::IN)?, UpdateOp::Add(_)));
    /// assert_eq!(UpdateOp::classify(rrs.next().unwrap()?, Class::IN).unwrap_err(), Error::InvalidUpdate);
    /// # Ok::<(), Error>(())
    /// ```
    pub fn classify(rr: Record<'a>, zone_class: Class) -> Result<Self> {
        let (class, rtype) = (rr.class(), rr.rtype());
        Ok(if class == Class::ANY {
            if rr.ttl() != 0 || !rr.rdata().is_empty() {
                return Err(Error::InvalidUpdate);
            }
            if rtype == Rtype::ANY {
                UpdateOp::DeleteName(rr.name())
            } else if is_rrset_type(rtype) {
                UpdateOp::DeleteRrset {
                    name: rr.name(),
                    rtype,
                }
            } else {
                return Err(Error::InvalidUpdate);
            }
        } else if class == Class::NONE {
            if rr.ttl() != 0 || !is_rrset_type(rtype) {
                return Err(Error::InvalidUpdate);
            }
            UpdateOp::DeleteRr(rr)
        } else if class == zone_class && is_rrset_type(rtype) {
            UpdateOp::Add(rr)
        } else {
            return Err(Error::InvalidUpdate);
        })
    }
}

/// A parsed UPDATE message (RFC 2136 §2): a view over a [`Message`].
///
/// See the [module example](self). A server typically checks, in order
/// (RFC 2136 §3): the zone, [`validate`](Self::validate) (FORMERR),
/// [`in_zone`](Self::in_zone) for every name (NOTZONE), then the
/// prerequisites and updates.
///
/// ```
/// use dnsbox::update::{UpdateBuilder, UpdateMessage};
/// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rcode};
///
/// # let zone: NameBuf = "example.com".parse()?;
/// # let host: NameBuf = "www.example.com".parse()?;
/// # let mut buf = [0u8; 256];
/// # let mut u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
/// # u.delete_name(&host)?;
/// # let wire = u.finish();
/// fn precheck(update: &UpdateMessage<'_>, our_zone: &NameBuf) -> Rcode {
///     if update.zone_name() != our_zone.as_name() {
///         return Rcode::NOTAUTH;
///     }
///     if update.validate().is_err() {
///         return Rcode::FORMERR;
///     }
///     let names = update.prerequisites().filter_map(Result::ok).map(|p| p.name())
///         .chain(update.updates().filter_map(Result::ok).map(|op| op.name()));
///     for name in names {
///         if !update.in_zone(&name) {
///             return Rcode::NOTZONE;
///         }
///     }
///     Rcode::NOERROR
/// }
/// let update = UpdateMessage::new(Message::parse(wire)?)?;
/// assert_eq!(precheck(&update, &zone), Rcode::NOERROR);
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct UpdateMessage<'a> {
    msg: Message<'a>,
    zone: Question<'a>,
}

impl<'a> UpdateMessage<'a> {
    /// Wraps a message, checking that it is an UPDATE (opcode 5) with
    /// exactly one zone entry of type SOA (§3.1.1).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUpdate`] if it is not, or the parse error of the
    /// zone entry.
    ///
    /// ```
    /// use dnsbox::update::UpdateMessage;
    /// use dnsbox::{Class, Error, Message, MessageBuilder, NameBuf, Rtype};
    ///
    /// // A plain SOA query is not an UPDATE.
    /// let zone: NameBuf = "example.com".parse()?;
    /// let mut buf = [0u8; 512];
    /// let query = MessageBuilder::query(&mut buf, 1, &zone, Rtype::SOA, Class::IN)?.finish();
    /// assert_eq!(UpdateMessage::new(Message::parse(query)?).unwrap_err(), Error::InvalidUpdate);
    /// # Ok::<(), Error>(())
    /// ```
    pub fn new(msg: Message<'a>) -> Result<Self> {
        if msg.flags().opcode() != Opcode::UPDATE || msg.header().qdcount != 1 {
            return Err(Error::InvalidUpdate);
        }
        let zone = msg.questions().next().ok_or(Error::UnexpectedEof)??;
        if zone.qtype() != Rtype::SOA {
            return Err(Error::InvalidUpdate);
        }
        Ok(UpdateMessage { msg, zone })
    }

    /// The underlying message.
    ///
    /// ```
    /// use dnsbox::update::{UpdateBuilder, UpdateMessage};
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf};
    ///
    /// let zone: NameBuf = "example.com".parse()?;
    /// let mut buf = [0u8; 512];
    /// let mut u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
    /// u.builder().set_id(99);
    /// let update = UpdateMessage::new(Message::parse(u.finish())?)?;
    /// // The response echoes the ID (RFC 2136 §3.8).
    /// assert_eq!(update.message().id(), 99);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub const fn message(&self) -> Message<'a> {
        self.msg
    }

    /// The zone section entry.
    ///
    /// ```
    /// use dnsbox::update::{UpdateBuilder, UpdateMessage};
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf};
    ///
    /// let zone: NameBuf = "example.com".parse()?;
    /// let mut buf = [0u8; 512];
    /// let u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
    /// let update = UpdateMessage::new(Message::parse(u.finish())?)?;
    /// assert_eq!(update.zone().to_string(), "example.com. IN SOA");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub const fn zone(&self) -> Question<'a> {
        self.zone
    }

    /// The zone name (ZNAME).
    ///
    /// ```
    /// use dnsbox::update::{UpdateBuilder, UpdateMessage};
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf};
    ///
    /// let zone: NameBuf = "example.com".parse()?;
    /// let mut buf = [0u8; 512];
    /// let u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
    /// let update = UpdateMessage::new(Message::parse(u.finish())?)?;
    /// // A server answers NOTAUTH for zones it is not primary for.
    /// let ours: NameBuf = "example.com".parse()?;
    /// assert_eq!(update.zone_name(), ours.as_name());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub const fn zone_name(&self) -> Name<'a> {
        self.zone.name()
    }

    /// The zone class (ZCLASS).
    ///
    /// ```
    /// use dnsbox::update::{UpdateBuilder, UpdateMessage};
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf};
    ///
    /// let zone: NameBuf = "example.com".parse()?;
    /// let mut buf = [0u8; 512];
    /// let u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
    /// let update = UpdateMessage::new(Message::parse(u.finish())?)?;
    /// assert_eq!(update.zone_class(), Class::IN);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub const fn zone_class(&self) -> Class {
        self.zone.qclass()
    }

    /// Whether `name` is at or below the zone name: servers answer NOTZONE
    /// for prerequisites or updates outside the zone (§3.2, §3.4.1.3).
    ///
    /// ```
    /// use dnsbox::update::{UpdateBuilder, UpdateMessage};
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf};
    ///
    /// let zone: NameBuf = "example.com".parse()?;
    /// let mut buf = [0u8; 512];
    /// let u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
    /// let update = UpdateMessage::new(Message::parse(u.finish())?)?;
    /// let (inside, apex, outside): (NameBuf, NameBuf, NameBuf) =
    ///     ("www.example.com".parse()?, "EXAMPLE.com".parse()?, "example.org".parse()?);
    /// assert!(update.in_zone(&inside.as_name()) && update.in_zone(&apex.as_name()));
    /// assert!(!update.in_zone(&outside.as_name())); // NOTZONE
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn in_zone(&self, name: &Name<'_>) -> bool {
        name.is_subdomain_of(&self.zone.name())
    }

    /// The prerequisite section (answer section), classified.
    ///
    /// ```
    /// use dnsbox::update::{Prerequisite, UpdateBuilder, UpdateMessage};
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
    ///
    /// let zone: NameBuf = "example.com".parse()?;
    /// let host: NameBuf = "host.example.com".parse()?;
    /// let mut buf = [0u8; 512];
    /// let mut u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
    /// u.require_name_in_use(&host)?;
    /// u.require_rrset_absent(&host, Rtype::CNAME)?;
    /// let update = UpdateMessage::new(Message::parse(u.finish())?)?;
    /// let prereqs: Vec<Prerequisite<'_>> = update.prerequisites().collect::<Result<_, _>>()?;
    /// assert!(matches!(prereqs[..], [Prerequisite::NameInUse(_), Prerequisite::RrsetAbsent { .. }]));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn prerequisites(&self) -> Prerequisites<'a> {
        Prerequisites {
            inner: self.msg.answers(),
            class: self.zone_class(),
            failed: false,
        }
    }

    /// The update section (authority section), classified.
    ///
    /// ```
    /// use dnsbox::rdata::A;
    /// use dnsbox::update::{UpdateBuilder, UpdateMessage, UpdateOp};
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
    ///
    /// let zone: NameBuf = "example.com".parse()?;
    /// let host: NameBuf = "host.example.com".parse()?;
    /// let mut buf = [0u8; 512];
    /// let mut u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
    /// u.delete_rrset(&host, Rtype::A)?;
    /// u.add(&host, 300, &A::new([192, 0, 2, 6].into()))?;
    /// let update = UpdateMessage::new(Message::parse(u.finish())?)?;
    /// let mut adds = 0;
    /// for op in update.updates() {
    ///     if let UpdateOp::Add(rr) = op? {
    ///         assert_eq!(rr.ttl(), 300);
    ///         adds += 1;
    ///     }
    /// }
    /// assert_eq!(adds, 1);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn updates(&self) -> Updates<'a> {
        Updates {
            inner: self.msg.authority(),
            class: self.zone_class(),
            failed: false,
        }
    }

    /// The additional data section.
    ///
    /// ```
    /// use dnsbox::rdata::{A, Ns};
    /// use dnsbox::update::{UpdateBuilder, UpdateMessage};
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
    ///
    /// let zone: NameBuf = "example.com".parse()?;
    /// let (sub, ns): (NameBuf, NameBuf) = ("lab.example.com".parse()?, "ns.lab.example.com".parse()?);
    /// let mut buf = [0u8; 512];
    /// let mut u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
    /// u.add(&sub, 3600, &Ns::new(ns.as_name()))?;
    /// u.push_additional(&ns, Class::IN, 3600, &A::new([192, 0, 2, 53].into()))?;
    /// let update = UpdateMessage::new(Message::parse(u.finish())?)?;
    /// let glue = update.additional().next().unwrap()?;
    /// assert_eq!((glue.name(), glue.rtype()), (ns.as_name(), Rtype::A));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub fn additional(&self) -> Records<'a> {
        self.msg.additional()
    }

    /// Checks every prerequisite and update once (FORMERR conditions only;
    /// zone membership is left to [`in_zone`](Self::in_zone)).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUpdate`] for the first invalid prerequisite or
    /// update, or the parse error of a malformed record.
    ///
    /// ```
    /// use dnsbox::rdata::UnknownRdata;
    /// use dnsbox::update::{UpdateBuilder, UpdateMessage};
    /// use dnsbox::{Class, Error, Message, MessageBuilder, NameBuf, Rtype};
    ///
    /// // A hand-made update deleting an RRset but with a TTL: FORMERR (§3.4.1.3).
    /// let zone: NameBuf = "example.com".parse()?;
    /// let host: NameBuf = "host.example.com".parse()?;
    /// let mut buf = [0u8; 512];
    /// let mut u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
    /// u.builder().push_authority(&host, Class::ANY, 60, &UnknownRdata::new(Rtype::A, &[]))?;
    /// let update = UpdateMessage::new(Message::parse(u.finish())?)?;
    /// assert_eq!(update.validate(), Err(Error::InvalidUpdate));
    /// # Ok::<(), Error>(())
    /// ```
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
/// [`UpdateMessage::prerequisites`]. Stops after the first error. See the
/// [module example](self).
///
/// ```
/// use dnsbox::update::{Prerequisite, UpdateBuilder, UpdateMessage};
/// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
///
/// let zone: NameBuf = "example.com".parse()?;
/// let mut buf = [0u8; 256];
/// let mut u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
/// u.require_rrset_absent(&zone, Rtype::CAA)?;
/// let update = UpdateMessage::new(Message::parse(u.finish())?)?;
/// let prereqs: Vec<Prerequisite<'_>> = update.prerequisites().collect::<Result<_, _>>()?;
/// assert!(matches!(prereqs[0], Prerequisite::RrsetAbsent { rtype: Rtype::CAA, .. }));
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Debug)]
#[must_use = "iterators are lazy and do nothing unless consumed"]
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
/// [`UpdateMessage::updates`]. Stops after the first error. See the
/// [`UpdateOp`] example.
///
/// ```
/// use dnsbox::rdata::A;
/// use dnsbox::update::{UpdateBuilder, UpdateMessage};
/// use dnsbox::{Class, Message, MessageBuilder, NameBuf};
///
/// let zone: NameBuf = "example.com".parse()?;
/// let host: NameBuf = "a.example.com".parse()?;
/// let mut buf = [0u8; 256];
/// let mut u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
/// u.add(&host, 60, &A::new([192, 0, 2, 1].into()))?;
/// u.add(&host, 60, &A::new([192, 0, 2, 2].into()))?;
/// let update = UpdateMessage::new(Message::parse(u.finish())?)?;
/// assert_eq!(update.updates().count(), 2);
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Debug)]
#[must_use = "iterators are lazy and do nothing unless consumed"]
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
            assert_eq!(u.require_rrset_exists(n("x"), t), Err(Error::InvalidUpdate));
            assert_eq!(u.delete_rrset(n("x"), t), Err(Error::InvalidUpdate));
            assert_eq!(
                u.add(n("x"), 0, &UnknownRdata::new(t, &[])),
                Err(Error::InvalidUpdate)
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
                Some(Error::InvalidUpdate),
                "{class} {rtype} {ttl}"
            );
            assert!(it.next().is_none());
            assert_eq!(up.validate(), Err(Error::InvalidUpdate));
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
                Some(Error::InvalidUpdate),
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
            Some(Error::InvalidUpdate)
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
                Some(Error::InvalidUpdate)
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
