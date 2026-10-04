//! Convenience constructors: queries and response skeletons
//! (RFC 1035 §4.1.1, §7.3; RFC 4035 §3.1.6 for CD).

use super::MessageBuilder;
use crate::message::Message;
use crate::name::ToName;
use crate::wire::{OutBuf, WireWriter};
use crate::{Class, Flags, Opcode, Result, Rtype};

/// The flags of a response to a query with flags `query`: QR set, the
/// opcode, RD (RFC 1035 §4.1.1: "copied into the response") and CD
/// (RFC 4035 §3.1.6) copied, everything else (AA, TC, RA, Z, AD, RCODE)
/// clear. Set AA, RA, AD and the RCODE afterwards as appropriate.
///
/// ```
/// use dnsbox::Flags;
/// use dnsbox::builder::response_flags;
///
/// let q = Flags::default().with_rd(true).with_cd(true).with_ad(true);
/// let r = response_flags(q);
/// assert!(r.qr() && r.rd() && r.cd() && !r.ad());
/// ```
#[must_use]
pub const fn response_flags(query: Flags) -> Flags {
    Flags::from_bits(0)
        .with_qr(true)
        .with_opcode(query.opcode())
        .with_rd(query.rd())
        .with_cd(query.cd())
}

impl<B: OutBuf> MessageBuilder<B> {
    /// Turns this empty builder into a standard query (opcode QUERY, RD
    /// set, as a stub resolver sends it) for `name`, `qtype`, `qclass`,
    /// with transaction ID `id`.
    ///
    /// Clear RD for an iterative query with
    /// `b.set_flags(b.header().flags.with_rd(false))`. The builder is left
    /// after the question, so EDNS (an OPT record, RFC 6891 §6.1.1) or
    /// other records can be appended with
    /// [`push_additional`](Self::push_additional).
    ///
    /// # Errors
    ///
    /// [`Error::SectionOrder`](crate::Error::SectionOrder) if anything was
    /// written already, otherwise as
    /// [`push_question`](Self::push_question). On error the builder is
    /// unchanged.
    ///
    /// ```
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
    ///
    /// let name: NameBuf = "example.org".parse()?;
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.start_query(0xbeef, &name, Rtype::NS, Class::IN)?;
    /// // An iterative query (as a resolver sends to authoritative servers).
    /// b.set_flags(b.header().flags.with_rd(false));
    /// let query = Message::parse_validated(b.finish())?;
    /// assert_eq!((query.id(), query.flags().rd()), (0xbeef, false));
    /// assert_eq!(query.questions().next().unwrap()?.qtype(), Rtype::NS);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn start_query(
        &mut self,
        id: u16,
        name: impl ToName,
        qtype: Rtype,
        qclass: Class,
    ) -> Result<()> {
        self.ensure_fresh()?;
        let saved = self.header;
        self.header.id = id;
        self.header.flags = Flags::default().with_opcode(Opcode::QUERY).with_rd(true);
        self.sync_header();
        let res = self.push_question(name, qtype, qclass);
        if res.is_err() {
            self.header = saved;
            self.sync_header();
        }
        res
    }

    /// Turns this empty builder into the skeleton of a response to
    /// `query`: same ID, [`response_flags`] (QR, opcode, RD, CD), and a
    /// copy of the question section. Answers, the RCODE
    /// ([`set_rcode`](Self::set_rcode)) and flags like AA/RA are the
    /// caller's to add.
    ///
    /// EDNS: if the query carried an OPT record, RFC 6891 §7 requires one
    /// in the response (also when it is truncated).
    /// [`start_response_edns`](Self::start_response_edns) does this
    /// skeleton plus the EDNS bookkeeping (DO echo, BADVERS, reserved room
    /// for the OPT record).
    ///
    /// # Errors
    ///
    /// [`Error::SectionOrder`](crate::Error::SectionOrder) if anything was
    /// written already, the parse error if the query's question section
    /// is malformed (answer such queries with a header-only FORMERR built
    /// from [`response_flags`]), or
    /// [`Error::BufferTooSmall`](crate::Error::BufferTooSmall) if the
    /// questions do not fit. On error the builder is unchanged.
    ///
    /// ```
    /// use dnsbox::rdata::A;
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rcode, Rtype};
    ///
    /// let name: NameBuf = "www.example".parse()?;
    /// let mut qbuf = [0u8; 512];
    /// let query = MessageBuilder::query(&mut qbuf, 77, &name, Rtype::A, Class::IN)?.finish();
    /// let query = Message::parse(query)?;
    ///
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.start_response(&query)?;
    /// b.set_flags(b.header().flags.with_aa(true));
    /// b.push_answer(&name, Class::IN, 300, &A::new([192, 0, 2, 80].into()))?;
    /// let response = Message::parse_validated(b.finish())?;
    /// assert_eq!(response.id(), 77);
    /// assert!(response.flags().qr() && response.flags().aa() && response.flags().rd());
    /// assert_eq!(response.flags().rcode(), Rcode::NOERROR);
    /// assert_eq!((response.header().qdcount, response.header().ancount), (1, 1));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn start_response(&mut self, query: &Message<'_>) -> Result<()> {
        self.ensure_fresh()?;
        let saved = self.header;
        self.header.id = query.id();
        self.header.flags = response_flags(query.flags());
        self.sync_header();
        let mut copy = || -> Result<()> {
            for q in query.questions() {
                self.copy_question(&q?)?;
            }
            Ok(())
        };
        let res = copy();
        if res.is_err() {
            self.rollback(self.fresh_checkpoint());
            self.header = saved;
            self.sync_header();
        }
        res
    }

    /// Sets the header RCODE (the low 4 bits of `rcode`; extended RCODEs
    /// also need an OPT record, RFC 6891 §6.1.3).
    ///
    /// ```
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rcode, Rtype};
    ///
    /// let name: NameBuf = "missing.example".parse()?;
    /// let mut qbuf = [0u8; 512];
    /// let query = Message::parse(MessageBuilder::query(&mut qbuf, 3, &name, Rtype::A, Class::IN)?.finish())?;
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::response(&mut buf, &query)?;
    /// b.set_rcode(Rcode::NXDOMAIN);
    /// assert_eq!(Message::parse(b.finish())?.flags().rcode(), Rcode::NXDOMAIN);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn set_rcode(&mut self, rcode: crate::Rcode) {
        self.header.flags = self.header.flags.with_rcode(rcode);
        self.sync_header();
    }
}

impl<'b> MessageBuilder<WireWriter<'b>> {
    /// Starts a standard query in `buf`; see
    /// [`start_query`](Self::start_query).
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`](crate::Error::BufferTooSmall) if `buf`
    /// cannot hold the query.
    ///
    /// ```
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
    /// use dnsbox::edns::OptHeader;
    ///
    /// let name: NameBuf = "example.com".parse()?;
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::query(&mut buf, 0x1234, &name, Rtype::AAAA, Class::IN)?;
    /// // EDNS: an OPT record without options advertising a 1232-byte payload.
    /// b.push_edns(OptHeader::new(1232), &())?;
    /// let msg = Message::parse_validated(b.finish())?;
    /// assert!(msg.flags().rd() && !msg.flags().qr());
    /// assert_eq!(msg.header().arcount, 1);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn query(
        buf: &'b mut [u8],
        id: u16,
        name: impl ToName,
        qtype: Rtype,
        qclass: Class,
    ) -> Result<Self> {
        let mut b = Self::new(buf)?;
        b.start_query(id, name, qtype, qclass)?;
        Ok(b)
    }

    /// Starts a response to `query` in `buf`; see
    /// [`start_response`](Self::start_response).
    ///
    /// # Errors
    ///
    /// As [`start_response`](Self::start_response), or
    /// [`Error::BufferTooSmall`](crate::Error::BufferTooSmall) if `buf`
    /// cannot hold the skeleton.
    ///
    /// ```
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rcode, Rtype};
    ///
    /// let name: NameBuf = "nope.example".parse()?;
    /// let mut qbuf = [0u8; 512];
    /// let query = MessageBuilder::query(&mut qbuf, 77, &name, Rtype::A, Class::IN)?.finish();
    /// let query = Message::parse(query)?;
    ///
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::response(&mut buf, &query)?;
    /// b.set_rcode(Rcode::NXDOMAIN);
    /// let resp = Message::parse_validated(b.finish())?;
    /// assert_eq!(resp.id(), 77);
    /// assert!(resp.flags().qr() && resp.flags().rd());
    /// assert_eq!(resp.flags().rcode(), Rcode::NXDOMAIN);
    /// assert_eq!(resp.questions().next().unwrap()?.name(), name.as_name());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn response(buf: &'b mut [u8], query: &Message<'_>) -> Result<Self> {
        let mut b = Self::new(buf)?;
        b.start_response(query)?;
        Ok(b)
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl MessageBuilder<alloc::vec::Vec<u8>> {
    /// Starts a standard query in a new `Vec`; see
    /// [`start_query`](Self::start_query).
    ///
    /// # Errors
    ///
    /// None in practice: a question always fits in the 65535-byte limit.
    /// The `Result` mirrors [`query`](MessageBuilder::query).
    ///
    /// ```
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
    ///
    /// let name: NameBuf = "example.net".parse()?;
    /// let query: Vec<u8> = MessageBuilder::query_vec(7, &name, Rtype::NS, Class::IN)?.finish();
    /// assert_eq!(Message::parse_validated(&query)?.id(), 7);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn query_vec(id: u16, name: impl ToName, qtype: Rtype, qclass: Class) -> Result<Self> {
        let mut b = Self::new_vec();
        b.start_query(id, name, qtype, qclass)?;
        Ok(b)
    }

    /// Starts a response to `query` in a new `Vec`; see
    /// [`start_response`](Self::start_response).
    ///
    /// # Errors
    ///
    /// The parse error if the query's question section is malformed.
    ///
    /// ```
    /// use dnsbox::rdata::Txt;
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
    ///
    /// let name: NameBuf = "example.net".parse()?;
    /// let query = MessageBuilder::query_vec(9, &name, Rtype::TXT, Class::IN)?.finish();
    /// let query = Message::parse(&query)?;
    /// let mut b = MessageBuilder::response_vec(&query)?;
    /// b.push_answer(&name, Class::IN, 60, &Txt::from_wire(b"\x0bv=spf1 -all")?)?;
    /// let response: Vec<u8> = b.finish();
    /// let response = Message::parse_validated(&response)?;
    /// assert_eq!((response.id(), response.header().ancount), (9, 1));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn response_vec(query: &Message<'_>) -> Result<Self> {
        let mut b = Self::new_vec();
        b.start_response(query)?;
        Ok(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Section;
    use crate::name::NameBuf;
    use crate::rdata::{A, UnknownRdata};
    use crate::testutil::hex;
    use crate::{Error, Header, Rcode};

    fn name(s: &str) -> NameBuf {
        s.parse().unwrap()
    }

    #[test]
    fn query_bytes() {
        let mut buf = [0u8; 64];
        let b = MessageBuilder::query(&mut buf, 0xbeef, name("example.com"), Rtype::A, Class::IN)
            .unwrap();
        assert_eq!(
            b.finish(),
            &hex("beef01000001000000000000076578616d706c6503636f6d0000010001")[..]
        );
    }

    #[test]
    fn query_errors_leave_builder_unchanged() {
        // Too small for the question.
        let mut buf = [0u8; 20];
        assert_eq!(
            MessageBuilder::query(&mut buf, 1, name("example.com"), Rtype::A, Class::IN)
                .unwrap_err(),
            Error::BufferTooSmall
        );
        let mut buf = [0u8; 20];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.set_id(9);
        assert_eq!(
            b.start_query(1, name("example.com"), Rtype::A, Class::IN),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(b.header().id, 9);
        assert_eq!(b.as_bytes(), &[0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        // Not fresh.
        let mut buf = [0u8; 512];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.push_question(name("a"), Rtype::A, Class::IN).unwrap();
        assert_eq!(
            b.start_query(1, name("a"), Rtype::A, Class::IN),
            Err(Error::SectionOrder)
        );
        assert_eq!(b.header().qdcount, 1);
        let mut buf = [0u8; 512];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.push_answer(name("a"), Class::IN, 0, &A::new([1, 1, 1, 1].into()))
            .unwrap();
        let q = Message::parse(b"\0\0\0\0\0\0\0\0\0\0\0\0").unwrap();
        assert_eq!(b.start_response(&q), Err(Error::SectionOrder));
        assert_eq!(b.header().ancount, 1);
    }

    #[test]
    fn response_copies_id_opcode_rd_cd_question() {
        // A `dig +adflag +cdflag example.com A` style query with an empty
        // OPT record (hand-built: ID 0x8a4e, RD+AD+CD, opcode QUERY).
        let query = hex("8a4e01300001000000000001076578616d706c6503636f6d0000010001\
             0000291000000000000000");
        let q = Message::parse_validated(&query).unwrap();
        let mut buf = [0u8; 512];
        let mut b = MessageBuilder::response(&mut buf, &q).unwrap();
        b.push_answer(
            name("example.com"),
            Class::IN,
            60,
            &A::new([93, 184, 215, 14].into()),
        )
        .unwrap();
        let wire = b.finish();
        let r = Message::parse_validated(wire).unwrap();
        assert_eq!(r.id(), 0x8a4e);
        let f = r.flags();
        assert!(f.qr() && f.rd() && f.cd());
        assert!(!f.ad() && !f.aa() && !f.tc() && !f.ra());
        assert_eq!(f.opcode(), Opcode::QUERY);
        assert_eq!(f.rcode(), Rcode::NOERROR);
        assert_eq!(&wire[12..29], &query[12..29], "question copied verbatim");
        // The answer owner compresses against the copied question.
        assert_eq!(&wire[29..31], &[0xc0, 0x0c]);
    }

    #[test]
    fn response_to_notify_and_odd_queries() {
        // NOTIFY (opcode 4) with AA: response keeps the opcode only.
        let mut qb = [0u8; 512];
        let mut b = MessageBuilder::new(&mut qb).unwrap();
        b.set_id(5);
        b.set_flags(Flags::default().with_opcode(Opcode::NOTIFY).with_aa(true));
        b.push_question(name("example.com"), Rtype::SOA, Class::IN)
            .unwrap();
        let q = Message::parse(b.finish()).unwrap();
        let mut buf = [0u8; 512];
        let r = MessageBuilder::response(&mut buf, &q).unwrap().finish();
        let r = Message::parse_validated(r).unwrap();
        assert_eq!(r.flags().opcode(), Opcode::NOTIFY);
        assert!(r.flags().qr() && !r.flags().aa() && !r.flags().rd());

        // No question at all (e.g. a DSO keepalive or a cookie-only query).
        let q = Message::parse(b"\x00\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00").unwrap();
        let mut buf = [0u8; 512];
        let r = MessageBuilder::response(&mut buf, &q).unwrap().finish();
        assert_eq!(r, b"\x00\x07\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00");

        // Malformed question: error, builder untouched.
        let bad = b"\x00\x07\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03ab";
        let q = Message::parse(bad).unwrap();
        let mut buf = [0u8; 512];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        assert_eq!(b.start_response(&q), Err(Error::UnexpectedEof));
        assert_eq!(b.header(), Header::default());
        assert_eq!(b.len(), Header::LEN);
    }

    #[test]
    fn response_truncation_at_every_offset() {
        // A query whose question can fit only in large enough buffers;
        // every buffer size either works or fails cleanly.
        let query = hex("8a4e01300001000000000001076578616d706c6503636f6d0000010001\
             0000291000000000000000");
        let q = Message::parse(&query).unwrap();
        for size in 0..40 {
            let mut buf = std::vec![0u8; size];
            match MessageBuilder::response(&mut buf, &q) {
                Ok(b) => {
                    assert!(size >= 29);
                    Message::parse_validated(b.finish()).unwrap();
                }
                Err(e) => {
                    assert!(size < 29);
                    assert_eq!(e, Error::BufferTooSmall);
                }
            }
        }
        // Truncated queries never panic.
        for end in 0..query.len() {
            let Ok(q) = Message::parse(&query[..end]) else {
                continue;
            };
            let mut buf = [0u8; 512];
            let _ = MessageBuilder::response(&mut buf, &q);
        }
    }

    #[test]
    fn edns_echo_with_reserve() {
        // The documented pattern: reserve room for the OPT record, fill the
        // answer with truncation, then release and append OPT.
        let mut qbuf = [0u8; 512];
        let mut qb =
            MessageBuilder::query(&mut qbuf, 1, name("example.com"), Rtype::A, Class::IN).unwrap();
        let opt = UnknownRdata::new(Rtype::OPT, &[]);
        qb.push_additional(crate::Name::ROOT, Class::new(4096), 0, &opt)
            .unwrap();
        let q = Message::parse_validated(qb.finish()).unwrap();

        let mut buf = [0u8; 512];
        let mut b = MessageBuilder::response(&mut buf, &q).unwrap();
        b.set_limit(100);
        b.set_reserve(11);
        b.set_truncation(super::super::Truncation::SetTc);
        let addrs: std::vec::Vec<A> = (0..10).map(|i| A::new([192, 0, 2, i].into())).collect();
        let out = b
            .push_rrset(Section::Answer, name("example.com"), Class::IN, 60, &addrs)
            .unwrap();
        assert!(out.is_truncated());
        b.set_reserve(0);
        b.push_additional(crate::Name::ROOT, Class::new(1232), 0, &opt)
            .unwrap();
        let r = Message::parse_validated(b.finish()).unwrap();
        assert!(r.flags().tc());
        assert_eq!((r.header().ancount, r.header().arcount), (0, 1), "OPT kept");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn vec_constructors() {
        let b = MessageBuilder::query_vec(3, name("example.org"), Rtype::MX, Class::IN).unwrap();
        let q = b.finish();
        let q = Message::parse_validated(&q).unwrap();
        let r = MessageBuilder::response_vec(&q).unwrap().finish();
        let r = Message::parse_validated(&r).unwrap();
        assert_eq!(r.id(), 3);
        assert_eq!(r.questions().next().unwrap().unwrap().qtype(), Rtype::MX);
    }
}
