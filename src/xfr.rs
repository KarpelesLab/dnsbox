//! Zone transfers: AXFR (RFC 5936) and IXFR (RFC 1995).
//!
//! - [`build_axfr_query`] / [`build_ixfr_query`] write the queries (an
//!   IXFR query carries the client's SOA in the authority section, RFC
//!   1995 §3).
//! - [`XfrProcessor`] consumes the response **one message at a time**
//!   (a transfer may span any number of TCP messages, RFC 5936 §2.2) and
//!   turns the answer records into [`XfrEvent`]s that borrow from the
//!   current message. It keeps only a few integers between messages: no
//!   allocation, bounded work per message.
//!
//! The processor recognises every response shape:
//!
//! - **AXFR**, and **AXFR-style IXFR** (RFC 1995 §4: a full zone when the
//!   server has no history): SOA, the zone's records, the same SOA;
//! - **incremental IXFR** (RFC 1995 §4): the new SOA, then difference
//!   sequences `old SOA, deletions, new SOA, additions`, then the new SOA
//!   again; consecutive sequences must chain (each starts at the version
//!   the previous one ended at);
//! - **up to date** (RFC 1995 §2): a single SOA not newer than the
//!   client's version.
//!
//! Over UDP, an IXFR response holding only a newer SOA means "retry over
//! TCP" (RFC 1995 §2); the processor then reports
//! [`is_done`](XfrProcessor::is_done) `false` after that message.
//!
//! TSIG on transfer streams is verified separately with
//! [`crate::tsig::TsigVerifier`], message by message.
//!
//! ```
//! use dnsbox::{Message, NameBuf, Rtype};
//! use dnsbox::xfr::{XfrEvent, XfrProcessor};
//!
//! # fn run(messages: &[&[u8]]) -> Result<(), dnsbox::Error> {
//! let zone: NameBuf = "example.com".parse()?;
//! let mut xfr = XfrProcessor::axfr(&zone);
//! for wire in messages {
//!     let msg = Message::parse(wire)?;
//!     for event in xfr.process(&msg)? {
//!         match event? {
//!             XfrEvent::Start { soa, .. } => println!("serial {}", soa.serial),
//!             XfrEvent::Record(rr) => println!("{rr}"),
//!             XfrEvent::End { .. } => println!("done"),
//!             _ => {}
//!         }
//!     }
//!     if xfr.is_done() {
//!         break;
//!     }
//! }
//! # Ok(()) }
//! ```

use core::fmt;

use crate::builder::MessageBuilder;
use crate::message::{Message, Record, Records};
use crate::name::{NameBuf, ToName};
use crate::rdata::Soa;
use crate::wire::OutBuf;
use crate::{Class, Error, Opcode, Rcode, Result, Rtype};

/// Writes an AXFR query for `zone` (RFC 5936 §2.1) into an empty builder.
///
/// # Errors
///
/// [`Error::SectionOrder`] if the builder is not empty,
/// [`Error::BufferTooSmall`] if the query does not fit.
///
/// ```
/// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
///
/// let zone: NameBuf = "example.com".parse()?;
/// // Zone transfers run over TCP: build the query with its length prefix.
/// let mut buf = [0u8; 128];
/// let mut b = MessageBuilder::new_tcp(&mut buf)?;
/// b.set_id(0x5a5a);
/// dnsbox::xfr::build_axfr_query(&mut b, &zone, Class::IN)?;
/// let frame = b.finish();
/// let (msg, _) = dnsbox::tcp::split_frame(frame).unwrap();
/// assert_eq!(Message::parse(msg)?.questions().next().unwrap()?.qtype(), Rtype::AXFR);
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn build_axfr_query<B: OutBuf>(
    b: &mut MessageBuilder<B>,
    zone: impl ToName,
    class: Class,
) -> Result<()> {
    if !b.is_empty() {
        return Err(Error::SectionOrder);
    }
    b.push_question(zone, Rtype::AXFR, class)
}

/// Writes an IXFR query for `zone` (RFC 1995 §3) into an empty builder:
/// the question `zone IXFR class` and, in the authority section, the SOA
/// of the version the client has (only its serial matters to servers).
///
/// # Errors
///
/// [`Error::SectionOrder`] if the builder is not empty,
/// [`Error::BufferTooSmall`] if the query does not fit. On error the
/// builder is left unchanged.
///
/// ```
/// use dnsbox::rdata::{ParseRdataText, Soa};
/// use dnsbox::{Class, MessageBuilder, NameBuf};
///
/// let zone: NameBuf = "example.com".parse()?;
/// let mut sbuf = [0u8; 128];
/// let ours = Soa::from_text("ns1.example.com. hostmaster.example.com. 2024010101 1 1 1 1", &mut sbuf)?;
/// let mut buf = [0u8; 256];
/// let mut b = MessageBuilder::new(&mut buf)?;
/// dnsbox::xfr::build_ixfr_query(&mut b, &zone, Class::IN, &ours)?;
/// assert_eq!((b.header().qdcount, b.header().nscount), (1, 1));
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn build_ixfr_query<B: OutBuf>(
    b: &mut MessageBuilder<B>,
    zone: impl ToName,
    class: Class,
    soa: &Soa<'_>,
) -> Result<()> {
    if !b.is_empty() {
        return Err(Error::SectionOrder);
    }
    let cp = b.checkpoint();
    let zone = zone.to_name();
    let res = b
        .push_question(zone, Rtype::IXFR, class)
        .and_then(|()| b.push_authority(zone, class, 0, soa));
    if res.is_err() {
        b.rollback(cp);
    }
    res
}

/// Whether serial `a` is newer than serial `b` (RFC 1982 §3.2).
///
/// ```
/// use dnsbox::xfr::serial_newer;
///
/// assert!(serial_newer(2024010102, 2024010101));
/// assert!(serial_newer(5, u32::MAX)); // wrapped around
/// assert!(!serial_newer(7, 7));
/// ```
#[must_use]
pub const fn serial_newer(a: u32, b: u32) -> bool {
    matches!(
        crate::dnssec::serial_cmp(a, b),
        Some(core::cmp::Ordering::Greater)
    )
}

/// One step of a zone transfer, borrowing from the current message.
///
/// More kinds of events may be reported in future versions.
///
/// Applying an IXFR to a zone store:
///
/// ```
/// use dnsbox::xfr::XfrEvent;
///
/// fn apply(event: XfrEvent<'_>, log: &mut Vec<String>) {
///     match event {
///         XfrEvent::Start { soa, .. } => log.push(format!("to serial {}", soa.serial)),
///         XfrEvent::UpToDate { .. } => log.push("nothing to do".into()),
///         XfrEvent::Record(rr) | XfrEvent::Add(rr) => log.push(format!("+ {rr}")),
///         XfrEvent::Delete(rr) => log.push(format!("- {rr}")),
///         XfrEvent::DeleteStart { soa, .. } => log.push(format!("from {}", soa.serial)),
///         XfrEvent::AddStart { soa, .. } => log.push(format!("to {}", soa.serial)),
///         XfrEvent::End { .. } => log.push("commit".into()),
///         _ => {} // non-exhaustive
///     }
/// }
/// ```
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum XfrEvent<'a> {
    /// The first SOA: the version being transferred (RFC 5936 §2.2, RFC
    /// 1995 §4). For a full transfer it is also the zone's SOA record.
    Start {
        /// The SOA data.
        soa: Soa<'a>,
        /// The record.
        record: Record<'a>,
    },
    /// IXFR: the client is already up to date (single SOA not newer than
    /// the client's serial, RFC 1995 §2). The transfer is complete.
    UpToDate {
        /// The server's SOA.
        soa: Soa<'a>,
        /// The record.
        record: Record<'a>,
    },
    /// A zone record of a full transfer (AXFR or AXFR-style IXFR): every
    /// record between the leading and trailing SOA.
    Record(Record<'a>),
    /// IXFR: a difference sequence starts; `soa` is the old version's SOA
    /// (to be removed), and deletions follow.
    DeleteStart {
        /// The old SOA.
        soa: Soa<'a>,
        /// The record.
        record: Record<'a>,
    },
    /// IXFR: a record to delete.
    Delete(Record<'a>),
    /// IXFR: the sequence's new SOA (to be added); additions follow.
    AddStart {
        /// The new SOA.
        soa: Soa<'a>,
        /// The record.
        record: Record<'a>,
    },
    /// IXFR: a record to add.
    Add(Record<'a>),
    /// The trailing SOA: the transfer is complete.
    End {
        /// The SOA data (same serial as [`Start`](Self::Start)).
        soa: Soa<'a>,
        /// The record.
        record: Record<'a>,
    },
}

/// How the server answers, once known ([`XfrProcessor::style`]).
///
/// ```
/// use dnsbox::xfr::{XfrProcessor, XfrStyle};
///
/// let xfr = XfrProcessor::ixfr(&"example.com".parse::<dnsbox::NameBuf>()?, 7);
/// assert_eq!(xfr.style(), None); // nothing received yet
/// assert_ne!(XfrStyle::Full, XfrStyle::Incremental);
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XfrStyle {
    /// A full zone (AXFR, or AXFR-style IXFR).
    Full,
    /// Incremental difference sequences (IXFR).
    Incremental,
    /// A single SOA: the client is up to date.
    UpToDate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Waiting for the first SOA.
    Start,
    /// Got the first SOA (`serial`); the next record tells the style.
    First { serial: u32 },
    /// Full transfer body.
    Full { serial: u32 },
    /// IXFR deletions of a sequence.
    Deleting { serial: u32 },
    /// IXFR additions of a sequence ending at version `to`.
    Adding { serial: u32, to: u32 },
    /// Transfer complete.
    Done,
    /// A previous error; the transfer must be abandoned.
    Failed,
}

/// Streaming processor for AXFR / IXFR responses; see the
/// [module documentation](self).
///
/// Per message it checks (RFC 5936 §2.2): QR set, opcode QUERY, RCODE
/// NOERROR ([`Error::ErrorResponse`] otherwise), the ID (if set with
/// [`with_id`](Self::with_id)), and at most one question matching the
/// zone and query type. Record-sequence violations are
/// [`Error::InvalidXfr`]. Only the answer section is processed; TSIG and
/// OPT records elsewhere are ignored. After an error the processor stays
/// failed.
///
/// The server decides how long a transfer is: an AXFR may be any size and
/// an IXFR may chain any number of difference sequences. Each message
/// costs work linear in its size and the processor keeps no state that
/// grows, but whoever stores the events grows with the transfer: bound it
/// with [`with_max_records`](Self::with_max_records) and
/// [`with_max_messages`](Self::with_max_messages) when the server is not
/// trusted (beyond them, [`Error::LimitExceeded`]). There is no default
/// limit, as zones legitimately range from a few records to many millions.
///
/// ```
/// use dnsbox::rdata::{A, ParseRdataText, Soa};
/// use dnsbox::xfr::{XfrEvent, XfrProcessor, XfrStyle};
/// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
///
/// // A server's AXFR response: SOA, the zone's records, SOA again.
/// let zone: NameBuf = "example.com".parse()?;
/// let www: NameBuf = "www.example.com".parse()?;
/// let mut sbuf = [0u8; 128];
/// let soa = Soa::from_text("ns1.example.com. hostmaster.example.com. 42 7200 900 1209600 3600", &mut sbuf)?;
/// let mut buf = [0u8; 512];
/// let mut b = MessageBuilder::new(&mut buf)?;
/// b.set_id(9);
/// b.set_flags(dnsbox::Flags::default().with_qr(true).with_aa(true));
/// b.push_question(&zone, Rtype::AXFR, Class::IN)?;
/// b.push_answer(&zone, Class::IN, 3600, &soa)?;
/// b.push_answer(&www, Class::IN, 300, &A::new([192, 0, 2, 80].into()))?;
/// b.push_answer(&zone, Class::IN, 3600, &soa)?;
/// let response = Message::parse(b.finish())?;
///
/// let mut xfr = XfrProcessor::axfr(&zone).with_id(9);
/// let (mut serial, mut records) = (None, 0);
/// for event in xfr.process(&response)? {
///     match event? {
///         XfrEvent::Start { soa, .. } => serial = Some(soa.serial),
///         XfrEvent::Record(_) => records += 1,
///         _ => {}
///     }
/// }
/// assert!(xfr.is_done());
/// assert_eq!((xfr.style(), serial, records), (Some(XfrStyle::Full), Some(42), 1));
/// assert_eq!((xfr.message_count(), xfr.record_count()), (1, 3));
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone)]
pub struct XfrProcessor {
    zone: NameBuf,
    qtype: Rtype,
    client_serial: Option<u32>,
    id: Option<u16>,
    state: State,
    style: Option<XfrStyle>,
    messages: u32,
    records: u64,
    max_messages: u32,
    max_records: u64,
}

impl XfrProcessor {
    /// A processor for an AXFR of `zone`.
    ///
    /// ```
    /// # use dnsbox::zone::ZoneReader;
    /// # use dnsbox::{Class, Flags, Message, MessageBuilder, NameBuf, Rtype, Section};
    /// # // A transfer response message for example.com holding the records of `text`.
    /// # fn response<'b>(buf: &'b mut [u8], qtype: Rtype, text: &str) -> dnsbox::Result<&'b mut [u8]> {
    /// #     let zone: NameBuf = "example.com".parse()?;
    /// #     let mut b = MessageBuilder::new(buf)?;
    /// #     b.set_flags(Flags::default().with_qr(true).with_aa(true));
    /// #     b.push_question(&zone, qtype, Class::IN)?;
    /// #     let mut reader = ZoneReader::new(text).with_origin(zone.as_name());
    /// #     let mut rdata = [0u8; 512];
    /// #     while let Some(rr) = reader.next_record(&mut rdata)? {
    /// #         b.push_record(Section::Answer, &rr.name, rr.class, rr.ttl, &rr.data()?)?;
    /// #     }
    /// #     Ok(b.finish())
    /// # }
    /// use dnsbox::xfr::{XfrProcessor, XfrStyle};
    ///
    /// let zone: NameBuf = "example.com".parse()?;
    /// let mut xfr = XfrProcessor::axfr(&zone);
    /// let mut buf = [0u8; 512];
    /// let wire = response(&mut buf, Rtype::AXFR, "@ 3600 IN SOA ns1 hostmaster 42 2h 15m 2w 1h
    /// www 300 IN A 192.0.2.80
    /// @ 3600 IN SOA ns1 hostmaster 42 2h 15m 2w 1h")?;
    /// let events = xfr.process(&Message::parse(wire)?)?.count();
    /// assert_eq!(events, 3); // start, the A record, end
    /// assert!(xfr.is_done());
    /// assert_eq!(xfr.style(), Some(XfrStyle::Full));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn axfr(zone: impl ToName) -> Self {
        XfrProcessor {
            zone: zone.to_name().to_buf(),
            qtype: Rtype::AXFR,
            client_serial: None,
            id: None,
            state: State::Start,
            style: None,
            messages: 0,
            records: 0,
            max_messages: u32::MAX,
            max_records: u64::MAX,
        }
    }

    /// A processor for an IXFR of `zone` from version `client_serial`.
    ///
    /// ```
    /// # use dnsbox::zone::ZoneReader;
    /// # use dnsbox::{Class, Flags, Message, MessageBuilder, NameBuf, Rtype, Section};
    /// # // A transfer response message for example.com holding the records of `text`.
    /// # fn response<'b>(buf: &'b mut [u8], qtype: Rtype, text: &str) -> dnsbox::Result<&'b mut [u8]> {
    /// #     let zone: NameBuf = "example.com".parse()?;
    /// #     let mut b = MessageBuilder::new(buf)?;
    /// #     b.set_flags(Flags::default().with_qr(true).with_aa(true));
    /// #     b.push_question(&zone, qtype, Class::IN)?;
    /// #     let mut reader = ZoneReader::new(text).with_origin(zone.as_name());
    /// #     let mut rdata = [0u8; 512];
    /// #     while let Some(rr) = reader.next_record(&mut rdata)? {
    /// #         b.push_record(Section::Answer, &rr.name, rr.class, rr.ttl, &rr.data()?)?;
    /// #     }
    /// #     Ok(b.finish())
    /// # }
    /// use dnsbox::xfr::{XfrProcessor, XfrStyle};
    ///
    /// // We hold version 42; the server has nothing newer.
    /// let zone: NameBuf = "example.com".parse()?;
    /// let mut xfr = XfrProcessor::ixfr(&zone, 42);
    /// let mut buf = [0u8; 512];
    /// let wire = response(&mut buf, Rtype::IXFR, "@ 3600 IN SOA ns1 hostmaster 42 2h 15m 2w 1h")?;
    /// for event in xfr.process(&Message::parse(wire)?)? {
    ///     event?;
    /// }
    /// assert!(xfr.is_done());
    /// assert_eq!(xfr.style(), Some(XfrStyle::UpToDate));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn ixfr(zone: impl ToName, client_serial: u32) -> Self {
        XfrProcessor {
            qtype: Rtype::IXFR,
            client_serial: Some(client_serial),
            ..Self::axfr(zone)
        }
    }

    /// Also requires every response message to carry this ID (the
    /// query's).
    ///
    /// ```
    /// # use dnsbox::zone::ZoneReader;
    /// # use dnsbox::{Class, Flags, Message, MessageBuilder, NameBuf, Rtype, Section};
    /// # // A transfer response message for example.com holding the records of `text`.
    /// # fn response<'b>(buf: &'b mut [u8], qtype: Rtype, text: &str) -> dnsbox::Result<&'b mut [u8]> {
    /// #     let zone: NameBuf = "example.com".parse()?;
    /// #     let mut b = MessageBuilder::new(buf)?;
    /// #     b.set_flags(Flags::default().with_qr(true).with_aa(true));
    /// #     b.push_question(&zone, qtype, Class::IN)?;
    /// #     let mut reader = ZoneReader::new(text).with_origin(zone.as_name());
    /// #     let mut rdata = [0u8; 512];
    /// #     while let Some(rr) = reader.next_record(&mut rdata)? {
    /// #         b.push_record(Section::Answer, &rr.name, rr.class, rr.ttl, &rr.data()?)?;
    /// #     }
    /// #     Ok(b.finish())
    /// # }
    /// use dnsbox::xfr::XfrProcessor;
    /// use dnsbox::Error;
    ///
    /// let zone: NameBuf = "example.com".parse()?;
    /// let mut xfr = XfrProcessor::axfr(&zone).with_id(0x7777);
    /// let mut buf = [0u8; 512];
    /// let wire = response(&mut buf, Rtype::AXFR, "@ 3600 IN SOA ns1 hostmaster 42 2h 15m 2w 1h")?;
    /// // A message with another ID (here 0) is not part of our transfer.
    /// assert_eq!(xfr.process(&Message::parse(wire)?).err(), Some(Error::InvalidXfr));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn with_id(mut self, id: u16) -> Self {
        self.id = Some(id);
        self
    }

    /// Fails the transfer with [`Error::LimitExceeded`] at its answer
    /// record number `max + 1` (no limit by default).
    ///
    /// ```
    /// use dnsbox::rdata::{A, ParseRdataText, Soa};
    /// use dnsbox::xfr::XfrProcessor;
    /// use dnsbox::{Class, Error, Message, MessageBuilder, NameBuf, Rtype};
    ///
    /// // A server that streams records without ever ending the transfer.
    /// let zone: NameBuf = "example.".parse()?;
    /// let mut sbuf = [0u8; 64];
    /// let soa = Soa::from_text("ns. host. 1 2 3 4 5", &mut sbuf)?;
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.set_flags(dnsbox::Flags::default().with_qr(true));
    /// b.push_answer(&zone, Class::IN, 60, &soa)?;
    /// for i in 0..10u8 {
    ///     b.push_answer(&zone, Class::IN, 60, &A::new([192, 0, 2, i].into()))?;
    /// }
    /// let msg = Message::parse(b.finish())?;
    ///
    /// let mut xfr = XfrProcessor::axfr(&zone).with_max_records(8);
    /// let results: Vec<_> = xfr.process(&msg)?.collect();
    /// assert_eq!(results.len(), 9);
    /// assert_eq!(results[8].as_ref().err(), Some(&Error::LimitExceeded));
    /// assert!(xfr.process(&msg).is_err()); // the transfer has failed
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn with_max_records(mut self, max: u64) -> Self {
        self.max_records = max;
        self
    }

    /// Fails the transfer with [`Error::LimitExceeded`] at its message
    /// number `max + 1` (no limit by default).
    ///
    /// ```
    /// use dnsbox::rdata::{A, ParseRdataText, Soa};
    /// use dnsbox::xfr::XfrProcessor;
    /// use dnsbox::{Class, Error, Flags, Message, MessageBuilder, NameBuf};
    ///
    /// // A server that opens the transfer, then sends one record per
    /// // message without ever ending it.
    /// let zone: NameBuf = "example.".parse()?;
    /// let mut sbuf = [0u8; 64];
    /// let soa = Soa::from_text("ns. host. 1 2 3 4 5", &mut sbuf)?;
    /// let mut first = [0u8; 512];
    /// let mut b = MessageBuilder::new(&mut first)?;
    /// b.set_flags(Flags::default().with_qr(true));
    /// b.push_answer(&zone, Class::IN, 60, &soa)?;
    /// let first = Message::parse(b.finish())?;
    /// let mut more = [0u8; 512];
    /// let mut b = MessageBuilder::new(&mut more)?;
    /// b.set_flags(Flags::default().with_qr(true));
    /// b.push_answer(&zone, Class::IN, 60, &A::new([192, 0, 2, 1].into()))?;
    /// let more = Message::parse(b.finish())?;
    ///
    /// let mut xfr = XfrProcessor::axfr(&zone).with_max_messages(3);
    /// assert!(xfr.process(&first)?.all(|r| r.is_ok()));
    /// assert!(xfr.process(&more)?.all(|r| r.is_ok()));
    /// assert!(xfr.process(&more)?.all(|r| r.is_ok()));
    /// assert_eq!(xfr.process(&more).err(), Some(Error::LimitExceeded));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn with_max_messages(mut self, max: u32) -> Self {
        self.max_messages = max;
        self
    }

    /// Whether the transfer is complete.
    ///
    /// ```
    /// # use dnsbox::zone::ZoneReader;
    /// # use dnsbox::{Class, Flags, Message, MessageBuilder, NameBuf, Rtype, Section};
    /// # // A transfer response message for example.com holding the records of `text`.
    /// # fn response<'b>(buf: &'b mut [u8], qtype: Rtype, text: &str) -> dnsbox::Result<&'b mut [u8]> {
    /// #     let zone: NameBuf = "example.com".parse()?;
    /// #     let mut b = MessageBuilder::new(buf)?;
    /// #     b.set_flags(Flags::default().with_qr(true).with_aa(true));
    /// #     b.push_question(&zone, qtype, Class::IN)?;
    /// #     let mut reader = ZoneReader::new(text).with_origin(zone.as_name());
    /// #     let mut rdata = [0u8; 512];
    /// #     while let Some(rr) = reader.next_record(&mut rdata)? {
    /// #         b.push_record(Section::Answer, &rr.name, rr.class, rr.ttl, &rr.data()?)?;
    /// #     }
    /// #     Ok(b.finish())
    /// # }
    /// use dnsbox::xfr::XfrProcessor;
    ///
    /// // A transfer spread over two messages, as servers send large zones.
    /// let zone: NameBuf = "example.com".parse()?;
    /// let mut xfr = XfrProcessor::axfr(&zone);
    /// let mut buf = [0u8; 512];
    /// let first = response(&mut buf, Rtype::AXFR, "@ 3600 IN SOA ns1 hostmaster 42 2h 15m 2w 1h
    /// www 300 IN A 192.0.2.80")?;
    /// xfr.process(&Message::parse(first)?)?.try_for_each(|e| e.map(drop))?;
    /// assert!(!xfr.is_done()); // keep reading from the connection
    /// let mut buf = [0u8; 512];
    /// let second = response(&mut buf, Rtype::AXFR, "mail 300 IN A 192.0.2.25
    /// @ 3600 IN SOA ns1 hostmaster 42 2h 15m 2w 1h")?;
    /// xfr.process(&Message::parse(second)?)?.try_for_each(|e| e.map(drop))?;
    /// assert!(xfr.is_done());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.state == State::Done
    }

    /// The response style, once the server's answer has revealed it.
    ///
    /// ```
    /// # use dnsbox::zone::ZoneReader;
    /// # use dnsbox::{Class, Flags, Message, MessageBuilder, NameBuf, Rtype, Section};
    /// # // A transfer response message for example.com holding the records of `text`.
    /// # fn response<'b>(buf: &'b mut [u8], qtype: Rtype, text: &str) -> dnsbox::Result<&'b mut [u8]> {
    /// #     let zone: NameBuf = "example.com".parse()?;
    /// #     let mut b = MessageBuilder::new(buf)?;
    /// #     b.set_flags(Flags::default().with_qr(true).with_aa(true));
    /// #     b.push_question(&zone, qtype, Class::IN)?;
    /// #     let mut reader = ZoneReader::new(text).with_origin(zone.as_name());
    /// #     let mut rdata = [0u8; 512];
    /// #     while let Some(rr) = reader.next_record(&mut rdata)? {
    /// #         b.push_record(Section::Answer, &rr.name, rr.class, rr.ttl, &rr.data()?)?;
    /// #     }
    /// #     Ok(b.finish())
    /// # }
    /// use dnsbox::xfr::{XfrEvent, XfrProcessor, XfrStyle};
    ///
    /// // An incremental answer from version 42 to 43: one A record replaced.
    /// let zone: NameBuf = "example.com".parse()?;
    /// let mut xfr = XfrProcessor::ixfr(&zone, 42);
    /// let mut buf = [0u8; 512];
    /// let wire = response(&mut buf, Rtype::IXFR, "@ 3600 IN SOA ns1 hostmaster 43 2h 15m 2w 1h
    /// @ 3600 IN SOA ns1 hostmaster 42 2h 15m 2w 1h
    /// www 300 IN A 192.0.2.80
    /// @ 3600 IN SOA ns1 hostmaster 43 2h 15m 2w 1h
    /// www 300 IN A 192.0.2.81
    /// @ 3600 IN SOA ns1 hostmaster 43 2h 15m 2w 1h")?;
    /// let mut changes = (0, 0);
    /// for event in xfr.process(&Message::parse(wire)?)? {
    ///     match event? {
    ///         XfrEvent::Delete(_) => changes.0 += 1,
    ///         XfrEvent::Add(_) => changes.1 += 1,
    ///         _ => {}
    ///     }
    /// }
    /// assert_eq!(xfr.style(), Some(XfrStyle::Incremental));
    /// assert_eq!(changes, (1, 1));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub fn style(&self) -> Option<XfrStyle> {
        self.style
    }

    /// The serial of the version being transferred (the first SOA), once
    /// seen and while the transfer is in progress (`None` again once it is
    /// [done](Self::is_done) or failed; [`XfrEvent::End`] carries it).
    ///
    /// ```
    /// # use dnsbox::zone::ZoneReader;
    /// # use dnsbox::{Class, Flags, Message, MessageBuilder, NameBuf, Rtype, Section};
    /// # // A transfer response message for example.com holding the records of `text`.
    /// # fn response<'b>(buf: &'b mut [u8], qtype: Rtype, text: &str) -> dnsbox::Result<&'b mut [u8]> {
    /// #     let zone: NameBuf = "example.com".parse()?;
    /// #     let mut b = MessageBuilder::new(buf)?;
    /// #     b.set_flags(Flags::default().with_qr(true).with_aa(true));
    /// #     b.push_question(&zone, qtype, Class::IN)?;
    /// #     let mut reader = ZoneReader::new(text).with_origin(zone.as_name());
    /// #     let mut rdata = [0u8; 512];
    /// #     while let Some(rr) = reader.next_record(&mut rdata)? {
    /// #         b.push_record(Section::Answer, &rr.name, rr.class, rr.ttl, &rr.data()?)?;
    /// #     }
    /// #     Ok(b.finish())
    /// # }
    /// use dnsbox::xfr::XfrProcessor;
    ///
    /// let zone: NameBuf = "example.com".parse()?;
    /// let mut xfr = XfrProcessor::axfr(&zone);
    /// assert_eq!(xfr.serial(), None);
    /// let mut buf = [0u8; 512];
    /// let first = response(&mut buf, Rtype::AXFR, "@ 3600 IN SOA ns1 hostmaster 2024060101 2h 15m 2w 1h
    /// www 300 IN A 192.0.2.80")?;
    /// xfr.process(&Message::parse(first)?)?.try_for_each(|e| e.map(drop))?;
    /// assert_eq!(xfr.serial(), Some(2024060101)); // the version on its way
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn serial(&self) -> Option<u32> {
        match self.state {
            State::First { serial }
            | State::Full { serial }
            | State::Deleting { serial }
            | State::Adding { serial, .. } => Some(serial),
            _ => None,
        }
    }

    /// Number of messages processed so far.
    ///
    /// ```
    /// # use dnsbox::zone::ZoneReader;
    /// # use dnsbox::{Class, Flags, Message, MessageBuilder, NameBuf, Rtype, Section};
    /// # // A transfer response message for example.com holding the records of `text`.
    /// # fn response<'b>(buf: &'b mut [u8], qtype: Rtype, text: &str) -> dnsbox::Result<&'b mut [u8]> {
    /// #     let zone: NameBuf = "example.com".parse()?;
    /// #     let mut b = MessageBuilder::new(buf)?;
    /// #     b.set_flags(Flags::default().with_qr(true).with_aa(true));
    /// #     b.push_question(&zone, qtype, Class::IN)?;
    /// #     let mut reader = ZoneReader::new(text).with_origin(zone.as_name());
    /// #     let mut rdata = [0u8; 512];
    /// #     while let Some(rr) = reader.next_record(&mut rdata)? {
    /// #         b.push_record(Section::Answer, &rr.name, rr.class, rr.ttl, &rr.data()?)?;
    /// #     }
    /// #     Ok(b.finish())
    /// # }
    /// use dnsbox::xfr::XfrProcessor;
    ///
    /// let zone: NameBuf = "example.com".parse()?;
    /// let mut xfr = XfrProcessor::axfr(&zone);
    /// let mut buf = [0u8; 512];
    /// let first = response(&mut buf, Rtype::AXFR, "@ 3600 IN SOA ns1 hostmaster 42 2h 15m 2w 1h")?;
    /// xfr.process(&Message::parse(first)?)?.try_for_each(|e| e.map(drop))?;
    /// let mut buf = [0u8; 512];
    /// let second = response(&mut buf, Rtype::AXFR, "@ 3600 IN SOA ns1 hostmaster 42 2h 15m 2w 1h")?;
    /// xfr.process(&Message::parse(second)?)?.try_for_each(|e| e.map(drop))?;
    /// assert_eq!(xfr.message_count(), 2);
    /// assert!(xfr.is_done());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub fn message_count(&self) -> u32 {
        self.messages
    }

    /// Number of answer records processed so far.
    ///
    /// ```
    /// # use dnsbox::zone::ZoneReader;
    /// # use dnsbox::{Class, Flags, Message, MessageBuilder, NameBuf, Rtype, Section};
    /// # // A transfer response message for example.com holding the records of `text`.
    /// # fn response<'b>(buf: &'b mut [u8], qtype: Rtype, text: &str) -> dnsbox::Result<&'b mut [u8]> {
    /// #     let zone: NameBuf = "example.com".parse()?;
    /// #     let mut b = MessageBuilder::new(buf)?;
    /// #     b.set_flags(Flags::default().with_qr(true).with_aa(true));
    /// #     b.push_question(&zone, qtype, Class::IN)?;
    /// #     let mut reader = ZoneReader::new(text).with_origin(zone.as_name());
    /// #     let mut rdata = [0u8; 512];
    /// #     while let Some(rr) = reader.next_record(&mut rdata)? {
    /// #         b.push_record(Section::Answer, &rr.name, rr.class, rr.ttl, &rr.data()?)?;
    /// #     }
    /// #     Ok(b.finish())
    /// # }
    /// use dnsbox::xfr::XfrProcessor;
    ///
    /// let zone: NameBuf = "example.com".parse()?;
    /// let mut xfr = XfrProcessor::axfr(&zone);
    /// let mut buf = [0u8; 512];
    /// let wire = response(&mut buf, Rtype::AXFR, "@ 3600 IN SOA ns1 hostmaster 42 2h 15m 2w 1h
    /// @ 3600 IN NS ns1
    /// ns1 3600 IN A 192.0.2.53
    /// @ 3600 IN SOA ns1 hostmaster 42 2h 15m 2w 1h")?;
    /// xfr.process(&Message::parse(wire)?)?.try_for_each(|e| e.map(drop))?;
    /// // Both SOA records count: a cap on transfer size can use it.
    /// assert_eq!(xfr.record_count(), 4);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub fn record_count(&self) -> u64 {
        self.records
    }

    /// Checks the header and question of the next response message and
    /// returns an iterator over its events.
    ///
    /// # Errors
    ///
    /// [`Error::ErrorResponse`] for an error RCODE (e.g. a refused
    /// transfer), [`Error::InvalidXfr`] for a message that is not a
    /// response to the transfer (QR, opcode, ID, question) or for any
    /// message after an error or after the end,
    /// [`Error::LimitExceeded`] for a message beyond
    /// [`with_max_messages`](Self::with_max_messages), and the parse error
    /// of a malformed question. Errors in the records (including
    /// [`Error::LimitExceeded`] beyond
    /// [`with_max_records`](Self::with_max_records)) are yielded by the
    /// iterator.
    ///
    /// ```
    /// # use dnsbox::zone::ZoneReader;
    /// # use dnsbox::{Class, Flags, Message, MessageBuilder, NameBuf, Rtype, Section};
    /// # // A transfer response message for example.com holding the records of `text`.
    /// # fn response<'b>(buf: &'b mut [u8], qtype: Rtype, text: &str) -> dnsbox::Result<&'b mut [u8]> {
    /// #     let zone: NameBuf = "example.com".parse()?;
    /// #     let mut b = MessageBuilder::new(buf)?;
    /// #     b.set_flags(Flags::default().with_qr(true).with_aa(true));
    /// #     b.push_question(&zone, qtype, Class::IN)?;
    /// #     let mut reader = ZoneReader::new(text).with_origin(zone.as_name());
    /// #     let mut rdata = [0u8; 512];
    /// #     while let Some(rr) = reader.next_record(&mut rdata)? {
    /// #         b.push_record(Section::Answer, &rr.name, rr.class, rr.ttl, &rr.data()?)?;
    /// #     }
    /// #     Ok(b.finish())
    /// # }
    /// use dnsbox::xfr::XfrProcessor;
    /// use dnsbox::{Error, Rcode};
    ///
    /// // The primary refuses the transfer (we are not an allowed secondary).
    /// let zone: NameBuf = "example.com".parse()?;
    /// let mut qbuf = [0u8; 128];
    /// let mut q = MessageBuilder::new(&mut qbuf)?;
    /// dnsbox::xfr::build_axfr_query(&mut q, &zone, Class::IN)?;
    /// let query = Message::parse(q.finish())?;
    /// let mut buf = [0u8; 128];
    /// let mut b = MessageBuilder::response(&mut buf, &query)?;
    /// b.set_rcode(Rcode::REFUSED);
    /// let refused = Message::parse(b.finish())?;
    /// let mut xfr = XfrProcessor::axfr(&zone);
    /// assert_eq!(xfr.process(&refused).err(), Some(Error::ErrorResponse));
    /// // The processor stays failed.
    /// let mut rbuf = [0u8; 512];
    /// let wire = response(&mut rbuf, Rtype::AXFR, "@ 3600 IN SOA ns1 hostmaster 42 2h 15m 2w 1h")?;
    /// assert!(xfr.process(&Message::parse(wire)?).is_err());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn process<'p, 'a>(&'p mut self, msg: &Message<'a>) -> Result<XfrEvents<'p, 'a>> {
        match self.check_message(msg) {
            Ok(()) => {
                self.messages = self.messages.saturating_add(1);
                Ok(XfrEvents {
                    proc: self,
                    answers: msg.answers(),
                    remaining: msg.header().ancount,
                })
            }
            Err(e) => {
                self.state = State::Failed;
                Err(e)
            }
        }
    }

    fn check_message(&self, msg: &Message<'_>) -> Result<()> {
        match self.state {
            State::Done | State::Failed => return Err(Error::InvalidXfr),
            _ => {}
        }
        if self.messages >= self.max_messages {
            return Err(Error::LimitExceeded);
        }
        let flags = msg.flags();
        if flags.rcode() != Rcode::NOERROR {
            return Err(Error::ErrorResponse);
        }
        if !flags.qr() || flags.opcode() != Opcode::QUERY {
            return Err(Error::InvalidXfr);
        }
        if let Some(id) = self.id
            && msg.id() != id
        {
            return Err(Error::InvalidXfr);
        }
        match msg.header().qdcount {
            0 => {}
            1 => {
                let q = msg.questions().next().ok_or(Error::UnexpectedEof)??;
                if q.name() != self.zone.as_name() || q.qtype() != self.qtype {
                    return Err(Error::InvalidXfr);
                }
            }
            _ => return Err(Error::InvalidXfr),
        }
        Ok(())
    }

    /// Advances the state machine by one answer record. `only_record` is
    /// whether this is the sole answer of the message.
    fn step<'a>(&mut self, rr: Record<'a>, only_record: bool) -> Result<XfrEvent<'a>> {
        if self.records >= self.max_records {
            return Err(Error::LimitExceeded);
        }
        self.records = self.records.saturating_add(1);
        let soa = if rr.rtype() == Rtype::SOA {
            if rr.name() != self.zone.as_name() {
                return Err(Error::InvalidXfr);
            }
            Some(rr.data_as::<Soa<'a>>()?)
        } else {
            None
        };
        let record = rr;
        let (state, event) = match (self.state, soa) {
            (State::Start, Some(soa)) => {
                let up_to_date = only_record
                    && self
                        .client_serial
                        .is_some_and(|client| !serial_newer(soa.serial, client));
                if up_to_date {
                    self.style = Some(XfrStyle::UpToDate);
                    (State::Done, XfrEvent::UpToDate { soa, record })
                } else {
                    (
                        State::First { serial: soa.serial },
                        XfrEvent::Start { soa, record },
                    )
                }
            }
            (State::Start, None) => return Err(Error::InvalidXfr),
            (State::First { serial }, Some(soa)) if soa.serial == serial => {
                self.style = Some(XfrStyle::Full);
                (State::Done, XfrEvent::End { soa, record })
            }
            (State::First { serial }, Some(soa)) => {
                if self.qtype != Rtype::IXFR {
                    return Err(Error::InvalidXfr);
                }
                self.style = Some(XfrStyle::Incremental);
                (
                    State::Deleting { serial },
                    XfrEvent::DeleteStart { soa, record },
                )
            }
            (State::First { serial }, None) => {
                self.style = Some(XfrStyle::Full);
                (State::Full { serial }, XfrEvent::Record(record))
            }
            (State::Full { serial }, Some(soa)) => {
                if soa.serial != serial {
                    return Err(Error::InvalidXfr);
                }
                (State::Done, XfrEvent::End { soa, record })
            }
            (State::Full { serial }, None) => (State::Full { serial }, XfrEvent::Record(record)),
            (State::Deleting { serial }, Some(soa)) => (
                State::Adding {
                    serial,
                    to: soa.serial,
                },
                XfrEvent::AddStart { soa, record },
            ),
            (State::Deleting { serial }, None) => {
                (State::Deleting { serial }, XfrEvent::Delete(record))
            }
            (State::Adding { serial, to }, Some(soa)) => {
                if to == serial && soa.serial == serial {
                    (State::Done, XfrEvent::End { soa, record })
                } else if soa.serial == to {
                    (
                        State::Deleting { serial },
                        XfrEvent::DeleteStart { soa, record },
                    )
                } else {
                    return Err(Error::InvalidXfr);
                }
            }
            (State::Adding { serial, to }, None) => {
                (State::Adding { serial, to }, XfrEvent::Add(record))
            }
            (State::Done | State::Failed, _) => return Err(Error::InvalidXfr),
        };
        self.state = state;
        Ok(event)
    }
}

impl fmt::Debug for XfrProcessor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XfrProcessor")
            .field("zone", &self.zone)
            .field("qtype", &self.qtype)
            .field("client_serial", &self.client_serial)
            .field("state", &self.state)
            .field("style", &self.style)
            .field("messages", &self.messages)
            .field("records", &self.records)
            .field("max_messages", &self.max_messages)
            .field("max_records", &self.max_records)
            .finish()
    }
}

/// The events of one response message; see [`XfrProcessor::process`].
///
/// Yields one event per answer record; on an error it yields the error
/// once, marks the processor failed and stops. See the [`XfrProcessor`]
/// example.
///
/// ```
/// use dnsbox::xfr::XfrProcessor;
/// use dnsbox::Message;
///
/// // Count the records of each message as it arrives.
/// fn count(xfr: &mut XfrProcessor, msg: &Message<'_>) -> dnsbox::Result<usize> {
///     let mut n = 0;
///     for event in xfr.process(msg)? {
///         event?;
///         n += 1;
///     }
///     Ok(n)
/// }
/// ```
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct XfrEvents<'p, 'a> {
    proc: &'p mut XfrProcessor,
    answers: Records<'a>,
    remaining: u16,
}

impl<'a> Iterator for XfrEvents<'_, 'a> {
    type Item = Result<XfrEvent<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.proc.state == State::Failed {
            return None;
        }
        let rr = self.answers.next()?;
        let only = self.remaining == 1 && self.proc.messages == 1;
        self.remaining = self.remaining.saturating_sub(1);
        let res = rr.and_then(|rr| self.proc.step(rr, only));
        if res.is_err() {
            self.proc.state = State::Failed;
        }
        Some(res)
    }
}

impl fmt::Debug for XfrEvents<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XfrEvents")
            .field("remaining", &self.remaining)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
