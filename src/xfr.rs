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
/// On error the builder is left unchanged.
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

/// How the server answers, once known.
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
/// [`Error::MalformedXfr`]. Only the answer section is processed; TSIG and
/// OPT records elsewhere are ignored. After an error the processor stays
/// failed.
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
}

impl XfrProcessor {
    /// A processor for an AXFR of `zone`.
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
        }
    }

    /// A processor for an IXFR of `zone` from version `client_serial`.
    pub fn ixfr(zone: impl ToName, client_serial: u32) -> Self {
        XfrProcessor {
            qtype: Rtype::IXFR,
            client_serial: Some(client_serial),
            ..Self::axfr(zone)
        }
    }

    /// Also requires every response message to carry this ID (the
    /// query's).
    #[must_use]
    pub fn with_id(mut self, id: u16) -> Self {
        self.id = Some(id);
        self
    }

    /// Whether the transfer is complete.
    #[inline]
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.state == State::Done
    }

    /// The response style, once the server's answer has revealed it.
    #[inline]
    #[must_use]
    pub fn style(&self) -> Option<XfrStyle> {
        self.style
    }

    /// The serial of the version being transferred (the first SOA), once
    /// seen.
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
    #[inline]
    #[must_use]
    pub fn message_count(&self) -> u32 {
        self.messages
    }

    /// Number of answer records processed so far.
    #[inline]
    #[must_use]
    pub fn record_count(&self) -> u64 {
        self.records
    }

    /// Checks the header and question of the next response message and
    /// returns an iterator over its events.
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
            State::Done | State::Failed => return Err(Error::MalformedXfr),
            _ => {}
        }
        let flags = msg.flags();
        if flags.rcode() != Rcode::NOERROR {
            return Err(Error::ErrorResponse);
        }
        if !flags.qr() || flags.opcode() != Opcode::QUERY {
            return Err(Error::MalformedXfr);
        }
        if let Some(id) = self.id
            && msg.id() != id
        {
            return Err(Error::MalformedXfr);
        }
        match msg.header().qdcount {
            0 => {}
            1 => {
                let q = msg.questions().next().ok_or(Error::UnexpectedEof)??;
                if q.name() != self.zone.as_name() || q.qtype() != self.qtype {
                    return Err(Error::MalformedXfr);
                }
            }
            _ => return Err(Error::MalformedXfr),
        }
        Ok(())
    }

    /// Advances the state machine by one answer record. `only_record` is
    /// whether this is the sole answer of the message.
    fn step<'a>(&mut self, rr: Record<'a>, only_record: bool) -> Result<XfrEvent<'a>> {
        self.records = self.records.saturating_add(1);
        let soa = if rr.rtype() == Rtype::SOA {
            if rr.name() != self.zone.as_name() {
                return Err(Error::MalformedXfr);
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
            (State::Start, None) => return Err(Error::MalformedXfr),
            (State::First { serial }, Some(soa)) if soa.serial == serial => {
                self.style = Some(XfrStyle::Full);
                (State::Done, XfrEvent::End { soa, record })
            }
            (State::First { serial }, Some(soa)) => {
                if self.qtype != Rtype::IXFR {
                    return Err(Error::MalformedXfr);
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
                    return Err(Error::MalformedXfr);
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
                    return Err(Error::MalformedXfr);
                }
            }
            (State::Adding { serial, to }, None) => {
                (State::Adding { serial, to }, XfrEvent::Add(record))
            }
            (State::Done | State::Failed, _) => return Err(Error::MalformedXfr),
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
            .finish()
    }
}

/// The events of one response message; see [`XfrProcessor::process`].
///
/// Yields one event per answer record; on an error it yields the error
/// once, marks the processor failed and stops.
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
