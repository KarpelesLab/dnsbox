//! The OPT pseudo-record's fixed fields (RFC 6891 §6.1.2–6.1.3) and the
//! [`Edns`] view of a whole OPT record.

use core::fmt;

use super::{Opt, Options, ParseOption, RawOptions};
use crate::message::Record;
use crate::{Class, Error, Flags, Rcode, Result, Rtype};

/// The EDNS header flags: the low 16 bits of the OPT record's TTL
/// (RFC 6891 §6.1.4; IANA "EDNS Header Flags" registry).
///
/// Unassigned bits ("Z") are preserved as they are.
///
/// ```
/// use dnsbox::edns::EdnsFlags;
///
/// let flags = EdnsFlags::default().with_dnssec_ok(true).with_bit(0x0001, true);
/// assert_eq!(flags.bits(), 0x8001);
/// assert!(flags.dnssec_ok() && !flags.compact_ok());
/// assert_eq!(flags.to_string(), "do 0x0001");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct EdnsFlags(u16);

impl EdnsFlags {
    /// DO: DNSSEC answer OK (RFC 3225 §3, RFC 6891 §6.1.4), bit 0.
    pub const DO: u16 = 0x8000;
    /// CO: Compact Answers OK (RFC 9824 §5), bit 1.
    pub const CO: u16 = 0x4000;

    /// Wraps the raw 16-bit flags field.
    #[inline]
    #[must_use]
    pub const fn from_bits(bits: u16) -> Self {
        EdnsFlags(bits)
    }

    /// The raw 16-bit flags field.
    #[inline]
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Whether the DO (DNSSEC OK) bit is set (RFC 3225 §3).
    #[inline]
    #[must_use]
    pub const fn dnssec_ok(self) -> bool {
        self.0 & Self::DO != 0
    }

    /// Returns a copy with the DO bit set to `value`.
    #[inline]
    #[must_use]
    pub const fn with_dnssec_ok(self, value: bool) -> Self {
        self.with_bit(Self::DO, value)
    }

    /// Whether the CO (Compact Answers OK) bit is set (RFC 9824 §5).
    #[inline]
    #[must_use]
    pub const fn compact_ok(self) -> bool {
        self.0 & Self::CO != 0
    }

    /// Returns a copy with the CO bit set to `value`.
    #[inline]
    #[must_use]
    pub const fn with_compact_ok(self, value: bool) -> Self {
        self.with_bit(Self::CO, value)
    }

    /// Returns a copy with the bits in `mask` set or cleared.
    #[inline]
    #[must_use]
    pub const fn with_bit(self, mask: u16, value: bool) -> Self {
        if value {
            EdnsFlags(self.0 | mask)
        } else {
            EdnsFlags(self.0 & !mask)
        }
    }
}

impl fmt::Debug for EdnsFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EdnsFlags({self})")
    }
}

impl fmt::Display for EdnsFlags {
    /// The set flags as in `dig` output: `do`, `co`, then any other set bit
    /// as `0xNNNN`, space-separated (empty when no flag is set).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut sep = "";
        for (mask, name) in [(Self::DO, "do"), (Self::CO, "co")] {
            if self.0 & mask != 0 {
                write!(f, "{sep}{name}")?;
                sep = " ";
            }
        }
        let rest = self.0 & !(Self::DO | Self::CO);
        if rest != 0 {
            write!(f, "{sep}{rest:#06x}")?;
        }
        Ok(())
    }
}

/// The fixed fields of an OPT record, which RFC 6891 §6.1.2–6.1.3 packs into
/// its CLASS and TTL:
///
/// ```text
/// CLASS:  requestor's UDP payload size
/// TTL:    | EXTENDED-RCODE (8) | VERSION (8) | DO | Z (15) |
/// ```
///
/// Used both to read ([`Edns::header`]) and to build
/// ([`MessageBuilder::push_edns`](crate::MessageBuilder::push_edns)) OPT
/// records.
///
/// ```
/// use dnsbox::edns::OptHeader;
/// use dnsbox::{Class, Flags, Rcode};
///
/// let header = OptHeader::new(1232).with_dnssec_ok(true).with_rcode(Rcode::BADVERS);
/// assert_eq!(header.class(), Class::new(1232));
/// assert_eq!(header.ttl(), 0x0100_8000); // extended RCODE 1, version 0, DO
/// assert_eq!(OptHeader::from_fields(header.class(), header.ttl()), header);
/// // BADVERS is 16: all of it is in the extended RCODE.
/// assert_eq!(header.rcode(Flags::default()), Rcode::BADVERS);
/// assert_eq!(header.to_string(), "version: 0, flags: do; udp: 1232");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OptHeader {
    /// Largest UDP payload the sender can reassemble (RFC 6891 §6.2.3);
    /// values below 512 are treated as 512 (§6.2.5).
    pub udp_payload_size: u16,
    /// Upper 8 bits of the 12-bit RCODE (RFC 6891 §6.1.3).
    pub extended_rcode: u8,
    /// EDNS version; 0 for RFC 6891 (§6.1.3).
    pub version: u8,
    /// DO and the other flag bits (§6.1.4).
    pub flags: EdnsFlags,
}

impl OptHeader {
    /// The smallest UDP payload size a requestor may announce; smaller
    /// values are treated as this one (RFC 6891 §6.2.5).
    pub const MIN_UDP_PAYLOAD_SIZE: u16 = 512;

    /// EDNS version 0, no flags, extended RCODE 0, with the given UDP
    /// payload size (1232 is the common choice that avoids IP
    /// fragmentation).
    #[inline]
    #[must_use]
    pub const fn new(udp_payload_size: u16) -> Self {
        OptHeader {
            udp_payload_size,
            extended_rcode: 0,
            version: 0,
            flags: EdnsFlags(0),
        }
    }

    /// Decodes the fields from an OPT record's raw CLASS and TTL.
    #[inline]
    #[must_use]
    pub const fn from_fields(class: Class, ttl: u32) -> Self {
        OptHeader {
            udp_payload_size: class.get(),
            extended_rcode: (ttl >> 24) as u8,
            version: (ttl >> 16) as u8,
            flags: EdnsFlags(ttl as u16),
        }
    }

    /// The CLASS field to write: the UDP payload size.
    #[inline]
    #[must_use]
    pub const fn class(&self) -> Class {
        Class::new(self.udp_payload_size)
    }

    /// The TTL field to write: extended RCODE, version and flags.
    #[inline]
    #[must_use]
    pub const fn ttl(&self) -> u32 {
        ((self.extended_rcode as u32) << 24) | ((self.version as u32) << 16) | self.flags.0 as u32
    }

    /// The OPT header of a response to a query whose OPT header is
    /// `query` (RFC 6891 §7): our own `udp_payload_size`, version 0, the
    /// DO bit copied from the query (RFC 3225 §3), the other flags clear
    /// and an extended RCODE of 0.
    ///
    /// If the query's version is above 0 the response must carry RCODE
    /// BADVERS instead (RFC 6891 §6.1.3); see [`Self::rcode`] and
    /// [`MessageBuilder::start_response_edns`](crate::MessageBuilder::start_response_edns),
    /// which handles it.
    ///
    /// ```
    /// use dnsbox::edns::OptHeader;
    ///
    /// let q = OptHeader::new(4096).with_dnssec_ok(true).with_version(0);
    /// let r = OptHeader::response_to(q, 1232);
    /// assert_eq!((r.udp_payload_size, r.version, r.dnssec_ok()), (1232, 0, true));
    /// ```
    #[inline]
    #[must_use]
    pub const fn response_to(query: OptHeader, udp_payload_size: u16) -> Self {
        OptHeader::new(udp_payload_size).with_dnssec_ok(query.dnssec_ok())
    }

    /// The UDP payload size, raised to 512 if smaller (RFC 6891 §6.2.5).
    #[inline]
    #[must_use]
    pub const fn effective_udp_payload_size(&self) -> u16 {
        if self.udp_payload_size < Self::MIN_UDP_PAYLOAD_SIZE {
            Self::MIN_UDP_PAYLOAD_SIZE
        } else {
            self.udp_payload_size
        }
    }

    /// Whether the DO bit is set (RFC 3225 §3).
    #[inline]
    #[must_use]
    pub const fn dnssec_ok(&self) -> bool {
        self.flags.dnssec_ok()
    }

    /// Returns a copy with the DO bit set to `value`.
    #[inline]
    #[must_use]
    pub const fn with_dnssec_ok(mut self, value: bool) -> Self {
        self.flags = self.flags.with_dnssec_ok(value);
        self
    }

    /// Returns a copy with the flags replaced.
    #[inline]
    #[must_use]
    pub const fn with_flags(mut self, flags: EdnsFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Returns a copy with the EDNS version replaced.
    #[inline]
    #[must_use]
    pub const fn with_version(mut self, version: u8) -> Self {
        self.version = version;
        self
    }

    /// Returns a copy with the extended RCODE set to the upper 8 bits of
    /// `rcode` (RFC 6891 §6.1.3). The lower 4 bits go in the message
    /// header: set them with [`Flags::with_rcode`].
    #[inline]
    #[must_use]
    pub const fn with_rcode(mut self, rcode: Rcode) -> Self {
        self.extended_rcode = rcode.extended_bits();
        self
    }

    /// The full 12-bit RCODE, combining the header's 4 bits with the
    /// extended RCODE (RFC 6891 §6.1.3).
    #[inline]
    #[must_use]
    pub const fn rcode(&self, header: Flags) -> Rcode {
        Rcode::from_parts(header.rcode().header_bits(), self.extended_rcode)
    }
}

impl fmt::Display for OptHeader {
    /// As in `dig`'s OPT pseudo-section: `version: 0, flags: do; udp:
    /// 1232` (`flags:;` when no flag is set).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "version: {}, flags:", self.version)?;
        if self.flags.0 != 0 {
            write!(f, " {}", self.flags)?;
        }
        write!(f, "; udp: {}", self.udp_payload_size)
    }
}

/// The OPT record of a message, decoded: header fields plus options
/// (RFC 6891 §6.1). Returned by [`Message::edns`](crate::Message::edns).
///
/// ```
/// use dnsbox::{Message, MessageBuilder};
/// use dnsbox::edns::{Nsid, OptHeader};
///
/// let mut buf = [0u8; 512];
/// let mut b = MessageBuilder::new(&mut buf)?;
/// b.push_edns(OptHeader::new(1400), &Nsid::new(b"anycast-7"))?;
/// let msg = Message::parse(b.finish())?;
/// let edns = msg.edns()?.expect("OPT present");
/// assert_eq!(edns.header(), OptHeader::new(1400));
/// assert_eq!(edns.get::<Nsid>().expect("NSID")?.as_str(), Some("anycast-7"));
/// assert!(edns.record().name().is_root());
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Edns<'a> {
    header: OptHeader,
    opt: Opt<'a>,
    record: Record<'a>,
}

impl<'a> Edns<'a> {
    /// Decodes an OPT record.
    ///
    /// # Errors
    ///
    /// [`Error::WrongType`] for another type, [`Error::OptNotRoot`] if the
    /// owner name is not the root (RFC 6891 §6.1.2), or
    /// [`Error::UnexpectedEof`] for a truncated option.
    pub fn from_record(record: &Record<'a>) -> Result<Self> {
        if record.rtype() != Rtype::OPT {
            return Err(Error::WrongType);
        }
        if !record.name().is_root() {
            return Err(Error::OptNotRoot);
        }
        Ok(Edns {
            header: OptHeader::from_fields(record.class(), record.ttl()),
            opt: record.data_as()?,
            record: *record,
        })
    }

    /// The fixed fields.
    #[inline]
    #[must_use]
    pub const fn header(&self) -> OptHeader {
        self.header
    }

    /// The requestor's UDP payload size, as sent (RFC 6891 §6.2.3). See
    /// [`OptHeader::effective_udp_payload_size`] for the value to honour.
    #[inline]
    #[must_use]
    pub const fn udp_payload_size(&self) -> u16 {
        self.header.udp_payload_size
    }

    /// The upper 8 bits of the 12-bit RCODE (RFC 6891 §6.1.3).
    #[inline]
    #[must_use]
    pub const fn extended_rcode(&self) -> u8 {
        self.header.extended_rcode
    }

    /// The EDNS version (RFC 6891 §6.1.3).
    #[inline]
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.header.version
    }

    /// The flags (DO and the rest, preserved).
    #[inline]
    #[must_use]
    pub const fn flags(&self) -> EdnsFlags {
        self.header.flags
    }

    /// Whether the DO bit is set (RFC 3225 §3).
    #[inline]
    #[must_use]
    pub const fn dnssec_ok(&self) -> bool {
        self.header.dnssec_ok()
    }

    /// The full 12-bit RCODE given the message header flags.
    #[inline]
    #[must_use]
    pub const fn rcode(&self, header: Flags) -> Rcode {
        self.header.rcode(header)
    }

    /// The options.
    #[inline]
    #[must_use]
    pub const fn opt(&self) -> Opt<'a> {
        self.opt
    }

    /// Iterates over the decoded options; see [`Opt::options`].
    #[inline]
    pub fn options(&self) -> Options<'a> {
        self.opt.options()
    }

    /// Iterates over the raw options; see [`Opt::raw_options`].
    #[inline]
    pub fn raw_options(&self) -> RawOptions<'a> {
        self.opt.raw_options()
    }

    /// Decodes the first option of type `T`; see [`Opt::get`].
    #[inline]
    #[must_use]
    pub fn get<T: ParseOption<'a>>(&self) -> Option<Result<T>> {
        self.opt.get()
    }

    /// The underlying record (for its byte range, e.g. to strip it).
    #[inline]
    #[must_use]
    pub const fn record(&self) -> Record<'a> {
        self.record
    }
}

impl fmt::Display for Edns<'_> {
    /// `version: 0, flags: do; udp: 1232`, followed by `; ` and the
    /// options if there are any.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.header, f)?;
        if !self.opt.is_empty() {
            write!(f, "; {}", self.opt)?;
        }
        Ok(())
    }
}
