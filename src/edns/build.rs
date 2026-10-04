//! Building OPT records with [`MessageBuilder`], and RFC 8467 padding
//! policies.

use super::{ComposeOption, ComposeOptions, OptData, OptHeader, PaddingLen};
use crate::builder::MessageBuilder;
use crate::message::Message;
use crate::name::Name;
use crate::rdata::ComposeRdata;
use crate::wire::{Composer, NameEncoding, OutBuf};
use crate::{Error, Rcode, Result, Rtype};

/// Size of an OPT record without its RDATA: root owner (1), TYPE (2),
/// CLASS (2), TTL (4), RDLENGTH (2).
pub const OPT_RR_OVERHEAD: usize = 11;

/// Size of an option's code and length fields.
const OPTION_HEADER: usize = 4;

/// How much EDNS(0) Padding (RFC 7830) to add to a message
/// (RFC 8467 §4).
///
/// The padding length is chosen so that the whole message — header,
/// sections, and the OPT record including the Padding option — reaches the
/// target size. Padding never takes the message past the builder's size
/// limit.
///
/// RFC 8467 §4.1 recommends [`QUERY`](Self::QUERY) (block length 128) for
/// queries and [`RESPONSE`](Self::RESPONSE) (block length 468) for
/// responses, over encrypted transports. For the random policies of
/// §4.2.2–4.2.3, draw the length (or block length) yourself and use
/// [`Fixed`](Self::Fixed) or [`BlockLength`](Self::BlockLength). The size
/// is that of the DNS message alone, without the TCP length prefix (§3).
///
/// ```
/// use dnsbox::edns::PaddingPolicy;
///
/// // A 100-byte query (with an empty Padding option) padded to 128 bytes.
/// assert_eq!(PaddingPolicy::QUERY.padding_len(100, 1232), 28);
/// assert_eq!(PaddingPolicy::BlockLength(128).padding_len(128, 1232), 0);
/// // Never past the size limit.
/// assert_eq!(PaddingPolicy::RESPONSE.padding_len(500, 512), 12);
/// assert_eq!(PaddingPolicy::Fixed(16).padding_len(100, 1232), 16);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PaddingPolicy {
    /// Pad to the next multiple of the block length (RFC 8467 §4.1); if
    /// that exceeds the size limit, pad up to the limit. A block length of
    /// 0 adds an empty Padding option.
    BlockLength(u16),
    /// Pad to the size limit (RFC 8467 §4.2.1; NOT RECOMMENDED there).
    Maximal,
    /// Add exactly this many padding octets; fails with
    /// [`Error::BufferTooSmall`] if they do not fit.
    Fixed(u16),
}

impl PaddingPolicy {
    /// Recommended policy for queries: block length 128 (RFC 8467 §4.1).
    pub const QUERY: PaddingPolicy = PaddingPolicy::BlockLength(128);
    /// Recommended policy for responses: block length 468 (RFC 8467 §4.1).
    pub const RESPONSE: PaddingPolicy = PaddingPolicy::BlockLength(468);

    /// The number of padding octets to add to a message that would be
    /// `unpadded_len` bytes long with an empty Padding option, given the
    /// message size limit `limit`. At most 65535 (the option length is 16
    /// bits).
    #[must_use]
    pub const fn padding_len(self, unpadded_len: usize, limit: usize) -> usize {
        let room = limit.saturating_sub(unpadded_len);
        let pad = match self {
            PaddingPolicy::BlockLength(0) => 0,
            PaddingPolicy::BlockLength(block) => {
                let block = block as usize;
                let rem = unpadded_len % block;
                let pad = if rem == 0 { 0 } else { block - rem };
                if pad > room { room } else { pad }
            }
            PaddingPolicy::Maximal => room,
            PaddingPolicy::Fixed(n) => n as usize,
        };
        if pad > u16::MAX as usize {
            u16::MAX as usize
        } else {
            pad
        }
    }
}

/// A [`Composer`] that only counts bytes, used to size options before
/// writing them.
struct Counter(usize);

impl Composer for Counter {
    #[inline]
    fn pos(&self) -> usize {
        self.0
    }

    #[inline]
    fn put_bytes(&mut self, data: &[u8]) -> Result<()> {
        self.0 = self
            .0
            .checked_add(data.len())
            .ok_or(Error::BufferTooSmall)?;
        Ok(())
    }

    #[inline]
    fn patch(&mut self, _pos: usize, _data: &[u8]) -> Result<()> {
        Ok(())
    }

    #[inline]
    fn put_name(&mut self, name: Name<'_>, _encoding: NameEncoding) -> Result<()> {
        self.0 = self
            .0
            .checked_add(name.wire_len())
            .ok_or(Error::BufferTooSmall)?;
        Ok(())
    }
}

/// OPT RDATA: some options followed by a Padding option of `pad` zeros.
struct Padded<'o, O: ?Sized> {
    options: &'o O,
    pad: u16,
}

impl<O: ComposeOptions + ?Sized> ComposeRdata for Padded<'_, O> {
    fn rtype(&self) -> Rtype {
        Rtype::OPT
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        self.options.compose_options(c)?;
        PaddingLen(self.pad).compose_tlv(c)
    }
}

impl<B: OutBuf> MessageBuilder<B> {
    /// Appends an OPT record (RFC 6891 §6.1) to the additional section:
    /// owner `.`, CLASS and TTL from `header`, RDATA from `options`.
    ///
    /// A message carries at most one OPT record (§6.1.1); the builder does
    /// not check this. If the message will be signed (TSIG, SIG(0)), push
    /// the OPT record before the signature. Like every push, this is
    /// atomic.
    ///
    /// # Errors
    ///
    /// As [`push_additional`](Self::push_additional): typically
    /// [`Error::BufferTooSmall`] or [`Error::SectionOrder`].
    ///
    /// ```
    /// use dnsbox::{Class, Flags, Message, MessageBuilder, NameBuf, Rcode, Rtype};
    /// use dnsbox::edns::{ExtendedError, InfoCode, OptHeader};
    ///
    /// // A BADCOOKIE response: RCODE 23 is split between the header and
    /// // the OPT record.
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.set_flags(Flags::default().with_qr(true).with_rcode(Rcode::BADCOOKIE));
    /// let ede = ExtendedError::new(InfoCode::OTHER_ERROR, b"bad cookie");
    /// b.push_edns(OptHeader::new(1232).with_rcode(Rcode::BADCOOKIE), &ede)?;
    /// let msg = Message::parse_validated(b.finish())?;
    /// assert_eq!(msg.effective_rcode()?, Rcode::BADCOOKIE);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn push_edns<O: ComposeOptions + ?Sized>(
        &mut self,
        header: OptHeader,
        options: &O,
    ) -> Result<()> {
        self.push_additional(Name::ROOT, header.class(), header.ttl(), &OptData(options))
    }

    /// Like [`push_edns`](Self::push_edns), followed by a Padding option
    /// (RFC 7830) sized by `policy` (RFC 8467) against the whole message.
    ///
    /// The Padding option is written after `options`, as the last option
    /// (RFC 8467 §3). Push this last (only a TSIG or SIG(0) signature
    /// should follow): anything added afterwards changes the padded size.
    ///
    /// # Errors
    ///
    /// As [`push_edns`](Self::push_edns); with
    /// [`PaddingPolicy::Fixed`], [`Error::BufferTooSmall`] if the padding
    /// does not fit.
    ///
    /// ```
    /// use dnsbox::{Class, MessageBuilder, NameBuf, Rtype};
    /// use dnsbox::edns::{OptHeader, PaddingPolicy};
    ///
    /// let name: NameBuf = "example.com".parse()?;
    /// let mut buf = [0u8; 1232];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.push_question(&name, Rtype::AAAA, Class::IN)?;
    /// b.push_edns_padded(OptHeader::new(1232), &(), PaddingPolicy::QUERY)?;
    /// assert_eq!(b.len(), 128);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn push_edns_padded<O: ComposeOptions + ?Sized>(
        &mut self,
        header: OptHeader,
        options: &O,
        policy: PaddingPolicy,
    ) -> Result<()> {
        let mut counter = Counter(0);
        options.compose_options(&mut counter)?;
        let unpadded = self
            .len()
            .saturating_add(OPT_RR_OVERHEAD)
            .saturating_add(counter.0)
            .saturating_add(OPTION_HEADER);
        let pad = policy.padding_len(unpadded, self.limit());
        let pad = u16::try_from(pad).map_err(|_| Error::BufferTooSmall)?;
        let data = Padded { options, pad };
        self.push_additional(Name::ROOT, header.class(), header.ttl(), &data)
    }

    /// Starts the skeleton of a response to `query`, like
    /// [`start_response`](Self::start_response), and prepares the EDNS
    /// echo RFC 6891 §7 requires: if the query carried an OPT record,
    /// returns the [`OptHeader`] for the response
    /// ([`OptHeader::response_to`] with our `udp_payload_size`) and adds
    /// [`OPT_RR_OVERHEAD`] bytes to the [reserve](Self::set_reserve), so the
    /// OPT record still fits when the answer is truncated. Add the answers,
    /// then append the OPT record with
    /// [`push_reserved_edns`](Self::push_reserved_edns).
    ///
    /// If the query's EDNS version is above 0, the RCODE is set to BADVERS
    /// (header bits here, extended bits in the returned header; RFC 6891
    /// §6.1.3) and the response should carry nothing else.
    ///
    /// For a UDP response, cap the size first with
    /// [`set_limit`](Self::set_limit) at the smaller of our maximum and the
    /// query's [effective payload size](OptHeader::effective_udp_payload_size)
    /// (RFC 6891 §6.2.5).
    ///
    /// # Errors
    ///
    /// The parse error if the query's OPT record is malformed or
    /// duplicated ([`Error::DuplicateOpt`], [`Error::OptNotRoot`]: answer
    /// FORMERR, RFC 6891 §6.1.1), and as
    /// [`start_response`](Self::start_response) otherwise. On error the
    /// builder is unchanged.
    ///
    /// ```
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
    /// use dnsbox::edns::OptHeader;
    /// use dnsbox::rdata::A;
    ///
    /// // A query with EDNS (DO set).
    /// let name: NameBuf = "example.com".parse()?;
    /// let mut qbuf = [0u8; 512];
    /// let mut q = MessageBuilder::query(&mut qbuf, 7, &name, Rtype::A, Class::IN)?;
    /// q.push_edns(OptHeader::new(1232).with_dnssec_ok(true), &())?;
    /// let query = Message::parse(q.finish())?;
    ///
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// let opt = b.start_response_edns(&query, 1232)?.expect("query had EDNS");
    /// b.push_answer(&name, Class::IN, 300, &A::new([192, 0, 2, 1].into()))?;
    /// b.push_reserved_edns(opt, &())?;
    /// let resp = Message::parse_validated(b.finish())?;
    /// let edns = resp.edns()?.expect("OPT echoed");
    /// assert!(edns.dnssec_ok() && edns.udp_payload_size() == 1232);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn start_response_edns(
        &mut self,
        query: &Message<'_>,
        udp_payload_size: u16,
    ) -> Result<Option<OptHeader>> {
        let edns = query.edns()?;
        self.start_response(query)?;
        let Some(edns) = edns else {
            return Ok(None);
        };
        let mut header = OptHeader::response_to(edns.header(), udp_payload_size);
        if edns.version() > 0 {
            header = header.with_rcode(Rcode::BADVERS);
            self.set_rcode(Rcode::BADVERS);
        }
        self.set_reserve(self.reserve().saturating_add(OPT_RR_OVERHEAD));
        Ok(Some(header))
    }

    /// Releases the [`OPT_RR_OVERHEAD`] bytes reserved by
    /// [`start_response_edns`](Self::start_response_edns) and appends the
    /// OPT record with [`push_edns`](Self::push_edns).
    ///
    /// The reserve only guarantees room for an OPT record without options.
    /// Push it before any TSIG or SIG(0) record.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] if `options` do not fit: the reserve is
    /// then restored, and the caller can retry with fewer options (e.g.
    /// `&()`). Otherwise as [`push_edns`](Self::push_edns).
    ///
    /// ```
    /// use dnsbox::builder::Truncation;
    /// use dnsbox::edns::{Nsid, OptHeader};
    /// use dnsbox::rdata::A;
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype, Section};
    ///
    /// let name: NameBuf = "pool.example".parse()?;
    /// let mut qbuf = [0u8; 512];
    /// let mut q = MessageBuilder::query(&mut qbuf, 1, &name, Rtype::A, Class::IN)?;
    /// q.push_edns(OptHeader::new(512), &())?;
    /// let query = Message::parse(q.finish())?;
    ///
    /// // Far too many addresses for 512 bytes: the answer is truncated, yet the
    /// // OPT record still fits thanks to the reserve.
    /// let mut buf = [0u8; 4096];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// b.set_limit(512);
    /// b.set_truncation(Truncation::SetTc);
    /// let opt = b.start_response_edns(&query, 1232)?.expect("query had EDNS");
    /// let pool: Vec<A> = (0..=255).map(|i| A::new([192, 0, 2, i].into())).collect();
    /// b.push_rrset(Section::Answer, &name, Class::IN, 60, &pool)?;
    /// b.push_reserved_edns(opt, &Nsid::new(b"ns1"))
    ///     .or_else(|_| b.push_reserved_edns(opt, &()))?; // no room for NSID: retry bare
    /// let resp = Message::parse_validated(b.finish())?;
    /// assert!(resp.flags().tc());
    /// assert!(resp.edns()?.is_some());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn push_reserved_edns<O: ComposeOptions + ?Sized>(
        &mut self,
        header: OptHeader,
        options: &O,
    ) -> Result<()> {
        let reserve = self.reserve();
        self.set_reserve(reserve.saturating_sub(OPT_RR_OVERHEAD));
        let res = self.push_edns(header, options);
        if res.is_err() {
            self.set_reserve(reserve);
        }
        res
    }
}
