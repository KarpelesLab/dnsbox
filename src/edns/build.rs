//! Building OPT records with [`MessageBuilder`], and RFC 8467 padding
//! policies.

use super::{ComposeOption, ComposeOptions, OptData, OptHeader, PaddingLen};
use crate::builder::MessageBuilder;
use crate::name::Name;
use crate::rdata::ComposeRdata;
use crate::wire::{Composer, NameEncoding, OutBuf};
use crate::{Error, Result, Rtype};

/// Size of an OPT record without its RDATA: root owner (1), TYPE (2),
/// CLASS (2), TTL (4), RDLENGTH (2).
const OPT_RR_OVERHEAD: usize = 11;

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
}
