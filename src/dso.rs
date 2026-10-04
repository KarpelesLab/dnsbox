//! DNS Stateful Operations: DSO (RFC 8490).
//!
//! A DSO message is a 12-byte header with opcode DSO (6) and all four
//! section counts zero, followed by TLVs (RFC 8490 §5.4):
//!
//! ```text
//! DSO-TYPE (16) | DSO-LENGTH (16) | DSO-DATA (DSO-LENGTH bytes)
//! ```
//!
//! The first TLV of a request or unidirectional message is the *Primary
//! TLV* (it says what the message is); in a response it is the *Response
//! Primary TLV*. The rest are *Additional TLVs* (§5.4.2–5.4.4). Requests
//! carry a non-zero message ID; unidirectional messages carry ID 0
//! (§5.4).
//!
//! This module provides [`DsoMessage`] (a zero-copy view with TLV
//! iteration and validation), [`DsoBuilder`] (writing into any
//! [`OutBuf`]), the [`DsoType`] registry, and the TLVs defined by RFC 8490
//! itself: [`Keepalive`] (§7.1), [`RetryDelay`] (§7.2) and
//! [`EncryptionPadding`] (§7.3).
//!
//! ```
//! use dnsbox::dso::{DsoBuilder, DsoMessage, DsoType, Keepalive};
//! use dnsbox::WireWriter;
//!
//! let mut buf = [0u8; 128];
//! let mut b = DsoBuilder::request(WireWriter::new(&mut buf), 1)?;
//! b.push(&Keepalive { inactivity_timeout: 15_000, keepalive_interval: 15_000 })?;
//! b.pad_to(64)?;
//! let wire = b.finish()?;
//! assert_eq!(wire.len(), 64);
//!
//! let msg = DsoMessage::parse(wire)?;
//! let primary = msg.primary()?.unwrap();
//! assert_eq!(primary.dso_type, DsoType::KEEPALIVE);
//! assert_eq!(primary.parse::<Keepalive>()?.inactivity_timeout, 15_000);
//! # Ok::<(), dnsbox::Error>(())
//! ```

use core::fmt;

use crate::builder::MAX_MESSAGE_LEN;
use crate::wire::{Composer, OutBuf, WireReader};
use crate::{Error, Flags, Header, Opcode, Rcode, Result};

open_enum! {
    /// A DSO TLV type (RFC 8490 §10.3, IANA "DSO Type Codes").
    pub struct DsoType(u16), generic "DSOTYPE";
    /// Keepalive (RFC 8490 §7.1).
    KEEPALIVE = 0x0001 => "KeepAlive",
    /// Retry Delay (RFC 8490 §7.2).
    RETRY_DELAY = 0x0002 => "RetryDelay",
    /// Encryption Padding (RFC 8490 §7.3).
    ENCRYPTION_PADDING = 0x0003 => "EncryptionPadding",
    /// DNS Push subscribe (RFC 8765 §6.2).
    SUBSCRIBE = 0x0040 => "SUBSCRIBE",
    /// DNS Push notification (RFC 8765 §6.3).
    PUSH = 0x0041 => "PUSH",
    /// DNS Push unsubscribe (RFC 8765 §6.4).
    UNSUBSCRIBE = 0x0042 => "UNSUBSCRIBE",
    /// DNS Push reconfirm (RFC 8765 §6.5).
    RECONFIRM = 0x0043 => "RECONFIRM",
}

impl DsoType {
    /// Whether the value is in the experimental/local range 0xF800–0xFBFF
    /// (RFC 8490 §10.3).
    #[inline]
    pub const fn is_experimental(self) -> bool {
        self.0 >= 0xf800 && self.0 <= 0xfbff
    }
}

/// One TLV of a DSO message (RFC 8490 §5.4.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DsoTlv<'a> {
    /// DSO-TYPE.
    pub dso_type: DsoType,
    /// DSO-DATA.
    pub data: &'a [u8],
}

impl<'a> DsoTlv<'a> {
    /// Decodes the data as a typed TLV, failing with [`Error::WrongType`]
    /// if the type differs.
    pub fn parse<T: ParseDsoTlv<'a>>(&self) -> Result<T> {
        if self.dso_type != T::TYPE {
            return Err(Error::WrongType);
        }
        T::parse_data(self.data)
    }
}

/// Parsing half of a typed DSO TLV.
pub trait ParseDsoTlv<'a>: Sized {
    /// The TLV type.
    const TYPE: DsoType;

    /// Parses DSO-DATA; fails with [`Error::MalformedDso`] on a bad
    /// length.
    fn parse_data(data: &'a [u8]) -> Result<Self>;
}

/// Composing half of a typed DSO TLV; what [`DsoBuilder::push`] accepts.
pub trait ComposeDsoTlv {
    /// The TLV type.
    fn dso_type(&self) -> DsoType;

    /// Writes DSO-DATA (without the type and length).
    fn compose_data<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()>;
}

impl ComposeDsoTlv for DsoTlv<'_> {
    fn dso_type(&self) -> DsoType {
        self.dso_type
    }

    fn compose_data<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_bytes(self.data)
    }
}

/// Reads a fixed-size array from DSO-DATA that must have exactly `N`
/// bytes.
fn exact<const N: usize>(data: &[u8]) -> Result<[u8; N]> {
    data.try_into().map_err(|_| Error::MalformedDso)
}

/// The Keepalive TLV (RFC 8490 §7.1): both values are in milliseconds;
/// `0xFFFFFFFF` means "infinite".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Keepalive {
    /// How long the connection may stay idle (no outstanding operations)
    /// before the client must close it.
    pub inactivity_timeout: u32,
    /// How often the client must send traffic on an otherwise idle
    /// connection (at least 10 000 ms, §6.5.2).
    pub keepalive_interval: u32,
}

impl Keepalive {
    /// The "infinite" value of either timer.
    pub const INFINITE: u32 = u32::MAX;
}

impl ParseDsoTlv<'_> for Keepalive {
    const TYPE: DsoType = DsoType::KEEPALIVE;

    fn parse_data(data: &[u8]) -> Result<Self> {
        let [a, b, c, d, e, f, g, h] = exact::<8>(data)?;
        Ok(Keepalive {
            inactivity_timeout: u32::from_be_bytes([a, b, c, d]),
            keepalive_interval: u32::from_be_bytes([e, f, g, h]),
        })
    }
}

impl ComposeDsoTlv for Keepalive {
    fn dso_type(&self) -> DsoType {
        DsoType::KEEPALIVE
    }

    fn compose_data<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_u32(self.inactivity_timeout)?;
        c.put_u32(self.keepalive_interval)
    }
}

/// The Retry Delay TLV (RFC 8490 §7.2): how long, in milliseconds, the
/// client should wait before reconnecting (as a primary TLV in a
/// unidirectional message) or retrying (as an additional TLV in an error
/// response).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RetryDelay {
    /// Delay in milliseconds.
    pub delay: u32,
}

impl ParseDsoTlv<'_> for RetryDelay {
    const TYPE: DsoType = DsoType::RETRY_DELAY;

    fn parse_data(data: &[u8]) -> Result<Self> {
        Ok(RetryDelay {
            delay: u32::from_be_bytes(exact::<4>(data)?),
        })
    }
}

impl ComposeDsoTlv for RetryDelay {
    fn dso_type(&self) -> DsoType {
        DsoType::RETRY_DELAY
    }

    fn compose_data<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_u32(self.delay)
    }
}

/// The Encryption Padding TLV (RFC 8490 §7.3): padding of any length
/// (contents should be zero and are ignored). It may only be the last
/// additional TLV.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EncryptionPadding<'a> {
    /// The padding bytes.
    pub padding: &'a [u8],
}

impl<'a> ParseDsoTlv<'a> for EncryptionPadding<'a> {
    const TYPE: DsoType = DsoType::ENCRYPTION_PADDING;

    fn parse_data(data: &'a [u8]) -> Result<Self> {
        Ok(EncryptionPadding { padding: data })
    }
}

impl ComposeDsoTlv for EncryptionPadding<'_> {
    fn dso_type(&self) -> DsoType {
        DsoType::ENCRYPTION_PADDING
    }

    fn compose_data<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_bytes(self.padding)
    }
}

/// A parsed DSO message: a view over the caller's buffer.
#[derive(Clone, Copy, Debug)]
pub struct DsoMessage<'a> {
    buf: &'a [u8],
    header: Header,
}

impl<'a> DsoMessage<'a> {
    /// Parses the header: opcode must be DSO ([`Error::WrongType`]
    /// otherwise) and all four counts zero ([`Error::MalformedDso`], RFC
    /// 8490 §5.4). TLVs are decoded lazily; see
    /// [`validate`](Self::validate).
    pub fn parse(buf: &'a [u8]) -> Result<Self> {
        let header = Header::parse(buf)?;
        if header.flags.opcode() != Opcode::DSO {
            return Err(Error::WrongType);
        }
        if header.qdcount != 0 || header.ancount != 0 || header.nscount != 0 || header.arcount != 0
        {
            return Err(Error::MalformedDso);
        }
        Ok(DsoMessage { buf, header })
    }

    /// Parses and [validates](Self::validate) the message.
    pub fn parse_validated(buf: &'a [u8]) -> Result<Self> {
        let msg = Self::parse(buf)?;
        msg.validate()?;
        Ok(msg)
    }

    /// The raw bytes.
    #[inline]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.buf
    }

    /// The header.
    #[inline]
    pub const fn header(&self) -> Header {
        self.header
    }

    /// The message ID.
    #[inline]
    pub const fn id(&self) -> u16 {
        self.header.id
    }

    /// Whether this is a response (QR set).
    #[inline]
    pub const fn is_response(&self) -> bool {
        self.header.flags.qr()
    }

    /// Whether this is a unidirectional message: a non-response with ID 0
    /// (RFC 8490 §5.4), which must not be answered.
    #[inline]
    pub const fn is_unidirectional(&self) -> bool {
        !self.is_response() && self.header.id == 0
    }

    /// The header RCODE (responses).
    #[inline]
    pub const fn rcode(&self) -> Rcode {
        self.header.flags.rcode()
    }

    /// Iterates over all TLVs, primary first.
    #[inline]
    pub fn tlvs(&self) -> DsoTlvs<'a> {
        DsoTlvs {
            reader: WireReader::with_range(
                self.buf,
                Header::LEN.min(self.buf.len()),
                self.buf.len(),
            )
            .unwrap_or(WireReader::new(&[])),
            failed: false,
        }
    }

    /// The primary (or response primary) TLV: the first one, if any.
    pub fn primary(&self) -> Result<Option<DsoTlv<'a>>> {
        self.tlvs().next().transpose()
    }

    /// Iterates over the additional TLVs (all but the first).
    pub fn additional(&self) -> DsoTlvs<'a> {
        let mut it = self.tlvs();
        if let Some(Err(_)) = it.next() {
            // Re-create so the error is reported by the returned iterator.
            return self.tlvs();
        }
        it
    }

    /// Walks every TLV once and checks the message structure:
    ///
    /// - every TLV is complete (no trailing partial TLV);
    /// - a request or unidirectional message has a primary TLV (§5.4.2);
    /// - Encryption Padding, if present, is not primary, appears once and
    ///   is the last TLV (§7.3).
    ///
    /// Fails with [`Error::MalformedDso`] (or the framing error).
    pub fn validate(&self) -> Result<()> {
        let mut count = 0usize;
        let mut padded = false;
        for tlv in self.tlvs() {
            let tlv = tlv?;
            if padded {
                return Err(Error::MalformedDso);
            }
            if tlv.dso_type == DsoType::ENCRYPTION_PADDING {
                if count == 0 {
                    return Err(Error::MalformedDso);
                }
                padded = true;
            }
            count += 1;
        }
        if count == 0 && !self.is_response() {
            return Err(Error::MalformedDso);
        }
        Ok(())
    }
}

/// Iterator over the TLVs of a DSO message. Yields an error once (a
/// truncated TLV) and then stops.
#[derive(Clone, Debug)]
pub struct DsoTlvs<'a> {
    reader: WireReader<'a>,
    failed: bool,
}

impl<'a> Iterator for DsoTlvs<'a> {
    type Item = Result<DsoTlv<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.reader.is_empty() {
            return None;
        }
        let mut r = self.reader;
        let res = (|| {
            let dso_type = DsoType::new(r.read_u16()?);
            let len = r.read_u16()?;
            let data = r.read_bytes(len as usize)?;
            Ok(DsoTlv { dso_type, data })
        })();
        match res {
            Ok(tlv) => {
                self.reader = r;
                Some(Ok(tlv))
            }
            Err(e) => {
                self.failed = true;
                Some(Err(e))
            }
        }
    }
}

impl core::iter::FusedIterator for DsoTlvs<'_> {}

/// Writes a DSO message into an [`OutBuf`] (RFC 8490 §5.4).
///
/// The first pushed TLV is the primary TLV. Pushes are atomic; once an
/// Encryption Padding TLV is written ([`pad_to`](Self::pad_to) or
/// [`push`](Self::push)) nothing more may follow
/// ([`Error::SectionOrder`]).
pub struct DsoBuilder<B: OutBuf> {
    buf: B,
    base: usize,
    limit: usize,
    tlvs: usize,
    padded: bool,
}

impl<B: OutBuf> DsoBuilder<B> {
    /// Starts a message with the given header ID and flags (the opcode is
    /// forced to DSO) at the current end of `buf`.
    pub fn new(mut buf: B, id: u16, flags: Flags) -> Result<Self> {
        let base = buf.as_bytes().len();
        let limit = buf
            .capacity_limit()
            .saturating_sub(base)
            .min(MAX_MESSAGE_LEN);
        let header = Header {
            id,
            flags: flags.with_opcode(Opcode::DSO),
            ..Header::default()
        };
        if limit < Header::LEN {
            return Err(Error::BufferTooSmall);
        }
        buf.append(&header.to_bytes())?;
        Ok(DsoBuilder {
            buf,
            base,
            limit,
            tlvs: 0,
            padded: false,
        })
    }

    /// Starts a request with a (non-zero) message ID (§5.4).
    pub fn request(buf: B, id: u16) -> Result<Self> {
        if id == 0 {
            return Err(Error::MalformedDso);
        }
        Self::new(buf, id, Flags::default())
    }

    /// Starts a unidirectional message (ID 0, §5.4).
    pub fn unidirectional(buf: B) -> Result<Self> {
        Self::new(buf, 0, Flags::default())
    }

    /// Starts the response to `request` with `rcode` (§5.4: same ID, QR
    /// set).
    pub fn response(buf: B, request: &DsoMessage<'_>, rcode: Rcode) -> Result<Self> {
        if request.is_response() || request.is_unidirectional() {
            return Err(Error::MalformedDso);
        }
        Self::new(
            buf,
            request.id(),
            Flags::default().with_qr(true).with_rcode(rcode),
        )
    }

    /// Length of the message so far.
    #[inline]
    pub fn len(&self) -> usize {
        self.buf.as_bytes().len() - self.base
    }

    /// Whether no TLV has been written yet.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.tlvs == 0
    }

    /// Caps the message size (clamped to the buffer and 65535).
    pub fn set_limit(&mut self, limit: usize) {
        let cap = self
            .buf
            .capacity_limit()
            .saturating_sub(self.base)
            .min(MAX_MESSAGE_LEN);
        self.limit = limit.min(cap);
    }

    /// The message written so far.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.buf.as_bytes().get(self.base..).unwrap_or(&[])
    }

    /// Appends a TLV.
    pub fn push<T: ComposeDsoTlv + ?Sized>(&mut self, tlv: &T) -> Result<()> {
        let dso_type = tlv.dso_type();
        if self.padded {
            return Err(Error::SectionOrder);
        }
        if dso_type == DsoType::ENCRYPTION_PADDING && self.tlvs == 0 {
            // Padding is never the primary TLV (§7.3).
            return Err(Error::MalformedDso);
        }
        let start = self.buf.as_bytes().len();
        let res = (|| {
            self.buf.put_u16(dso_type.get())?;
            self.buf.put_u16_prefixed(|c| tlv.compose_data(c))?;
            if self.buf.as_bytes().len() - self.base > self.limit {
                return Err(Error::BufferTooSmall);
            }
            Ok(())
        })();
        if res.is_err() {
            self.buf.truncate(start);
            return res;
        }
        self.tlvs += 1;
        self.padded = dso_type == DsoType::ENCRYPTION_PADDING;
        Ok(())
    }

    /// Appends an Encryption Padding TLV (zero bytes) so that the message
    /// length becomes a multiple of `block` (RFC 8490 §7.3 with the
    /// block-length strategy of RFC 8467 §4.1). The TLV itself takes 4
    /// bytes, so it is always written (possibly with empty data) and the
    /// message grows to the next multiple of `block` that fits it.
    pub fn pad_to(&mut self, block: usize) -> Result<()> {
        if block == 0 {
            return Err(Error::MalformedDso);
        }
        let with_header = self.len() + 4;
        let pad = (block - with_header % block) % block;
        let zeros = [0u8; 64];
        // Write the padding in chunks to avoid a large stack buffer.
        struct Zeros<'z> {
            len: usize,
            chunk: &'z [u8],
        }
        impl ComposeDsoTlv for Zeros<'_> {
            fn dso_type(&self) -> DsoType {
                DsoType::ENCRYPTION_PADDING
            }
            fn compose_data<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
                let mut left = self.len;
                while left > 0 {
                    let n = left.min(self.chunk.len());
                    c.put_bytes(self.chunk.get(..n).unwrap_or(&[]))?;
                    left -= n;
                }
                Ok(())
            }
        }
        self.push(&Zeros {
            len: pad,
            chunk: &zeros,
        })
    }

    /// Finishes the message. A request or unidirectional message must have
    /// a primary TLV ([`Error::MalformedDso`] otherwise).
    pub fn finish(self) -> Result<B::Output> {
        let header = Header::parse(self.as_bytes())?;
        if self.tlvs == 0 && !header.flags.qr() {
            return Err(Error::MalformedDso);
        }
        Ok(self.buf.into_output())
    }
}

impl<B: OutBuf> fmt::Debug for DsoBuilder<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DsoBuilder")
            .field("len", &self.len())
            .field("tlvs", &self.tlvs)
            .field("padded", &self.padded)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WireWriter;
    use std::string::ToString;
    use std::vec::Vec;

    /// A keepalive request (ID 1, inactivity 60 s, interval 50 s), built by
    /// hand from RFC 8490 §5.4 / §7.1.
    const KEEPALIVE_REQUEST: &[u8] = &[
        0x00, 0x01, 0x30, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, // header: opcode 6
        0x00, 0x01, 0x00, 0x08, // KeepAlive, length 8
        0x00, 0x00, 0xea, 0x60, // inactivity timeout 60000 ms
        0x00, 0x00, 0xc3, 0x50, // keepalive interval 50000 ms
    ];

    #[test]
    fn parse_keepalive() {
        let msg = DsoMessage::parse_validated(KEEPALIVE_REQUEST).unwrap();
        assert_eq!(msg.id(), 1);
        assert!(!msg.is_response() && !msg.is_unidirectional());
        let p = msg.primary().unwrap().unwrap();
        assert_eq!(p.dso_type, DsoType::KEEPALIVE);
        assert_eq!(
            p.parse::<Keepalive>().unwrap(),
            Keepalive {
                inactivity_timeout: 60_000,
                keepalive_interval: 50_000
            }
        );
        assert_eq!(p.parse::<RetryDelay>(), Err(Error::WrongType));
        assert_eq!(msg.additional().count(), 0);
        assert_eq!(msg.as_bytes().len(), KEEPALIVE_REQUEST.len());
        assert_eq!(msg.header().qdcount, 0);
    }

    #[test]
    fn build_matches_hand_vector() {
        let mut buf = [0u8; 64];
        let mut b = DsoBuilder::request(WireWriter::new(&mut buf), 1).unwrap();
        assert!(b.is_empty());
        b.push(&Keepalive {
            inactivity_timeout: 60_000,
            keepalive_interval: 50_000,
        })
        .unwrap();
        assert_eq!(b.as_bytes(), KEEPALIVE_REQUEST);
        assert_eq!(b.finish().unwrap(), KEEPALIVE_REQUEST);
    }

    #[test]
    fn response_and_unidirectional() {
        let req = DsoMessage::parse(KEEPALIVE_REQUEST).unwrap();
        let mut buf = [0u8; 64];
        let mut b = DsoBuilder::response(WireWriter::new(&mut buf), &req, Rcode::NOERROR).unwrap();
        b.push(&Keepalive {
            inactivity_timeout: 30_000,
            keepalive_interval: Keepalive::INFINITE,
        })
        .unwrap();
        let wire = b.finish().unwrap().to_vec();
        let resp = DsoMessage::parse_validated(&wire).unwrap();
        assert!(resp.is_response());
        assert_eq!(resp.id(), 1);
        assert_eq!(resp.rcode(), Rcode::NOERROR);
        // Error responses may carry no TLV at all.
        let mut buf = [0u8; 64];
        let b = DsoBuilder::response(WireWriter::new(&mut buf), &req, Rcode::DSOTYPENI).unwrap();
        let wire = b.finish().unwrap().to_vec();
        let resp = DsoMessage::parse_validated(&wire).unwrap();
        assert_eq!(resp.rcode(), Rcode::DSOTYPENI);
        assert_eq!(resp.primary(), Ok(None));
        // Responding to a response or a unidirectional message is wrong.
        assert!(
            DsoBuilder::response(WireWriter::new(&mut [0u8; 64]), &resp, Rcode::NOERROR).is_err()
        );

        // Retry Delay as the primary TLV of a unidirectional message.
        let mut buf = [0u8; 64];
        let mut b = DsoBuilder::unidirectional(WireWriter::new(&mut buf)).unwrap();
        b.push(&RetryDelay { delay: 5000 }).unwrap();
        let wire = b.finish().unwrap().to_vec();
        assert_eq!(
            wire,
            [
                0, 0, 0x30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 4, 0, 0, 0x13, 0x88
            ]
        );
        let m = DsoMessage::parse_validated(&wire).unwrap();
        assert!(m.is_unidirectional());
        assert_eq!(
            m.primary().unwrap().unwrap().parse::<RetryDelay>(),
            Ok(RetryDelay { delay: 5000 })
        );
        assert!(DsoBuilder::response(WireWriter::new(&mut [0u8; 64]), &m, Rcode::NOERROR).is_err());
        assert_eq!(
            DsoBuilder::request(WireWriter::new(&mut [0u8; 64]), 0).err(),
            Some(Error::MalformedDso)
        );
        // A request without a primary TLV.
        let mut empty = [0u8; 64];
        let b = DsoBuilder::request(WireWriter::new(&mut empty), 3).unwrap();
        assert_eq!(b.finish().err(), Some(Error::MalformedDso));
    }

    #[test]
    fn padding() {
        for block in [1usize, 16, 64, 128, 468] {
            let mut buf = std::vec![0u8; 1024];
            let mut b = DsoBuilder::request(WireWriter::new(&mut buf), 7).unwrap();
            b.push(&Keepalive {
                inactivity_timeout: 1,
                keepalive_interval: 2,
            })
            .unwrap();
            b.pad_to(block).unwrap();
            assert_eq!(b.len() % block, 0, "block {block}");
            // Nothing after padding.
            assert_eq!(b.push(&RetryDelay { delay: 1 }), Err(Error::SectionOrder));
            assert_eq!(b.pad_to(block), Err(Error::SectionOrder));
            let wire = b.finish().unwrap().to_vec();
            let m = DsoMessage::parse_validated(&wire).unwrap();
            let add: Vec<_> = m.additional().map(|t| t.unwrap()).collect();
            assert_eq!(add.len(), 1);
            let pad = add[0].parse::<EncryptionPadding>().unwrap();
            assert!(pad.padding.iter().all(|&b| b == 0));
        }
        // Padding cannot be primary.
        let mut buf = [0u8; 64];
        let mut b = DsoBuilder::request(WireWriter::new(&mut buf), 7).unwrap();
        assert_eq!(b.pad_to(16), Err(Error::MalformedDso));
        assert_eq!(
            b.push(&EncryptionPadding { padding: &[0; 3] }),
            Err(Error::MalformedDso)
        );
        b.push(&RetryDelay { delay: 1 }).unwrap();
        assert_eq!(b.pad_to(0), Err(Error::MalformedDso));
    }

    #[test]
    fn malformed() {
        // Not DSO.
        let mut m = KEEPALIVE_REQUEST.to_vec();
        m[2] = 0;
        assert_eq!(DsoMessage::parse(&m).err(), Some(Error::WrongType));
        // Non-zero counts.
        for i in [4, 7, 9, 11] {
            let mut m = KEEPALIVE_REQUEST.to_vec();
            m[i] = 1;
            assert_eq!(DsoMessage::parse(&m).err(), Some(Error::MalformedDso));
        }
        // Wrong Keepalive / Retry Delay lengths.
        assert_eq!(Keepalive::parse_data(&[0; 7]), Err(Error::MalformedDso));
        assert_eq!(Keepalive::parse_data(&[0; 9]), Err(Error::MalformedDso));
        assert_eq!(RetryDelay::parse_data(&[0; 5]), Err(Error::MalformedDso));
        // Padding as primary, or not last.
        let mut m = KEEPALIVE_REQUEST[..12].to_vec();
        m.extend_from_slice(&[0, 3, 0, 1, 0]);
        assert_eq!(
            DsoMessage::parse_validated(&m).err(),
            Some(Error::MalformedDso)
        );
        let mut m = KEEPALIVE_REQUEST.to_vec();
        m.extend_from_slice(&[0, 3, 0, 0, 0, 2, 0, 4, 0, 0, 0, 1]);
        assert_eq!(
            DsoMessage::parse_validated(&m).err(),
            Some(Error::MalformedDso)
        );
        // A request with no TLV.
        assert_eq!(
            DsoMessage::parse_validated(&KEEPALIVE_REQUEST[..12]).err(),
            Some(Error::MalformedDso)
        );
        // Every truncation fails cleanly.
        for end in 0..KEEPALIVE_REQUEST.len() {
            let cut = &KEEPALIVE_REQUEST[..end];
            if let Ok(m) = DsoMessage::parse(cut) {
                assert!(m.validate().is_err());
                let _ = m.additional().count();
                let _ = m.primary();
            }
        }
        // Unknown types iterate as raw TLVs.
        let mut m = KEEPALIVE_REQUEST.to_vec();
        m.extend_from_slice(&[0xf8, 0x00, 0, 2, 0xab, 0xcd]);
        let msg = DsoMessage::parse_validated(&m).unwrap();
        let t = msg.additional().next().unwrap().unwrap();
        assert!(t.dso_type.is_experimental());
        assert_eq!(t.data, &[0xab, 0xcd]);
        assert_eq!(t.dso_type.to_string(), "DSOTYPE63488");
        // Re-emit a raw TLV.
        let mut buf = [0u8; 64];
        let mut b = DsoBuilder::request(WireWriter::new(&mut buf), 1).unwrap();
        b.push(&msg.primary().unwrap().unwrap()).unwrap();
        b.push(&t).unwrap();
        assert_eq!(b.finish().unwrap(), &m[..]);
    }

    #[test]
    fn limits_and_atomicity() {
        let mut buf = [0u8; 30];
        let mut b = DsoBuilder::request(WireWriter::new(&mut buf), 1).unwrap();
        b.push(&RetryDelay { delay: 1 }).unwrap();
        let before = b.as_bytes().to_vec();
        assert_eq!(
            b.push(&Keepalive {
                inactivity_timeout: 0,
                keepalive_interval: 0
            }),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(b.as_bytes(), &before[..]);
        b.set_limit(24);
        assert_eq!(b.push(&RetryDelay { delay: 2 }), Err(Error::BufferTooSmall));
        assert_eq!(b.as_bytes(), &before[..]);
        assert!(DsoBuilder::request(WireWriter::new(&mut [0u8; 11]), 1).is_err());
        assert_eq!(
            std::format!("{b:?}"),
            "DsoBuilder { len: 20, tlvs: 1, padded: false }"
        );
    }

    #[test]
    fn registry() {
        assert_eq!(DsoType::KEEPALIVE.to_string(), "KeepAlive");
        assert_eq!("retrydelay".parse(), Ok(DsoType::RETRY_DELAY));
        assert_eq!("DSOTYPE64".parse(), Ok(DsoType::SUBSCRIBE));
        assert!(!DsoType::PUSH.is_experimental());
    }
}
