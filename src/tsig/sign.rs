//! Generating TSIG records (RFC 8945 §5.1, §5.3).

use core::fmt;

use super::input::{TsigVariables, feed_message, feed_prior_mac};
use super::key::{MAX_MAC_LEN, MacBuf, TsigKey, TsigMac};
use super::verify::{MAX_UNSIGNED, check_mac_size};
use crate::builder::{MAX_MESSAGE_LEN, MessageBuilder};
use crate::name::Name;
use crate::rdata::{MAX_TIME_SIGNED, Tsig, TsigRcode};
use crate::wire::{Composer, NameEncoding, OutBuf};
use crate::{Class, Error, Header, Result, Rtype};

/// The fudge dnsbox signs with unless told otherwise: 300 seconds, as
/// recommended by RFC 8945 §10.
pub const DEFAULT_FUDGE: u16 = 300;

/// Size of a TSIG record on the wire, with an uncompressed owner name:
/// useful to reserve room for the signature (e.g. lower the builder
/// [limit](MessageBuilder::set_limit) by this much while filling a
/// response, then raise it back before signing).
pub fn record_len(
    key_name: Name<'_>,
    algorithm: Name<'_>,
    mac_len: usize,
    other_len: usize,
) -> usize {
    // Owner, TYPE/CLASS/TTL/RDLENGTH, then the RDATA: algorithm, Time
    // Signed (6), Fudge, MAC Size, MAC, Original ID, Error, Other Len,
    // Other Data.
    key_name.wire_len() + 10 + algorithm.wire_len() + 16 + mac_len + other_len
}

/// Signs DNS messages with TSIG (RFC 8945 §5.1, §5.3).
///
/// One signer covers one transaction:
///
/// - a **request**: [`TsigSigner::request`], then [`sign`](Self::sign)
///   once; keep the returned MAC to verify the response;
/// - a **response** or a **response stream** (AXFR/IXFR over TCP):
///   [`TsigSigner::response`] with the request MAC (or
///   [`Verified::signer`](super::Verified::signer)), then
///   [`sign`](Self::sign) every message. The first MAC covers the request
///   MAC, the message and all TSIG variables; each later one covers the
///   previous MAC, the messages since, and only the timers (RFC 8945
///   §5.3.1). Messages may be left unsigned with [`skip`](Self::skip), at
///   most 99 in a row; the last message of a stream must be signed.
///
/// The TSIG record is appended as the last record of the additional
/// section, with an uncompressed owner name; nothing may be added to the
/// message afterwards. Signing either succeeds or leaves both the message
/// and the signer unchanged.
pub struct TsigSigner<'k, K: TsigKey> {
    key: &'k K,
    /// The request MAC (responses) or the previous MAC (streams).
    prior: Option<MacBuf>,
    /// Whether the next signed message is the first one (full variables).
    first: bool,
    /// MAC already fed with unsigned stream messages.
    pending: Option<K::Mac>,
    unsigned: usize,
    fudge: u16,
}

impl<'k, K: TsigKey> TsigSigner<'k, K> {
    /// A signer for a request (no prior MAC).
    pub fn request(key: &'k K) -> Self {
        TsigSigner {
            key,
            prior: None,
            first: true,
            pending: None,
            unsigned: 0,
            fudge: DEFAULT_FUDGE,
        }
    }

    /// A signer for the response(s) to a request whose MAC was
    /// `request_mac` (as received: truncated MACs stay truncated, RFC 8945
    /// §5.2.2.1). Fails with [`Error::BadMacSize`] beyond
    /// [`MAX_MAC_LEN`] bytes.
    pub fn response(key: &'k K, request_mac: &[u8]) -> Result<Self> {
        Ok(TsigSigner {
            prior: Some(MacBuf::new(request_mac)?),
            ..Self::request(key)
        })
    }

    /// Sets the fudge (permitted clock skew, seconds) of the TSIG records
    /// written from now on.
    #[must_use]
    pub fn with_fudge(mut self, fudge: u16) -> Self {
        self.fudge = fudge;
        self
    }

    /// The key.
    #[inline]
    pub fn key(&self) -> &'k K {
        self.key
    }

    /// The MAC of the last signed message (or the request MAC of a
    /// response signer that has not signed yet).
    pub fn last_mac(&self) -> Option<&[u8]> {
        self.prior.as_ref().map(MacBuf::as_slice)
    }

    /// Signs the message in `b` at time `now` (seconds since the epoch) and
    /// appends the TSIG record. Returns the MAC.
    pub fn sign<B: OutBuf>(&mut self, b: &mut MessageBuilder<B>, now: u64) -> Result<MacBuf> {
        self.sign_with(b, now, TsigRcode::NOERROR, &[])
    }

    /// Like [`sign`](Self::sign), with an explicit TSIG error and other
    /// data (e.g. BADTIME responses carry the server time, RFC 8945 §5.2.3)
    /// and `time_signed` instead of the current time.
    pub fn sign_with<B: OutBuf>(
        &mut self,
        b: &mut MessageBuilder<B>,
        time_signed: u64,
        error: TsigRcode,
        other: &[u8],
    ) -> Result<MacBuf> {
        let rr_len = self.check(time_signed, other)?;
        if b.len() + rr_len > b.limit() {
            return Err(Error::BufferTooSmall);
        }
        if b.header().arcount == u16::MAX {
            return Err(Error::CountOverflow);
        }
        let vars = self.variables(time_signed, error, other);
        let original_id = b.header().id;
        let mac = self.compute(b.as_bytes(), &vars)?;
        let tsig = Tsig {
            algorithm: vars.algorithm,
            time_signed,
            fudge: self.fudge,
            mac: mac.as_slice(),
            original_id,
            error,
            other,
        };
        let compression = b.compression();
        b.set_compression(false);
        let res = b.push_additional(self.key.name(), Class::ANY, 0, &tsig);
        b.set_compression(compression);
        res?;
        self.commit(mac);
        Ok(mac)
    }

    /// Signs a message already written to `buf`, starting at offset `start`
    /// (anything before it, such as a TCP length prefix, is left alone),
    /// appending the TSIG record and incrementing ARCOUNT in place.
    pub fn sign_buf<B: OutBuf>(&mut self, buf: &mut B, start: usize, now: u64) -> Result<MacBuf> {
        let rr_len = self.check(now, &[])?;
        let len = buf.as_bytes().len();
        let msg_len = len.checked_sub(start).ok_or(Error::UnexpectedEof)?;
        if msg_len + rr_len > MAX_MESSAGE_LEN || len + rr_len > buf.capacity_limit() {
            return Err(Error::BufferTooSmall);
        }
        let msg = buf.as_bytes().get(start..).ok_or(Error::UnexpectedEof)?;
        let mut header = Header::parse(msg)?;
        header.arcount = header.arcount.checked_add(1).ok_or(Error::CountOverflow)?;
        let vars = self.variables(now, TsigRcode::NOERROR, &[]);
        let mac = self.compute(msg, &vars)?;
        let tsig = Tsig {
            algorithm: vars.algorithm,
            time_signed: now,
            fudge: self.fudge,
            mac: mac.as_slice(),
            original_id: header.id,
            error: TsigRcode::NOERROR,
            other: &[],
        };
        let res = (|| {
            buf.put_name(self.key.name(), NameEncoding::Plain)?;
            buf.put_u16(Rtype::TSIG.get())?;
            buf.put_u16(Class::ANY.get())?;
            buf.put_u32(0)?;
            buf.put_u16_prefixed(|c| crate::ComposeRdata::compose_rdata(&tsig, c))?;
            buf.patch(start + 10, &header.arcount.to_be_bytes())
        })();
        if let Err(e) = res {
            buf.truncate(len);
            return Err(e);
        }
        self.commit(mac);
        Ok(mac)
    }

    /// Leaves a message of a response stream unsigned, folding it into the
    /// next MAC (RFC 8945 §5.3.1). Fails with [`Error::Unsigned`] before
    /// the first signed message or after 99 unsigned messages in a row.
    pub fn skip(&mut self, msg: &[u8]) -> Result<()> {
        if self.first || self.unsigned >= MAX_UNSIGNED {
            return Err(Error::Unsigned);
        }
        Header::parse(msg)?;
        let mut mac = self.take_pending();
        mac.update(msg);
        self.pending = Some(mac);
        self.unsigned += 1;
        Ok(())
    }

    /// Validates the parameters; returns the TSIG record length.
    fn check(&self, time_signed: u64, other: &[u8]) -> Result<usize> {
        if time_signed > MAX_TIME_SIGNED || other.len() > usize::from(u16::MAX) {
            return Err(Error::InvalidRdata);
        }
        // RFC 8945 §5.2.2.1: never generate a MAC longer than the digest
        // or shorter than the truncation floor.
        let mac_len = self.key.mac_len();
        check_mac_size(mac_len, self.key.digest_len())?;
        Ok(record_len(
            self.key.name(),
            self.key.algorithm(),
            mac_len,
            other.len(),
        ))
    }

    fn variables<'v>(
        &self,
        time_signed: u64,
        error: TsigRcode,
        other: &'v [u8],
    ) -> TsigVariables<'v>
    where
        'k: 'v,
    {
        let key: &'k K = self.key;
        TsigVariables {
            key_name: key.name(),
            algorithm: key.algorithm(),
            time_signed,
            fudge: self.fudge,
            error,
            other,
        }
    }

    fn take_pending(&mut self) -> K::Mac {
        match self.pending.take() {
            Some(mac) => mac,
            None => {
                let mut mac = self.key.new_mac();
                if let Some(prior) = &self.prior {
                    feed_prior_mac(prior.as_slice(), &mut |d| mac.update(d));
                }
                mac
            }
        }
    }

    /// Computes the MAC of `msg` (no TSIG yet). Leaves `self` unchanged
    /// except for consuming a pending MAC, which only happens once the
    /// caller has checked that the record fits.
    fn compute(&mut self, msg: &[u8], vars: &TsigVariables<'_>) -> Result<MacBuf> {
        let original_id = Header::parse(msg)?.id;
        let first = self.first;
        let mut mac = self.take_pending();
        let mut sink = |d: &[u8]| mac.update(d);
        feed_message(msg, None, original_id, &mut sink)?;
        if first {
            vars.feed(&mut sink);
        } else {
            vars.feed_timers(&mut sink);
        }
        let mut out = [0u8; MAX_MAC_LEN];
        let full = mac.finalize(&mut out);
        let len = full.min(self.key.mac_len()).min(MAX_MAC_LEN);
        let res = MacBuf::new(out.get(..len).unwrap_or(&[]));
        out.fill(0);
        res
    }

    fn commit(&mut self, mac: MacBuf) {
        self.prior = Some(mac);
        self.first = false;
        self.unsigned = 0;
    }
}

impl<K: TsigKey> fmt::Debug for TsigSigner<'_, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TsigSigner")
            .field("key", &self.key.name())
            .field("algorithm", &self.key.algorithm())
            .field("first", &self.first)
            .field("unsigned", &self.unsigned)
            .field("fudge", &self.fudge)
            .finish_non_exhaustive()
    }
}
