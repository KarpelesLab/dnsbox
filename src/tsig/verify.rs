//! Locating and verifying TSIG records (RFC 8945 §5.2, §5.3.1, §5.4).

use core::fmt;

use super::input::{TsigVariables, feed_message, feed_prior_mac};
use super::key::{KeyStore, MAX_MAC_LEN, MacBuf, TsigKey, TsigMac};
use super::sign::TsigSigner;
use crate::builder::MessageBuilder;
use crate::message::{Message, Section};
use crate::name::Name;
use crate::rdata::{Tsig, TsigRcode};
use crate::wire::OutBuf;
use crate::{Class, Error, Rcode, Result, Rtype};

/// The most messages a TSIG stream may leave unsigned in a row (RFC 8945
/// §5.3.1: every 100th message at least must be signed).
pub const MAX_UNSIGNED: usize = 99;

/// A TSIG record found in a message by [`find`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TsigRecord<'a> {
    /// The key name (the record's owner name).
    pub key_name: Name<'a>,
    /// The record data.
    pub data: Tsig<'a>,
    /// Offset of the record in the message: the MAC covers the bytes
    /// before it.
    pub start: usize,
}

impl<'a> TsigRecord<'a> {
    /// The TSIG variables of this record (RFC 8945 §4.3.3).
    #[inline]
    pub const fn variables(&self) -> TsigVariables<'a> {
        TsigVariables::from_record(self.key_name, &self.data)
    }

    /// The MAC carried by the record.
    #[inline]
    pub const fn mac(&self) -> &'a [u8] {
        self.data.mac
    }

    /// Checks that `now` lies within Time Signed ± Fudge (RFC 8945
    /// §5.2.3); fails with [`Error::BadTime`] otherwise.
    pub const fn check_time(&self, now: u64) -> Result<()> {
        if now.abs_diff(self.data.time_signed) > self.data.fudge as u64 {
            Err(Error::BadTime)
        } else {
            Ok(())
        }
    }

    /// Feeds the MAC input of the message `msg` this record belongs to
    /// (RFC 8945 §4.3): the prior MAC if any (responses, streams), the
    /// message without its TSIG and with the original ID, then either all
    /// TSIG variables or, for the later messages of a stream
    /// (`timers_only`), just Time Signed and Fudge (§5.3.1).
    pub fn feed_mac_input(
        &self,
        msg: &[u8],
        prior_mac: Option<&[u8]>,
        timers_only: bool,
        f: &mut impl FnMut(&[u8]),
    ) -> Result<()> {
        if let Some(prior) = prior_mac {
            feed_prior_mac(prior, f);
        }
        feed_message(msg, Some(self.start), self.data.original_id, f)?;
        if timers_only {
            self.variables().feed_timers(f);
        } else {
            self.variables().feed(f);
        }
        Ok(())
    }
}

/// Locates the TSIG record of a message.
///
/// Returns `Ok(None)` if there is none. A TSIG anywhere but as the last
/// record of the additional section, or more than one TSIG, yields
/// [`Error::MisplacedSignature`] (RFC 8945 §5.1: the message is answered
/// with FORMERR); a TSIG whose CLASS is not ANY or TTL not 0 (§4.2)
/// yields [`Error::InvalidRdata`]. Walks every record once.
pub fn find<'a>(msg: &Message<'a>) -> Result<Option<TsigRecord<'a>>> {
    let arcount = msg.header().arcount;
    let mut additional = 0u16;
    let mut found = None;
    for item in msg.records() {
        let (section, rr) = item?;
        if section == Section::Additional {
            additional = additional.saturating_add(1);
        }
        if rr.rtype() != Rtype::TSIG {
            continue;
        }
        if section != Section::Additional || additional != arcount {
            return Err(Error::MisplacedSignature);
        }
        if rr.class() != Class::ANY || rr.ttl() != 0 {
            return Err(Error::InvalidRdata);
        }
        found = Some(TsigRecord {
            key_name: rr.name(),
            data: rr.data_as::<Tsig<'a>>()?,
            start: rr.start(),
        });
    }
    Ok(found)
}

/// Checks a received MAC size against the MAC function's output length
/// (RFC 8945 §5.2.2.1): it must be at most `digest_len` (and
/// [`MAX_MAC_LEN`]) and at least the larger of 10 octets and half of
/// `digest_len`. Fails with [`Error::BadMacSize`] (FORMERR) otherwise.
pub const fn check_mac_size(mac_len: usize, digest_len: usize) -> Result<()> {
    let floor = if digest_len / 2 > 10 {
        digest_len / 2
    } else {
        10
    };
    if mac_len > digest_len || mac_len > MAX_MAC_LEN || mac_len < floor {
        Err(Error::BadMacSize)
    } else {
        Ok(())
    }
}

/// Verifies a MAC with a fresh computation; `prior` and `timers_only` as
/// in [`TsigRecord::feed_mac_input`].
fn verify_mac<K: TsigKey>(
    mut mac: K::Mac,
    record: &TsigRecord<'_>,
    msg: &[u8],
    prior: Option<&[u8]>,
    timers_only: bool,
) -> Result<()> {
    record.feed_mac_input(msg, prior, timers_only, &mut |d| mac.update(d))?;
    if mac.verify(record.data.mac) {
        Ok(())
    } else {
        Err(Error::BadSig)
    }
}

/// A request whose TSIG verified; see [`verify_request`].
pub struct Verified<'a, 'k, K: TsigKey> {
    /// The key that signed it.
    pub key: &'k K,
    /// Its TSIG record.
    pub record: TsigRecord<'a>,
}

impl<'a, 'k, K: TsigKey> Verified<'a, 'k, K> {
    /// The request MAC, which the response MAC covers.
    #[inline]
    pub const fn request_mac(&self) -> &'a [u8] {
        self.record.data.mac
    }

    /// A signer for the response (or response stream) to this request.
    pub fn signer(&self) -> TsigSigner<'k, K> {
        // The MAC size was checked against MAX_MAC_LEN, so this cannot
        // fail; fall back to a request signer rather than panicking.
        TsigSigner::response(self.key, self.request_mac())
            .unwrap_or_else(|_| TsigSigner::request(self.key))
    }
}

impl<K: TsigKey> Clone for Verified<'_, '_, K> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<K: TsigKey> Copy for Verified<'_, '_, K> {}

impl<K: TsigKey> fmt::Debug for Verified<'_, '_, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verified")
            .field("record", &self.record)
            .finish_non_exhaustive()
    }
}

/// A request that failed TSIG processing; see [`verify_request`]. It knows
/// how the server must answer (RFC 8945 §5.2, §5.3.2).
pub struct Rejected<'a, 'k, K: TsigKey> {
    /// Why: [`Error::MisplacedSignature`], [`Error::BadMacSize`] or any
    /// parse error (FORMERR), or [`Error::BadKey`], [`Error::BadSig`],
    /// [`Error::BadTime`], [`Error::BadTrunc`] (NOTAUTH).
    pub error: Error,
    /// The TSIG record, if one could be located.
    pub record: Option<TsigRecord<'a>>,
    /// The key, if it was found.
    pub key: Option<&'k K>,
}

impl<K: TsigKey> Rejected<'_, '_, K> {
    /// The RCODE of the error response (FORMERR or NOTAUTH).
    pub const fn rcode(&self) -> Rcode {
        super::response_codes(self.error).0
    }

    /// The TSIG error of the error response.
    pub const fn tsig_error(&self) -> TsigRcode {
        super::response_codes(self.error).1
    }

    /// Appends the TSIG record of the error response to `b`, as RFC 8945
    /// requires (set the header RCODE to [`rcode`](Self::rcode) yourself):
    ///
    /// - BADKEY, BADSIG: an *unsigned* TSIG (MAC size 0) echoing the
    ///   request's key, algorithm, Time Signed and Fudge (§5.3.2);
    /// - BADTIME: signed with the request MAC, Time Signed copied from the
    ///   request and the server time `now` in Other Data (§5.2.3);
    /// - BADTRUNC: signed with the request MAC at time `now` (§5.2.4);
    /// - FORMERR: no TSIG at all.
    pub fn sign_response<B: OutBuf>(&self, b: &mut MessageBuilder<B>, now: u64) -> Result<()> {
        let Some(record) = self.record else {
            return Ok(());
        };
        let error = self.tsig_error();
        match (error, self.key) {
            (TsigRcode::BADTIME, Some(key)) => {
                let t = now.to_be_bytes();
                let other = t.get(2..).unwrap_or(&[]);
                TsigSigner::response(key, record.data.mac)?
                    .with_fudge(record.data.fudge)
                    .sign_with(b, record.data.time_signed, error, other)
                    .map(|_| ())
            }
            (TsigRcode::BADTRUNC, Some(key)) => TsigSigner::response(key, record.data.mac)?
                .with_fudge(record.data.fudge)
                .sign_with(b, now, error, &[])
                .map(|_| ()),
            (TsigRcode::NOERROR, _) => Ok(()),
            _ => {
                let tsig = Tsig {
                    mac: &[],
                    error,
                    other: &[],
                    ..record.data
                };
                let compression = b.compression();
                b.set_compression(false);
                let res = b.push_additional(record.key_name, Class::ANY, 0, &tsig);
                b.set_compression(compression);
                res
            }
        }
    }
}

impl<K: TsigKey> Clone for Rejected<'_, '_, K> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<K: TsigKey> Copy for Rejected<'_, '_, K> {}

impl<K: TsigKey> fmt::Debug for Rejected<'_, '_, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rejected")
            .field("error", &self.error)
            .field("record", &self.record)
            .field("key", &self.key.map(|k| k.name()))
            .finish()
    }
}

/// The outcome of [`verify_request`].
pub enum RequestStatus<'a, 'k, K: TsigKey> {
    /// The request carries no TSIG.
    Unsigned,
    /// The TSIG verified.
    Verified(Verified<'a, 'k, K>),
    /// TSIG processing failed; answer as the [`Rejected`] value says.
    Rejected(Rejected<'a, 'k, K>),
}

impl<'a, 'k, K: TsigKey> RequestStatus<'a, 'k, K> {
    /// The verified request, if the TSIG verified.
    pub fn verified(self) -> Option<Verified<'a, 'k, K>> {
        match self {
            RequestStatus::Verified(v) => Some(v),
            _ => None,
        }
    }

    /// The rejection, if TSIG processing failed.
    pub fn rejected(self) -> Option<Rejected<'a, 'k, K>> {
        match self {
            RequestStatus::Rejected(r) => Some(r),
            _ => None,
        }
    }

    /// The error, if TSIG processing failed.
    pub fn error(&self) -> Option<Error> {
        match self {
            RequestStatus::Rejected(r) => Some(r.error),
            _ => None,
        }
    }
}

impl<K: TsigKey> Clone for RequestStatus<'_, '_, K> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<K: TsigKey> Copy for RequestStatus<'_, '_, K> {}

impl<K: TsigKey> fmt::Debug for RequestStatus<'_, '_, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RequestStatus::Unsigned => f.write_str("Unsigned"),
            RequestStatus::Verified(v) => f.debug_tuple("Verified").field(v).finish(),
            RequestStatus::Rejected(r) => f.debug_tuple("Rejected").field(r).finish(),
        }
    }
}

/// Server-side TSIG processing of a request (RFC 8945 §5.2).
///
/// Returns [`RequestStatus::Unsigned`] for a request without TSIG,
/// [`RequestStatus::Verified`] when the TSIG verifies, and
/// [`RequestStatus::Rejected`] otherwise. Checks, in the RFC's order:
/// placement (§5.1, FORMERR), key and algorithm (§5.2.1, BADKEY), MAC
/// size (§5.2.2.1, FORMERR), MAC (§5.2.2, BADSIG), time (§5.2.3, BADTIME;
/// `now` is the server's clock in seconds since the epoch), and truncation
/// policy (§5.2.4, BADTRUNC: the MAC is shorter than the key's
/// [`mac_len`](TsigKey::mac_len)).
///
/// Replay protection beyond the time window (rejecting a Time Signed
/// older than the last one seen for the key, §5.2.3 "SHOULD") is left to
/// the caller, which has the state: compare `verified.record.data.time_signed`.
pub fn verify_request<'a, 'k, S: KeyStore + ?Sized>(
    msg: &Message<'a>,
    keys: &'k S,
    now: u64,
) -> RequestStatus<'a, 'k, S::Key> {
    let record = match find(msg) {
        Ok(Some(record)) => record,
        Ok(None) => return RequestStatus::Unsigned,
        Err(error) => {
            return RequestStatus::Rejected(Rejected {
                error,
                record: None,
                key: None,
            });
        }
    };
    let Some(key) = keys.find_key(record.key_name, record.data.algorithm) else {
        return RequestStatus::Rejected(Rejected {
            error: Error::BadKey,
            record: Some(record),
            key: None,
        });
    };
    let check = || -> Result<()> {
        check_mac_size(record.data.mac.len(), key.digest_len())?;
        verify_mac::<S::Key>(key.new_mac(), &record, msg.as_bytes(), None, false)?;
        record.check_time(now)?;
        if record.data.mac.len() < key.mac_len() {
            return Err(Error::BadTrunc);
        }
        Ok(())
    };
    match check() {
        Ok(()) => RequestStatus::Verified(Verified { key, record }),
        Err(error) => RequestStatus::Rejected(Rejected {
            error,
            record: Some(record),
            key: Some(key),
        }),
    }
}

/// Client-side verification of a TSIG-signed response or response stream
/// (RFC 8945 §5.3.1, §5.4).
///
/// Create it with the MAC of the request (returned by
/// [`TsigSigner::sign`]), feed it every message of the response in order
/// with [`verify`](Self::verify), then call [`finish`](Self::finish) once
/// the stream is complete.
///
/// After an error the transaction must be abandoned: the verifier's chain
/// state is no longer meaningful.
pub struct TsigVerifier<'k, K: TsigKey> {
    key: &'k K,
    prior: MacBuf,
    first: bool,
    pending: Option<K::Mac>,
    unsigned: usize,
}

impl<'k, K: TsigKey> TsigVerifier<'k, K> {
    /// A verifier for the response to a request signed with `key` whose MAC
    /// was `request_mac`.
    pub fn new(key: &'k K, request_mac: &[u8]) -> Result<Self> {
        Ok(TsigVerifier {
            key,
            prior: MacBuf::new(request_mac)?,
            first: true,
            pending: None,
            unsigned: 0,
        })
    }

    /// Verifies the next message of the response.
    ///
    /// Returns `Ok(Some(record))` for a correctly signed message and
    /// `Ok(None)` for an unsigned message in the middle of a stream (at
    /// most 99 in a row, never the first; RFC 8945 §5.3.1). Errors:
    ///
    /// - [`Error::Unsigned`]: no TSIG where one is required;
    /// - [`Error::BadKey`]: signed with another key or algorithm;
    /// - [`Error::TsigErrorResponse`]: an unsigned TSIG error response
    ///   (BADKEY/BADSIG from the server, which cannot be authenticated);
    /// - [`Error::BadMacSize`] / [`Error::BadSig`]: the MAC is invalid;
    /// - [`Error::BadTime`], [`Error::BadTrunc`], [`Error::BadSig`],
    ///   [`Error::BadKey`]: an authenticated response carrying that TSIG
    ///   error (for BADTIME, the server's clock is in the record's other
    ///   data; use [`find`] to read it), or a local time / truncation
    ///   check failure (`now` is the client's clock).
    pub fn verify<'a>(&mut self, msg: &Message<'a>, now: u64) -> Result<Option<TsigRecord<'a>>> {
        let Some(record) = find(msg)? else {
            if self.first || self.unsigned >= MAX_UNSIGNED {
                return Err(Error::Unsigned);
            }
            let mut mac = self.take_pending();
            mac.update(msg.as_bytes());
            self.pending = Some(mac);
            self.unsigned += 1;
            return Ok(None);
        };
        if record.key_name != self.key.name() || record.data.algorithm != self.key.algorithm() {
            return Err(Error::BadKey);
        }
        if record.data.mac.is_empty() && record.data.error != TsigRcode::NOERROR {
            return Err(Error::TsigErrorResponse);
        }
        check_mac_size(record.data.mac.len(), self.key.digest_len())?;
        let mac = self.take_pending();
        let timers_only = !self.first;
        verify_mac::<K>(mac, &record, msg.as_bytes(), None, timers_only)?;
        self.prior = MacBuf::new(record.data.mac)?;
        self.first = false;
        self.unsigned = 0;
        match record.data.error {
            TsigRcode::NOERROR => {}
            TsigRcode::BADTIME => return Err(Error::BadTime),
            TsigRcode::BADTRUNC => return Err(Error::BadTrunc),
            TsigRcode::BADSIG => return Err(Error::BadSig),
            TsigRcode::BADKEY => return Err(Error::BadKey),
            _ => return Err(Error::TsigErrorResponse),
        }
        record.check_time(now)?;
        if record.data.mac.len() < self.key.mac_len() {
            return Err(Error::BadTrunc);
        }
        Ok(Some(record))
    }

    /// Checks that the stream ended with a signed message (RFC 8945
    /// §5.3.1); fails with [`Error::Unsigned`] otherwise.
    pub fn finish(&self) -> Result<()> {
        if self.first || self.unsigned > 0 {
            Err(Error::Unsigned)
        } else {
            Ok(())
        }
    }

    /// The MAC of the last verified message (initially the request MAC).
    #[inline]
    pub fn last_mac(&self) -> &[u8] {
        self.prior.as_slice()
    }

    /// A MAC computation primed with the prior MAC (or the pending one
    /// that already covers unsigned messages).
    fn take_pending(&mut self) -> K::Mac {
        match self.pending.take() {
            Some(mac) => mac,
            None => {
                let mut mac = self.key.new_mac();
                feed_prior_mac(self.prior.as_slice(), &mut |d| mac.update(d));
                mac
            }
        }
    }
}

impl<K: TsigKey> fmt::Debug for TsigVerifier<'_, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TsigVerifier")
            .field("key", &self.key.name())
            .field("first", &self.first)
            .field("unsigned", &self.unsigned)
            .finish_non_exhaustive()
    }
}
