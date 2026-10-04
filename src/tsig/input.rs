//! MAC input construction (RFC 8945 §4.3). Pure byte-stream logic: every
//! function feeds the digest components to a sink closure, so they work
//! with any MAC backend (or with a buffer, for inspection).

use crate::name::{MAX_NAME_LEN, Name};
use crate::rdata::{Tsig, TsigRcode};
use crate::{Class, Error, Header, Result};

/// The TSIG variables covered by the MAC (RFC 8945 §4.3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TsigVariables<'a> {
    /// The key name (TSIG owner name).
    pub key_name: Name<'a>,
    /// The algorithm name.
    pub algorithm: Name<'a>,
    /// Time Signed (48 bits).
    pub time_signed: u64,
    /// Fudge.
    pub fudge: u16,
    /// TSIG error.
    pub error: TsigRcode,
    /// Other data.
    pub other: &'a [u8],
}

/// Feeds a name in canonical form: uncompressed and lowercase (RFC 8945
/// §4.3.3, RFC 4034 §6.2).
fn feed_canonical_name(name: Name<'_>, f: &mut impl FnMut(&[u8])) {
    let mut buf = [0u8; MAX_NAME_LEN];
    let len = name.flatten(&mut buf);
    if let Some(bytes) = buf.get_mut(..len) {
        bytes.make_ascii_lowercase();
        f(bytes);
    }
}

impl<'a> TsigVariables<'a> {
    /// The variables of a received TSIG record owned by `key_name`.
    #[must_use]
    pub const fn from_record(key_name: Name<'a>, tsig: &Tsig<'a>) -> Self {
        TsigVariables {
            key_name,
            algorithm: tsig.algorithm,
            time_signed: tsig.time_signed,
            fudge: tsig.fudge,
            error: tsig.error,
            other: tsig.other,
        }
    }

    /// Feeds the full variables (RFC 8945 §4.3.3): key name and algorithm
    /// in canonical form, CLASS ANY, TTL 0, Time Signed, Fudge, Error,
    /// Other Len and Other Data.
    pub fn feed(&self, f: &mut impl FnMut(&[u8])) {
        feed_canonical_name(self.key_name, f);
        f(&Class::ANY.get().to_be_bytes());
        f(&0u32.to_be_bytes());
        feed_canonical_name(self.algorithm, f);
        self.feed_timers(f);
        f(&self.error.get().to_be_bytes());
        // Other data longer than 65535 bytes cannot be in a record; it is
        // rejected when the record is written.
        f(&(self.other.len() as u16).to_be_bytes());
        f(self.other);
    }

    /// Feeds only the timers, Time Signed and Fudge: what the MAC of the
    /// second and later messages of a TCP stream covers (RFC 8945 §5.3.1).
    pub fn feed_timers(&self, f: &mut impl FnMut(&[u8])) {
        let t = self.time_signed.to_be_bytes();
        f(t.get(2..).unwrap_or(&[]));
        f(&self.fudge.to_be_bytes());
    }
}

/// Feeds a prior MAC (the request MAC of a response, or the previous MAC of
/// a stream) as covered by the next MAC: a 2-byte length then the MAC as it
/// was sent, truncated or not (RFC 8945 §4.3.1, §5.2.2.1).
pub fn feed_prior_mac(mac: &[u8], f: &mut impl FnMut(&[u8])) {
    f(&(mac.len() as u16).to_be_bytes());
    f(mac);
}

/// Feeds a DNS message as covered by a TSIG MAC (RFC 8945 §4.3.1–4.3.2).
///
/// `msg` is the whole message. If `tsig_start` is `Some(offset)`, the
/// message carries a TSIG record starting at `offset` (the last record):
/// only the bytes before it are fed, and ARCOUNT is decremented as if the
/// TSIG had not been added. In both cases the header's ID is replaced by
/// `original_id` (RFC 8945 §4.3.1: forwarded messages may have a new ID).
///
/// Fails with [`Error::UnexpectedEof`] if the message is shorter than its
/// header or `tsig_start` is out of range.
pub fn feed_message(
    msg: &[u8],
    tsig_start: Option<usize>,
    original_id: u16,
    f: &mut impl FnMut(&[u8]),
) -> Result<()> {
    let mut header = Header::parse(msg)?;
    let end = match tsig_start {
        Some(end) => {
            header.arcount = header.arcount.checked_sub(1).ok_or(Error::UnexpectedEof)?;
            end
        }
        None => msg.len(),
    };
    let body = msg.get(Header::LEN..end).ok_or(Error::UnexpectedEof)?;
    header.id = original_id;
    f(&header.to_bytes());
    f(body);
    Ok(())
}
