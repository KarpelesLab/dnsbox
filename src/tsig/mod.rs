//! Transaction signatures: TSIG (RFC 8945).
//!
//! TSIG authenticates a DNS transaction with a shared secret: the sender
//! appends a TSIG record holding a MAC over the message (and, in
//! responses, over the request's MAC) as the very last record of the
//! additional section.
//!
//! This module is split along the crypto boundary:
//!
//! - **Wire format and MAC input construction** (always available, no
//!   crypto): the [`Tsig`] record data, [`TsigVariables`] and the
//!   `feed_*` helpers that produce the exact byte stream of RFC 8945 §4.3,
//!   [`find`] (locating the TSIG and enforcing its placement, §5.1), the
//!   MAC-size/truncation rules (§5.2.2.1) and the time check (§5.2.3).
//! - **The MAC itself** is pluggable through the [`TsigKey`] / [`TsigMac`]
//!   traits. With the `tsig` feature, [`HmacKey`] implements them on top
//!   of the `purecrypto` crate for every HMAC algorithm of RFC 8945 §6;
//!   dnsbox never implements a hash or HMAC itself.
//!
//! On top of that:
//!
//! - [`TsigSigner`] signs a request, a response, or a multi-message TCP
//!   response stream (§5.3.1: after the first message, MACs cover the
//!   prior MAC, every message since, and only the timers; up to 99
//!   messages may be left unsigned in between);
//! - [`verify_request`] is the server side: it returns the
//!   [`RequestStatus`]: unsigned, the [`Verified`] request (whose [`signer`](Verified::signer) signs the
//!   response) or a [`Rejected`] request that knows which RCODE / TSIG
//!   error to answer with and how to sign that answer (§5.2, §5.3.2);
//! - [`TsigVerifier`] is the client side, for single responses and
//!   zone-transfer streams (§5.3.1, §5.4).
//!
//! Time is always passed in by the caller (seconds since the UNIX epoch):
//! the crate is `no_std` and has no clock.
//!
//! ```
//! # #[cfg(feature = "tsig")] {
//! use dnsbox::{Class, Flags, Message, MessageBuilder, Rtype, NameBuf};
//! use dnsbox::tsig::{self, HmacKey, TsigAlgorithm, TsigSigner, TsigVerifier};
//!
//! let key_name: NameBuf = "tsig-key".parse()?;
//! let key = HmacKey::new(&key_name, TsigAlgorithm::HmacSha256, b"0123456789abcdef");
//! let now = 1_700_000_000;
//!
//! // Client: sign a query and keep its MAC.
//! let zone: NameBuf = "example.com".parse()?;
//! let mut buf = [0u8; 512];
//! let mut b = MessageBuilder::new(&mut buf)?;
//! b.set_id(42);
//! b.push_question(&zone, Rtype::SOA, Class::IN)?;
//! let request_mac = TsigSigner::request(&key).sign(&mut b, now)?;
//! let query = b.finish();
//!
//! // Server: verify it, then sign the response with the request MAC.
//! let msg = Message::parse(query)?;
//! let verified = tsig::verify_request(&msg, &key, now).verified().expect("valid");
//! let mut buf2 = [0u8; 512];
//! let mut r = MessageBuilder::new(&mut buf2)?;
//! r.set_id(42);
//! r.set_flags(Flags::default().with_qr(true));
//! r.push_question(&zone, Rtype::SOA, Class::IN)?;
//! verified.signer().sign(&mut r, now)?;
//! let response = r.finish();
//!
//! // Client: verify the response against the request MAC.
//! let mut v = TsigVerifier::new(&key, request_mac.as_slice())?;
//! assert!(v.verify(&Message::parse(response)?, now)?.is_some());
//! v.finish()?;
//! # }
//! # Ok::<(), dnsbox::Error>(())
//! ```

mod algorithm;
#[cfg(feature = "tsig")]
mod hmac;
mod input;
mod key;
mod sign;
mod verify;

pub use self::algorithm::TsigAlgorithm;
#[cfg(feature = "tsig")]
#[cfg_attr(docsrs, doc(cfg(feature = "tsig")))]
pub use self::hmac::{HmacKey, HmacState};
pub use self::input::{TsigVariables, feed_message, feed_prior_mac};
pub use self::key::{KeyStore, MAX_MAC_LEN, MacBuf, TsigKey, TsigMac};
pub use self::sign::{DEFAULT_FUDGE, TsigSigner, record_len};
pub use self::verify::{
    MAX_UNSIGNED, Rejected, RequestStatus, TsigRecord, TsigVerifier, Verified, check_mac_size,
    find, verify_request,
};
pub use crate::rdata::{Tsig, TsigRcode};

use crate::{Error, Rcode};

/// The response RCODE and TSIG error a server answers with when a request
/// fails TSIG processing with `error` (RFC 8945 §5.2).
///
/// | error | RCODE | TSIG error |
/// |---|---|---|
/// | [`Error::BadKey`] | NOTAUTH | BADKEY |
/// | [`Error::BadSig`] | NOTAUTH | BADSIG |
/// | [`Error::BadTime`] | NOTAUTH | BADTIME |
/// | [`Error::BadTrunc`] | NOTAUTH | BADTRUNC |
/// | anything else ([`Error::MisplacedSignature`], [`Error::BadMacSize`], parse errors) | FORMERR | NOERROR |
pub const fn response_codes(error: Error) -> (Rcode, TsigRcode) {
    match error {
        Error::BadKey => (Rcode::NOTAUTH, TsigRcode::BADKEY),
        Error::BadSig => (Rcode::NOTAUTH, TsigRcode::BADSIG),
        Error::BadTime => (Rcode::NOTAUTH, TsigRcode::BADTIME),
        Error::BadTrunc => (Rcode::NOTAUTH, TsigRcode::BADTRUNC),
        _ => (Rcode::FORMERR, TsigRcode::NOERROR),
    }
}

#[cfg(test)]
mod tests;
