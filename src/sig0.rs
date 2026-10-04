//! SIG(0) transaction signatures (RFC 2931).
//!
//! A SIG(0) is a SIG record (owner `.`, CLASS ANY, TTL 0, type covered 0)
//! appended as the last record of the additional section, signing the
//! whole message with a public-key algorithm (RFC 2931 §3). This module
//! builds the exact signed data (§3.1):
//!
//! ```text
//! data = SIG RDATA without the signature (signer name canonical)
//!      | the full request, SIG(0) included   (responses only)
//!      | the message without the SIG(0), ARCOUNT as before it was added
//! ```
//!
//! and locates/places the record. The signature itself goes through the
//! small [`Sig0Signer`] / [`Sig0Verifier`] traits, so any crypto backend
//! can be plugged in; dnsbox never implements signature algorithms.
//!
//! The signed data is handed to the backend as a short list of byte
//! slices (no allocation): hash them in order, or concatenate them for
//! algorithms that need the whole message (Ed25519).
//!
//! With the `alloc` feature, [`DnssecSig0Signer`] and [`DnssecSig0Verifier`]
//! adapt any DNSSEC [`Signer`](crate::dnssec::Signer) /
//! [`Verifier`](crate::dnssec::Verifier) — in particular the
//! purecrypto-backed [`SigningKey`] and [`PurecryptoVerifier`] of the
//! `dnssec` feature — to these traits, giving SIG(0) RSA, ECDSA and EdDSA.
//!
//! Validity times are 32-bit seconds since the epoch compared with RFC
//! 1982 serial arithmetic, as in RFC 4034 §3.1.5. RFC 2931 §3.1 suggests a
//! validity window of a few minutes around the signing time.
//!
//! # Examples
//!
//! A dynamic update signed with SIG(0), as `nsupdate -k` sends it:
//!
//! ```
//! # #[cfg(feature = "dnssec")] {
//! use dnsbox::dnssec::{Algorithm, PurecryptoVerifier, SigningKey};
//! use dnsbox::rdata::A;
//! use dnsbox::sig0::{self, DnssecSig0Signer, DnssecSig0Verifier, Validity};
//! use dnsbox::update::UpdateBuilder;
//! use dnsbox::{Class, Message, MessageBuilder, NameBuf};
//!
//! let zone: NameBuf = "example.com".parse()?;
//! let host: NameBuf = "laptop.example.com".parse()?;
//! let key = SigningKey::from_private_bytes(Algorithm::ECDSAP256SHA256, &[0x11; 32])?;
//! let signer = DnssecSig0Signer::new(&key, host.as_name(), 512);
//! let now = 1_800_000_000;
//!
//! let mut buf = [0u8; 512];
//! let mut u = UpdateBuilder::new(MessageBuilder::new(&mut buf)?, &zone, Class::IN)?;
//! u.add(&host, 300, &A::new([192, 0, 2, 44].into()))?;
//! let mut b = u.into_builder();
//! sig0::sign(&mut b, &signer, Validity::around(now, 300), None)?;
//! let update = Message::parse(b.finish())?;
//!
//! // The server looks up the KEY record named by the signature.
//! let record = sig0::find(&update)?.expect("signed");
//! assert_eq!(record.data.signer_name, host.as_name());
//! let verifier = DnssecSig0Verifier::new(PurecryptoVerifier, host.as_name(), signer.key());
//! sig0::verify(&update, &verifier, now + 60, None)?;
//! # }
//! # Ok::<(), dnsbox::Error>(())
//! ```
#![cfg_attr(
    feature = "alloc",
    doc = "
[`DnssecSig0Signer`]: DnssecSig0Signer
[`DnssecSig0Verifier`]: DnssecSig0Verifier"
)]
#![cfg_attr(
    not(feature = "alloc"),
    doc = "
[`DnssecSig0Signer`]: crate#cargo-features
[`DnssecSig0Verifier`]: crate#cargo-features"
)]
#![cfg_attr(
    feature = "dnssec",
    doc = "
[`SigningKey`]: crate::dnssec::SigningKey
[`PurecryptoVerifier`]: crate::dnssec::PurecryptoVerifier"
)]
#![cfg_attr(
    not(feature = "dnssec"),
    doc = "
[`SigningKey`]: crate#cargo-features
[`PurecryptoVerifier`]: crate#cargo-features"
)]

use crate::builder::MessageBuilder;
use crate::dnssec::Algorithm;
use crate::message::{Message, Section};
use crate::name::{MAX_NAME_LEN, Name};
use crate::rdata::Sig;
use crate::wire::{Canonical, OutBuf, WireWriter};
use crate::{Class, Error, Header, Result, Rtype};

/// The largest signature [`sign`] can produce (an RSA-8192 signature).
pub const MAX_SIGNATURE_LEN: usize = 1024;

/// Fixed part of SIG RDATA before the signer name (RFC 2535 §4.1).
const SIG_FIXED_LEN: usize = 18;

/// Produces SIG(0) signatures (RFC 2931 §3).
///
/// [`DnssecSig0Signer`] implements it over any DNSSEC
/// [`Signer`](crate::dnssec::Signer). Implement it directly for keys held
/// elsewhere (an HSM, a signing service), hashing the parts of the signed
/// data in order:
///
/// ```
/// use dnsbox::dnssec::Algorithm;
/// use dnsbox::sig0::Sig0Signer;
/// use dnsbox::{Name, Result};
///
/// struct RemoteKey<'n> {
///     name: Name<'n>,
///     key_tag: u16,
/// }
///
/// impl Sig0Signer for RemoteKey<'_> {
///     fn algorithm(&self) -> Algorithm {
///         Algorithm::ED25519
///     }
///     fn key_tag(&self) -> u16 {
///         self.key_tag
///     }
///     fn signer_name(&self) -> Name<'_> {
///         self.name
///     }
///     fn signature_len(&self) -> usize {
///         64
///     }
///     fn sign(&self, data: &[&[u8]], out: &mut [u8]) -> Result<usize> {
///         let message: Vec<u8> = data.concat(); // Ed25519 signs the whole message
///         let _ = message; // ...send it to the signing service...
///         out[..64].fill(0);
///         Ok(64)
///     }
/// }
/// ```
///
#[cfg_attr(feature = "alloc", doc = "[`DnssecSig0Signer`]: DnssecSig0Signer")]
#[cfg_attr(
    not(feature = "alloc"),
    doc = "[`DnssecSig0Signer`]: crate#cargo-features"
)]
pub trait Sig0Signer {
    /// DNSSEC algorithm (RFC 4034 Appendix A.1, e.g.
    /// [`Algorithm::ED25519`]).
    ///
    /// ```
    /// # #[cfg(feature = "dnssec")] {
    /// use dnsbox::dnssec::{Algorithm, SigningKey};
    /// use dnsbox::sig0::{DnssecSig0Signer, Sig0Signer};
    /// use dnsbox::NameBuf;
    ///
    /// let key = SigningKey::from_private_bytes(Algorithm::ED25519, &[7; 32])?;
    /// let name: NameBuf = "client.example".parse()?;
    /// let signer = DnssecSig0Signer::new(&key, name.as_name(), 512);
    /// assert_eq!(signer.algorithm(), Algorithm::ED25519); // goes into the SIG RDATA
    /// # }
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    fn algorithm(&self) -> Algorithm;

    /// Key tag of the public KEY record (RFC 4034 Appendix B).
    ///
    /// ```
    /// # #[cfg(feature = "dnssec")] {
    /// use dnsbox::dnssec::{Algorithm, SigningKey};
    /// use dnsbox::sig0::{DnssecSig0Signer, Sig0Signer};
    /// use dnsbox::NameBuf;
    ///
    /// let key = SigningKey::from_private_bytes(Algorithm::ED25519, &[7; 32])?;
    /// let name: NameBuf = "client.example".parse()?;
    /// let signer = DnssecSig0Signer::new(&key, name.as_name(), 512);
    /// // The tag of the KEY record the receiver looks the key up with.
    /// assert_eq!(signer.key_tag(), signer.key().key_tag());
    /// # }
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    fn key_tag(&self) -> u16;

    /// Owner name of the public KEY record (the SIG signer name).
    ///
    /// ```
    /// # #[cfg(feature = "dnssec")] {
    /// use dnsbox::dnssec::{Algorithm, SigningKey};
    /// use dnsbox::sig0::{DnssecSig0Signer, Sig0Signer};
    /// use dnsbox::NameBuf;
    ///
    /// let key = SigningKey::from_private_bytes(Algorithm::ED25519, &[7; 32])?;
    /// let name: NameBuf = "client.example".parse()?;
    /// let signer = DnssecSig0Signer::new(&key, name.as_name(), 512);
    /// assert_eq!(signer.signer_name().to_string(), "client.example.");
    /// # }
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    fn signer_name(&self) -> Name<'_>;

    /// Length of the signatures this signer produces, or an upper bound
    /// (used to check the message has room before signing).
    ///
    /// ```
    /// # #[cfg(feature = "dnssec")] {
    /// use dnsbox::dnssec::{Algorithm, SigningKey};
    /// use dnsbox::sig0::{DnssecSig0Signer, Sig0Signer};
    /// use dnsbox::NameBuf;
    ///
    /// let name: NameBuf = "client.example".parse()?;
    /// let ed25519 = SigningKey::from_private_bytes(Algorithm::ED25519, &[7; 32])?;
    /// let p384 = SigningKey::from_private_bytes(Algorithm::ECDSAP384SHA384, &[9; 48])?;
    /// assert_eq!(DnssecSig0Signer::new(&ed25519, name.as_name(), 512).signature_len(), 64);
    /// assert_eq!(DnssecSig0Signer::new(&p384, name.as_name(), 512).signature_len(), 96);
    /// # }
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    fn signature_len(&self) -> usize;

    /// Signs the concatenation of `data` and writes the signature, in its
    /// DNS wire encoding (e.g. `r || s` for ECDSA, RFC 6605 §4), to the
    /// start of `out`, returning its length.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] if `out` is too short, or the backend's
    /// error.
    ///
    /// ```
    /// # #[cfg(feature = "dnssec")] {
    /// use dnsbox::dnssec::{Algorithm, PurecryptoVerifier, SigningKey, Verifier};
    /// use dnsbox::sig0::{DnssecSig0Signer, Sig0Signer};
    /// use dnsbox::NameBuf;
    ///
    /// let key = SigningKey::from_private_bytes(Algorithm::ED25519, &[7; 32])?;
    /// let name: NameBuf = "client.example".parse()?;
    /// let signer = DnssecSig0Signer::new(&key, name.as_name(), 512);
    /// // The parts are signed as one byte string.
    /// let mut sig = [0u8; 64];
    /// let len = signer.sign(&[b"SIG fields", b"", b"header", b"rest"], &mut sig)?;
    /// let public = signer.key();
    /// PurecryptoVerifier.verify(Algorithm::ED25519, public.public_key, b"SIG fieldsheaderrest", &sig[..len])?;
    /// # }
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    fn sign(&self, data: &[&[u8]], out: &mut [u8]) -> Result<usize>;
}

/// Checks SIG(0) signatures (RFC 2931 §3).
///
/// [`DnssecSig0Verifier`] implements it for one KEY record over any DNSSEC
/// [`Verifier`](crate::dnssec::Verifier); a server with many clients looks
/// the key up by name:
///
/// ```
/// use dnsbox::rdata::Sig;
/// use dnsbox::sig0::Sig0Verifier;
/// use dnsbox::{Error, Result};
///
/// struct KeyDirectory;
///
/// impl Sig0Verifier for KeyDirectory {
///     fn verify(&self, sig: &Sig<'_>, data: &[&[u8]]) -> Result<()> {
///         // Look up the KEY record of `sig.signer_name` (with matching
///         // algorithm and key tag), then check `sig.signature` over the
///         // concatenated `data` with it.
///         let _ = (sig, data);
///         Err(Error::BadKey) // unknown key
///     }
/// }
/// ```
///
#[cfg_attr(feature = "alloc", doc = "[`DnssecSig0Verifier`]: DnssecSig0Verifier")]
#[cfg_attr(
    not(feature = "alloc"),
    doc = "[`DnssecSig0Verifier`]: crate#cargo-features"
)]
pub trait Sig0Verifier {
    /// Verifies `sig.signature` over the concatenation of `data`, with the
    /// key identified by `sig.signer_name`, `sig.algorithm` and `sig.key_tag`.
    ///
    /// # Errors
    ///
    /// [`Error::BadKey`] if the key is unknown and
    /// [`Error::BadSignature`] if the signature does not verify.
    ///
    /// ```
    /// # #[cfg(feature = "dnssec")] {
    /// use dnsbox::dnssec::{Algorithm, PurecryptoVerifier, SigningKey};
    /// use dnsbox::sig0::{self, DnssecSig0Signer, DnssecSig0Verifier, Sig0Verifier, SignedData, Validity};
    /// use dnsbox::{Class, Error, Message, MessageBuilder, NameBuf, Rtype};
    ///
    /// let key = SigningKey::from_private_bytes(Algorithm::ED25519, &[7; 32])?;
    /// let name: NameBuf = "client.example".parse()?;
    /// let signer = DnssecSig0Signer::new(&key, name.as_name(), 512);
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::query(&mut buf, 1, &name, Rtype::A, Class::IN)?;
    /// sig0::sign(&mut b, &signer, Validity::around(1_800_000_000, 300), None)?;
    /// let msg = Message::parse(b.finish())?;
    ///
    /// // What `sig0::verify` does after its placement and time checks.
    /// let record = sig0::find(&msg)?.expect("signed");
    /// let data = SignedData::new(&record.data, msg.as_bytes(), Some(record.start), None)?;
    /// let verifier = DnssecSig0Verifier::new(PurecryptoVerifier, name.as_name(), signer.key());
    /// verifier.verify(&record.data, &data.parts())?;
    /// // Another client's key does not match the signature's key tag and name.
    /// let other: NameBuf = "other.example".parse()?;
    /// let stranger = DnssecSig0Verifier::new(PurecryptoVerifier, other.as_name(), signer.key());
    /// assert_eq!(stranger.verify(&record.data, &data.parts()), Err(Error::BadKey));
    /// # }
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    fn verify(&self, sig: &Sig<'_>, data: &[&[u8]]) -> Result<()>;
}

/// The data a SIG(0) signs (RFC 2931 §3.1), held without allocation.
///
/// [`sign`] and [`verify`] build it; it is public for backends that need
/// it elsewhere.
///
/// ```
/// use dnsbox::dnssec::Algorithm;
/// use dnsbox::rdata::Sig;
/// use dnsbox::sig0::SignedData;
/// use dnsbox::{Class, MessageBuilder, NameBuf, Rtype};
///
/// let signer: NameBuf = "client.example".parse()?;
/// let sig = Sig {
///     type_covered: Rtype::new(0), algorithm: Algorithm::ED25519, labels: 0, original_ttl: 0,
///     expiration: 1_800_000_300, inception: 1_799_999_700, key_tag: 4711,
///     signer_name: signer.as_name(), signature: &[],
/// };
/// let mut buf = [0u8; 128];
/// let query = MessageBuilder::query(&mut buf, 1, &signer, Rtype::A, Class::IN)?.finish();
/// let data = SignedData::new(&sig, query, None, None)?;
/// let [fields, request, header, rest] = data.parts();
/// assert_eq!(fields.len(), 18 + signer.wire_len());
/// assert!(request.is_empty()); // only responses cover the request
/// assert_eq!((header.len(), rest.len()), (12, query.len() - 12));
/// assert_eq!(data.len(), fields.len() + query.len());
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct SignedData<'a> {
    fields: [u8; SIG_FIXED_LEN + MAX_NAME_LEN],
    fields_len: usize,
    request: &'a [u8],
    header: [u8; Header::LEN],
    body: &'a [u8],
}

impl<'a> SignedData<'a> {
    /// The signed data for a message `msg` whose SIG(0) RDATA is `sig` (the
    /// signature field is ignored).
    ///
    /// `sig_start` is the offset of the SIG(0) record in `msg` if it is
    /// already there (verification: the bytes from it on are excluded and
    /// ARCOUNT is decremented), or `None` when signing a message that does
    /// not have it yet. `request` is the full request message (SIG(0)
    /// included) when `msg` is a response to it.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedEof`] if `msg` is shorter than its header,
    /// `sig_start` is out of range, or ARCOUNT is 0 with a `sig_start`.
    ///
    /// ```
    /// use dnsbox::dnssec::Algorithm;
    /// use dnsbox::rdata::Sig;
    /// use dnsbox::sig0::SignedData;
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
    ///
    /// let signer: NameBuf = "client.example".parse()?;
    /// let sig = Sig {
    ///     type_covered: Rtype::new(0), algorithm: Algorithm::ED25519, labels: 0, original_ttl: 0,
    ///     expiration: 1_800_000_300, inception: 1_799_999_700, key_tag: 4711,
    ///     signer_name: signer.as_name(), signature: &[],
    /// };
    /// let mut qbuf = [0u8; 128];
    /// let query = MessageBuilder::query(&mut qbuf, 1, &signer, Rtype::A, Class::IN)?.finish();
    /// // A response's signed data starts with the whole request.
    /// let mut rbuf = [0u8; 128];
    /// let response = MessageBuilder::response(&mut rbuf, &Message::parse(query)?)?.finish();
    /// let data = SignedData::new(&sig, response, None, Some(query))?;
    /// assert_eq!(data.parts()[1], &query[..]);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn new(
        sig: &Sig<'_>,
        msg: &'a [u8],
        sig_start: Option<usize>,
        request: Option<&'a [u8]>,
    ) -> Result<Self> {
        let mut fields = [0u8; SIG_FIXED_LEN + MAX_NAME_LEN];
        let mut w = WireWriter::new(&mut fields);
        sig.compose_unsigned(&mut Canonical::new(&mut w))?;
        let fields_len = w.len();
        let mut header = Header::parse(msg)?;
        let end = match sig_start {
            Some(end) => {
                header.arcount = header.arcount.checked_sub(1).ok_or(Error::UnexpectedEof)?;
                end
            }
            None => msg.len(),
        };
        Ok(SignedData {
            fields,
            fields_len,
            request: request.unwrap_or(&[]),
            header: header.to_bytes(),
            body: msg.get(Header::LEN..end).ok_or(Error::UnexpectedEof)?,
        })
    }

    /// The signed data as consecutive slices: SIG RDATA fields, request
    /// (empty for requests), header, rest of the message.
    ///
    /// ```
    /// use dnsbox::dnssec::Algorithm;
    /// use dnsbox::rdata::Sig;
    /// use dnsbox::sig0::SignedData;
    /// use dnsbox::{Class, MessageBuilder, NameBuf, Rtype};
    ///
    /// let signer: NameBuf = "client.example".parse()?;
    /// let sig = Sig {
    ///     type_covered: Rtype::new(0), algorithm: Algorithm::ECDSAP256SHA256, labels: 0, original_ttl: 0,
    ///     expiration: 1_800_000_300, inception: 1_799_999_700, key_tag: 4711,
    ///     signer_name: signer.as_name(), signature: &[],
    /// };
    /// let mut buf = [0u8; 128];
    /// let query = MessageBuilder::query(&mut buf, 1, &signer, Rtype::A, Class::IN)?.finish();
    /// let data = SignedData::new(&sig, query, None, None)?;
    /// // Feed a streaming hash part by part (here: just count the bytes).
    /// let mut hashed = 0;
    /// for part in data.parts() {
    ///     hashed += part.len();
    /// }
    /// assert_eq!(hashed, data.len());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn parts(&self) -> [&[u8]; 4] {
        [
            self.fields.get(..self.fields_len).unwrap_or(&[]),
            self.request,
            &self.header,
            self.body,
        ]
    }

    /// Total length of the signed data.
    ///
    /// ```
    /// use dnsbox::dnssec::Algorithm;
    /// use dnsbox::rdata::Sig;
    /// use dnsbox::sig0::SignedData;
    /// use dnsbox::{Class, MessageBuilder, NameBuf, Rtype};
    ///
    /// let signer: NameBuf = "client.example".parse()?;
    /// let sig = Sig {
    ///     type_covered: Rtype::new(0), algorithm: Algorithm::ED25519, labels: 0, original_ttl: 0,
    ///     expiration: 1_800_000_300, inception: 1_799_999_700, key_tag: 4711,
    ///     signer_name: signer.as_name(), signature: &[],
    /// };
    /// let mut buf = [0u8; 128];
    /// let query = MessageBuilder::query(&mut buf, 1, &signer, Rtype::A, Class::IN)?.finish();
    /// let data = SignedData::new(&sig, query, None, None)?;
    /// // The SIG RDATA without the signature (18 bytes + signer name), then the message.
    /// assert_eq!(data.len(), 18 + signer.wire_len() + query.len());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.parts().iter().map(|p| p.len()).sum()
    }

    /// Whether the signed data is empty (never true for a valid message).
    ///
    /// ```
    /// use dnsbox::dnssec::Algorithm;
    /// use dnsbox::rdata::Sig;
    /// use dnsbox::sig0::SignedData;
    /// use dnsbox::{Class, MessageBuilder, NameBuf, Rtype};
    ///
    /// let signer: NameBuf = "client.example".parse()?;
    /// let sig = Sig {
    ///     type_covered: Rtype::new(0), algorithm: Algorithm::ED25519, labels: 0, original_ttl: 0,
    ///     expiration: 1_800_000_300, inception: 1_799_999_700, key_tag: 4711,
    ///     signer_name: signer.as_name(), signature: &[],
    /// };
    /// let mut buf = [0u8; 128];
    /// let query = MessageBuilder::query(&mut buf, 1, &signer, Rtype::A, Class::IN)?.finish();
    /// assert!(!SignedData::new(&sig, query, None, None)?.is_empty());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Validity window of a SIG(0) being generated.
///
/// ```
/// use dnsbox::sig0::Validity;
///
/// let v = Validity::around(1_800_000_000, 300);
/// assert_eq!((v.inception, v.expiration), (1_799_999_700, 1_800_000_300));
/// assert!(v.contains(1_800_000_299) && !v.contains(1_800_000_301));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Validity {
    /// Signature inception (seconds since the epoch, mod 2³²).
    pub inception: u32,
    /// Signature expiration.
    pub expiration: u32,
}

impl Validity {
    /// The window `now - skew ..= now + skew` (wrapping, as RFC 1982
    /// serial arithmetic expects).
    ///
    /// ```
    /// use dnsbox::sig0::Validity;
    ///
    /// // Five minutes either side of the signing time, for clock skew.
    /// let now = 1_800_000_000;
    /// let v = Validity::around(now, 300);
    /// assert_eq!(v.expiration - v.inception, 600);
    /// // Near the end of the 32-bit range the window wraps (RFC 1982).
    /// let wrapped = Validity::around(u32::MAX - 10, 300);
    /// assert!(wrapped.expiration < wrapped.inception && wrapped.contains(5));
    /// ```
    #[must_use]
    pub const fn around(now: u32, skew: u32) -> Self {
        Validity {
            inception: now.wrapping_sub(skew),
            expiration: now.wrapping_add(skew),
        }
    }

    /// Whether `now` lies within the window (RFC 1982 serial arithmetic,
    /// as for RRSIG in RFC 4034 §3.1.5).
    ///
    /// ```
    /// use dnsbox::sig0::Validity;
    ///
    /// let v = Validity { inception: 1_800_000_000, expiration: 1_800_003_600 };
    /// assert!(v.contains(1_800_001_000));
    /// assert!(!v.contains(1_799_999_999)); // not yet valid
    /// assert!(!v.contains(1_800_003_601)); // expired
    /// ```
    #[must_use]
    pub const fn contains(&self, now: u32) -> bool {
        crate::dnssec::check_validity(self.inception, self.expiration, now).is_ok()
    }
}

/// Signs the message in `b` with SIG(0) and appends the SIG record as the
/// last record of the additional section (RFC 2931 §3). For a response,
/// pass the full `request` it answers (including the request's SIG(0)).
///
/// Nothing may be added to the message afterwards. See the [module
/// example](self).
///
/// # Errors
///
/// [`Error::BufferTooSmall`] if the SIG record does not fit (or the
/// signer's signature length exceeds [`MAX_SIGNATURE_LEN`]),
/// [`Error::CountOverflow`] for a full additional section, or the
/// signer's error. On error the message is left unchanged.
///
/// ```
/// # #[cfg(feature = "dnssec")] {
/// use dnsbox::dnssec::{Algorithm, SigningKey};
/// use dnsbox::sig0::{self, DnssecSig0Signer, Validity};
/// use dnsbox::{Class, MessageBuilder, NameBuf, Rtype};
///
/// let key = SigningKey::from_private_bytes(Algorithm::ED25519, &[5; 32])?;
/// let name: NameBuf = "client.example".parse()?;
/// let signer = DnssecSig0Signer::new(&key, name.as_name(), 512);
/// let mut buf = [0u8; 512];
/// let mut b = MessageBuilder::query(&mut buf, 1, &name, Rtype::TXT, Class::IN)?;
/// sig0::sign(&mut b, &signer, Validity::around(1_800_000_000, 300), None)?;
/// assert_eq!(b.header().arcount, 1); // the SIG(0) record
/// # }
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn sign<B: OutBuf, S: Sig0Signer + ?Sized>(
    b: &mut MessageBuilder<B>,
    signer: &S,
    validity: Validity,
    request: Option<&[u8]>,
) -> Result<()> {
    let signer_name = signer.signer_name();
    let sig_len = signer.signature_len();
    if sig_len > MAX_SIGNATURE_LEN {
        return Err(Error::BufferTooSmall);
    }
    // Owner `.`, TYPE/CLASS/TTL/RDLENGTH, fixed fields, signer, signature.
    let rr_len = 1 + 10 + SIG_FIXED_LEN + signer_name.wire_len() + sig_len;
    if b.len() + rr_len > b.limit() {
        return Err(Error::BufferTooSmall);
    }
    if b.header().arcount == u16::MAX {
        return Err(Error::CountOverflow);
    }
    let mut sig = Sig {
        type_covered: Rtype::new(0),
        algorithm: signer.algorithm(),
        labels: 0,
        original_ttl: 0,
        expiration: validity.expiration,
        inception: validity.inception,
        key_tag: signer.key_tag(),
        signer_name,
        signature: &[],
    };
    let mut out = [0u8; MAX_SIGNATURE_LEN];
    let len = {
        let data = SignedData::new(&sig, b.as_bytes(), None, request)?;
        signer.sign(&data.parts(), &mut out)?
    };
    sig.signature = out.get(..len).ok_or(Error::BufferTooSmall)?;
    b.push_additional(Name::ROOT, Class::ANY, 0, &sig)
}

/// A SIG(0) record found in a message by [`find`] (see the [module
/// example](self)).
///
/// ```
/// use dnsbox::sig0::Sig0Record;
/// use dnsbox::Message;
///
/// fn signer_of<'a>(msg: &Message<'a>) -> dnsbox::Result<Option<String>> {
///     let record: Option<Sig0Record<'a>> = dnsbox::sig0::find(msg)?;
///     Ok(record.map(|r| format!("{} (key {})", r.data.signer_name, r.data.key_tag)))
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Sig0Record<'a> {
    /// The record data.
    pub data: Sig<'a>,
    /// Offset of the record in the message.
    pub start: usize,
}

/// Locates the SIG(0) of a message: a SIG record with type covered 0.
///
/// Returns `Ok(None)` if there is none. A SIG(0) anywhere but as the last
/// record of the additional section (or more than one) yields
/// [`Error::MisplacedSignature`] (RFC 2931 §3); one whose owner is not the
/// root, CLASS not ANY, TTL not 0, or labels / original TTL not 0 yields
/// [`Error::InvalidRdata`], and octets after it (which the signature does
/// not cover) yield [`Error::TrailingData`]. SIG records covering a real
/// type (legacy DNSSEC, RFC 2535) are ignored.
///
/// # Errors
///
/// [`Error::MisplacedSignature`], [`Error::InvalidRdata`] and
/// [`Error::TrailingData`] as above, and the parse error of a malformed
/// message.
///
/// ```
/// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
///
/// let name: NameBuf = "example".parse()?;
/// let mut buf = [0u8; 64];
/// let query = Message::parse(MessageBuilder::query(&mut buf, 1, &name, Rtype::A, Class::IN)?.finish())?;
/// assert!(dnsbox::sig0::find(&query)?.is_none()); // not signed
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn find<'a>(msg: &Message<'a>) -> Result<Option<Sig0Record<'a>>> {
    let arcount = msg.header().arcount;
    let mut additional = 0u16;
    let mut found = None;
    for item in msg.records() {
        let (section, rr) = item?;
        if section == Section::Additional {
            additional = additional.saturating_add(1);
        }
        if rr.rtype() != Rtype::SIG {
            continue;
        }
        let data = rr.data_as::<Sig<'a>>()?;
        if data.type_covered.get() != 0 {
            continue;
        }
        if found.is_some() || section != Section::Additional || additional != arcount {
            return Err(Error::MisplacedSignature);
        }
        if !rr.name().is_root()
            || rr.class() != Class::ANY
            || rr.ttl() != 0
            || data.labels != 0
            || data.original_ttl != 0
        {
            return Err(Error::InvalidRdata);
        }
        if rr.end() != msg.as_bytes().len() {
            return Err(Error::TrailingData);
        }
        found = Some(Sig0Record {
            data,
            start: rr.start(),
        });
    }
    Ok(found)
}

/// Verifies the SIG(0) of `msg` (RFC 2931 §3.1): it must be present
/// ([`Error::Unsigned`] otherwise) and well placed, `now` must lie in its
/// validity window ([`Error::BadTime`]), and `verifier` must accept the
/// signature over the signed data. For a response, pass the full
/// `request` it answers. See the [module example](self).
///
/// # Errors
///
/// [`Error::Unsigned`], [`Error::BadTime`], the errors of [`find`], and
/// the verifier's error ([`Error::BadKey`], [`Error::BadSignature`], ...).
///
/// ```
/// use dnsbox::sig0::Sig0Verifier;
/// use dnsbox::{Error, Message, Result};
///
/// // Server side: accept an update only if a known key signed it.
/// fn authorize<V: Sig0Verifier>(update: &Message<'_>, keys: &V, now: u32) -> Result<()> {
///     match dnsbox::sig0::verify(update, keys, now, None) {
///         Ok(record) => {
///             println!("update signed by {}", record.data.signer_name);
///             Ok(())
///         }
///         Err(Error::Unsigned) => Err(Error::BadKey), // unsigned updates are refused
///         Err(e) => Err(e),
///     }
/// }
/// ```
pub fn verify<'a, V: Sig0Verifier + ?Sized>(
    msg: &Message<'a>,
    verifier: &V,
    now: u32,
    request: Option<&[u8]>,
) -> Result<Sig0Record<'a>> {
    let record = find(msg)?.ok_or(Error::Unsigned)?;
    let validity = Validity {
        inception: record.data.inception,
        expiration: record.data.expiration,
    };
    if !validity.contains(now) {
        return Err(Error::BadTime);
    }
    let data = SignedData::new(&record.data, msg.as_bytes(), Some(record.start), request)?;
    verifier.verify(&record.data, &data.parts())?;
    Ok(record)
}

/// A SIG(0) signer backed by a DNSSEC [`Signer`](crate::dnssec::Signer)
/// (e.g. [`SigningKey`] with the `dnssec`
/// feature): the key published as a KEY record named `name` with KEY flags
/// `flags` (RFC 2535 §3.1.2, RFC 2931 §2; `dnssec-keygen -T KEY -n HOST`
/// uses 512).
///
/// The signed data is concatenated into a temporary buffer, since the
/// DNSSEC signer takes one slice.
///
/// ```
/// # #[cfg(feature = "dnssec")] {
/// use dnsbox::dnssec::{Algorithm, PurecryptoVerifier, SigningKey};
/// use dnsbox::sig0::{self, DnssecSig0Signer, DnssecSig0Verifier, Validity};
/// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
///
/// let key = SigningKey::from_private_bytes(Algorithm::ED25519, &[7; 32])?;
/// let name: NameBuf = "client.example".parse()?;
/// let signer = DnssecSig0Signer::new(&key, name.as_name(), 512);
///
/// let mut buf = [0u8; 512];
/// let mut b = MessageBuilder::query(&mut buf, 1, &name, Rtype::A, Class::IN)?;
/// sig0::sign(&mut b, &signer, Validity::around(1_800_000_000, 300), None)?;
/// let msg = Message::parse(b.finish())?;
///
/// // The receiver knows the KEY record.
/// let verifier = DnssecSig0Verifier::new(PurecryptoVerifier, name.as_name(), signer.key());
/// sig0::verify(&msg, &verifier, 1_800_000_000, None)?;
/// # }
/// # Ok::<(), dnsbox::Error>(())
/// ```
///
#[cfg_attr(feature = "dnssec", doc = "[`SigningKey`]: crate::dnssec::SigningKey")]
#[cfg_attr(not(feature = "dnssec"), doc = "[`SigningKey`]: crate#cargo-features")]
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[derive(Clone, Copy, Debug)]
pub struct DnssecSig0Signer<'n, S> {
    signer: S,
    name: Name<'n>,
    flags: u16,
    key_tag: u16,
}

#[cfg(feature = "alloc")]
impl<'n, S: crate::dnssec::Signer> DnssecSig0Signer<'n, S> {
    /// Wraps `signer`, whose public key is the KEY record `name` with KEY
    /// flags `flags` and protocol 3. The key tag is computed from them
    /// (RFC 4034 Appendix B).
    ///
    /// ```
    /// # #[cfg(feature = "dnssec")] {
    /// use dnsbox::dnssec::{Algorithm, SigningKey};
    /// use dnsbox::sig0::{DnssecSig0Signer, Sig0Signer};
    /// use dnsbox::NameBuf;
    ///
    /// // A host key, as `dnssec-keygen -T KEY -n HOST` makes (flags 512).
    /// let key = SigningKey::from_private_bytes(Algorithm::ECDSAP256SHA256, &[0x11; 32])?;
    /// let host: NameBuf = "laptop.example.com".parse()?;
    /// let signer = DnssecSig0Signer::new(&key, host.as_name(), 512);
    /// assert_eq!(signer.algorithm(), Algorithm::ECDSAP256SHA256);
    /// assert_eq!(signer.signer_name(), host.as_name());
    /// # }
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn new(signer: S, name: Name<'n>, flags: u16) -> Self {
        let key_tag = crate::dnssec::key_tag(flags, 3, signer.algorithm(), signer.public_key());
        DnssecSig0Signer {
            signer,
            name,
            flags,
            key_tag,
        }
    }

    /// The KEY record data to publish for this signer (RFC 2931 §2).
    ///
    /// ```
    /// # #[cfg(feature = "dnssec")] {
    /// use dnsbox::dnssec::{Algorithm, SigningKey};
    /// use dnsbox::sig0::DnssecSig0Signer;
    /// use dnsbox::NameBuf;
    ///
    /// let key = SigningKey::from_private_bytes(Algorithm::ED25519, &[7; 32])?;
    /// let host: NameBuf = "laptop.example.com".parse()?;
    /// let signer = DnssecSig0Signer::new(&key, host.as_name(), 512);
    /// // The record to publish in the zone, as `laptop.example.com. KEY ...`.
    /// let record = signer.key();
    /// assert_eq!((record.flags, record.protocol, record.algorithm), (512, 3, Algorithm::ED25519));
    /// assert!(record.to_string().starts_with("512 3 15 "));
    /// # }
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn key(&self) -> crate::rdata::Key<'_> {
        crate::rdata::Key::new(
            self.flags,
            3,
            self.signer.algorithm(),
            self.signer.public_key(),
        )
    }
}

#[cfg(feature = "alloc")]
impl<S: crate::dnssec::Signer> Sig0Signer for DnssecSig0Signer<'_, S> {
    fn algorithm(&self) -> Algorithm {
        self.signer.algorithm()
    }

    fn key_tag(&self) -> u16 {
        self.key_tag
    }

    fn signer_name(&self) -> Name<'_> {
        self.name
    }

    fn signature_len(&self) -> usize {
        self.signer.signature_len()
    }

    fn sign(&self, data: &[&[u8]], out: &mut [u8]) -> Result<usize> {
        self.signer.sign(&data.concat(), out)
    }
}

/// A SIG(0) verifier backed by a DNSSEC
/// [`Verifier`](crate::dnssec::Verifier) (e.g.
/// [`PurecryptoVerifier`] with the
/// `dnssec` feature) for one KEY record: `name` and its record data `key`.
///
/// A SIG(0) whose signer name, algorithm or key tag does not match the KEY
/// fails with [`Error::BadKey`]; otherwise the verifier's error is returned
/// ([`Error::BadSignature`], [`Error::InvalidKey`],
/// [`Error::UnsupportedAlgorithm`]). See [`DnssecSig0Signer`] for an
/// example.
///
/// ```
/// # #[cfg(feature = "dnssec")] {
/// use dnsbox::dnssec::PurecryptoVerifier;
/// use dnsbox::rdata::{Key, ParseRdataText};
/// use dnsbox::sig0::DnssecSig0Verifier;
/// use dnsbox::NameBuf;
///
/// // The client's KEY record, as published in the zone.
/// let name: NameBuf = "client.example".parse()?;
/// let mut buf = [0u8; 64];
/// let key = Key::from_text("512 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=", &mut buf)?;
/// let verifier = DnssecSig0Verifier::new(PurecryptoVerifier, name.as_name(), key);
/// # let _ = verifier;
/// # }
/// # Ok::<(), dnsbox::Error>(())
/// ```
///
#[cfg_attr(
    feature = "dnssec",
    doc = "[`PurecryptoVerifier`]: crate::dnssec::PurecryptoVerifier"
)]
#[cfg_attr(
    not(feature = "dnssec"),
    doc = "[`PurecryptoVerifier`]: crate#cargo-features"
)]
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[derive(Clone, Copy, Debug)]
pub struct DnssecSig0Verifier<'k, V> {
    verifier: V,
    name: Name<'k>,
    key: crate::rdata::Key<'k>,
}

#[cfg(feature = "alloc")]
impl<'k, V: crate::dnssec::Verifier> DnssecSig0Verifier<'k, V> {
    /// Checks signatures made with the KEY record `name` / `key`.
    ///
    /// ```
    /// # #[cfg(feature = "dnssec")] {
    /// use dnsbox::dnssec::{Algorithm, PurecryptoVerifier, SigningKey};
    /// use dnsbox::sig0::{self, DnssecSig0Signer, DnssecSig0Verifier, Validity};
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
    ///
    /// let key = SigningKey::from_private_bytes(Algorithm::ED25519, &[7; 32])?;
    /// let host: NameBuf = "laptop.example.com".parse()?;
    /// let signer = DnssecSig0Signer::new(&key, host.as_name(), 512);
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::query(&mut buf, 1, &host, Rtype::SOA, Class::IN)?;
    /// sig0::sign(&mut b, &signer, Validity::around(1_800_000_000, 300), None)?;
    /// let msg = Message::parse(b.finish())?;
    /// // The server knows the host's KEY record.
    /// let verifier = DnssecSig0Verifier::new(PurecryptoVerifier, host.as_name(), signer.key());
    /// sig0::verify(&msg, &verifier, 1_800_000_100, None)?;
    /// # }
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub const fn new(verifier: V, name: Name<'k>, key: crate::rdata::Key<'k>) -> Self {
        DnssecSig0Verifier {
            verifier,
            name,
            key,
        }
    }
}

#[cfg(feature = "alloc")]
impl<V: crate::dnssec::Verifier> Sig0Verifier for DnssecSig0Verifier<'_, V> {
    fn verify(&self, sig: &Sig<'_>, data: &[&[u8]]) -> Result<()> {
        if sig.signer_name != self.name
            || sig.algorithm != self.key.algorithm
            || sig.key_tag != self.key.key_tag()
        {
            return Err(Error::BadKey);
        }
        self.verifier.verify(
            self.key.algorithm,
            self.key.public_key,
            &data.concat(),
            sig.signature,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NameBuf;
    use crate::rdata::A;
    use std::vec::Vec;

    /// A stand-in "signature": the signed data itself, truncated, so the
    /// tests can check exactly what was signed.
    struct EchoSigner {
        name: NameBuf,
    }

    impl Sig0Signer for EchoSigner {
        fn algorithm(&self) -> Algorithm {
            Algorithm::PRIVATEDNS
        }
        fn key_tag(&self) -> u16 {
            0xbeef
        }
        fn signer_name(&self) -> Name<'_> {
            self.name.as_name()
        }
        fn signature_len(&self) -> usize {
            64
        }
        fn sign(&self, data: &[&[u8]], out: &mut [u8]) -> Result<usize> {
            let all: Vec<u8> = data.concat();
            // "Signature" = length of the data and its last 62 bytes.
            out[..2].copy_from_slice(&(all.len() as u16).to_be_bytes());
            let tail = &all[all.len().saturating_sub(62)..];
            out[2..2 + tail.len()].copy_from_slice(tail);
            Ok(2 + tail.len())
        }
    }

    impl Sig0Verifier for EchoSigner {
        fn verify(&self, sig: &Sig<'_>, data: &[&[u8]]) -> Result<()> {
            if sig.signer_name != self.name.as_name() {
                return Err(Error::BadKey);
            }
            let mut out = [0u8; 64];
            let n = self.sign(data, &mut out)?;
            if out[..n] == *sig.signature {
                Ok(())
            } else {
                Err(Error::BadSignature)
            }
        }
    }

    fn signer() -> EchoSigner {
        EchoSigner {
            name: "Key.Example".parse().unwrap(),
        }
    }

    fn update_message(buf: &mut [u8]) -> MessageBuilder<WireWriter<'_>> {
        let zone: NameBuf = "example.com".parse().unwrap();
        let host: NameBuf = "www.example.com".parse().unwrap();
        let mut b = MessageBuilder::new(buf).unwrap();
        b.set_id(0x4242);
        b.push_question(&zone, Rtype::SOA, Class::IN).unwrap();
        b.push_authority(&host, Class::IN, 300, &A::new([192, 0, 2, 1].into()))
            .unwrap();
        b
    }

    #[test]
    fn sign_and_verify() {
        let s = signer();
        let mut buf = [0u8; 512];
        let mut b = update_message(&mut buf);
        let unsigned = b.as_bytes().to_vec();
        sign(&mut b, &s, Validity::around(1000, 300), None).unwrap();
        let wire = b.finish().to_vec();
        let msg = Message::parse_validated(&wire).unwrap();
        assert_eq!(msg.header().arcount, 1);
        let rec = verify(&msg, &s, 1000, None).unwrap();
        assert_eq!(rec.data.key_tag, 0xbeef);
        assert_eq!(rec.data.inception, 700);
        assert_eq!(rec.data.expiration, 1300);
        assert_eq!(&wire[12..rec.start], &unsigned[12..]);
        // The signed data: SIG fields with a lowercase signer, then the
        // message as it was before the SIG was added.
        let data = SignedData::new(&rec.data, &wire, Some(rec.start), None).unwrap();
        let mut expected = std::vec![0, 0, 253, 0, 0, 0, 0, 0];
        expected.extend_from_slice(&1300u32.to_be_bytes());
        expected.extend_from_slice(&700u32.to_be_bytes());
        expected.extend_from_slice(&[0xbe, 0xef]);
        expected.extend_from_slice(b"\x03key\x07example\x00");
        expected.extend_from_slice(&unsigned);
        assert_eq!(data.parts().concat(), expected);
        assert_eq!(data.len(), expected.len());
        assert!(!data.is_empty());

        // Time window.
        assert_eq!(verify(&msg, &s, 699, None), Err(Error::BadTime));
        assert_eq!(verify(&msg, &s, 1301, None), Err(Error::BadTime));
        assert!(verify(&msg, &s, 700, None).is_ok());
        // Tampering.
        let mut bad = wire.clone();
        bad[rec.start - 1] ^= 1;
        assert_eq!(
            verify(&Message::parse(&bad).unwrap(), &s, 1000, None),
            Err(Error::BadSignature)
        );
        // Unsigned.
        assert_eq!(
            verify(&Message::parse(&unsigned).unwrap(), &s, 1000, None),
            Err(Error::Unsigned)
        );
        // Wrong key.
        let other = EchoSigner {
            name: "other".parse().unwrap(),
        };
        assert_eq!(verify(&msg, &other, 1000, None), Err(Error::BadKey));
    }

    #[test]
    fn response_covers_request() {
        let s = signer();
        let mut qbuf = [0u8; 512];
        let mut q = update_message(&mut qbuf);
        sign(&mut q, &s, Validity::around(5, 10), None).unwrap();
        let request = q.finish().to_vec();

        let mut rbuf = [0u8; 512];
        let mut r = MessageBuilder::new(&mut rbuf).unwrap();
        r.set_id(0x4242);
        sign(&mut r, &s, Validity::around(5, 10), Some(&request)).unwrap();
        let response = r.finish().to_vec();
        let msg = Message::parse(&response).unwrap();
        assert!(verify(&msg, &s, 5, Some(&request)).is_ok());
        let rec = find(&msg).unwrap().unwrap();
        let data = SignedData::new(&rec.data, &response, Some(rec.start), Some(&request)).unwrap();
        assert_eq!(data.parts()[1], &request[..]);
        // Without the request, the data differs.
        assert_eq!(verify(&msg, &s, 5, None), Err(Error::BadSignature));
    }

    #[test]
    fn wrapping_validity() {
        let v = Validity::around(5, 10);
        assert_eq!(v.inception, u32::MAX - 4);
        assert!(v.contains(u32::MAX) && v.contains(0) && v.contains(15));
        assert!(!v.contains(16) && !v.contains(u32::MAX - 5));
    }

    #[test]
    fn signing_is_atomic() {
        let s = signer();
        let mut buf = [0u8; 512];
        let mut b = update_message(&mut buf);
        let before = b.as_bytes().to_vec();
        b.set_limit(before.len() + 1 + 10 + 18 + 13 + 64 - 1);
        assert_eq!(
            sign(&mut b, &s, Validity::around(1, 1), None),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(b.as_bytes(), &before[..]);
    }

    #[test]
    fn placement_and_form() {
        let s = signer();
        let mut buf = [0u8; 512];
        let mut b = update_message(&mut buf);
        sign(&mut b, &s, Validity::around(1, 1), None).unwrap();
        let wire = b.finish().to_vec();
        let msg = Message::parse(&wire).unwrap();
        let rec = find(&msg).unwrap().unwrap();

        // A record after the SIG(0).
        let mut buf = [0u8; 512];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.push_additional(Name::ROOT, Class::ANY, 0, &rec.data)
            .unwrap();
        b.push_additional(Name::ROOT, Class::IN, 0, &A::new([1, 2, 3, 4].into()))
            .unwrap();
        let m = b.finish().to_vec();
        assert_eq!(
            find(&Message::parse(&m).unwrap()),
            Err(Error::MisplacedSignature)
        );
        // In the answer section.
        let mut buf = [0u8; 512];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.push_answer(Name::ROOT, Class::ANY, 0, &rec.data).unwrap();
        let m = b.finish().to_vec();
        assert_eq!(
            find(&Message::parse(&m).unwrap()),
            Err(Error::MisplacedSignature)
        );
        // Wrong owner / class / TTL.
        let owner: NameBuf = "x".parse().unwrap();
        for (name, class, ttl) in [
            (owner.as_name(), Class::ANY, 0),
            (Name::ROOT, Class::IN, 0),
            (Name::ROOT, Class::ANY, 5),
        ] {
            let mut buf = [0u8; 512];
            let mut b = MessageBuilder::new(&mut buf).unwrap();
            b.push_additional(name, class, ttl, &rec.data).unwrap();
            let m = b.finish().to_vec();
            assert_eq!(find(&Message::parse(&m).unwrap()), Err(Error::InvalidRdata));
        }
        // A SIG covering a real type is not a SIG(0).
        let mut legacy = rec.data;
        legacy.type_covered = Rtype::A;
        let mut buf = [0u8; 512];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.push_answer(Name::ROOT, Class::IN, 0, &legacy).unwrap();
        let m = b.finish().to_vec();
        assert_eq!(find(&Message::parse(&m).unwrap()), Ok(None));
        // Truncations never panic.
        for end in 0..wire.len() {
            if let Ok(m) = Message::parse(&wire[..end]) {
                assert!(verify(&m, &s, 1, None).is_err());
            }
        }
    }
}
