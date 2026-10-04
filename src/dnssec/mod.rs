//! DNSSEC (RFC 4033, RFC 4034, RFC 4035, RFC 5155, RFC 6840): algorithm
//! registries, canonical forms, key tags, DS digests, NSEC3 hashing, RRSIG
//! validation and signing, the chain of trust and authenticated denial of
//! existence.
//!
//! The record types themselves live in [`crate::rdata`]: [`Dnskey`],
//! [`Rrsig`], [`Nsec`], [`Ds`], [`Nsec3`], [`Nsec3param`], [`Cds`],
//! [`Cdnskey`] (with the RFC 8078 delete forms), plus [`Key`], [`Sig`],
//! [`Dlv`] and [`Ta`], and the shared [`TypeBitmap`].
//!
//! # Layers
//!
//! Everything that is wire format or protocol logic works without any
//! cryptography and without allocation:
//!
//! - [`Algorithm`], [`DigestType`], [`Nsec3HashAlgorithm`]: open registries.
//! - [`canonical_name`], [`CanonicalRrset`]: canonical forms and RRset
//!   order (RFC 4034 §6).
//! - [`key_tag`], [`RsaPublicKey`]: key tags (RFC 4034 Appendix B) and the
//!   RFC 3110 key format.
//! - [`ds_digest_input`]: what a DS digest covers (RFC 4034 §5.1.4).
//! - [`signed_data`], [`rrsig_owner`], [`check_rrsig`],
//!   [`ZoneKey::check_rrsig`]: the RRSIG signed data (RFC 4034 §3.1.8.1)
//!   and the RFC 4035 §5.3 checks, including wildcard handling and
//!   validity periods with serial arithmetic ([`serial_cmp`],
//!   [`Timestamp`]).
//! - [`Verifier`] / [`Signer`]: the traits a crypto backend implements;
//!   [`verify_rrsig`] and [`sign_rrset`] tie everything together.
//! - [`TrustedKeys`]: the chain of trust (RFC 4035 §5): a DNSKEY RRset
//!   authenticated by trust anchors ([`TrustedKeys::from_anchors`]) or by
//!   the parent's DS RRset (`TrustedKeys::from_ds`), which then verifies
//!   the zone's RRsets, wildcard expansions included
//!   ([`TrustedKeys::verify_answer`]), with bounded work
//!   ([`MAX_CRYPTO_OPERATIONS`]).
//! - [`NsecProof`], [`Nsec3Proof`] ([`DenialProof`]): NSEC and NSEC3
//!   proofs for NXDOMAIN, NODATA, wildcard answers, wildcard NODATA and
//!   unsigned delegations, with closest encloser proofs, Opt-Out, the
//!   RFC 6840 §4 corrections and RFC 9276 iteration limits
//!   ([`Nsec3Limits`]); the outcome is a [`DenialStatus`]. NSEC3 hashing
//!   is pluggable ([`Nsec3Hasher`]).
//!
//! Cryptography comes from the optional `purecrypto` dependency:
//!
//! - feature `dnssec-digest` (no `alloc` needed): `DsDigest`,
//!   `verify_ds`, `ZoneKey::ds` (SHA-1, SHA-256, SHA-384),
//!   `TrustedKeys::from_ds`, `nsec3_hash` (SHA-1, RFC 5155 §5) and
//!   `PurecryptoNsec3Hasher`;
//! - feature `dnssec`: `PurecryptoVerifier` and `SigningKey`, verifying and
//!   signing RSA/SHA-1, RSA/SHA-256, RSA/SHA-512, ECDSA P-256/SHA-256,
//!   ECDSA P-384/SHA-384, Ed25519 and Ed448.
//!
//! # Example
//!
//! Validating a signed RRset from a response, without allocating (the
//! scratch buffer holds the signed data):
//!
//! ```
//! # #[cfg(feature = "dnssec")] {
//! use dnsbox::dnssec::{PurecryptoVerifier, RecordRdata, Rrset, ZoneKey, verify_rrsig};
//! use dnsbox::rdata::{Dnskey, Rrsig};
//! use dnsbox::{Message, Name, Rtype, WireWriter};
//!
//! fn check(msg: &Message<'_>, owner: Name<'_>, key: &ZoneKey<'_>, now: u32) -> dnsbox::Result<()> {
//!     let mut buf = [0u8; 4096];
//!     let mut scratch = WireWriter::new(&mut buf);
//!     for rr in msg.answers() {
//!         let rr = rr?;
//!         let Ok(rrsig) = rr.data_as::<Rrsig<'_>>() else { continue };
//!         let records = msg
//!             .answers()
//!             .filter_map(Result::ok)
//!             .filter(|r| r.rtype() == rrsig.type_covered && r.name() == owner)
//!             .map(RecordRdata);
//!         let rrset = Rrset::new(owner, rr.class(), records);
//!         verify_rrsig(&PurecryptoVerifier, key, &rrsig, rrset, now, &mut scratch)?;
//!     }
//!     Ok(())
//! }
//! # }
//! ```

mod alg;
#[cfg(feature = "dnssec")]
mod backend;
mod canonical;
mod chain;
mod crypto;
mod denial;
mod ds;
mod keys;
mod nsec3;
mod rrsig;
#[cfg(test)]
pub(crate) mod testvec;
mod time;

pub use alg::{Algorithm, DigestType, Nsec3HashAlgorithm};
#[cfg(feature = "dnssec")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
pub use backend::{PrivateKey, PurecryptoVerifier, SigningKey};
pub use canonical::{CanonicalRrset, canonical_name};
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub use canonical::{canonical_rdata, sort_rrset};
pub use chain::{Answer, MAX_CRYPTO_OPERATIONS, TrustedKeys, Verified};
pub use crypto::{Signer, Verifier};
#[cfg(feature = "dnssec-digest")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec-digest")))]
pub use denial::PurecryptoNsec3Hasher;
pub use denial::{
    BogusReason, ClosestEncloser, Denial, DenialProof, DenialStatus, InsecureReason, Nsec3Hasher,
    Nsec3Limits, Nsec3Proof, Nsec3Record, NsecProof, NsecRecord,
};
pub use ds::ds_digest_input;
#[cfg(feature = "dnssec-digest")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec-digest")))]
pub use ds::{DsDigest, verify_ds};
pub use keys::{RsaPublicKey, key_tag};
pub use nsec3::Nsec3Hash;
#[cfg(feature = "dnssec-digest")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec-digest")))]
pub use nsec3::nsec3_hash;
pub use rrsig::{
    RecordRdata, Rrset, ZoneKey, check_rrsig, rrsig_owner, sign_rrset, signed_data, verify_rrsig,
};
pub use time::{Timestamp, check_validity, serial_cmp};

/// The `purecrypto` crate dnsbox was built against, for naming its key and
/// RNG types (e.g. `purecrypto::rng::OsRng`).
#[cfg(feature = "dnssec-digest")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec-digest")))]
pub use ::purecrypto;

#[cfg(doc)]
use crate::rdata::{
    Cdnskey, Cds, Dlv, Dnskey, Ds, Key, Nsec, Nsec3, Nsec3param, Rrsig, Sig, Ta, TypeBitmap,
};
