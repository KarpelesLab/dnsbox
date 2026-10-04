//! RRSIG signed data, validation and signing (RFC 4034 §3.1.8.1,
//! RFC 4035 §5.3, RFC 6840 §5).

use super::{CanonicalRrset, Signer, Verifier, check_validity};
use crate::message::Record;
use crate::name::{Name, NameBuf};
use crate::rdata::{ComposeRdata, Dnskey, Rrsig};
use crate::wire::{Canonical, Composer, OutBuf};
use crate::{Class, Error, Result, Rtype};

/// An RRset to sign or verify: the owner name and class shared by its
/// records, and their record data (any iterable of [`ComposeRdata`], e.g.
/// a slice of typed data, `RData` values, or [`RecordRdata`] wrappers
/// around message records).
///
/// The records must all be of the type the RRSIG covers; their order does
/// not matter and duplicates are ignored (RFC 4034 §6.3).
#[derive(Clone, Copy, Debug)]
pub struct Rrset<'a, I> {
    /// The owner name, as found in the message (possibly the result of
    /// wildcard expansion).
    pub owner: Name<'a>,
    /// The class.
    pub class: Class,
    /// The record data.
    pub rdata: I,
}

impl<'a, I> Rrset<'a, I>
where
    I: IntoIterator,
    I::Item: ComposeRdata,
{
    /// Groups an owner name, class and record data.
    #[inline]
    pub const fn new(owner: Name<'a>, class: Class, rdata: I) -> Self {
        Rrset {
            owner,
            class,
            rdata,
        }
    }
}

/// Adapts a message [`Record`] so its data can be fed to [`Rrset`]
/// without allocating: composing parses the record data
/// ([`Record::data`]) and re-encodes it.
#[derive(Clone, Copy, Debug)]
pub struct RecordRdata<'a>(pub Record<'a>);

impl ComposeRdata for RecordRdata<'_> {
    #[inline]
    fn rtype(&self) -> Rtype {
        self.0.rtype()
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        self.0.data()?.compose_rdata(c)
    }
}

/// A DNSKEY together with its owner name (the zone apex): what signs and
/// validates RRSIGs.
///
/// ```
/// use dnsbox::dnssec::{Algorithm, ZoneKey};
/// use dnsbox::rdata::Dnskey;
/// use dnsbox::{NameBuf, Rtype};
///
/// let apex: NameBuf = "example.".parse()?;
/// let www: NameBuf = "www.example.".parse()?;
/// let key = ZoneKey::new(apex.as_name(), Dnskey::new(256, 3, Algorithm::ED25519, &[1; 32]));
/// let template = key.rrsig_template(www.as_name(), Rtype::A, 3600, 1_000, 2_000);
/// assert_eq!((template.labels, template.key_tag), (2, key.key_tag()));
/// assert_eq!(key.check_rrsig(&template), Ok(()));
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ZoneKey<'a> {
    /// The DNSKEY owner name: the zone apex and RRSIG signer name.
    pub owner: Name<'a>,
    /// The key.
    pub dnskey: Dnskey<'a>,
}

impl<'a> ZoneKey<'a> {
    /// Pairs a DNSKEY with its owner name.
    #[inline]
    pub const fn new(owner: Name<'a>, dnskey: Dnskey<'a>) -> Self {
        ZoneKey { owner, dnskey }
    }

    /// The key tag (RFC 4034 Appendix B).
    #[inline]
    pub fn key_tag(&self) -> u16 {
        self.dnskey.key_tag()
    }

    /// Checks that `rrsig` designates this key (RFC 4035 §5.3.1): the
    /// signer's name is the key's owner, the algorithm and key tag match,
    /// the protocol is 3 and the Zone Key flag is set.
    ///
    /// Fails with [`Error::KeyMismatch`].
    pub fn check_rrsig(&self, rrsig: &Rrsig<'_>) -> Result<()> {
        let k = &self.dnskey;
        if rrsig.signer_name != self.owner
            || rrsig.algorithm != k.algorithm
            || k.protocol != 3
            || !k.is_zone_key()
            || rrsig.key_tag != k.key_tag()
        {
            return Err(Error::KeyMismatch);
        }
        Ok(())
    }

    /// An RRSIG for the RRset at `owner` of type `rtype` and TTL `ttl`, to
    /// be signed by this key: the labels field counts `owner` without a
    /// leading wildcard label (RFC 4034 §3.1.3), and the signature is
    /// empty. Sign it with [`sign_rrset`] and complete it with
    /// [`Rrsig::with_signature`].
    pub fn rrsig_template(
        &self,
        owner: Name<'_>,
        rtype: Rtype,
        ttl: u32,
        inception: u32,
        expiration: u32,
    ) -> Rrsig<'a> {
        let labels = owner.label_count() - usize::from(owner.is_wildcard());
        Rrsig {
            type_covered: rtype,
            algorithm: self.dnskey.algorithm,
            labels: labels as u8,
            original_ttl: ttl,
            expiration,
            inception,
            key_tag: self.key_tag(),
            signer_name: self.owner,
            signature: &[],
        }
    }

    /// The DS digest of this key (RFC 4034 §5.1.4).
    #[cfg(feature = "dnssec-digest")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec-digest")))]
    pub fn ds(&self, digest_type: super::DigestType) -> Result<super::DsDigest> {
        super::DsDigest::compute(self.owner, &self.dnskey, digest_type)
    }
}

/// The owner name an RRSIG's signature covers: `owner` lowercased, or, if
/// the RRSIG's labels field is smaller than its label count (the RRset was
/// synthesized from a wildcard), `*.` followed by the rightmost `labels`
/// labels (RFC 4035 §5.3.2, RFC 4034 §3.1.3).
///
/// Fails with [`Error::RrsetMismatch`] if the labels field exceeds the
/// owner's label count.
///
/// ```
/// use dnsbox::dnssec::{Algorithm, ZoneKey, rrsig_owner};
/// use dnsbox::rdata::Dnskey;
/// use dnsbox::{NameBuf, Rtype};
///
/// let apex: NameBuf = "example.".parse()?;
/// let key = ZoneKey::new(apex.as_name(), Dnskey::new(256, 3, Algorithm::ED25519, &[1; 32]));
/// let wildcard: NameBuf = "*.example.".parse()?;
/// let rrsig = key.rrsig_template(wildcard.as_name(), Rtype::A, 60, 0, 1);
/// let expanded: NameBuf = "A.B.Example.".parse()?;
/// assert_eq!(rrsig_owner(&rrsig, expanded.as_name())?.to_string(), "*.example.");
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn rrsig_owner(rrsig: &Rrsig<'_>, owner: Name<'_>) -> Result<NameBuf> {
    let count = owner.label_count();
    let labels = usize::from(rrsig.labels);
    let extra = count.checked_sub(labels).ok_or(Error::RrsetMismatch)?;
    let mut name = if extra == 0 {
        NameBuf::from_name(owner)
    } else {
        let mut n = NameBuf::from_name(owner.strip_labels(extra).ok_or(Error::RrsetMismatch)?);
        n.prepend_label(b"*")?;
        n
    };
    name.make_ascii_lowercase();
    Ok(name)
}

/// Checks the parts of RFC 4035 §5.3.1 that depend only on the RRSIG and
/// the RRset owner: the labels field does not exceed the owner's label
/// count and the owner is inside the signer's zone
/// ([`Error::RrsetMismatch`]), and `now` (seconds since 1970, modulo
/// 2^32) is within the validity period ([`Error::SignatureExpired`],
/// [`Error::SignatureNotYetValid`]; serial arithmetic, RFC 4034 §3.1.5).
///
/// The RRSIG's class and owner must equal the RRset's and its type
/// covered must be the RRset type; the caller selects records that way.
pub fn check_rrsig(rrsig: &Rrsig<'_>, owner: Name<'_>, now: u32) -> Result<()> {
    check_coverage(rrsig, owner)?;
    check_validity(rrsig.inception, rrsig.expiration, now)
}

/// The time-independent part of [`check_rrsig`].
fn check_coverage(rrsig: &Rrsig<'_>, owner: Name<'_>) -> Result<()> {
    if usize::from(rrsig.labels) > owner.label_count() || !owner.is_subdomain_of(&rrsig.signer_name)
    {
        return Err(Error::RrsetMismatch);
    }
    Ok(())
}

/// Appends the data an RRSIG signs to `out` (RFC 4034 §3.1.8.1): the
/// RRSIG RDATA without the signature, with the signer's name in canonical
/// form, followed by the RRset in canonical form and order with the
/// RRSIG's original TTL and the owner from [`rrsig_owner`] (wildcard
/// reconstruction, RFC 4035 §5.3.2).
///
/// Fails with [`Error::RrsetMismatch`] if a record is not of the type
/// covered, if the RRset is empty, or if the labels field exceeds the
/// owner's label count. On error, `out` is left as it was.
///
/// ```
/// use dnsbox::dnssec::{Algorithm, Rrset, ZoneKey, signed_data};
/// use dnsbox::rdata::{A, Dnskey};
/// use dnsbox::{Class, NameBuf, Rtype, WireWriter};
///
/// let apex: NameBuf = "example.".parse()?;
/// let www: NameBuf = "www.example.".parse()?;
/// let key = ZoneKey::new(apex.as_name(), Dnskey::new(256, 3, Algorithm::ED25519, &[1; 32]));
/// let rrsig = key.rrsig_template(www.as_name(), Rtype::A, 3600, 1_000, 2_000);
/// let rdata = [A::new([192, 0, 2, 1].into())];
/// let mut buf = [0u8; 128];
/// let mut out = WireWriter::new(&mut buf);
/// signed_data(&mut out, &rrsig, Rrset::new(www.as_name(), Class::IN, &rdata))?;
/// assert_eq!(out.len(), 18 + 9 + (13 + 10 + 4));
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn signed_data<B, I>(out: &mut B, rrsig: &Rrsig<'_>, rrset: Rrset<'_, I>) -> Result<()>
where
    B: OutBuf,
    I: IntoIterator,
    I::Item: ComposeRdata,
{
    let start = out.as_bytes().len();
    let r = write_signed_data(out, rrsig, rrset);
    if r.is_err() {
        out.truncate(start);
    }
    r
}

fn write_signed_data<B, I>(out: &mut B, rrsig: &Rrsig<'_>, rrset: Rrset<'_, I>) -> Result<()>
where
    B: OutBuf,
    I: IntoIterator,
    I::Item: ComposeRdata,
{
    let owner = rrsig_owner(rrsig, rrset.owner)?;
    rrsig.compose_unsigned(&mut Canonical::new(&mut *out))?;
    let mut set = CanonicalRrset::new(
        out,
        owner.as_name(),
        rrsig.type_covered,
        rrset.class,
        rrsig.original_ttl,
    );
    for rdata in rrset.rdata {
        set.push(&rdata)?;
    }
    if set.is_empty() {
        return Err(Error::RrsetMismatch);
    }
    Ok(())
}

/// Validates `rrsig` over `rrset` with `key` (RFC 4035 §5.3): runs
/// [`check_rrsig`] and [`ZoneKey::check_rrsig`], builds the signed data
/// at the end of `scratch` (removed again afterwards) and has `verifier`
/// check the signature.
///
/// `now` is the current time in seconds since 1970 (modulo 2^32). The
/// caller is responsible for having authenticated `key` (through a DS or
/// a trust anchor) and for matching the RRSIG's owner, class and type
/// covered with the RRset's.
///
/// ```
/// # #[cfg(feature = "dnssec")] {
/// use dnsbox::dnssec::{Algorithm, PurecryptoVerifier, Rrset, Signer, SigningKey, ZoneKey, sign_rrset, verify_rrsig};
/// use dnsbox::rdata::{A, Dnskey};
/// use dnsbox::{Class, NameBuf, Rtype};
///
/// let signer = SigningKey::from_private_bytes(Algorithm::ED25519, &[7; 32])?;
/// let apex: NameBuf = "example.".parse()?;
/// let www: NameBuf = "www.example.".parse()?;
/// let key = ZoneKey::new(apex.as_name(), signer.dnskey(Dnskey::ZONE));
/// let template = key.rrsig_template(www.as_name(), Rtype::A, 3600, 1_000, 2_000);
/// let rdata = [A::new([192, 0, 2, 1].into())];
/// let rrset = Rrset::new(www.as_name(), Class::IN, &rdata);
///
/// let mut scratch = Vec::new();
/// let mut sig = [0u8; 64];
/// let len = sign_rrset(&signer, &template, rrset, &mut scratch, &mut sig)?;
/// let rrsig = template.with_signature(&sig[..len]);
/// verify_rrsig(&PurecryptoVerifier, &key, &rrsig, rrset, 1_500, &mut scratch)?;
/// # }
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn verify_rrsig<V, B, I>(
    verifier: &V,
    key: &ZoneKey<'_>,
    rrsig: &Rrsig<'_>,
    rrset: Rrset<'_, I>,
    now: u32,
    scratch: &mut B,
) -> Result<()>
where
    V: Verifier + ?Sized,
    B: OutBuf,
    I: IntoIterator,
    I::Item: ComposeRdata,
{
    check_rrsig(rrsig, rrset.owner, now)?;
    key.check_rrsig(rrsig)?;
    if !verifier.supports(rrsig.algorithm) {
        return Err(Error::UnsupportedAlgorithm);
    }
    let start = scratch.as_bytes().len();
    signed_data(scratch, rrsig, rrset)?;
    let data = scratch.as_bytes().get(start..).unwrap_or(&[]);
    let r = verifier.verify(
        rrsig.algorithm,
        key.dnskey.public_key,
        data,
        rrsig.signature,
    );
    scratch.truncate(start);
    r
}

/// Signs `rrset` for the RRSIG `template` (see
/// [`ZoneKey::rrsig_template`]; its signature field is ignored), writing
/// the signature to `out` and returning its length. The signed data is
/// built at the end of `scratch` and removed again afterwards.
///
/// Fails with [`Error::KeyMismatch`] if the template's algorithm is not
/// the signer's, and with [`Error::RrsetMismatch`] if the template does
/// not fit the RRset (see [`signed_data`], [`check_rrsig`]).
pub fn sign_rrset<S, B, I>(
    signer: &S,
    template: &Rrsig<'_>,
    rrset: Rrset<'_, I>,
    scratch: &mut B,
    out: &mut [u8],
) -> Result<usize>
where
    S: Signer + ?Sized,
    B: OutBuf,
    I: IntoIterator,
    I::Item: ComposeRdata,
{
    if template.algorithm != signer.algorithm() {
        return Err(Error::KeyMismatch);
    }
    check_coverage(template, rrset.owner)?;
    let start = scratch.as_bytes().len();
    signed_data(scratch, template, rrset)?;
    let data = scratch.as_bytes().get(start..).unwrap_or(&[]);
    let r = signer.sign(data, out);
    scratch.truncate(start);
    r
}

#[cfg(test)]
mod tests;
