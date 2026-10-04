//! ZONEMD zone digests (RFC 8976 §3, §4): the SIMPLE collation scheme,
//! SHA-384 and SHA-512 digests, and verification.

use alloc::vec::Vec;
use core::cmp::Ordering;
#[cfg(feature = "dnssec-digest")]
use core::fmt;
use core::ops::Range;

use super::{RecordRdata, canonical_name};
#[cfg(feature = "dnssec-digest")]
use crate::Error;
use crate::message::Record;
use crate::name::{MAX_LABELS, MAX_NAME_LEN, Name, NameBuf};
use crate::rdata::ComposeRdata;
#[cfg(feature = "dnssec-digest")]
use crate::rdata::{Zonemd, ZonemdHashAlg, ZonemdScheme};
use crate::wire::{Canonical, Composer, WireReader};
use crate::{Class, Result, Rtype};

/// One record of a zone, as fed to [`ZoneCollation`]: owner name, class,
/// TTL and record data (any [`ComposeRdata`], e.g. typed data, `RData`, or
/// [`RecordRdata`] around a message record).
#[derive(Clone, Copy, Debug)]
pub struct ZonemdRecord<'a, D> {
    /// The owner name.
    pub name: Name<'a>,
    /// The class.
    pub class: Class,
    /// The TTL.
    pub ttl: u32,
    /// The record data.
    pub data: D,
}

impl<'a, D> ZonemdRecord<'a, D> {
    /// Groups the parts of a record.
    #[inline]
    pub const fn new(name: Name<'a>, class: Class, ttl: u32, data: D) -> Self {
        ZonemdRecord {
            name,
            class,
            ttl,
            data,
        }
    }
}

impl<'a> From<Record<'a>> for ZonemdRecord<'a, RecordRdata<'a>> {
    /// A message record (e.g. from a zone transfer), its data re-encoded
    /// through [`RecordRdata`].
    #[inline]
    fn from(rr: Record<'a>) -> Self {
        ZonemdRecord::new(rr.name(), rr.class(), rr.ttl(), RecordRdata(rr))
    }
}

/// One collated RR: where it lives in the shared buffer.
#[derive(Clone, Copy, Debug)]
struct Entry {
    /// Offset of the RR (its canonical owner name).
    start: usize,
    /// Length of the owner name.
    owner_len: usize,
    /// Length of the whole RR.
    len: usize,
}

/// A zone collated for the ZONEMD SIMPLE scheme (RFC 8976 §3.3.1): every
/// in-zone RR in canonical form (RFC 4034 §6.2), sorted by owner name in
/// canonical order (§6.1), then numerically by type, then by RDATA
/// (§6.3), with duplicates removed (RFC 8976 §3.3.1.1).
///
/// Excluded: records outside the zone, the apex ZONEMD RRset and the
/// apex RRSIGs covering ZONEMD (both kept aside for [`verify`]); occluded
/// data and glue are included, as are non-apex ZONEMD records.
///
/// Building the collation allocates (one buffer holding every RR, plus an
/// index); hashing it needs the `dnssec-digest` feature, or any digest
/// over [`rrs`](Self::rrs).
///
/// [`verify`]: Self::verify
#[derive(Clone, Debug)]
pub struct ZoneCollation {
    apex: NameBuf,
    data: Vec<u8>,
    entries: Vec<Entry>,
    /// The apex ZONEMD RDATAs, in canonical form.
    zonemd: Vec<u8>,
    zonemd_ranges: Vec<Range<usize>>,
}

impl ZoneCollation {
    /// Collates `records` for the zone at `apex`.
    ///
    /// Fails with the error of composing a record's data (e.g.
    /// [`Error::InvalidRdata`](crate::Error::InvalidRdata)) or
    /// [`Error::BufferTooSmall`](crate::Error::BufferTooSmall) for RDATA
    /// longer than 65535 octets.
    pub fn new<'r, I, D>(apex: Name<'_>, records: I) -> Result<Self>
    where
        I: IntoIterator<Item = ZonemdRecord<'r, D>>,
        D: ComposeRdata,
    {
        let mut apex_buf = NameBuf::from_name(apex);
        apex_buf.make_ascii_lowercase();
        let mut c = ZoneCollation {
            apex: apex_buf,
            data: Vec::new(),
            entries: Vec::new(),
            zonemd: Vec::new(),
            zonemd_ranges: Vec::new(),
        };
        for rr in records {
            c.push(rr)?;
        }
        let data = &c.data;
        c.entries.sort_by(|a, b| cmp_entries(data, a, b));
        c.entries
            .dedup_by(|a, b| cmp_entries(data, a, b) == Ordering::Equal);
        Ok(c)
    }

    /// Adds one record.
    fn push<D: ComposeRdata>(&mut self, rr: ZonemdRecord<'_, D>) -> Result<()> {
        let apex = self.apex.as_name();
        if !rr.name.is_subdomain_of(&apex) {
            return Ok(()); // out-of-zone data (RFC 8976 Appendix A.2)
        }
        let rtype = rr.data.rtype();
        let at_apex = rr.name == apex;
        if at_apex && rtype == Rtype::ZONEMD {
            // Kept aside, not digested. One that fails to encode (e.g. a
            // digest of the wrong length, rejected by typed parsing) is
            // kept as empty RDATA: it cannot verify, but does not make
            // the zone fail to collate (RFC 8976 §4 step 5).
            let start = self.zonemd.len();
            if rr
                .data
                .compose_rdata(&mut Canonical::new(&mut self.zonemd))
                .is_err()
            {
                self.zonemd.truncate(start);
            }
            let new = self.zonemd.get(start..).unwrap_or(&[]);
            if self.zonemd_rdata().any(|old| old == new) {
                // A duplicate RR (RFC 2181 §5).
                self.zonemd.truncate(start);
            } else {
                self.zonemd_ranges.push(start..self.zonemd.len());
            }
            return Ok(());
        }
        let start = self.data.len();
        let r = write_rr(&mut self.data, &rr, rtype);
        let owner_len = match r {
            Ok(n) => n,
            Err(e) => {
                self.data.truncate(start);
                return Err(e);
            }
        };
        let len = self.data.len() - start;
        // The RRSIG covering the apex ZONEMD RRset (RFC 8976 §3.3.1.1):
        // its type covered is the first RDATA field.
        let rdata = self.data.get(start + owner_len + 10..).unwrap_or(&[]);
        if at_apex
            && rtype == Rtype::RRSIG
            && rdata.get(..2) == Some(&Rtype::ZONEMD.get().to_be_bytes()[..])
        {
            self.data.truncate(start);
            return Ok(());
        }
        self.entries.push(Entry {
            start,
            owner_len,
            len,
        });
        Ok(())
    }

    /// The zone apex (lowercase).
    #[inline]
    #[must_use]
    pub fn apex(&self) -> Name<'_> {
        self.apex.as_name()
    }

    /// Number of RRs in the collation (after removing duplicates).
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the collation holds no RR.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The collated RRs in canonical wire form and order: the SIMPLE
    /// digest is the hash of their concatenation (RFC 8976 §3.3.1.2).
    pub fn rrs(&self) -> impl Iterator<Item = &[u8]> + '_ {
        self.entries
            .iter()
            .map(|e| self.data.get(e.start..e.start + e.len).unwrap_or(&[]))
    }

    /// The serial of the apex SOA, or `None` unless there is exactly one
    /// (distinct) apex SOA RR.
    #[must_use]
    pub fn soa_serial(&self) -> Option<u32> {
        let mut serials = self
            .entries
            .iter()
            .filter(|e| self.owner(e) == self.apex.as_wire() && self.rtype(e) == Rtype::SOA)
            .map(|e| {
                let mut r = WireReader::new(self.rdata(e));
                r.read_name_uncompressed()?;
                r.read_name_uncompressed()?;
                r.read_u32()
            });
        match (serials.next(), serials.next()) {
            (Some(Ok(serial)), None) => Some(serial),
            _ => None,
        }
    }

    /// The apex ZONEMD RRs (excluded from the digest), as raw canonical
    /// RDATA in input order. Parse them with
    /// [`ParseRdata`](crate::ParseRdata) for [`Zonemd`](crate::rdata::Zonemd).
    pub fn zonemd_rdata(&self) -> impl Iterator<Item = &[u8]> + '_ {
        self.zonemd_ranges
            .iter()
            .map(|r| self.zonemd.get(r.clone()).unwrap_or(&[]))
    }

    fn owner(&self, e: &Entry) -> &[u8] {
        self.data.get(e.start..e.start + e.owner_len).unwrap_or(&[])
    }

    fn rtype(&self, e: &Entry) -> Rtype {
        let at = e.start + e.owner_len;
        self.data.get(at..at + 2).map_or(Rtype::new(0), |b| {
            Rtype::new(u16::from_be_bytes([b[0], b[1]]))
        })
    }

    fn rdata(&self, e: &Entry) -> &[u8] {
        self.data
            .get(e.start + e.owner_len + 10..e.start + e.len)
            .unwrap_or(&[])
    }
}

/// Writes one RR in canonical form at the end of `out`; returns the
/// owner name's length.
fn write_rr<D: ComposeRdata>(
    out: &mut Vec<u8>,
    rr: &ZonemdRecord<'_, D>,
    rtype: Rtype,
) -> Result<usize> {
    let mut owner = [0u8; MAX_NAME_LEN];
    let owner_len = canonical_name(rr.name, &mut owner);
    out.put_bytes(owner.get(..owner_len).unwrap_or(&[]))?;
    out.put_u16(rtype.get())?;
    out.put_u16(rr.class.get())?;
    out.put_u32(rr.ttl)?;
    Canonical::new(out).put_u16_prefixed(|c| rr.data.compose_rdata(c))?;
    Ok(owner_len)
}

/// Canonical order of two collated RRs (RFC 8976 §3.3.1): owner name
/// (RFC 4034 §6.1), type, class, RDATA (§6.3). The TTL does not take part:
/// RRs equal in everything else are duplicates.
fn cmp_entries(data: &[u8], a: &Entry, b: &Entry) -> Ordering {
    let field =
        |e: &Entry, r: Range<usize>| data.get(e.start + r.start..e.start + r.end).unwrap_or(&[]);
    let (ao, bo) = (field(a, 0..a.owner_len), field(b, 0..b.owner_len));
    cmp_wire_names(ao, bo)
        // type, class
        .then_with(|| {
            field(a, a.owner_len..a.owner_len + 4).cmp(field(b, b.owner_len..b.owner_len + 4))
        })
        // RDATA (skipping TTL and RDLENGTH)
        .then_with(|| field(a, a.owner_len + 10..a.len).cmp(field(b, b.owner_len + 10..b.len)))
}

/// Canonical order (RFC 4034 §6.1) of two lowercase uncompressed wire
/// names: labels compared right to left as octet strings.
fn cmp_wire_names(a: &[u8], b: &[u8]) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let mut a_off = [0u8; MAX_LABELS];
    let mut b_off = [0u8; MAX_LABELS];
    let a_n = label_offsets(a, &mut a_off);
    let b_n = label_offsets(b, &mut b_off);
    for i in 1..=a_n.min(b_n) {
        let la = label_at(a, a_off[a_n - i]);
        let lb = label_at(b, b_off[b_n - i]);
        match la.cmp(lb) {
            Ordering::Equal => {}
            o => return o,
        }
    }
    a_n.cmp(&b_n)
}

/// Records the offset of each label of a wire name; returns the count.
fn label_offsets(wire: &[u8], out: &mut [u8; MAX_LABELS]) -> usize {
    let mut n = 0;
    let mut pos = 0usize;
    while let Some(&l) = wire.get(pos) {
        if l == 0 || n >= MAX_LABELS {
            break;
        }
        out[n] = pos as u8;
        n += 1;
        pos += 1 + usize::from(l);
    }
    n
}

/// The label at `off` of a wire name.
fn label_at(wire: &[u8], off: u8) -> &[u8] {
    let off = usize::from(off);
    let len = usize::from(wire.get(off).copied().unwrap_or(0));
    wire.get(off + 1..off + 1 + len).unwrap_or(&[])
}

/// Why ZONEMD verification did not succeed (RFC 8976 §4).
///
/// With several ZONEMD RRs, the failure of the one that got furthest
/// through the RFC 8976 §4 checks is reported.
#[cfg(feature = "dnssec-digest")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec-digest")))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ZonemdFailure {
    /// The zone data could not be collated (a record failed to encode).
    Malformed(Error),
    /// The zone has no apex SOA RR, or more than one.
    NoSoa,
    /// The zone has no apex ZONEMD RR (RFC 8976 §4 step 2).
    NoZonemd,
    /// The ZONEMD RDATA is malformed: too short to hold its fixed fields,
    /// or rejected when encoded (e.g. by typed parsing, for a digest of
    /// the wrong length; RFC 8976 §2.2.4).
    BadZonemd,
    /// Several ZONEMD RRs have the same scheme and hash algorithm
    /// (RFC 8976 §4 step 4).
    DuplicateTuple,
    /// The ZONEMD serial is not the SOA serial (RFC 8976 §4 step 5a).
    SerialMismatch,
    /// The scheme is not supported (only SIMPLE is; RFC 8976 §4 step 5b).
    UnsupportedScheme,
    /// The hash algorithm is not supported (only SHA-384 and SHA-512 are;
    /// RFC 8976 §4 step 5c).
    UnsupportedHashAlgorithm,
    /// The digest is shorter than 12 octets or not the hash algorithm's
    /// length (RFC 8976 §4 step 5d).
    DigestLength,
    /// The computed digest differs (RFC 8976 §4 step 5f).
    DigestMismatch,
}

#[cfg(feature = "dnssec-digest")]
impl ZonemdFailure {
    /// How far through the RFC 8976 §4 checks the failure happened.
    const fn rank(self) -> u8 {
        match self {
            ZonemdFailure::Malformed(_) | ZonemdFailure::NoSoa | ZonemdFailure::NoZonemd => 0,
            ZonemdFailure::BadZonemd => 1,
            ZonemdFailure::DuplicateTuple => 2,
            ZonemdFailure::SerialMismatch => 3,
            ZonemdFailure::UnsupportedScheme => 4,
            ZonemdFailure::UnsupportedHashAlgorithm => 5,
            ZonemdFailure::DigestLength => 6,
            ZonemdFailure::DigestMismatch => 7,
        }
    }
}

#[cfg(feature = "dnssec-digest")]
impl fmt::Display for ZonemdFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZonemdFailure::Malformed(e) => write!(f, "malformed zone data: {e}"),
            ZonemdFailure::NoSoa => f.write_str("no unique apex SOA"),
            ZonemdFailure::NoZonemd => f.write_str("no apex ZONEMD"),
            ZonemdFailure::BadZonemd => f.write_str("malformed ZONEMD"),
            ZonemdFailure::DuplicateTuple => {
                f.write_str("duplicate ZONEMD scheme and hash algorithm")
            }
            ZonemdFailure::SerialMismatch => f.write_str("ZONEMD serial does not match the SOA"),
            ZonemdFailure::UnsupportedScheme => f.write_str("unsupported ZONEMD scheme"),
            ZonemdFailure::UnsupportedHashAlgorithm => {
                f.write_str("unsupported ZONEMD hash algorithm")
            }
            ZonemdFailure::DigestLength => f.write_str("wrong ZONEMD digest length"),
            ZonemdFailure::DigestMismatch => f.write_str("ZONEMD digest mismatch"),
        }
    }
}

#[cfg(feature = "dnssec-digest")]
impl core::error::Error for ZonemdFailure {}

/// A successful ZONEMD verification: the ZONEMD RR that matched.
#[cfg(feature = "dnssec-digest")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec-digest")))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ZonemdVerified {
    /// The zone serial (SOA and ZONEMD).
    pub serial: u32,
    /// The scheme (SIMPLE).
    pub scheme: ZonemdScheme,
    /// The hash algorithm.
    pub hash_alg: ZonemdHashAlg,
}

/// The fixed fields of a ZONEMD RDATA, read without enforcing the digest
/// length (so that verification can report it).
#[cfg(feature = "dnssec-digest")]
fn zonemd_fields(rdata: &[u8]) -> Option<Zonemd<'_>> {
    let mut r = WireReader::new(rdata);
    let serial = r.read_u32().ok()?;
    let [scheme, hash_alg] = r.read_array().ok()?;
    Some(Zonemd {
        serial,
        scheme: ZonemdScheme::new(scheme),
        hash_alg: ZonemdHashAlg::new(hash_alg),
        digest: r.read_rest(),
    })
}

/// A computed ZONEMD digest (RFC 8976 §3.3.1.2).
#[cfg(feature = "dnssec-digest")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec-digest")))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ZonemdDigest {
    hash_alg: ZonemdHashAlg,
    digest: [u8; 64],
    len: u8,
}

#[cfg(feature = "dnssec-digest")]
impl ZonemdDigest {
    /// The hash algorithm.
    #[inline]
    #[must_use]
    pub const fn hash_alg(&self) -> ZonemdHashAlg {
        self.hash_alg
    }

    /// The digest.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.digest.get(..usize::from(self.len)).unwrap_or(&[])
    }

    /// The ZONEMD record data publishing this digest for the zone at SOA
    /// serial `serial` (RFC 8976 §3.4).
    #[inline]
    #[must_use]
    pub fn to_zonemd(&self, serial: u32) -> Zonemd<'_> {
        Zonemd {
            serial,
            scheme: ZonemdScheme::SIMPLE,
            hash_alg: self.hash_alg,
            digest: self.as_bytes(),
        }
    }
}

#[cfg(feature = "dnssec-digest")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec-digest")))]
impl ZoneCollation {
    /// The SIMPLE digest of the zone with `hash_alg` (RFC 8976 §3.3.1.2),
    /// computed by `purecrypto`.
    ///
    /// Fails with [`Error::UnsupportedAlgorithm`] for hash algorithms other
    /// than SHA-384 and SHA-512.
    pub fn digest(&self, hash_alg: ZonemdHashAlg) -> Result<ZonemdDigest> {
        use purecrypto::hash::{Digest, Sha384, Sha512};
        fn run<H: Digest>(c: &ZoneCollation, out: &mut [u8; 64]) -> u8 {
            let mut h = H::new();
            for rr in c.rrs() {
                h.update(rr);
            }
            let d = h.finalize();
            let d = d.as_ref();
            let len = d.len().min(out.len());
            if let (Some(dst), Some(src)) = (out.get_mut(..len), d.get(..len)) {
                dst.copy_from_slice(src);
            }
            len as u8
        }
        let mut digest = [0u8; 64];
        let len = match hash_alg {
            ZonemdHashAlg::SHA384 => run::<Sha384>(self, &mut digest),
            ZonemdHashAlg::SHA512 => run::<Sha512>(self, &mut digest),
            _ => return Err(Error::UnsupportedAlgorithm),
        };
        Ok(ZonemdDigest {
            hash_alg,
            digest,
            len,
        })
    }

    /// Verifies the zone against its apex ZONEMD RRs (RFC 8976 §4 steps
    /// 4 and 5): succeeds if any ZONEMD RR with a unique (scheme, hash
    /// algorithm) tuple, the SOA serial, the SIMPLE scheme, SHA-384 or
    /// SHA-512 and a digest of the right length matches the computed
    /// digest.
    ///
    /// The DNSSEC steps (1–3: the ZONEMD and SOA RRsets must be validated
    /// when the zone is signed) are the caller's.
    pub fn verify(&self) -> core::result::Result<ZonemdVerified, ZonemdFailure> {
        let serial = self.soa_serial().ok_or(ZonemdFailure::NoSoa)?;
        let mut failure = ZonemdFailure::NoZonemd;
        let mut computed: [Option<ZonemdDigest>; 2] = [None, None];
        for rdata in self.zonemd_rdata() {
            let outcome = self.check(rdata, serial, &mut computed);
            match outcome {
                Ok(v) => return Ok(v),
                Err(f) if f.rank() >= failure.rank() => failure = f,
                Err(_) => {}
            }
        }
        Err(failure)
    }

    /// Checks one ZONEMD RR (RFC 8976 §4 step 5).
    fn check(
        &self,
        rdata: &[u8],
        serial: u32,
        computed: &mut [Option<ZonemdDigest>; 2],
    ) -> core::result::Result<ZonemdVerified, ZonemdFailure> {
        let z = zonemd_fields(rdata).ok_or(ZonemdFailure::BadZonemd)?;
        let same_tuple = self
            .zonemd_rdata()
            .filter_map(zonemd_fields)
            .filter(|o| o.scheme == z.scheme && o.hash_alg == z.hash_alg)
            .count();
        if same_tuple > 1 {
            return Err(ZonemdFailure::DuplicateTuple);
        }
        if z.serial != serial {
            return Err(ZonemdFailure::SerialMismatch);
        }
        if z.scheme != ZonemdScheme::SIMPLE {
            return Err(ZonemdFailure::UnsupportedScheme);
        }
        let slot = match z.hash_alg {
            ZonemdHashAlg::SHA384 => 0,
            ZonemdHashAlg::SHA512 => 1,
            _ => return Err(ZonemdFailure::UnsupportedHashAlgorithm),
        };
        if Some(z.digest.len()) != z.hash_alg.digest_len()
            || z.digest.len() < Zonemd::MIN_DIGEST_LEN
        {
            return Err(ZonemdFailure::DigestLength);
        }
        let digest = match computed[slot] {
            Some(d) => d,
            None => {
                let d = self.digest(z.hash_alg).map_err(ZonemdFailure::Malformed)?;
                computed[slot] = Some(d);
                d
            }
        };
        if digest.as_bytes() != z.digest {
            return Err(ZonemdFailure::DigestMismatch);
        }
        Ok(ZonemdVerified {
            serial,
            scheme: z.scheme,
            hash_alg: z.hash_alg,
        })
    }
}

/// Computes the SIMPLE ZONEMD digest of the zone at `apex` with
/// `hash_alg` (RFC 8976 §3): collates `records` with [`ZoneCollation`]
/// and hashes them. Fails as [`ZoneCollation::new`] and
/// [`ZoneCollation::digest`].
///
/// ```
/// use dnsbox::dnssec::{ZonemdRecord, zonemd_digest};
/// use dnsbox::rdata::{Ns, RData, Soa, ZonemdHashAlg, A, Aaaa};
/// use dnsbox::{Class, NameBuf};
///
/// // RFC 8976 Appendix A.1.
/// let n = |s: &str| s.parse::<NameBuf>();
/// let (apex, ns1, ns2, admin) = (n("example")?, n("ns1.example")?, n("ns2.example")?, n("admin.example")?);
/// let soa = Soa { mname: ns1.as_name(), rname: admin.as_name(), serial: 2018031900,
///     refresh: 1800, retry: 900, expire: 604800, minimum: 86400 };
/// let records = [
///     ZonemdRecord::new(apex.as_name(), Class::IN, 86400, RData::Soa(soa)),
///     ZonemdRecord::new(apex.as_name(), Class::IN, 86400, RData::Ns(Ns::new(ns1.as_name()))),
///     ZonemdRecord::new(apex.as_name(), Class::IN, 86400, RData::Ns(Ns::new(ns2.as_name()))),
///     ZonemdRecord::new(ns1.as_name(), Class::IN, 3600, RData::A(A::new([203, 0, 113, 63].into()))),
///     ZonemdRecord::new(ns2.as_name(), Class::IN, 3600, RData::Aaaa(Aaaa::new("2001:db8::63".parse().unwrap()))),
/// ];
/// let digest = zonemd_digest(apex.as_name(), records, ZonemdHashAlg::SHA384)?;
/// assert!(digest.as_bytes().starts_with(&[0xc6, 0x80, 0x90, 0xd9]));
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[cfg(feature = "dnssec-digest")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec-digest")))]
pub fn zonemd_digest<'r, I, D>(
    apex: Name<'_>,
    records: I,
    hash_alg: ZonemdHashAlg,
) -> Result<ZonemdDigest>
where
    I: IntoIterator<Item = ZonemdRecord<'r, D>>,
    D: ComposeRdata,
{
    ZoneCollation::new(apex, records)?.digest(hash_alg)
}

/// Verifies the zone at `apex` against its apex ZONEMD RRs (RFC 8976 §4):
/// collates `records` with [`ZoneCollation`] and runs
/// [`ZoneCollation::verify`].
#[cfg(feature = "dnssec-digest")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec-digest")))]
pub fn verify_zonemd<'r, I, D>(
    apex: Name<'_>,
    records: I,
) -> core::result::Result<ZonemdVerified, ZonemdFailure>
where
    I: IntoIterator<Item = ZonemdRecord<'r, D>>,
    D: ComposeRdata,
{
    ZoneCollation::new(apex, records)
        .map_err(ZonemdFailure::Malformed)?
        .verify()
}

#[cfg(test)]
mod tests;
