//! DNSSEC canonical form and ordering (RFC 4034 §6, RFC 6840 §5.1).
//!
//! - Canonical **names** are uncompressed and lowercase (§6.2);
//!   [`canonical_name`] writes one.
//! - Canonical **RDATA** is what [`ComposeRdata`] writes through
//!   [`Canonical`]: no compression, and the names of the types listed in
//!   §6.2 (as corrected by RFC 6840 §5.1, which removes NSEC) lowercased.
//!   Each record type declares this with its
//!   [`NameEncoding`](crate::NameEncoding).
//! - Canonical **RRset order** sorts records by their canonical RDATA as
//!   left-justified octet strings and drops duplicates (§6.3);
//!   [`CanonicalRrset`] writes a whole RRset that way without allocating.

use crate::name::{MAX_NAME_LEN, Name};
use crate::rdata::ComposeRdata;
use crate::wire::{Canonical, Composer, OutBuf};
use crate::{Class, Error, Result, Rtype};

/// Writes the canonical wire form of `name` — uncompressed, ASCII letters
/// lowercased (RFC 4034 §6.2) — into `out` and returns its length.
///
/// This is also the NSEC3 hash input (RFC 5155 §5) and the owner-name part
/// of the DS digest input (RFC 4034 §5.1.4).
///
/// ```
/// use dnsbox::NameBuf;
/// use dnsbox::dnssec::canonical_name;
///
/// let name: NameBuf = "WWW.Example".parse()?;
/// let mut buf = [0u8; 255];
/// let len = canonical_name(name.as_name(), &mut buf);
/// assert_eq!(&buf[..len], b"\x03www\x07example\x00");
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn canonical_name(name: Name<'_>, out: &mut [u8; MAX_NAME_LEN]) -> usize {
    let len = name.flatten(out);
    if let Some(bytes) = out.get_mut(..len) {
        bytes.make_ascii_lowercase();
    }
    len
}

/// Writes the RRs of one RRset in canonical form (RFC 4034 §6.2) and
/// canonical order (§6.3) into an [`OutBuf`], dropping duplicates.
///
/// Every record gets the same owner (lowercased), type, class and TTL; the
/// records are kept sorted by canonical RDATA as they are pushed, by
/// insertion directly in the output buffer, so no allocation is needed.
/// Each push costs time linear in the bytes already written.
///
/// This is the RRset part of the RRSIG signed data (RFC 4034 §3.1.8.1) and
/// can be used for any other canonical digest (e.g. ZONEMD, RFC 8976).
///
/// ```
/// use dnsbox::dnssec::CanonicalRrset;
/// use dnsbox::rdata::A;
/// use dnsbox::{Class, NameBuf, Rtype, WireWriter};
///
/// let owner: NameBuf = "A.Example".parse()?;
/// let mut buf = [0u8; 128];
/// let mut out = WireWriter::new(&mut buf);
/// let mut rrset = CanonicalRrset::new(&mut out, owner.as_name(), Rtype::A, Class::IN, 300);
/// rrset.push(&A::new([192, 0, 2, 2].into()))?;
/// rrset.push(&A::new([192, 0, 2, 1].into()))?;
/// assert!(!rrset.push(&A::new([192, 0, 2, 2].into()))?); // duplicate
/// assert_eq!(rrset.len(), 2);
/// let rr = b"\x01a\x07example\x00\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04";
/// assert_eq!(rrset.finish(), 2 * (rr.len() + 4));
/// assert_eq!(out.written(), [&rr[..], &[192, 0, 2, 1], rr, &[192, 0, 2, 2]].concat());
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Debug)]
pub struct CanonicalRrset<'b, B: OutBuf> {
    out: &'b mut B,
    /// Offset in `out` of the first RR.
    start: usize,
    owner: [u8; MAX_NAME_LEN],
    owner_len: usize,
    rtype: Rtype,
    class: Class,
    ttl: u32,
    count: usize,
}

impl<'b, B: OutBuf> CanonicalRrset<'b, B> {
    /// Starts an RRset at the current end of `out`. `owner` is lowercased;
    /// `ttl` should be the RRSIG's original TTL when building signed data.
    pub fn new(out: &'b mut B, owner: Name<'_>, rtype: Rtype, class: Class, ttl: u32) -> Self {
        let mut buf = [0u8; MAX_NAME_LEN];
        let owner_len = canonical_name(owner, &mut buf);
        let start = out.as_bytes().len();
        CanonicalRrset {
            out,
            start,
            owner: buf,
            owner_len,
            rtype,
            class,
            ttl,
            count: 0,
        }
    }

    /// Number of distinct records written.
    #[inline]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether no record has been written.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The canonical RRset written so far.
    pub fn as_bytes(&self) -> &[u8] {
        self.out.as_bytes().get(self.start..).unwrap_or(&[])
    }

    /// Length of the owner + type + class + TTL prefix of each RR.
    const fn header_len(&self) -> usize {
        self.owner_len + 8
    }

    /// Adds one record. Returns `Ok(false)` if an identical record (same
    /// canonical RDATA) was already present (RFC 4034 §6.3).
    ///
    /// Fails with [`Error::RrsetMismatch`] if `rdata` is not of the
    /// RRset's type, and with the composer's error (e.g.
    /// [`Error::BufferTooSmall`]) if it cannot be written; in both cases
    /// the output is left as it was.
    pub fn push<D: ComposeRdata + ?Sized>(&mut self, rdata: &D) -> Result<bool> {
        if rdata.rtype() != self.rtype {
            return Err(Error::RrsetMismatch);
        }
        let entry = self.out.as_bytes().len();
        if let Err(e) = self.write_entry(rdata) {
            self.out.truncate(entry);
            return Err(e);
        }
        let hdr = self.header_len() + 2;
        let bytes = self.out.as_bytes();
        let new = bytes.get(entry + hdr..).unwrap_or(&[]);
        let mut pos = self.start;
        let mut insert_at = entry;
        while pos < entry {
            let rdlen = bytes
                .get(pos + hdr - 2..pos + hdr)
                .map_or(0, |l| usize::from(u16::from_be_bytes([l[0], l[1]])));
            let old = bytes.get(pos + hdr..pos + hdr + rdlen).unwrap_or(&[]);
            match old.cmp(new) {
                core::cmp::Ordering::Less => pos += hdr + rdlen,
                core::cmp::Ordering::Equal => {
                    self.out.truncate(entry);
                    return Ok(false);
                }
                core::cmp::Ordering::Greater => {
                    insert_at = pos;
                    break;
                }
            }
        }
        if insert_at < entry {
            let len = bytes.len() - entry;
            if let Some(tail) = self.out.as_bytes_mut().get_mut(insert_at..) {
                tail.rotate_right(len);
            }
        }
        self.count += 1;
        Ok(true)
    }

    fn write_entry<D: ComposeRdata + ?Sized>(&mut self, rdata: &D) -> Result<()> {
        let owner = self.owner.get(..self.owner_len).unwrap_or(&[]);
        self.out.put_bytes(owner)?;
        self.out.put_u16(self.rtype.get())?;
        self.out.put_u16(self.class.get())?;
        self.out.put_u32(self.ttl)?;
        Canonical::new(&mut *self.out).put_u16_prefixed(|c| rdata.compose_rdata(c))
    }

    /// Ends the RRset, returning the number of bytes written.
    pub fn finish(self) -> usize {
        self.out.as_bytes().len() - self.start
    }
}

/// The canonical form of one RDATA (RFC 4034 §6.2).
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub fn canonical_rdata<D: ComposeRdata + ?Sized>(rdata: &D) -> Result<alloc::vec::Vec<u8>> {
    let mut out = alloc::vec::Vec::new();
    rdata.compose_rdata(&mut Canonical::new(&mut out))?;
    Ok(out)
}

/// Sorts record data into canonical RRset order (RFC 4034 §6.3) and
/// removes duplicates (records with the same canonical RDATA).
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub fn sort_rrset<D: ComposeRdata>(rrset: &mut alloc::vec::Vec<D>) -> Result<()> {
    use alloc::vec::Vec;
    let keys = rrset
        .iter()
        .map(canonical_rdata)
        .collect::<Result<Vec<_>>>()?;
    let mut items: Vec<(Vec<u8>, D)> = keys.into_iter().zip(rrset.drain(..)).collect();
    items.sort_by(|a, b| a.0.cmp(&b.0));
    items.dedup_by(|a, b| a.0 == b.0);
    rrset.extend(items.into_iter().map(|(_, d)| d));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdata::{A, Mx, Nsec, TypeBitmap, UnknownRdata};
    use crate::{NameBuf, WireWriter};
    use std::vec::Vec;

    fn name(s: &str) -> NameBuf {
        NameBuf::from_text(s.as_bytes()).unwrap()
    }

    #[test]
    fn rrset_order() {
        // RFC 4034 §6.3: ordering by RDATA octets, shorter prefix first.
        let owner = name("Owner.Example");
        let mut out = Vec::new();
        let mut set = CanonicalRrset::new(&mut out, owner.as_name(), Rtype::new(999), Class::IN, 7);
        let datas: [&[u8]; 6] = [b"\x02\x01", b"\x01", b"\x02", b"", b"\x01\x00", b"\x02"];
        let mut fresh = Vec::new();
        for d in datas {
            fresh.push(set.push(&UnknownRdata::new(Rtype::new(999), d)).unwrap());
        }
        assert_eq!(fresh, [true, true, true, true, true, false]);
        assert_eq!(set.len(), 5);
        assert!(!set.is_empty());
        assert_eq!(
            set.push(&A::new([1, 2, 3, 4].into())),
            Err(Error::RrsetMismatch)
        );
        let total = set.as_bytes().len();
        assert_eq!(set.finish(), total);
        let hdr = b"\x05owner\x07example\x00\x03\xe7\x00\x01\x00\x00\x00\x07";
        let mut expected = Vec::new();
        for d in [&b""[..], b"\x01", b"\x01\x00", b"\x02", b"\x02\x01"] {
            expected.extend_from_slice(hdr);
            expected.extend_from_slice(&(d.len() as u16).to_be_bytes());
            expected.extend_from_slice(d);
        }
        assert_eq!(out, expected);
    }

    #[test]
    fn rdata_is_canonical() {
        // MX exchange is lowercased; NSEC next name is not (RFC 6840 §5.1).
        let ex = name("MAIL.Example");
        let mut buf = [0u8; 128];
        let mut w = WireWriter::new(&mut buf);
        let mut set = CanonicalRrset::new(&mut w, Name::ROOT, Rtype::MX, Class::IN, 0);
        set.push(&Mx {
            preference: 1,
            exchange: ex.as_name(),
        })
        .unwrap();
        assert!(set.as_bytes().ends_with(b"\x00\x01\x04mail\x07example\x00"));
        let mut w = WireWriter::new(&mut buf);
        let mut set = CanonicalRrset::new(&mut w, Name::ROOT, Rtype::NSEC, Class::IN, 0);
        set.push(&Nsec::new(ex.as_name(), TypeBitmap::default()))
            .unwrap();
        assert!(set.as_bytes().ends_with(b"\x04MAIL\x07Example\x00"));
    }

    #[test]
    fn failures_leave_output_untouched() {
        let mut buf = [0u8; 30];
        let mut w = WireWriter::new(&mut buf);
        w.put_u8(0xaa).unwrap();
        let mut set = CanonicalRrset::new(&mut w, Name::ROOT, Rtype::A, Class::IN, 0);
        set.push(&A::new([1, 1, 1, 1].into())).unwrap();
        // 1 + 15 + 15 > 30
        assert_eq!(
            set.push(&A::new([0, 0, 0, 0].into())),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(set.len(), 1);
        assert_eq!(set.finish(), 15);
        assert_eq!(w.len(), 16);
        assert_eq!(w.written()[0], 0xaa);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn sorting() {
        let mut v = std::vec![
            A::new([10, 0, 0, 2].into()),
            A::new([10, 0, 0, 1].into()),
            A::new([10, 0, 0, 2].into()),
        ];
        sort_rrset(&mut v).unwrap();
        assert_eq!(
            v,
            [A::new([10, 0, 0, 1].into()), A::new([10, 0, 0, 2].into())]
        );
        let ex = name("X.Y");
        let mx = Mx {
            preference: 5,
            exchange: ex.as_name(),
        };
        assert_eq!(canonical_rdata(&mx).unwrap(), b"\x00\x05\x01x\x01y\x00");
    }
}
