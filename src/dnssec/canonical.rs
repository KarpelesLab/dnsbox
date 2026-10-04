//! DNSSEC canonical form and ordering (RFC 4034 §6, RFC 6840 §5.1).
//!
//! - Canonical **names** are uncompressed and lowercase (§6.2);
//!   [`canonical_name`] writes one.
//! - Canonical **RDATA** is what [`ComposeRdata`] writes through
//!   [`Canonical`]: no compression, and the names of the types listed in
//!   §6.2 lowercased, as corrected by RFC 6840 §5.1 (NSEC next names keep
//!   their case, RRSIG signer names are lowercased, HINFO holds no names).
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
/// Every record gets the same owner (lowercased), type, class and TTL.
/// [`push`](Self::push) appends records as given; [`finish`](Self::finish)
/// sorts them by canonical RDATA (as left-justified octet strings) and
/// removes duplicates. Sorting happens in the output buffer itself, so no
/// allocation is needed, with O(n log n) comparisons and linear copying;
/// it temporarily needs room for a second copy of the RRset plus four
/// octets per record after it.
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
/// let mut buf = [0u8; 256];
/// let mut out = WireWriter::new(&mut buf);
/// let mut rrset = CanonicalRrset::new(&mut out, owner.as_name(), Rtype::A, Class::IN, 300);
/// rrset.push(&A::new([192, 0, 2, 2].into()))?;
/// rrset.push(&A::new([192, 0, 2, 1].into()))?;
/// rrset.push(&A::new([192, 0, 2, 2].into()))?; // duplicate
/// assert_eq!(rrset.len(), 3);
/// let rr = b"\x01a\x07example\x00\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04";
/// assert_eq!(rrset.finish()?, 2 * (rr.len() + 4));
/// assert_eq!(out.as_bytes(), [&rr[..], &[192, 0, 2, 1], rr, &[192, 0, 2, 2]].concat());
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

    /// Number of records pushed (duplicates included).
    #[inline]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether no record has been pushed.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The RRs written so far, in push order.
    pub fn as_bytes(&self) -> &[u8] {
        self.out.as_bytes().get(self.start..).unwrap_or(&[])
    }

    /// Length of the owner + type + class + TTL + RDLENGTH prefix of each
    /// RR.
    const fn prefix_len(&self) -> usize {
        self.owner_len + 10
    }

    /// Appends one record in canonical form.
    ///
    /// Fails with [`Error::RrsetMismatch`] if `rdata` is not of the
    /// RRset's type, and with the composer's error (e.g.
    /// [`Error::BufferTooSmall`]) if it cannot be written; in both cases
    /// the output is left as it was.
    pub fn push<D: ComposeRdata + ?Sized>(&mut self, rdata: &D) -> Result<()> {
        if rdata.rtype() != self.rtype {
            return Err(Error::RrsetMismatch);
        }
        let entry = self.out.as_bytes().len();
        if let Err(e) = self.write_entry(rdata) {
            self.out.truncate(entry);
            return Err(e);
        }
        self.count += 1;
        Ok(())
    }

    fn write_entry<D: ComposeRdata + ?Sized>(&mut self, rdata: &D) -> Result<()> {
        let owner = self.owner.get(..self.owner_len).unwrap_or(&[]);
        self.out.put_bytes(owner)?;
        self.out.put_u16(self.rtype.get())?;
        self.out.put_u16(self.class.get())?;
        self.out.put_u32(self.ttl)?;
        Canonical::new(&mut *self.out).put_u16_prefixed(|c| rdata.compose_rdata(c))
    }

    /// Sorts the records into canonical order, removes duplicates, and
    /// returns the length of the finished RRset.
    ///
    /// Fails with [`Error::BufferTooSmall`] if the output has no room for
    /// the temporary sort space (see the type documentation); the RRset is
    /// then removed from the output.
    pub fn finish(mut self) -> Result<usize> {
        let r = self.sort();
        if r.is_err() {
            self.out.truncate(self.start);
        }
        r
    }

    fn sort(&mut self) -> Result<usize> {
        let end = self.out.as_bytes().len();
        let total = end - self.start;
        let n = self.count;
        if n < 2 {
            return Ok(total);
        }
        let prefix = self.prefix_len();

        // 1. A table of entry offsets after the RRs.
        let table = end;
        let mut pos = self.start;
        for _ in 0..n {
            let offset = u32::try_from(pos).map_err(|_| Error::BufferTooSmall)?;
            self.out.put_bytes(&offset.to_ne_bytes())?;
            pos += prefix + rdlen_at(self.out.as_bytes(), pos + prefix - 2);
        }

        // 2. Heapsort the table by RDATA.
        let bytes = self.out.as_bytes_mut();
        let less = |b: &[u8], i: usize, j: usize| {
            rdata_of(b, slot(b, table, i), prefix) < rdata_of(b, slot(b, table, j), prefix)
        };
        let sift = |b: &mut [u8], mut root: usize, len: usize| {
            loop {
                let mut child = 2 * root + 1;
                if child >= len {
                    break;
                }
                if child + 1 < len && less(b, child, child + 1) {
                    child += 1;
                }
                if !less(b, root, child) {
                    break;
                }
                swap_slots(b, table, root, child);
                root = child;
            }
        };
        for i in (0..n / 2).rev() {
            sift(bytes, i, n);
        }
        for last in (1..n).rev() {
            swap_slots(bytes, table, 0, last);
            sift(bytes, 0, last);
        }

        // 3. Room for the sorted copy.
        let dest = self.out.as_bytes().len();
        let mut left = total;
        while left > 0 {
            let chunk = left.min(64);
            self.out.put_bytes(&[0; 64][..chunk])?;
            left -= chunk;
        }

        // 4. Copy in order, skipping duplicates, then move into place.
        let bytes = self.out.as_bytes_mut();
        let mut w = dest;
        let mut prev: Option<usize> = None;
        let mut distinct = 0;
        for i in 0..n {
            let off = slot(bytes, table, i);
            if prev.is_some_and(|p| rdata_of(bytes, p, prefix) == rdata_of(bytes, off, prefix)) {
                continue;
            }
            let len = prefix + rdlen_at(bytes, off + prefix - 2);
            copy_within(bytes, off..off + len, w)?;
            w += len;
            prev = Some(off);
            distinct += 1;
        }
        copy_within(bytes, dest..w, self.start)?;
        let sorted = w - dest;
        self.out.truncate(self.start + sorted);
        self.count = distinct;
        Ok(sorted)
    }
}

/// The RDLENGTH stored at `at`.
fn rdlen_at(bytes: &[u8], at: usize) -> usize {
    bytes
        .get(at..at + 2)
        .map_or(0, |l| usize::from(u16::from_be_bytes([l[0], l[1]])))
}

/// The RDATA of the RR at `off`.
fn rdata_of(bytes: &[u8], off: usize, prefix: usize) -> &[u8] {
    let start = off + prefix;
    let len = rdlen_at(bytes, start - 2);
    bytes.get(start..start + len).unwrap_or(&[])
}

/// The offset stored in slot `i` of the table at `table`.
fn slot(bytes: &[u8], table: usize, i: usize) -> usize {
    let at = table + 4 * i;
    bytes
        .get(at..at + 4)
        .map_or(0, |b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]]) as usize)
}

/// Swaps slots `i` and `j` of the table at `table`.
fn swap_slots(bytes: &mut [u8], table: usize, i: usize, j: usize) {
    let (a, b) = (slot(bytes, table, i), slot(bytes, table, j));
    for (at, v) in [(table + 4 * i, b), (table + 4 * j, a)] {
        if let Some(dst) = bytes.get_mut(at..at + 4) {
            dst.copy_from_slice(&(v as u32).to_ne_bytes());
        }
    }
}

/// `copy_within` that reports out-of-range indices instead of panicking.
fn copy_within(bytes: &mut [u8], src: core::ops::Range<usize>, dest: usize) -> Result<()> {
    let len = src
        .end
        .checked_sub(src.start)
        .ok_or(Error::BufferTooSmall)?;
    if src.end > bytes.len() || dest.checked_add(len).is_none_or(|e| e > bytes.len()) {
        return Err(Error::BufferTooSmall);
    }
    bytes.copy_within(src, dest);
    Ok(())
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
        let mut buf = [0u8; 512];
        let mut out = WireWriter::new(&mut buf);
        let mut set = CanonicalRrset::new(&mut out, owner.as_name(), Rtype::new(999), Class::IN, 7);
        let datas: [&[u8]; 6] = [b"\x02\x01", b"\x01", b"\x02", b"", b"\x01\x00", b"\x02"];
        for d in datas {
            set.push(&UnknownRdata::new(Rtype::new(999), d)).unwrap();
        }
        assert_eq!(set.len(), 6);
        assert!(!set.is_empty());
        assert_eq!(
            set.push(&A::new([1, 2, 3, 4].into())),
            Err(Error::RrsetMismatch)
        );
        let hdr = b"\x05owner\x07example\x00\x03\xe7\x00\x01\x00\x00\x00\x07";
        assert!(set.as_bytes().starts_with(hdr));
        let mut expected = Vec::new();
        for d in [&b""[..], b"\x01", b"\x01\x00", b"\x02", b"\x02\x01"] {
            expected.extend_from_slice(hdr);
            expected.extend_from_slice(&(d.len() as u16).to_be_bytes());
            expected.extend_from_slice(d);
        }
        assert_eq!(set.finish(), Ok(expected.len()));
        assert_eq!(out.as_bytes(), expected);
    }

    #[test]
    fn sorting_matches_reference() {
        // Random RRsets with duplicates, against a straightforward sort.
        let mut state = 0x1234_5678_9abc_def1u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let t = Rtype::new(65000);
        for round in 0..300 {
            let n = (next() % 40) as usize;
            let datas: Vec<Vec<u8>> = (0..n)
                .map(|_| {
                    let len = (next() % 6) as usize;
                    (0..len).map(|_| (next() % 3) as u8).collect()
                })
                .collect();
            let mut buf = [0u8; 4096];
            let mut out = WireWriter::new(&mut buf);
            out.put_u16(0xbeef).unwrap();
            let mut set = CanonicalRrset::new(&mut out, Name::ROOT, t, Class::IN, 1);
            for d in &datas {
                set.push(&UnknownRdata::new(t, d)).unwrap();
            }
            let len = set.finish().unwrap();
            let mut sorted = datas.clone();
            sorted.sort();
            sorted.dedup();
            let mut expected = std::vec![0xbe, 0xef];
            for d in &sorted {
                expected.extend_from_slice(b"\x00\xfd\xe8\x00\x01\x00\x00\x00\x01");
                expected.extend_from_slice(&(d.len() as u16).to_be_bytes());
                expected.extend_from_slice(d);
            }
            assert_eq!(out.as_bytes(), expected, "round {round}");
            assert_eq!(len, expected.len() - 2);
        }
    }

    #[test]
    fn finish_needs_room() {
        // Two 15-octet RRs need 30 + 8 + 30 octets to sort.
        for (size, ok) in [(68, true), (67, false), (40, false)] {
            let mut buf = std::vec![0u8; size];
            let mut w = WireWriter::new(&mut buf);
            let mut set = CanonicalRrset::new(&mut w, Name::ROOT, Rtype::A, Class::IN, 0);
            set.push(&A::new([2, 2, 2, 2].into())).unwrap();
            set.push(&A::new([1, 1, 1, 1].into())).unwrap();
            if ok {
                assert_eq!(set.finish(), Ok(30));
                assert_eq!(&w.as_bytes()[11..15], [1, 1, 1, 1]);
            } else {
                assert_eq!(set.finish(), Err(Error::BufferTooSmall));
                assert!(w.is_empty());
            }
        }
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
        // HINFO holds no names and keeps its case (RFC 6840 §5.1).
        let mut w = WireWriter::new(&mut buf);
        let mut set = CanonicalRrset::new(&mut w, Name::ROOT, Rtype::HINFO, Class::IN, 0);
        set.push(&crate::rdata::Hinfo {
            cpu: crate::CharStr::new(b"KLH-10").unwrap(),
            os: crate::CharStr::new(b"ITS").unwrap(),
        })
        .unwrap();
        assert!(set.as_bytes().ends_with(b"\x06KLH-10\x03ITS"));
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
        assert_eq!(set.finish(), Ok(15));
        assert_eq!(w.len(), 16);
        assert_eq!(w.as_bytes()[0], 0xaa);
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
