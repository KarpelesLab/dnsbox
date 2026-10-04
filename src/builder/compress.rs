//! Allocation-free name compression (RFC 1035 §4.1.4).
//!
//! The table remembers, for every label written uncompressed into the
//! message at an offset that a pointer can reach (< 0x4000), a hash of the
//! name suffix that starts there. To write a name, the builder hashes each
//! of its suffixes (longest first), looks the hash up, verifies a candidate
//! by decoding the name at that offset in the output, and emits the
//! unmatched leading labels followed by a pointer to the match.
//!
//! Matching is exact (case-sensitive) so the case of every name written is
//! preserved — important for 0x20 case randomisation. The table has a fixed
//! capacity ([`CAPACITY`] entries); once full, later names are still written
//! correctly, just less compactly. Entries are appended in increasing offset
//! order, so rolling the builder back is a simple truncation. The work per
//! name is bounded: at most [`MAX_PROBES`] candidates are verified.

use crate::name::{MAX_LABELS, Name};

/// Number of suffix entries the table can hold.
pub const CAPACITY: usize = 128;

/// Maximum number of candidate verifications per name. FNV is not
/// collision-resistant, so names chosen by an attacker (e.g. echoed query
/// names) could otherwise make every lookup verify many false candidates;
/// past this budget the rest of the name is simply written uncompressed.
pub const MAX_PROBES: u32 = 32;

/// Largest offset a compression pointer can encode.
pub(crate) const MAX_POINTER_OFFSET: usize = 0x3fff;

/// FNV-1a offset basis, used as the hash of the root suffix.
const SEED: u32 = 0x811c_9dc5;

/// Extends a suffix hash with one more label (length octet included).
#[inline]
pub(crate) fn hash_label(mut h: u32, label_with_len: &[u8]) -> u32 {
    for &b in label_with_len {
        h ^= u32::from(b);
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

/// Fixed-size table of (suffix hash, message offset) pairs.
#[derive(Clone)]
pub(crate) struct CompressionTable {
    hashes: [u32; CAPACITY],
    offsets: [u16; CAPACITY],
    len: usize,
}

impl CompressionTable {
    pub(crate) const fn new() -> Self {
        CompressionTable {
            hashes: [0; CAPACITY],
            offsets: [0; CAPACITY],
            len: 0,
        }
    }

    #[inline]
    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub(crate) fn truncate(&mut self, len: usize) {
        self.len = self.len.min(len);
    }

    #[inline]
    pub(crate) fn push(&mut self, hash: u32, offset: usize) {
        if self.len < CAPACITY && offset <= MAX_POINTER_OFFSET {
            self.hashes[self.len] = hash;
            self.offsets[self.len] = offset as u16;
            self.len += 1;
        }
    }

    /// Finds an entry with `hash` whose name, decoded from `msg`, exactly
    /// equals `suffix`. Each verification consumes one unit of `budget`.
    pub(crate) fn find(
        &self,
        msg: &[u8],
        hash: u32,
        suffix: &[u8],
        budget: &mut u32,
    ) -> Option<u16> {
        let suffix_name = Name::from_wire(suffix).ok()?;
        let first = *suffix.first()?;
        let hashes = self.hashes.get(..self.len)?;
        for (_, &off) in hashes
            .iter()
            .zip(&self.offsets)
            .filter(|(h, _)| **h == hash)
        {
            // Cheap pre-check: the first label length must match.
            if msg.get(off as usize) != Some(&first) {
                continue;
            }
            if *budget == 0 {
                return None;
            }
            *budget -= 1;
            if Name::parse_bounded(msg, off as usize, msg.len(), true)
                .is_ok_and(|(n, _)| n.eq_exact(&suffix_name))
            {
                return Some(off);
            }
        }
        None
    }
}

/// How to write a name given the current table: the number of leading
/// bytes of the flattened name to emit literally, an optional pointer, and
/// the per-label offsets/hashes to register afterwards.
pub(crate) struct Plan {
    pub(crate) literal_len: usize,
    pub(crate) pointer: Option<u16>,
    pub(crate) new_labels: usize,
    pub(crate) offsets: [u8; MAX_LABELS],
    pub(crate) hashes: [u32; MAX_LABELS],
}

/// Plans the compressed encoding of the flattened name `wire`.
pub(crate) fn plan(table: &CompressionTable, msg: &[u8], wire: &[u8]) -> Plan {
    let mut offsets = [0u8; MAX_LABELS];
    let mut n = 0;
    let mut pos = 0usize;
    while let Some(&l) = wire.get(pos) {
        if l == 0 || n >= MAX_LABELS {
            break;
        }
        offsets[n] = pos as u8;
        n += 1;
        pos += 1 + l as usize;
    }
    let mut hashes = [0u32; MAX_LABELS];
    let mut h = SEED;
    for i in (0..n).rev() {
        let off = offsets[i] as usize;
        let len = wire.get(off).copied().unwrap_or(0) as usize;
        h = hash_label(h, wire.get(off..off + 1 + len).unwrap_or(&[]));
        hashes[i] = h;
    }
    let mut budget = MAX_PROBES;
    for i in 0..n {
        let off = offsets[i] as usize;
        let suffix = wire.get(off..).unwrap_or(&[]);
        if let Some(ptr) = table.find(msg, hashes[i], suffix, &mut budget) {
            return Plan {
                literal_len: off,
                pointer: Some(ptr),
                new_labels: i,
                offsets,
                hashes,
            };
        }
    }
    Plan {
        literal_len: wire.len(),
        pointer: None,
        new_labels: n,
        offsets,
        hashes,
    }
}
