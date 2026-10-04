//! Allocation-free name compression (RFC 1035 §4.1.4).
//!
//! The table is a small trie of the names already written into the
//! message. Each entry stands for one label written uncompressed at some
//! offset of the message, and links to its *parent*: the entry for the
//! rest of the name after that label (or the root). A name in the message
//! is therefore a path of entries ending at the root, and the suffixes a
//! new name can point to are found by walking that trie from the root:
//! look up the name's last label under the root, then the label before it
//! under that entry, and so on, until a label is missing. Lookups go
//! through a hash index keyed by (parent entry, label), so writing a name
//! costs one probe per label, whatever the size of the table and however
//! long the pointer chains in the message are. Before that, the table
//! checks the two commonest cases directly, without hashing: the name is
//! the last one written (the records of an RRset share their owner), or
//! that name with one more label in front.
//!
//! Every entry a lookup returns is checked against the message bytes, not
//! just the table: the label at the entry's offset must equal the label
//! being looked up, byte for byte, and the octets right after it must lead
//! to the parent — the root octet, the parent's own label (written
//! contiguously), or a compression pointer to the parent's offset, which
//! lies before the entry. Since the parent was checked the same way one
//! step earlier, a pointer to the deepest entry found decodes to exactly
//! the suffix that was matched, even if record data rewrote bytes of
//! earlier records through [`Composer::patch`](crate::Composer::patch).
//!
//! Matching is exact (case-sensitive) so the case of every name written is
//! preserved — important for 0x20 case randomisation. The table has a fixed
//! capacity ([`CAPACITY`] entries); once full, later names are still written
//! correctly, just less compactly. A name's labels are entered right to
//! left, so an entry's parent is always an earlier entry, and rolling the
//! builder back is a truncation. The work per name is bounded: one
//! verified entry per label, at most [`MAX_PROBES`] false candidates
//! verified against the message, and hash chains no longer than the table.

use crate::name::MAX_LABELS;

/// Number of label entries the table can hold.
pub(crate) const CAPACITY: usize = 128;

/// Maximum number of false candidates verified per name (candidates whose
/// hash matches but whose bytes in the message do not). The label hash is
/// not collision-resistant, so names chosen by an attacker (e.g. echoed
/// query names) could otherwise make every lookup verify many false
/// candidates; past this budget the rest of the name is simply written
/// uncompressed.
pub(crate) const MAX_PROBES: u32 = 32;

/// Largest offset a compression pointer can encode.
pub(crate) const MAX_POINTER_OFFSET: usize = 0x3fff;

/// Number of hash buckets (a power of two).
const BUCKETS: usize = 64;

/// "No entry": the parent of a name's last label (the root), and the end
/// of a hash chain. Entries are numbered from 1 (see [`CompressionTable`]).
const NONE: u8 = 0;

const _: () = assert!(CAPACITY < u8::MAX as usize && BUCKETS.is_power_of_two());

/// Multiplier of the label hash (2^64 / φ).
const K: u64 = 0x9e37_79b9_7f4a_7c15;

/// One label written at `offset` of the message, packed into a `u32` in
/// the table (which keeps the builder small and cheap to set up).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    /// Offset of the label's length octet in the message.
    offset: u16,
    /// The entry for the rest of the name, or [`NONE`] for the root.
    parent: u8,
    /// The previous entry in the same hash bucket, or [`NONE`].
    next: u8,
}

impl Entry {
    #[inline(always)]
    const fn pack(self) -> u32 {
        self.offset as u32 | (self.parent as u32) << 16 | (self.next as u32) << 24
    }

    #[inline(always)]
    const fn unpack(v: u32) -> Self {
        Entry {
            offset: v as u16,
            parent: (v >> 16) as u8,
            next: (v >> 24) as u8,
        }
    }
}

/// The first `n` (at most 8) octets of `buf` at `off` as a little-endian
/// word, zero-padded; `None` if `buf` holds fewer.
#[inline(always)]
fn word(buf: &[u8], off: usize, n: usize) -> Option<u64> {
    let rest = buf.get(off..)?;
    if let Some(w) = rest.first_chunk::<8>() {
        // Usually eight octets are there: one load and a mask.
        let w = u64::from_le_bytes(*w);
        return Some(if n >= 8 {
            w
        } else {
            w & ((1u64 << (8 * n)) - 1)
        });
    }
    let end = off + n;
    if (1..=8).contains(&n)
        && let Some(w) = end
            .checked_sub(8)
            .and_then(|start| buf.get(start..end))
            .and_then(<[u8]>::first_chunk::<8>)
    {
        // Near the end of the buffer: the eight octets ending with the
        // wanted ones, shifted down.
        return Some(u64::from_le_bytes(*w) >> (8 * (8 - n)));
    }
    let bytes = rest.get(..n)?;
    let mut w = 0;
    for (i, &b) in bytes.iter().enumerate() {
        w |= u64::from(b) << (8 * i);
    }
    Some(w)
}

/// A label of the name being written, prepared for lookups.
#[derive(Clone, Copy)]
struct Key<'w> {
    /// The label, length octet included (2 to 64 octets).
    bytes: &'w [u8],
    /// Its first eight octets as a little-endian word, zero-padded. The
    /// length octet comes first, so the padding is unambiguous.
    head: u64,
}

impl<'w> Key<'w> {
    /// The label starting at `off` of the wire-format name `wire`.
    #[inline(always)]
    fn new(wire: &'w [u8], off: u8) -> Self {
        let off = usize::from(off);
        let len = wire.get(off).map_or(0, |&l| 1 + usize::from(l));
        let bytes = wire.get(off..off + len).unwrap_or(&[]);
        Key {
            bytes,
            head: word(wire, off, len.min(8)).unwrap_or(0),
        }
    }

    /// Hashes the label under the entry `parent`.
    #[inline(always)]
    fn hash(&self, parent: u8) -> u16 {
        let mut h = (self.head ^ u64::from(parent).wrapping_mul(K)).wrapping_mul(K);
        if let Some(tail) = self.bytes.get(8..) {
            let (words, rest) = tail.as_chunks::<8>();
            for w in words {
                h = (h.rotate_left(23) ^ u64::from_le_bytes(*w)).wrapping_mul(K);
            }
            if !rest.is_empty() {
                let w = word(rest, 0, rest.len()).unwrap_or(0);
                h = (h.rotate_left(23) ^ w).wrapping_mul(K);
            }
        }
        // The top bits are the best mixed.
        (h >> 48) as u16
    }

    /// Whether `msg` holds the label at `off`.
    #[inline(always)]
    fn is_at(&self, msg: &[u8], off: usize) -> bool {
        let n = self.bytes.len();
        if n <= 8 {
            word(msg, off, n) == Some(self.head)
        } else {
            msg.get(off..off + n) == Some(self.bytes)
        }
    }
}

/// The bucket of a hash (its top bits, the best mixed ones).
#[inline(always)]
fn bucket(hash: u16) -> usize {
    (hash >> (16 - BUCKETS.trailing_zeros())) as usize % BUCKETS
}

/// Records the offsets of the labels of the uncompressed wire-format name
/// `wire` (root excluded) in `out`, returning how many there are.
#[inline]
pub(crate) fn label_offsets(wire: &[u8], out: &mut [u8; MAX_LABELS]) -> usize {
    let mut n = 0;
    let mut pos = 0usize;
    while let Some(&l) = wire.get(pos) {
        if l == 0 {
            break;
        }
        let Some(slot) = out.get_mut(n) else { break };
        // A wire name is at most 255 octets, so every offset fits.
        *slot = pos as u8;
        n += 1;
        pos += 1 + usize::from(l);
    }
    n
}

/// The best encoding of a name given the current table; see
/// [`CompressionTable::lookup`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Match {
    /// Number of leading labels to write literally.
    pub(crate) literal: usize,
    /// The entry the literal labels are followed by a pointer to, or
    /// [`NONE`] if the name is written in full (root octet included).
    entry: u8,
    /// The pointer to that entry's offset.
    pub(crate) pointer: Option<u16>,
}

impl Match {
    /// Number of leading bytes of `wire` (whose labels start at `offsets`)
    /// to write literally: the whole name, root octet included, unless a
    /// pointer follows.
    #[inline]
    pub(crate) fn literal_len(&self, wire: &[u8], offsets: &[u8]) -> usize {
        match self.pointer {
            Some(_) => offsets
                .get(self.literal)
                .map_or(wire.len(), |&o| usize::from(o)),
            None => wire.len(),
        }
    }
}

/// Fixed-size trie of the labels written so far, with a hash index; see
/// the [module documentation](self).
///
/// Entries are referred to by *id*, their index plus one, so that
/// [`NONE`] is 0 and an empty table is all zeros: the cheapest value to
/// set up, which matters since every message starts with one.
#[derive(Clone)]
pub(crate) struct CompressionTable {
    /// [`Entry::pack`]ed entries. Entries past `len` are never read.
    entries: [u32; CAPACITY],
    /// [`Key::hash`] of each entry's label under its parent.
    hashes: [u16; CAPACITY],
    /// Most recent entry of each hash bucket, or [`NONE`].
    heads: [u8; BUCKETS],
    len: usize,
    /// The entry for the first label of the last name written (a hint, or
    /// [`NONE`]), that name's wire length, and its first eight octets (to
    /// rule most other names out at once).
    last: u8,
    last_len: u8,
    last_head: u64,
}

impl CompressionTable {
    pub(crate) const fn new() -> Self {
        CompressionTable {
            entries: [0; CAPACITY],
            hashes: [0; CAPACITY],
            heads: [NONE; BUCKETS],
            len: 0,
            last: NONE,
            last_len: 0,
            last_head: 0,
        }
    }

    #[inline]
    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    /// The entry with id `id`, and its hash.
    #[inline(always)]
    fn get(&self, id: u8) -> Option<(Entry, u16)> {
        let i = usize::from(id).checked_sub(1)?;
        Some((Entry::unpack(*self.entries.get(i)?), *self.hashes.get(i)?))
    }

    /// Forgets every entry from index `len` on (the entries added since
    /// [`len`](Self::len) returned `len`).
    #[inline]
    pub(crate) fn truncate(&mut self, len: usize) {
        while self.len > len {
            // Entries leave in the reverse order they came in, so each one
            // is the head of its bucket at this point. `len <= CAPACITY`.
            if let Some((e, h)) = self.get(self.len as u8)
                && let Some(head) = self.heads.get_mut(bucket(h))
            {
                *head = e.next;
            }
            self.len -= 1;
        }
        if usize::from(self.last) > self.len {
            self.last = NONE;
        }
    }

    /// Adds an entry, returning its id (`None` once the table is full).
    #[inline]
    fn push(&mut self, hash: u16, offset: usize, parent: u8) -> Option<u8> {
        let offset = u16::try_from(offset).ok()?;
        let index = self.len;
        let (entry, slot) = (self.entries.get_mut(index)?, self.hashes.get_mut(index)?);
        let head = self.heads.get_mut(bucket(hash))?;
        *entry = Entry {
            offset,
            parent,
            next: *head,
        }
        .pack();
        *slot = hash;
        // `index < CAPACITY < u8::MAX`.
        let id = index as u8 + 1;
        *head = id;
        self.len += 1;
        Some(id)
    }

    /// Whether entry `e` holds `key` in `msg` and is followed by its
    /// parent; see the [module documentation](self).
    #[inline(always)]
    fn verify(&self, msg: &[u8], e: &Entry, key: &Key<'_>) -> bool {
        let off = usize::from(e.offset);
        if !key.is_at(msg, off) {
            return false;
        }
        let end = off + key.bytes.len();
        let Some((parent, _)) = self.get(e.parent) else {
            // The root.
            return msg.get(end) == Some(&0);
        };
        let target = usize::from(parent.offset);
        target == end
            || (target < off
                && target <= MAX_POINTER_OFFSET
                && msg.get(end..end + 2) == Some(&(0xc000 | parent.offset).to_be_bytes()))
    }

    /// Finds the child of `parent` holding `key`.
    #[inline(always)]
    fn find(&self, msg: &[u8], key: &Key<'_>, parent: u8, budget: &mut u32) -> Option<u8> {
        let h = key.hash(parent);
        let mut id = *self.heads.get(bucket(h))?;
        while let Some((e, eh)) = self.get(id) {
            if eh == h && e.parent == parent {
                if *budget == 0 {
                    return None;
                }
                if self.verify(msg, &e, key) {
                    return Some(id);
                }
                // Only false candidates count: genuine ones cost one
                // verification per label of the name at most.
                *budget -= 1;
            }
            // Chains only lead to earlier entries; this keeps the walk
            // finite whatever the table holds.
            if e.next >= id {
                return None;
            }
            id = e.next;
        }
        None
    }

    /// Whether the entry `id` stands for the name made of the labels of
    /// `wire` starting at `offsets`, checked against `msg` label by label
    /// down to the root.
    #[inline]
    fn holds(&self, msg: &[u8], mut id: u8, wire: &[u8], offsets: &[u8]) -> bool {
        for &off in offsets {
            let Some((e, _)) = self.get(id) else {
                return false;
            };
            if !self.verify(msg, &e, &Key::new(wire, off)) {
                return false;
            }
            id = e.parent;
        }
        id == NONE
    }

    /// The fast path of [`lookup`](Self::lookup): the name, or the name
    /// without its first label, is the last name written. That is the
    /// common case (the records of an RRset share their owner; names built
    /// up one label at a time) and it is checked without hashing.
    #[inline]
    fn lookup_last(&self, msg: &[u8], wire: &[u8], offsets: &[u8]) -> Option<Match> {
        let (last, _) = self.get(self.last)?;
        if usize::from(last.offset) > MAX_POINTER_OFFSET {
            return None;
        }
        let tail = usize::from(self.last_len);
        let head = |at| word(wire, at, tail.min(8)) == Some(self.last_head);
        if wire.len() == tail && head(0) && self.holds(msg, self.last, wire, offsets) {
            return Some(Match {
                literal: 0,
                entry: self.last,
                pointer: Some(last.offset),
            });
        }
        let (&first, rest) = offsets.split_first()?;
        let &second = rest.first()?;
        let second = usize::from(second);
        if wire.len() - second != tail || !head(second) || !self.holds(msg, self.last, wire, rest) {
            return None;
        }
        // The whole name may be there too, one label further.
        let mut budget = MAX_PROBES;
        if let Some(id) = self.find(msg, &Key::new(wire, first), self.last, &mut budget)
            && let Some((e, _)) = self.get(id)
            && usize::from(e.offset) <= MAX_POINTER_OFFSET
        {
            return Some(Match {
                literal: 0,
                entry: id,
                pointer: Some(e.offset),
            });
        }
        Some(Match {
            literal: 1,
            entry: self.last,
            pointer: Some(last.offset),
        })
    }

    /// Finds the longest suffix of `wire` (an uncompressed wire-format
    /// name whose labels start at `offsets`) that `msg` already holds at
    /// an offset a pointer can reach.
    #[inline]
    pub(crate) fn lookup(&self, msg: &[u8], wire: &[u8], offsets: &[u8]) -> Match {
        let mut best = Match {
            literal: offsets.len(),
            entry: NONE,
            pointer: None,
        };
        if self.len == 0 {
            return best;
        }
        if let Some(m) = self.lookup_last(msg, wire, offsets) {
            return m;
        }
        let mut parent = NONE;
        let mut budget = MAX_PROBES;
        let mut i = offsets.len();
        while let Some(&off) = i.checked_sub(1).and_then(|j| offsets.get(j)) {
            i -= 1;
            let Some(found) = self.find(msg, &Key::new(wire, off), parent, &mut budget) else {
                break;
            };
            parent = found;
            // Entries past the pointer range only serve as parents.
            if let Some((e, _)) = self.get(found)
                && usize::from(e.offset) <= MAX_POINTER_OFFSET
            {
                best = Match {
                    literal: i,
                    entry: found,
                    pointer: Some(e.offset),
                };
            }
        }
        best
    }

    /// Enters the labels written literally for `m` (the result of
    /// [`lookup`](Self::lookup) for the same name) once the name has been
    /// written at offset `start` of the message.
    #[inline]
    pub(crate) fn insert(&mut self, wire: &[u8], offsets: &[u8], m: &Match, start: usize) {
        if offsets.is_empty() {
            // The root (e.g. an OPT record's owner): nothing to remember.
            return;
        }
        // A name is at most 255 octets.
        self.last_len = wire.len() as u8;
        self.last_head = word(wire, 0, wire.len().min(8)).unwrap_or(0);
        self.last = m.entry;
        if m.literal == 0 {
            return;
        }
        self.last = NONE;
        // A name written entirely past the pointer range can never be
        // pointed to; one straddling it keeps its far labels as parents of
        // the near ones.
        if start > MAX_POINTER_OFFSET {
            return;
        }
        let mut parent = m.entry;
        for &off in offsets.get(..m.literal).unwrap_or(&[]).iter().rev() {
            let key = Key::new(wire, off);
            match self.push(key.hash(parent), start + usize::from(off), parent) {
                Some(id) => parent = id,
                // Full: the labels further left would have no parent.
                None => return,
            }
        }
        self.last = parent;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NameBuf;
    use std::vec::Vec;

    /// Looks `name` up without writing it.
    fn lookup(table: &CompressionTable, msg: &[u8], name: &str) -> Match {
        let name: NameBuf = name.parse().unwrap();
        let mut offs = [0u8; MAX_LABELS];
        let n = label_offsets(name.as_wire(), &mut offs);
        table.lookup(msg, name.as_wire(), &offs[..n])
    }

    /// Writes `name` into `msg` the way the builder does, returning the
    /// match used.
    fn write(table: &mut CompressionTable, msg: &mut Vec<u8>, name: &str) -> Match {
        let name: NameBuf = name.parse().unwrap();
        let wire = name.as_wire();
        let mut offs = [0u8; MAX_LABELS];
        let n = label_offsets(wire, &mut offs);
        let m = table.lookup(msg, wire, &offs[..n]);
        let start = msg.len();
        msg.extend_from_slice(&wire[..m.literal_len(wire, &offs[..n])]);
        if let Some(p) = m.pointer {
            msg.extend_from_slice(&(0xc000 | p).to_be_bytes());
        }
        table.insert(wire, &offs[..n], &m, start);
        m
    }

    fn decode(msg: &[u8], at: usize) -> std::string::String {
        let (name, _) = crate::Name::parse_bounded(msg, at, msg.len(), true).unwrap();
        std::format!("{name}")
    }

    #[test]
    fn finds_longest_suffix() {
        let mut t = CompressionTable::new();
        let mut msg = std::vec![0u8; 12];
        assert_eq!(write(&mut t, &mut msg, "www.example.com").pointer, None);
        assert_eq!(t.len(), 3);
        let at = msg.len();
        let m = write(&mut t, &mut msg, "mail.example.com");
        assert_eq!((m.literal, m.pointer), (1, Some(16)));
        assert_eq!(decode(&msg, at), "mail.example.com.");
        let m = write(&mut t, &mut msg, "www.example.com");
        assert_eq!((m.literal, m.pointer), (0, Some(12)));
        // Case-sensitive: a differently-cased label is a new one.
        let at = msg.len();
        let m = write(&mut t, &mut msg, "WWW.example.com");
        assert_eq!((m.literal, m.pointer), (1, Some(16)));
        assert_eq!(decode(&msg, at), "WWW.example.com.");
        // Through a pointer: "a.mail.example.com" -> "mail" + pointer.
        let at = msg.len();
        let m = write(&mut t, &mut msg, "a.mail.example.com");
        assert_eq!(m.literal, 1);
        assert_eq!(decode(&msg, at), "a.mail.example.com.");
        assert_eq!(write(&mut t, &mut msg, "com").pointer, Some(24));
        assert_eq!(write(&mut t, &mut msg, "org").pointer, None);
    }

    #[test]
    fn rejects_rewritten_bytes() {
        let mut t = CompressionTable::new();
        let mut msg = std::vec![0u8; 12];
        write(&mut t, &mut msg, "www.example.com");
        let at = msg.len();
        write(&mut t, &mut msg, "mail.example.com");
        assert_eq!(
            lookup(&t, &msg, "mail.example.com").pointer,
            Some(at as u16)
        );
        // A rewritten label: only "com" is still there.
        msg[17] = b'X';
        assert_eq!(lookup(&t, &msg, "example.com").pointer, Some(24));
        msg[17] = b'e';
        assert_eq!(lookup(&t, &msg, "example.com").pointer, Some(16));
        // A rewritten pointer after "mail".
        msg[at + 6] = 0x00;
        let m = lookup(&t, &msg, "mail.example.com");
        assert_eq!((m.literal, m.pointer), (1, Some(16)));
        // A rewritten root octet breaks every name ending there.
        msg[28] = 1;
        assert_eq!(lookup(&t, &msg, "com").pointer, None);
    }

    #[test]
    fn truncation_restores_the_index() {
        let mut t = CompressionTable::new();
        let mut msg = std::vec![0u8; 12];
        write(&mut t, &mut msg, "example.com");
        let (len, mlen) = (t.len(), msg.len());
        for i in 0..50 {
            write(&mut t, &mut msg, &std::format!("h{i}.example.com"));
        }
        t.truncate(len);
        msg.truncate(mlen);
        for i in 0..50 {
            let m = write(&mut t, &mut msg, &std::format!("h{i}.example.com"));
            assert_eq!(m.literal, 1);
        }
        assert_eq!(write(&mut t, &mut msg, "h7.example.com").literal, 0);
    }

    #[test]
    fn capacity_keeps_parents() {
        // Once full, a name's leftmost labels are the ones left out, so
        // every entry still has its parent.
        let mut t = CompressionTable::new();
        let mut msg = std::vec![0u8; 12];
        let mut i = 0;
        while t.len() < CAPACITY {
            write(&mut t, &mut msg, &std::format!("a{i}.b{i}.c{i}"));
            i += 1;
        }
        let at = msg.len();
        let m = write(&mut t, &mut msg, "x.y.z");
        assert_eq!(m.pointer, None);
        assert_eq!(decode(&msg, at), "x.y.z.");
        for id in 1..=t.len() as u8 {
            let (e, _) = t.get(id).unwrap();
            assert!(e.parent < id);
        }
    }

    #[test]
    fn last_name_fast_path() {
        let mut t = CompressionTable::new();
        let mut msg = std::vec![0u8; 12];
        write(&mut t, &mut msg, "example.com");
        // The same name again, then one label longer, then that again.
        let m = lookup(&t, &msg, "example.com");
        assert_eq!(
            t.lookup_last(&msg, &wire("example.com"), &offs("example.com")),
            Some(m)
        );
        assert_eq!((m.literal, m.pointer), (0, Some(12)));
        let at = msg.len();
        let m = write(&mut t, &mut msg, "www.example.com");
        assert_eq!((m.literal, m.pointer), (1, Some(12)));
        let m = write(&mut t, &mut msg, "www.example.com");
        assert_eq!((m.literal, m.pointer), (0, Some(at as u16)));
        // Neither the same nor one label longer: the general walk.
        assert_eq!(t.lookup_last(&msg, &wire("com"), &offs("com")), None);
        assert_eq!(
            t.lookup_last(&msg, &wire("a.b.example.com"), &offs("a.b.example.com")),
            None
        );
        assert_eq!(
            t.lookup_last(&msg, &wire("www.example.org"), &offs("www.example.org")),
            None
        );
        assert_eq!(lookup(&t, &msg, "com").pointer, Some(20));
        // One label longer, and that name is already there further on.
        write(&mut t, &mut msg, "example.com");
        let m = lookup(&t, &msg, "www.example.com");
        assert_eq!((m.literal, m.pointer), (0, Some(at as u16)));
        // Rewritten bytes of the last name: the hint is not trusted.
        write(&mut t, &mut msg, "www.example.com");
        msg[at + 1] = b'W';
        let m = lookup(&t, &msg, "www.example.com");
        assert_eq!((m.literal, m.pointer), (1, Some(12)));
        // Rolled back past the last name: the hint is dropped.
        write(&mut t, &mut msg, "mail.example.com");
        let len = t.len();
        t.truncate(len - 1);
        assert_eq!(t.last, NONE);
        assert_eq!(lookup(&t, &msg, "mail.example.com").literal, 1);
    }

    fn wire(name: &str) -> Vec<u8> {
        name.parse::<NameBuf>().unwrap().as_wire().to_vec()
    }

    fn offs(name: &str) -> Vec<u8> {
        let mut offs = [0u8; MAX_LABELS];
        let n = label_offsets(&wire(name), &mut offs);
        offs[..n].to_vec()
    }

    #[test]
    fn deep_names_compress_fully() {
        // x.x.….x.a.example, one label longer each time: every name is
        // one label and a pointer to the previous one, however deep, and
        // the second time round a bare pointer.
        let mut t = CompressionTable::new();
        let mut msg = std::vec![0u8; 12];
        write(&mut t, &mut msg, "a.example");
        for round in 0..2 {
            let mut name = std::string::String::from("a.example");
            for _ in 0..120 {
                name.insert_str(0, "x.");
                let at = msg.len();
                let m = write(&mut t, &mut msg, &name);
                assert_eq!(m.literal, 1 - round, "{name}");
                assert_eq!(msg.len() - at, 4 - 2 * round);
                assert_eq!(decode(&msg, at), std::format!("{name}."));
            }
        }
        assert_eq!(t.len(), 122);
    }

    #[test]
    fn collisions_are_bounded() {
        // Entries that all claim the probe's hash and parent but hold
        // other labels: a lookup gives up after MAX_PROBES verifications,
        // even though the genuine entry is further down the chain.
        let probe: NameBuf = "zz".parse().unwrap();
        let h = Key::new(b"\x02zz\x00", 0).hash(NONE);
        let mut msg = std::vec![0u8; 12];
        let mut t = CompressionTable::new();
        let genuine = msg.len();
        t.push(h, genuine, NONE).unwrap();
        msg.extend_from_slice(probe.as_wire());
        for i in 0..100u8 {
            t.push(h, msg.len(), NONE).unwrap();
            msg.extend_from_slice(&[2, b'a', b'a' + (i % 26), 0]);
        }
        const { assert!(MAX_PROBES < 100) };
        assert_eq!(lookup(&t, &msg, "zz").pointer, None);
        // With fewer decoys than the budget, it is found.
        t.truncate(MAX_PROBES as usize);
        assert_eq!(lookup(&t, &msg, "zz").pointer, Some(genuine as u16));
        assert_eq!(lookup(&t, &msg, "zz.zz").pointer, Some(genuine as u16));
    }

    #[test]
    fn labels_and_offsets() {
        let mut offs = [0u8; MAX_LABELS];
        assert_eq!(label_offsets(b"\x00", &mut offs), 0);
        assert_eq!(label_offsets(b"\x01a\x02bc\x00", &mut offs), 2);
        assert_eq!(&offs[..2], &[0, 2]);
        let k = Key::new(b"\x01a\x02bc\x00", 2);
        assert_eq!((k.bytes, k.head), (&b"\x02bc"[..], 0x00_63_62_02));
        assert_eq!(Key::new(b"\x01a", 9).bytes, b"");
        // Words near the end of a buffer, and too short a buffer.
        assert_eq!(word(b"\x01\x02\x03", 1, 2), Some(0x0302));
        assert_eq!(word(b"\x01\x02\x03", 1, 3), None);
        assert_eq!(word(b"\x01\x02\x03", 4, 1), None);
        assert_eq!(
            word(b"123456789", 1, 8),
            Some(u64::from_le_bytes(*b"23456789"))
        );
        // The hash depends on the parent and on every byte.
        let hash = |parent, label: &[u8]| {
            let mut wire = label.to_vec();
            wire.push(0);
            Key::new(&wire, 0).hash(parent)
        };
        assert_ne!(hash(NONE, b"\x01a"), hash(1, b"\x01a"));
        assert_ne!(hash(NONE, b"\x01a"), hash(NONE, b"\x01b"));
        let long = *b"\x3fabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk";
        for i in 1..long.len() {
            let mut other = long;
            other[i] ^= 1;
            assert_ne!(hash(NONE, &long), hash(NONE, &other), "{i}");
        }
        // Long labels are compared in full.
        let wire = [&long[..], b"\x00"].concat();
        let key = Key::new(&wire, 0);
        assert!(key.is_at(&wire, 0));
        let mut other = wire.clone();
        other[40] ^= 1;
        assert!(!key.is_at(&other, 0));
        assert!(!key.is_at(&wire[..30], 0));
    }
}
