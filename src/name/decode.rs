//! Wire-format name decoding (RFC 1035 §3.1, §4.1.4): the hot path of
//! message parsing.
//!
//! [`parse`] enforces every check listed in the [module
//! documentation](super) — label length, total length, label types, pointer
//! direction and the hop limit — in one pass over the labels.
//!
//! Compressed messages make the same suffixes appear again and again: every
//! owner name of a large response points at the question name, and a chain
//! of names that each add one label to the previous one makes a decoder
//! re-walk every earlier name. A [`SuffixCache`] remembers what decoding
//! from a given offset produced, so a pointer to an offset already decoded
//! *in this message* costs one lookup instead of a walk. The cache is only
//! an accelerator: an entry is used only when the combined name provably
//! passes the very checks the walk would have made, and in every other case
//! the decoder walks the labels as if there were no cache, so results and
//! errors are identical with and without it.

use super::{MAX_LABEL_LEN, MAX_NAME_LEN, MAX_POINTERS, Name};
use crate::{Error, Result};

/// Largest offset a compression pointer can encode (14 bits).
const MAX_POINTER_TARGET: usize = 0x3fff;

/// What decoding a name from one offset of a message produced: the suffix
/// that a pointer to that offset stands for.
///
/// The decoding it describes started with the whole message as its bound
/// and the offset itself as the start of the current label run, exactly
/// the state the decoder is in right after following a pointer there, so
/// the description is valid for every pointer to that offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Suffix {
    /// Offset of the first label (or root octet) after any leading
    /// pointers.
    first: u16,
    /// Label octets (length octets included), root excluded.
    len: u8,
    /// Number of labels, root excluded.
    labels: u8,
    /// Pointers followed.
    hops: u8,
    /// Whether no pointer follows the first label.
    contiguous: bool,
}

/// A memo of suffixes already decoded in one message; see the [module
/// documentation](self).
pub(crate) trait SuffixCache {
    /// The suffix decoded at `offset`, if remembered.
    fn get(&self, offset: usize) -> Option<Suffix>;

    /// Remembers the suffix decoded at `offset` (which may be ignored).
    fn put(&mut self, offset: usize, suffix: Suffix);
}

/// No memo: every pointer is followed by walking.
pub(crate) struct NoCache;

impl SuffixCache for NoCache {
    #[inline(always)]
    fn get(&self, _: usize) -> Option<Suffix> {
        None
    }

    #[inline(always)]
    fn put(&mut self, _: usize, _: Suffix) {}
}

/// Number of entries of a [`NameCache`] (a power of two).
const SLOTS: usize = 16;

/// Marks an empty [`NameCache`] slot (never a pointer target: those are at
/// most 0x3fff).
const EMPTY: u16 = u16::MAX;

/// A small direct-mapped [`SuffixCache`] for one message, kept by the
/// message iterators (128 bytes, no allocation).
///
/// It must only ever be used with one message buffer: entries describe
/// that buffer's bytes.
#[derive(Clone, Copy)]
pub(crate) struct NameCache {
    keys: [u16; SLOTS],
    suffixes: [Suffix; SLOTS],
}

impl NameCache {
    /// An empty cache.
    pub(crate) const fn new() -> Self {
        const NONE: Suffix = Suffix {
            first: 0,
            len: 0,
            labels: 0,
            hops: 0,
            contiguous: false,
        };
        NameCache {
            keys: [EMPTY; SLOTS],
            suffixes: [NONE; SLOTS],
        }
    }

    #[inline(always)]
    fn slot(offset: u16) -> usize {
        // Fibonacci hashing: neighbouring offsets land in different slots.
        (u32::from(offset).wrapping_mul(0x9e37_79b1) >> 28) as usize % SLOTS
    }
}

impl core::fmt::Debug for NameCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("NameCache { .. }")
    }
}

impl SuffixCache for NameCache {
    #[inline(always)]
    fn get(&self, offset: usize) -> Option<Suffix> {
        let key = u16::try_from(offset).ok()?;
        let i = Self::slot(key);
        if self.keys[i] == key {
            Some(self.suffixes[i])
        } else {
            None
        }
    }

    #[inline(always)]
    fn put(&mut self, offset: usize, suffix: Suffix) {
        if offset <= MAX_POINTER_TARGET {
            let key = offset as u16;
            let i = Self::slot(key);
            self.keys[i] = key;
            self.suffixes[i] = suffix;
        }
    }
}

/// The error for a label that pushes a name past [`MAX_NAME_LEN`]: a
/// label that is also cut short by the end of the input is reported as
/// truncation, which is what the input most likely is.
#[cold]
fn too_long(input_len: usize, label_end: usize) -> Error {
    if label_end > input_len {
        Error::UnexpectedEof
    } else {
        Error::NameTooLong
    }
}

/// The target of the compression pointer whose two octets are `hi`, `lo`.
#[inline(always)]
fn pointer_target(hi: u8, lo: u8) -> usize {
    (usize::from(hi & 0x3f) << 8) | usize::from(lo)
}

/// Parses a name at `start` in `msg`.
///
/// The in-place part of the encoding must end before `end`; pointers may
/// target anything earlier in `msg`. Returns the name and the offset just
/// past its in-place encoding. See the [module documentation](super) for
/// the checks.
#[inline]
pub(crate) fn parse<'a, C: SuffixCache>(
    msg: &'a [u8],
    start: usize,
    end: usize,
    allow_pointers: bool,
    cache: &mut C,
) -> Result<(Name<'a>, usize)> {
    // The in-place part: bounded by `end`. This loop is the whole decoder
    // for uncompressed names.
    let input = msg.get(..end).unwrap_or(msg);
    let mut pos = start;
    // Label octets so far (length octets included, root excluded). Always
    // below MAX_NAME_LEN, hence also `labels` <= MAX_LABELS.
    let mut total = 0usize;
    let mut labels = 0u8;
    let (hi, lo) = loop {
        let Some(&b) = input.get(pos) else {
            return Err(Error::UnexpectedEof);
        };
        if b == 0 {
            // An empty `labels` / `total` fits the u8 fields: see above.
            let suffix = Suffix {
                first: start as u16,
                len: total as u8,
                labels,
                hops: 0,
                contiguous: true,
            };
            cache.put(start, suffix);
            let name = Name {
                msg,
                start,
                len: total as u8 + 1,
                labels,
                contiguous: true,
            };
            return Ok((name, pos + 1));
        }
        if b <= MAX_LABEL_LEN as u8 {
            let step = 1 + usize::from(b);
            total += step;
            if total >= MAX_NAME_LEN {
                return Err(too_long(input.len(), pos + step));
            }
            labels += 1;
            // A label running past the input is caught by the next read.
            pos += step;
            continue;
        }
        if b < 0xc0 {
            return Err(Error::BadLabelType);
        }
        if !allow_pointers {
            return Err(Error::UnexpectedPointer);
        }
        let Some(&lo) = input.get(pos + 1) else {
            return Err(Error::UnexpectedEof);
        };
        break (b, lo);
    };
    let next = pos + 2;
    let (name, hit_first) = follow(msg, start, total, labels, pointer_target(hi, lo), cache)?;
    // Remember the whole name, and the suffix the first pointer stood for
    // (when it starts with a label: the common "owner name is a pointer"
    // case). The latter is skipped when it came from the cache anyway.
    let hops = name.hops;
    let suffix = Suffix {
        first: name.start as u16,
        len: name.total as u8,
        labels: name.labels,
        hops: hops as u8,
        contiguous: name.contiguous,
    };
    cache.put(start, suffix);
    let t1 = pointer_target(hi, lo);
    if !hit_first && msg.get(t1).is_some_and(|&b| b <= MAX_LABEL_LEN as u8) {
        // `total` / `labels` only grow, and `hops` >= 1 here.
        let suffix = Suffix {
            first: t1 as u16,
            len: (name.total - total) as u8,
            labels: name.labels - labels,
            hops: (hops - 1) as u8,
            contiguous: hops == 1,
        };
        cache.put(t1, suffix);
    }
    let name = Name {
        msg,
        start: name.start,
        len: name.total as u8 + 1,
        labels: name.labels,
        contiguous: name.contiguous,
    };
    Ok((name, next))
}

/// The state of a name decoded past its first pointer.
struct Followed {
    start: usize,
    total: usize,
    labels: u8,
    hops: usize,
    contiguous: bool,
}

/// Follows the compression pointer to `target` that ends the in-place part
/// of the name starting at `start` (with `total` octets in `labels` labels
/// before it), and decodes the rest. Also returns whether the first
/// pointer's suffix came from the cache.
#[inline]
fn follow<C: SuffixCache>(
    msg: &[u8],
    start: usize,
    mut total: usize,
    mut labels: u8,
    mut target: usize,
    cache: &mut C,
) -> Result<(Followed, bool)> {
    // Pointer targets must lie strictly before the current label run.
    let mut run_start = start;
    let mut name_start = start;
    let mut hops = 0usize;
    let mut contiguous = true;
    loop {
        // At a pointer to `target`.
        if target >= run_start {
            return Err(Error::BadPointer);
        }
        hops += 1;
        if hops > MAX_POINTERS {
            return Err(Error::TooManyPointers);
        }
        let leading = labels == 0;
        if leading {
            name_start = target;
        } else {
            contiguous = false;
        }
        if let Some(s) = cache.get(target)
            && total + usize::from(s.len) < MAX_NAME_LEN
            && hops + usize::from(s.hops) <= MAX_POINTERS
        {
            // Walking from `target` would pass every check (each limit
            // only grows along the walk, and the suffix was decoded from
            // the same state) and end exactly here.
            total += usize::from(s.len);
            labels += s.labels;
            hops += usize::from(s.hops);
            if leading {
                name_start = usize::from(s.first);
                contiguous = s.contiguous;
            }
            let name = Followed {
                start: name_start,
                total,
                labels,
                hops,
                contiguous,
            };
            return Ok((name, hops == 1 + usize::from(s.hops)));
        }
        let mut pos = target;
        run_start = target;
        let (hi, lo) = loop {
            let Some(&b) = msg.get(pos) else {
                return Err(Error::UnexpectedEof);
            };
            if b == 0 {
                let name = Followed {
                    start: name_start,
                    total,
                    labels,
                    hops,
                    contiguous,
                };
                return Ok((name, false));
            }
            if b <= MAX_LABEL_LEN as u8 {
                let step = 1 + usize::from(b);
                total += step;
                if total >= MAX_NAME_LEN {
                    return Err(too_long(msg.len(), pos + step));
                }
                labels += 1;
                pos += step;
                continue;
            }
            if b < 0xc0 {
                return Err(Error::BadLabelType);
            }
            let Some(&lo) = msg.get(pos + 1) else {
                return Err(Error::UnexpectedEof);
            };
            break (b, lo);
        };
        target = pointer_target(hi, lo);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;
    use std::vec::Vec;

    /// A [`NameCache`] that counts the lookups that hit.
    struct Counting {
        inner: NameCache,
        hits: Cell<usize>,
    }

    impl Counting {
        fn new() -> Self {
            Counting {
                inner: NameCache::new(),
                hits: Cell::new(0),
            }
        }
    }

    impl SuffixCache for Counting {
        fn get(&self, offset: usize) -> Option<Suffix> {
            let s = self.inner.get(offset);
            self.hits.set(self.hits.get() + usize::from(s.is_some()));
            s
        }

        fn put(&mut self, offset: usize, suffix: Suffix) {
            self.inner.put(offset, suffix);
        }
    }

    /// Decodes with and without a cache and checks they agree.
    fn both<'a>(msg: &'a [u8], start: usize, cache: &mut Counting) -> Result<(Name<'a>, usize)> {
        let plain = parse(msg, start, msg.len(), true, &mut NoCache);
        let cached = parse(msg, start, msg.len(), true, cache);
        match (&plain, &cached) {
            (Ok((a, ae)), Ok((b, be))) => {
                assert_eq!(ae, be);
                assert_eq!(
                    (a.start, a.len, a.labels, a.contiguous),
                    (b.start, b.len, b.labels, b.contiguous),
                    "at {start}"
                );
            }
            _ => assert_eq!(plain.is_ok(), cached.is_ok()),
        }
        assert_eq!(plain.as_ref().err(), cached.as_ref().err(), "at {start}");
        cached
    }

    #[test]
    fn chained_names_hit_the_cache() {
        // name_i = "x" + pointer to name_{i-1}; name_0 = "a.example".
        let mut m = std::vec![0u8; 12];
        let mut starts = Vec::new();
        starts.push(m.len());
        m.extend_from_slice(b"\x01a\x07example\x00");
        for _ in 0..200 {
            let prev = *starts.last().unwrap() as u16;
            starts.push(m.len());
            m.extend_from_slice(&[1, b'x', 0xc0 | (prev >> 8) as u8, prev as u8]);
        }
        let mut cache = Counting::new();
        for (i, &s) in starts.iter().enumerate() {
            let r = both(&m, s, &mut cache);
            // 2 + i labels; names beyond 127 labels / 255 octets fail the
            // same way in both decoders.
            if 10 + 2 * i < MAX_NAME_LEN {
                assert_eq!(r.unwrap().0.label_count(), 2 + i);
            } else {
                assert!(r.is_err());
            }
        }
        assert!(cache.hits.get() >= 120, "{}", cache.hits.get());
    }

    #[test]
    fn hop_limit_is_enforced_through_the_cache() {
        // name_i = pointer to name_{i-1} (pure pointer chains): the hop
        // limit is hit after MAX_POINTERS pointers with or without cache.
        let mut m = std::vec![0u8; 12];
        let mut starts = std::vec![m.len()];
        m.extend_from_slice(b"\x01a\x00");
        for _ in 0..300 {
            let prev = *starts.last().unwrap() as u16;
            starts.push(m.len());
            m.extend_from_slice(&[0xc0 | (prev >> 8) as u8, prev as u8]);
        }
        let mut cache = Counting::new();
        for (i, &s) in starts.iter().enumerate() {
            let r = both(&m, s, &mut cache);
            if i <= MAX_POINTERS {
                let (n, _) = r.unwrap();
                assert_eq!(n.as_contiguous(), Some(&b"\x01a\x00"[..]));
            } else {
                assert_eq!(r.unwrap_err(), Error::TooManyPointers);
            }
        }
        assert!(cache.hits.get() >= MAX_POINTERS, "{}", cache.hits.get());
    }

    #[test]
    fn cache_agrees_on_every_offset() {
        // Every start offset of a message mixing labels, pointers to
        // labels and pointers to pointers, decoded in order and in reverse.
        let mut m = std::vec![0u8; 12];
        m.extend_from_slice(b"\x03www\x07example\x03com\x00"); // 12
        m.extend_from_slice(b"\xc0\x0c"); // 29: -> www.example.com
        m.extend_from_slice(b"\x04mail\xc0\x10"); // 31: mail.example.com
        m.extend_from_slice(b"\xc0\x1d"); // 38: -> 29 -> 12
        m.extend_from_slice(b"\x02mx\xc0\x1f"); // 40: mx.mail.example.com
        m.extend_from_slice(b"\x01a\xc0\x26"); // 45: a + -> 38 -> 29 -> 12
        m.extend_from_slice(b"\x3f"); // 49: truncated label
        let mut cache = Counting::new();
        for s in 0..m.len() {
            let _ = both(&m, s, &mut cache);
        }
        for s in (0..m.len()).rev() {
            let _ = both(&m, s, &mut cache);
        }
        let mut cache = Counting::new();
        for s in [31, 40, 45, 38, 29, 12] {
            let (n, _) = both(&m, s, &mut cache).unwrap();
            assert!(n.label_count() >= 3);
        }
    }

    #[test]
    fn cache_agrees_on_random_messages() {
        // Random messages biased towards short labels and backward
        // pointers; every offset decoded with and without the cache, in
        // message order (as the iterators do).
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut rand = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut hits = 0;
        for _ in 0..20_000 {
            let len = 12 + (rand() % 200) as usize;
            let mut m = std::vec![0u8; len];
            for (i, byte) in m.iter_mut().enumerate().skip(12) {
                let r = rand();
                *byte = match r % 8 {
                    0 => 0,
                    1 | 2 => (r >> 8) as u8 % 4,
                    3 => 0xc0 | ((r >> 8) as u8 & 1),
                    4 => (r >> 16) as u8 % (i as u8).max(1),
                    5 => 0x3f,
                    _ => b'a' + (r >> 8) as u8 % 3,
                };
            }
            let mut cache = Counting::new();
            for s in 12..len {
                let _ = both(&m, s, &mut cache);
            }
            hits += cache.hits.get();
        }
        assert!(hits > 10_000, "{hits}");
    }

    #[test]
    fn cache_ignores_unreachable_offsets() {
        let mut cache = NameCache::new();
        let s = Suffix {
            first: 1,
            len: 1,
            labels: 1,
            hops: 0,
            contiguous: true,
        };
        cache.put(0x4000, s);
        assert_eq!(cache.get(0x4000), None);
        cache.put(0x3fff, s);
        assert_eq!(cache.get(0x3fff), Some(s));
        assert_eq!(cache.get(usize::MAX), None);
    }
}
