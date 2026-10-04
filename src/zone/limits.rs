//! [`ZoneLimits`]: the work and size limits of master-file reading.

use super::generate::MAX_GENERATE;

/// Work and size limits for reading master files (RFC 1035 §5) with
/// [`ZoneReader`](super::ZoneReader), [`Records`] and
/// [`parse_with_limits`].
///
/// Every limit is on by default ([`DEFAULT`](Self::DEFAULT)), sized for
/// real zones while bounding what a hostile file can cost: reading is
/// linear in the text except for `$GENERATE` (one line, many records) and
/// `$INCLUDE` (one line, a whole file), and the records collected by
/// [`Records`] take memory in proportion to their number.
/// Going over a limit is an [`Error::LimitExceeded`](crate::Error) with
/// the position of the entry, directive or text at fault. Too many records
/// or too much input stop the reader (it returns the error once, then the
/// end of the input); the other limits fail the entry at fault (a
/// `$GENERATE` or `$INCLUDE` directive, an entry with a line or token that
/// is too long) and reading resumes with the next entry, as after any
/// other error.
///
/// Raise the limits (or use [`UNLIMITED`](Self::UNLIMITED)) for large
/// zones from trusted sources.
///
/// | Limit | Default | Bounds |
/// |-------|---------|--------|
/// | [`max_records`](Self::max_records) | 1 000 000 | records read, `$GENERATE`d and `$INCLUDE`d ones included |
/// | [`max_generate`](Self::max_generate) | 65 536 ([`MAX_GENERATE`]) | records of one `$GENERATE` directive |
/// | [`max_include_depth`](Self::max_include_depth) | 8 | `$INCLUDE` nesting |
/// | [`max_includes`](Self::max_includes) | 256 | `$INCLUDE`d files in total |
/// | [`max_input_len`](Self::max_input_len) | 256 MiB | octets of text: the main text plus every included file |
/// | [`max_line_len`](Self::max_line_len) | 1 MiB | octets of one line |
/// | [`max_token_len`](Self::max_token_len) | 256 KiB | octets of one token (the hex form of the largest RDATA is 128 KiB) |
///
/// ```
/// use dnsbox::Error;
/// use dnsbox::zone::{ZoneLimits, ZoneReader};
///
/// // A hostile file: two lines, 131 072 records.
/// let text = "$TTL 60\n$GENERATE 0-65535 a$ A 192.0.2.1\n$GENERATE 0-65535 b$ A 192.0.2.2\n";
/// let limits = ZoneLimits::DEFAULT.with_max_records(100_000);
/// let mut reader = ZoneReader::new(text).with_limits(limits);
/// let mut buf = [0u8; 16];
/// let mut count = 0;
/// let err = loop {
///     match reader.next_record(&mut buf) {
///         Ok(Some(_)) => count += 1,
///         Ok(None) => unreachable!(),
///         Err(e) => break e,
///     }
/// };
/// assert_eq!(count, 100_000);
/// assert_eq!((err.error(), err.line(), err.column()), (Error::LimitExceeded, 3, 1));
/// // The reader stops at a limit.
/// assert!(reader.next_record(&mut buf)?.is_none());
/// # Ok::<(), dnsbox::Error>(())
/// ```
///
#[cfg_attr(
    feature = "alloc",
    doc = "[`Records`]: super::Records\n[`parse_with_limits`]: super::parse_with_limits"
)]
#[cfg_attr(
    not(feature = "alloc"),
    doc = "[`Records`]: crate#cargo-features\n[`parse_with_limits`]: crate#cargo-features"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ZoneLimits {
    /// The most records read, counting `$GENERATE`d records and those of
    /// `$INCLUDE`d files.
    pub max_records: u64,
    /// The most records one `$GENERATE` directive may produce; a larger
    /// range is refused (and skipped) before anything is generated.
    pub max_generate: u32,
    /// The deepest `$INCLUDE` nesting ([`Records`]; 0
    /// forbids `$INCLUDE`).
    ///
    #[cfg_attr(feature = "alloc", doc = "[`Records`]: super::Records")]
    #[cfg_attr(not(feature = "alloc"), doc = "[`Records`]: crate#cargo-features")]
    pub max_include_depth: usize,
    /// The most files `$INCLUDE`d in total ([`Records`]).
    ///
    #[cfg_attr(feature = "alloc", doc = "[`Records`]: super::Records")]
    #[cfg_attr(not(feature = "alloc"), doc = "[`Records`]: crate#cargo-features")]
    pub max_includes: usize,
    /// The most octets of text read: the main text and every included
    /// file together. An include resolver is asked for at most what is
    /// left ([`IncludeResolver::load_limited`]).
    ///
    #[cfg_attr(
        feature = "alloc",
        doc = "[`IncludeResolver::load_limited`]: super::IncludeResolver::load_limited"
    )]
    #[cfg_attr(
        not(feature = "alloc"),
        doc = "[`IncludeResolver::load_limited`]: crate#cargo-features"
    )]
    pub max_input_len: usize,
    /// The most octets on one line (between two newlines).
    pub max_line_len: usize,
    /// The most octets in one token (a quoted string with its quotes).
    pub max_token_len: usize,
}

impl ZoneLimits {
    /// The defaults: see the table in the [type documentation](Self).
    pub const DEFAULT: ZoneLimits = ZoneLimits {
        max_records: 1_000_000,
        max_generate: MAX_GENERATE,
        max_include_depth: 8,
        max_includes: 256,
        max_input_len: 256 << 20,
        max_line_len: 1 << 20,
        max_token_len: 256 << 10,
    };

    /// No size limits, for trusted input only. The `$INCLUDE` nesting
    /// keeps its default of 8 levels, so that a file including itself (a
    /// mistake, not a size) still fails instead of being read until memory
    /// runs out; raise it too if you need deeper nesting.
    pub const UNLIMITED: ZoneLimits = ZoneLimits {
        max_records: u64::MAX,
        max_generate: u32::MAX,
        max_include_depth: ZoneLimits::DEFAULT.max_include_depth,
        max_includes: usize::MAX,
        max_input_len: usize::MAX,
        max_line_len: usize::MAX,
        max_token_len: usize::MAX,
    };

    /// Sets [`max_records`](Self::max_records).
    #[inline]
    #[must_use]
    pub const fn with_max_records(mut self, max: u64) -> Self {
        self.max_records = max;
        self
    }

    /// Sets [`max_generate`](Self::max_generate).
    #[inline]
    #[must_use]
    pub const fn with_max_generate(mut self, max: u32) -> Self {
        self.max_generate = max;
        self
    }

    /// Sets [`max_include_depth`](Self::max_include_depth).
    #[inline]
    #[must_use]
    pub const fn with_max_include_depth(mut self, max: usize) -> Self {
        self.max_include_depth = max;
        self
    }

    /// Sets [`max_includes`](Self::max_includes).
    #[inline]
    #[must_use]
    pub const fn with_max_includes(mut self, max: usize) -> Self {
        self.max_includes = max;
        self
    }

    /// Sets [`max_input_len`](Self::max_input_len).
    #[inline]
    #[must_use]
    pub const fn with_max_input_len(mut self, max: usize) -> Self {
        self.max_input_len = max;
        self
    }

    /// Sets [`max_line_len`](Self::max_line_len).
    #[inline]
    #[must_use]
    pub const fn with_max_line_len(mut self, max: usize) -> Self {
        self.max_line_len = max;
        self
    }

    /// Sets [`max_token_len`](Self::max_token_len).
    #[inline]
    #[must_use]
    pub const fn with_max_token_len(mut self, max: usize) -> Self {
        self.max_token_len = max;
        self
    }
}

impl Default for ZoneLimits {
    #[inline]
    fn default() -> Self {
        Self::DEFAULT
    }
}
