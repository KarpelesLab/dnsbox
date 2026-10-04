//! Owned zone records, the record [`Iterator`] and `$INCLUDE` handling
//! (`alloc`).

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use super::ZoneLimits;
use super::reader::{Entry, State, ZoneError, ZoneReader, ZoneRecord, write_record};
use crate::name::NameBuf;
use crate::rdata::RData;
use crate::wire::WireReader;
use crate::{Class, Error, Result, Rtype};

/// Default limit on `$INCLUDE` nesting for [`Records`]
/// ([`ZoneLimits::max_include_depth`]).
pub const DEFAULT_MAX_INCLUDE_DEPTH: usize = ZoneLimits::DEFAULT.max_include_depth;

/// Default limit on the number of `$INCLUDE`d files for [`Records`]
/// ([`ZoneLimits::max_includes`]).
pub const DEFAULT_MAX_INCLUDES: usize = ZoneLimits::DEFAULT.max_includes;

/// An owned resource record read from a master file: a [`ZoneRecord`]
/// with its RDATA in a `Vec`.
///
/// ```
/// use dnsbox::rdata::RData;
///
/// let zone = dnsbox::zone::parse("$ORIGIN example.\n$TTL 1h\nmail MX 10 mx1\n")?;
/// let rr = &zone[0];
/// assert_eq!((rr.name.to_string(), rr.ttl, rr.line), ("mail.example.".into(), 3600, 3));
/// assert!(matches!(rr.data()?, RData::Mx(mx) if mx.preference == 10));
/// assert_eq!(rr.as_record().to_string(), "mail.example. 3600 IN MX 10 mx1.example.");
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ZoneRecordBuf {
    /// The owner name.
    pub name: NameBuf,
    /// The TTL.
    pub ttl: u32,
    /// The class.
    pub class: Class,
    /// The record type.
    pub rtype: Rtype,
    /// The RDATA in uncompressed wire format.
    pub rdata: Vec<u8>,
    /// The line the entry starts on (1-based) in its file.
    pub line: u32,
}

impl ZoneRecordBuf {
    /// The typed record data (see [`RData::parse`]).
    ///
    /// # Errors
    ///
    /// None in practice for records read by a [`ZoneReader`] (their RDATA
    /// was checked); the `Result` is that of [`RData::parse`], which also
    /// checks RDATA set by hand.
    #[inline]
    pub fn data(&self) -> Result<RData<'_>> {
        RData::parse(self.rtype, self.class, WireReader::new(&self.rdata))
    }

    /// Borrows the record as a [`ZoneRecord`].
    #[inline]
    #[must_use]
    pub fn as_record(&self) -> ZoneRecord<'_> {
        ZoneRecord {
            name: self.name.clone(),
            ttl: self.ttl,
            class: self.class,
            rtype: self.rtype,
            rdata: &self.rdata,
            line: self.line,
        }
    }
}

impl From<ZoneRecord<'_>> for ZoneRecordBuf {
    fn from(r: ZoneRecord<'_>) -> Self {
        ZoneRecordBuf {
            name: r.name,
            ttl: r.ttl,
            class: r.class,
            rtype: r.rtype,
            rdata: r.rdata.to_vec(),
            line: r.line,
        }
    }
}

impl fmt::Display for ZoneRecordBuf {
    /// Zone-file style: `owner ttl class type rdata`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_record(
            f,
            self.name.as_name(),
            self.ttl,
            self.class,
            self.rtype,
            &self.rdata,
        )
    }
}

/// Loads the files named by `$INCLUDE` directives (RFC 1035 §5.1) for
/// [`Records`].
///
/// Implemented by [`NoIncludes`] (the default: every `$INCLUDE` fails),
/// [`FsIncludes`](super::FsIncludes) with `std`, and closures
/// `FnMut(&str) -> Result<String>`. Return [`Error::BadInclude`] for a
/// file that cannot be loaded. See the [`Records`] example for a closure.
///
/// The path comes from the zone file: a resolver for untrusted zone files
/// must decide which files it serves (as [`FsIncludes::new`](super::FsIncludes::new)
/// does, confining them to a directory), and should implement
/// [`load_limited`](Self::load_limited) to stop reading a file that is too
/// large.
///
/// ```
/// use dnsbox::zone::IncludeResolver;
/// use dnsbox::Error;
/// use std::collections::HashMap;
///
/// /// Included files served from memory.
/// struct InMemory(HashMap<&'static str, &'static str>);
///
/// impl IncludeResolver for InMemory {
///     fn load(&mut self, path: &str) -> dnsbox::Result<String> {
///         self.0.get(path).map(|text| text.to_string()).ok_or(Error::BadInclude)
///     }
/// }
/// let files = InMemory(HashMap::from([("ns.db", "@ NS ns1\n")]));
/// let zone = dnsbox::zone::ZoneReader::new("$ORIGIN example.\n$TTL 60\n$INCLUDE ns.db\n")
///     .records()
///     .with_includes(files)
///     .collect::<Result<Vec<_>, _>>()?;
/// assert_eq!(zone[0].to_string(), "example. 60 IN NS ns1.example.");
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub trait IncludeResolver {
    /// Returns the text of the file named `path` (escapes already
    /// decoded).
    ///
    /// # Errors
    ///
    /// [`Error::BadInclude`] (or another error) if the file cannot be
    /// loaded; it is reported at the `$INCLUDE` directive.
    fn load(&mut self, path: &str) -> Result<String>;

    /// Returns the text of the file named `path`, if it is at most
    /// `max_len` octets long: what is left of
    /// [`ZoneLimits::max_input_len`]. [`Records`] calls this method.
    ///
    /// The default calls [`load`](Self::load) and checks the length
    /// afterwards; resolvers reading from a source of unknown size should
    /// stop reading after `max_len + 1` octets instead.
    ///
    /// # Errors
    ///
    /// [`Error::LimitExceeded`] for a file longer than `max_len`, and the
    /// errors of [`load`](Self::load).
    fn load_limited(&mut self, path: &str, max_len: usize) -> Result<String> {
        let text = self.load(path)?;
        if text.len() > max_len {
            return Err(Error::LimitExceeded);
        }
        Ok(text)
    }
}

impl<F: FnMut(&str) -> Result<String>> IncludeResolver for F {
    #[inline]
    fn load(&mut self, path: &str) -> Result<String> {
        self(path)
    }
}

/// An [`IncludeResolver`] that refuses every `$INCLUDE`
/// ([`Error::BadInclude`]): the default of [`Records`].
///
/// ```
/// use dnsbox::Error;
///
/// let err = dnsbox::zone::parse("$INCLUDE other.db\n").unwrap_err();
/// assert_eq!((err.error(), err.line()), (Error::BadInclude, 1));
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct NoIncludes;

impl IncludeResolver for NoIncludes {
    #[inline]
    fn load(&mut self, _path: &str) -> Result<String> {
        Err(Error::BadInclude)
    }
}

/// An [`IncludeResolver`] reading files from the file system.
///
/// [`new`](Self::new) confines the included files to a directory, which
/// makes it usable for zone files from untrusted sources: a path must be
/// relative and contain no `..` (nor a root or a drive prefix), and must
/// name a regular file inside the directory once symbolic links are
/// resolved, so that no link leads out of it. Anything else is
/// [`Error::BadInclude`].
///
/// [`unconfined`](Self::unconfined) resolves relative paths against a base
/// directory and opens whatever path the zone file names, absolute paths
/// and `..` included, as BIND does (relative to its working directory,
/// usually the zone directory): only for trusted zone files.
///
/// Both read regular files only (no devices or pipes), and at most what is
/// left of [`ZoneLimits::max_input_len`] ([`Error::LimitExceeded`] for a
/// longer file). The checks are made when the file is opened: they hold
/// against the content of the zone file, not against someone changing
/// the directory at the same time (replacing a checked file with a link).
///
/// ```no_run
/// use dnsbox::zone::{FsIncludes, ZoneReader};
///
/// let text = std::fs::read_to_string("/var/zones/customer/db.example")?;
/// let records = ZoneReader::new(&text)
///     .records()
///     .with_includes(FsIncludes::new("/var/zones/customer"))
///     .collect::<Result<Vec<_>, _>>()?;
/// println!("{} records", records.len());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// ```
/// use dnsbox::Error;
/// use dnsbox::zone::{FsIncludes, IncludeResolver};
///
/// let dir = std::env::temp_dir();
/// let mut includes = FsIncludes::new(&dir);
/// for path in ["/etc/passwd", "../etc/passwd", "a/../../etc/passwd"] {
///     assert_eq!(includes.load(path), Err(Error::BadInclude));
/// }
/// ```
#[cfg(feature = "std")]
#[derive(Clone, Debug)]
pub struct FsIncludes {
    base: std::path::PathBuf,
    confined: bool,
}

#[cfg(feature = "std")]
impl FsIncludes {
    /// Serves the regular files inside `base` (and its subdirectories),
    /// named by relative paths without `..`.
    pub fn new(base: impl Into<std::path::PathBuf>) -> Self {
        FsIncludes {
            base: base.into(),
            confined: true,
        }
    }

    /// Serves any regular file, resolving relative paths against `base`:
    /// for trusted zone files only.
    pub fn unconfined(base: impl Into<std::path::PathBuf>) -> Self {
        FsIncludes {
            base: base.into(),
            confined: false,
        }
    }

    /// The base directory.
    #[must_use]
    pub fn base(&self) -> &std::path::Path {
        &self.base
    }

    /// Whether files are confined to the base directory
    /// ([`new`](Self::new)).
    #[must_use]
    pub const fn is_confined(&self) -> bool {
        self.confined
    }

    /// The file `path` names, if it may be served.
    fn resolve(&self, path: &str) -> Result<std::path::PathBuf> {
        use std::path::{Component, Path};
        let rel = Path::new(path);
        if !self.confined {
            return Ok(self.base.join(rel));
        }
        let plain = rel
            .components()
            .all(|c| matches!(c, Component::Normal(_) | Component::CurDir));
        if path.is_empty() || !plain {
            return Err(Error::BadInclude);
        }
        // Resolving symbolic links on both sides: a link inside the
        // directory must not lead out of it.
        let base = self.base.canonicalize().map_err(|_| Error::BadInclude)?;
        let full = base
            .join(rel)
            .canonicalize()
            .map_err(|_| Error::BadInclude)?;
        if !full.starts_with(&base) {
            return Err(Error::BadInclude);
        }
        Ok(full)
    }
}

#[cfg(feature = "std")]
impl IncludeResolver for FsIncludes {
    fn load(&mut self, path: &str) -> Result<String> {
        self.load_limited(path, usize::MAX)
    }

    fn load_limited(&mut self, path: &str, max_len: usize) -> Result<String> {
        use std::io::Read;
        let file = self.resolve(path)?;
        // Regular files only: a device or a pipe could block or never end.
        let meta = std::fs::metadata(&file).map_err(|_| Error::BadInclude)?;
        if !meta.is_file() {
            return Err(Error::BadInclude);
        }
        let max = u64::try_from(max_len).unwrap_or(u64::MAX);
        if meta.len() > max {
            return Err(Error::LimitExceeded);
        }
        let f = std::fs::File::open(&file).map_err(|_| Error::BadInclude)?;
        if !f.metadata().is_ok_and(|m| m.is_file()) {
            return Err(Error::BadInclude);
        }
        // The file may have grown since: read one octet more than allowed
        // at most.
        let mut bytes = Vec::new();
        f.take(max.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| Error::BadInclude)?;
        if bytes.len() > max_len {
            return Err(Error::LimitExceeded);
        }
        String::from_utf8(bytes).map_err(|_| Error::BadInclude)
    }
}

/// An included file being read.
struct Frame {
    /// The file name, as written in the directive.
    name: String,
    text: String,
    state: State,
}

/// [`Iterator`] over the records of a master file, as owned
/// [`ZoneRecordBuf`]s; created by [`ZoneReader::records`].
///
/// Errors are yielded in place of the faulty entries and iteration
/// continues with the next entry; stop at the first one with
/// `collect::<Result<Vec<_>, _>>()` (see [`parse`]).
///
/// `$INCLUDE` directives are followed through the
/// [`IncludeResolver`] given to [`with_includes`](Self::with_includes):
/// the included file starts with the including file's state (owner,
/// class, TTLs) and the directive's origin, and when it ends the
/// including file continues with its own state, unchanged (RFC 1035 §5.1).
/// When the resolver fails, the directive yields its error
/// ([`Error::BadInclude`]).
///
/// The reader's [`ZoneLimits`] apply to all files together (see
/// [`with_limits`](Self::with_limits)): the records read, the total length
/// of the text, and the `$INCLUDE` nesting ([`DEFAULT_MAX_INCLUDE_DEPTH`]
/// levels) and count ([`DEFAULT_MAX_INCLUDES`] files); a directive over
/// the nesting, count or length limit yields [`Error::LimitExceeded`], and
/// so does the record after the last one allowed, which ends the
/// iteration.
///
/// ```
/// use dnsbox::zone::ZoneReader;
/// use dnsbox::Error;
///
/// let main = "$ORIGIN example.\n$TTL 300\n$INCLUDE hosts.inc sub\nwww A 192.0.2.80\n";
/// let records = ZoneReader::new(main)
///     .records()
///     .with_includes(|path: &str| match path {
///         "hosts.inc" => Ok("a A 192.0.2.1\n@ TXT \"in sub\"\n".to_string()),
///         _ => Err(Error::BadInclude),
///     })
///     .collect::<Result<Vec<_>, _>>()?;
/// let text: Vec<String> = records.iter().map(|r| r.to_string()).collect();
/// assert_eq!(text, [
///     "a.sub.example. 300 IN A 192.0.2.1",
///     "sub.example. 300 IN TXT \"in sub\"",
///     "www.example. 300 IN A 192.0.2.80",
/// ]);
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct Records<'a, R = NoIncludes> {
    top: Option<ZoneReader<'a>>,
    stack: Vec<Frame>,
    resolver: R,
    buf: Vec<u8>,
    limits: ZoneLimits,
    /// Records read so far, in all files.
    records: u64,
    /// Files included so far.
    includes: usize,
    /// Octets of text so far, in all files.
    input: usize,
}

impl<R> fmt::Debug for Records<'_, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Records")
            .field("top", &self.top)
            .field("depth", &self.stack.len())
            .field("limits", &self.limits)
            .field("records", &self.records)
            .field("includes", &self.includes)
            .field("input", &self.input)
            .finish_non_exhaustive()
    }
}

impl<'a> Records<'a, NoIncludes> {
    /// Iterates over `reader`'s records.
    pub(super) fn new(reader: ZoneReader<'a>) -> Self {
        Records {
            limits: reader.limits,
            records: reader.records,
            input: reader.input_len(),
            top: Some(reader),
            stack: Vec::new(),
            resolver: NoIncludes,
            buf: Vec::new(),
            includes: 0,
        }
    }
}

impl<'a, R: IncludeResolver> Records<'a, R> {
    /// Follows `$INCLUDE` directives by loading files through `resolver`.
    pub fn with_includes<R2: IncludeResolver>(self, resolver: R2) -> Records<'a, R2> {
        Records {
            top: self.top,
            stack: self.stack,
            resolver,
            buf: self.buf,
            limits: self.limits,
            records: self.records,
            includes: self.includes,
            input: self.input,
        }
    }

    /// Replaces the work and size limits (by default those of the
    /// [`ZoneReader`], [`ZoneLimits::DEFAULT`] unless set with
    /// [`ZoneReader::with_limits`]).
    pub fn with_limits(mut self, limits: ZoneLimits) -> Self {
        self.limits = limits;
        if let Some(top) = self.top.as_mut() {
            top.limits = limits;
        }
        self
    }

    /// The work and size limits.
    #[must_use]
    pub const fn limits(&self) -> &ZoneLimits {
        &self.limits
    }

    /// The number of records read so far, in all files.
    #[must_use]
    pub const fn record_count(&self) -> u64 {
        self.records
    }

    /// Sets the deepest `$INCLUDE` nesting allowed (0 forbids includes):
    /// [`ZoneLimits::max_include_depth`].
    pub fn max_include_depth(mut self, depth: usize) -> Self {
        self.limits.max_include_depth = depth;
        self
    }

    /// Sets the most files that may be included in total:
    /// [`ZoneLimits::max_includes`].
    pub fn max_includes(mut self, count: usize) -> Self {
        self.limits.max_includes = count;
        self
    }

    /// Reads the next entry of the innermost open file. `Ok(None)` means
    /// that file has ended (or everything has).
    fn step(&mut self) -> core::result::Result<Option<Step>, ZoneError> {
        if self.buf.is_empty() {
            self.buf = vec![0; usize::from(u16::MAX)];
        }
        if let Some(frame) = self.stack.last_mut() {
            let state = core::mem::replace(&mut frame.state, State::new());
            let mut r = ZoneReader::resume(frame.text.as_bytes(), state, self.limits, self.records);
            let res = r.next_entry(&mut self.buf);
            self.records = r.records;
            let step = match res {
                Ok(Some(e)) => Ok(Some(Step::from_entry(e, r.state())?)),
                Ok(None) => Ok(None),
                Err(e) => Err(e.in_file(&frame.name)),
            };
            frame.state = r.into_state();
            return step;
        }
        let Some(r) = self.top.as_mut() else {
            return Ok(None);
        };
        r.records = self.records;
        let res = r.next_entry(&mut self.buf);
        self.records = r.records;
        match res? {
            Some(e) => Ok(Some(Step::from_entry(e, r.state())?)),
            None => {
                self.top = None;
                Ok(None)
            }
        }
    }

    /// Opens an included file.
    fn include(&mut self, inc: IncludeStep) -> core::result::Result<(), ZoneError> {
        let fail = |e: Error| {
            let err = ZoneError::new(e, inc.line, inc.column);
            match self.stack.last() {
                Some(frame) => err.in_file(&frame.name),
                None => err,
            }
        };
        if self.stack.len() >= self.limits.max_include_depth
            || self.includes >= self.limits.max_includes
        {
            return Err(fail(Error::LimitExceeded));
        }
        let left = self.limits.max_input_len.saturating_sub(self.input);
        let text = match self.resolver.load_limited(&inc.path, left) {
            // The resolver may not have checked.
            Ok(text) if text.len() > left => return Err(fail(Error::LimitExceeded)),
            Ok(text) => text,
            Err(e) => return Err(fail(e)),
        };
        self.input += text.len();
        self.includes += 1;
        self.stack.push(Frame {
            name: inc.path,
            text,
            state: inc.state,
        });
        Ok(())
    }
}

/// An `$INCLUDE` to process.
struct IncludeStep {
    path: String,
    line: u32,
    column: u32,
    /// The included file's initial state.
    state: State,
}

/// An entry, detached from the reader's buffers (short-lived: one at a
/// time).
#[allow(clippy::large_enum_variant)]
enum Step {
    Record(ZoneRecordBuf),
    Include(IncludeStep),
}

impl Step {
    fn from_entry(e: Entry<'_, '_>, state: &State) -> core::result::Result<Step, ZoneError> {
        match e {
            Entry::Record(r) => Ok(Step::Record(r.into())),
            Entry::Include(inc) => {
                let bytes = inc
                    .path
                    .unescape()
                    .collect::<Result<Vec<u8>>>()
                    .and_then(|b| String::from_utf8(b).map_err(|_| Error::InvalidText))
                    .map_err(|e| ZoneError::new(e, inc.line, inc.column))?;
                Ok(Step::Include(IncludeStep {
                    path: bytes,
                    line: inc.line,
                    column: inc.column,
                    state: state.child(inc.origin),
                }))
            }
        }
    }
}

impl<R: IncludeResolver> Iterator for Records<'_, R> {
    type Item = core::result::Result<ZoneRecordBuf, ZoneError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.step() {
                Ok(Some(Step::Record(r))) => return Some(Ok(r)),
                Ok(Some(Step::Include(inc))) => {
                    if let Err(e) = self.include(inc) {
                        return Some(Err(e));
                    }
                }
                // The innermost file ended: continue with its parent.
                Ok(None) => {
                    self.stack.pop()?;
                }
                Err(e) => {
                    // The record limit ends the iteration.
                    if e.error() == Error::LimitExceeded && self.records >= self.limits.max_records
                    {
                        self.top = None;
                        self.stack.clear();
                    }
                    return Some(Err(e));
                }
            }
        }
    }
}

impl<R: IncludeResolver> core::iter::FusedIterator for Records<'_, R> {}

/// Parses a whole master file (no `$INCLUDE`), stopping at the first
/// error, under [`ZoneLimits::DEFAULT`] (see [`parse_with_limits`]).
///
/// # Errors
///
/// The first [`ZoneError`] (see [`ZoneReader::next_record`]); an
/// `$INCLUDE` fails with [`Error::BadInclude`], a limit reached with
/// [`Error::LimitExceeded`].
///
/// ```
/// let zone = dnsbox::zone::parse(
///     "$ORIGIN example.\n$TTL 1d\n@ NS ns1\nns1 A 192.0.2.53\n",
/// )?;
/// assert_eq!(zone.len(), 2);
/// assert_eq!(zone[1].to_string(), "ns1.example. 86400 IN A 192.0.2.53");
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn parse(text: &str) -> core::result::Result<Vec<ZoneRecordBuf>, ZoneError> {
    parse_with_limits(text, ZoneLimits::DEFAULT)
}

/// Parses a whole master file (no `$INCLUDE`) like [`parse`], under
/// `limits`.
///
/// # Errors
///
/// As [`parse`].
///
/// ```
/// use dnsbox::Error;
/// use dnsbox::zone::{ZoneLimits, parse_with_limits};
///
/// let text = "$TTL 60\n$GENERATE 1-200 host$ A 192.0.2.$\n";
/// let limits = ZoneLimits::DEFAULT.with_max_records(100);
/// let err = parse_with_limits(text, limits).unwrap_err();
/// assert_eq!((err.error(), err.line()), (Error::LimitExceeded, 2));
/// assert_eq!(parse_with_limits(text, limits.with_max_records(200))?.len(), 200);
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn parse_with_limits(
    text: &str,
    limits: ZoneLimits,
) -> core::result::Result<Vec<ZoneRecordBuf>, ZoneError> {
    ZoneReader::new(text)
        .with_limits(limits)
        .records()
        .collect()
}
