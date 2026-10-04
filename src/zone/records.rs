//! Owned zone records, the record [`Iterator`] and `$INCLUDE` handling
//! (`alloc`).

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use super::reader::{Entry, State, ZoneError, ZoneReader, ZoneRecord, write_record};
use crate::name::NameBuf;
use crate::rdata::RData;
use crate::wire::WireReader;
use crate::{Class, Error, Result, Rtype};

/// Default limit on `$INCLUDE` nesting for [`Records`].
pub const DEFAULT_MAX_INCLUDE_DEPTH: usize = 8;

/// Default limit on the number of `$INCLUDE`d files for [`Records`].
pub const DEFAULT_MAX_INCLUDES: usize = 256;

/// An owned resource record read from a master file: a [`ZoneRecord`]
/// with its RDATA in a `Vec`.
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
/// file that cannot be loaded.
pub trait IncludeResolver {
    /// Returns the text of the file named `path` (escapes already
    /// decoded).
    fn load(&mut self, path: &str) -> Result<String>;
}

impl<F: FnMut(&str) -> Result<String>> IncludeResolver for F {
    #[inline]
    fn load(&mut self, path: &str) -> Result<String> {
        self(path)
    }
}

/// An [`IncludeResolver`] that refuses every `$INCLUDE`
/// ([`Error::BadInclude`]).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoIncludes;

impl IncludeResolver for NoIncludes {
    #[inline]
    fn load(&mut self, _path: &str) -> Result<String> {
        Err(Error::BadInclude)
    }
}

/// An [`IncludeResolver`] reading files from the file system, relative
/// paths being resolved against a base directory (BIND resolves them
/// against its working directory, usually the zone directory).
///
/// It opens whatever path the zone file names, absolute paths and `..`
/// included: only use it for trusted zone files.
#[cfg(feature = "std")]
#[derive(Clone, Debug)]
pub struct FsIncludes {
    base: std::path::PathBuf,
}

#[cfg(feature = "std")]
impl FsIncludes {
    /// Resolves relative paths against `base`.
    pub fn new(base: impl Into<std::path::PathBuf>) -> Self {
        FsIncludes { base: base.into() }
    }
}

#[cfg(feature = "std")]
impl IncludeResolver for FsIncludes {
    fn load(&mut self, path: &str) -> Result<String> {
        std::fs::read_to_string(self.base.join(path)).map_err(|_| Error::BadInclude)
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
/// Nesting is limited to [`DEFAULT_MAX_INCLUDE_DEPTH`] levels and
/// [`DEFAULT_MAX_INCLUDES`] files in total (see
/// [`max_include_depth`](Self::max_include_depth) and
/// [`max_includes`](Self::max_includes)); beyond that, and when the
/// resolver fails, the directive yields [`Error::BadInclude`].
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
    max_depth: usize,
    max_includes: usize,
    includes: usize,
}

impl<R> fmt::Debug for Records<'_, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Records")
            .field("top", &self.top)
            .field("depth", &self.stack.len())
            .field("includes", &self.includes)
            .finish_non_exhaustive()
    }
}

impl<'a> Records<'a, NoIncludes> {
    /// Iterates over `reader`'s records.
    pub(super) fn new(reader: ZoneReader<'a>) -> Self {
        Records {
            top: Some(reader),
            stack: Vec::new(),
            resolver: NoIncludes,
            buf: Vec::new(),
            max_depth: DEFAULT_MAX_INCLUDE_DEPTH,
            max_includes: DEFAULT_MAX_INCLUDES,
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
            max_depth: self.max_depth,
            max_includes: self.max_includes,
            includes: self.includes,
        }
    }

    /// Sets the deepest `$INCLUDE` nesting allowed (0 forbids includes).
    pub fn max_include_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    /// Sets the most files that may be included in total.
    pub fn max_includes(mut self, count: usize) -> Self {
        self.max_includes = count;
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
            let mut r = ZoneReader::resume(frame.text.as_bytes(), state);
            let res = r.next_entry(&mut self.buf);
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
        match r.next_entry(&mut self.buf)? {
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
        if self.stack.len() >= self.max_depth || self.includes >= self.max_includes {
            return Err(fail(Error::BadInclude));
        }
        let text = match self.resolver.load(&inc.path) {
            Ok(text) => text,
            Err(e) => return Err(fail(e)),
        };
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
                Err(e) => return Some(Err(e)),
            }
        }
    }
}

impl<R: IncludeResolver> core::iter::FusedIterator for Records<'_, R> {}

/// Parses a whole master file (no `$INCLUDE`), stopping at the first
/// error.
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
    ZoneReader::new(text).records().collect()
}
