//! [`ZoneReader`]: streaming, allocation-free master-file parsing
//! (RFC 1035 §5).

use core::fmt;

use super::generate::{self, Range};
use super::lexer::{self, Cursor, Pos, is_blank};
use super::scanner::{Scanner, Token, parse_ttl, resolve_name};
use crate::name::{Name, NameBuf, ToName};
use crate::rdata::RData;
use crate::wire::{WireReader, WireWriter};
use crate::{Class, Error, Result, Rtype};

/// A resource record read from a master file.
///
/// The owner name is an inline [`NameBuf`]; the RDATA is in wire format
/// (uncompressed) in the buffer passed to [`ZoneReader::next_record`].
/// [`data`](Self::data) gives the typed view; to put the record in a
/// message, push that view (the builder compresses names where allowed):
///
/// ```
/// use dnsbox::zone::ZoneReader;
/// use dnsbox::{Message, MessageBuilder};
///
/// let mut zone = ZoneReader::new("www.example. 300 IN A 192.0.2.7\n");
/// let mut rdata = [0u8; 512];
/// let rr = zone.next_record(&mut rdata)?.expect("one record");
///
/// let mut buf = [0u8; 512];
/// let mut b = MessageBuilder::new(&mut buf)?;
/// b.push_answer(&rr.name, rr.class, rr.ttl, &rr.data()?)?;
/// let msg = Message::parse_validated(b.finish())?;
/// assert_eq!(msg.answers().next().unwrap()?.to_string(), "www.example. 300 IN A 192.0.2.7");
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ZoneRecord<'b> {
    /// The owner name.
    pub name: NameBuf,
    /// The TTL, explicit or defaulted (see the [module docs](super)).
    pub ttl: u32,
    /// The class.
    pub class: Class,
    /// The record type.
    pub rtype: Rtype,
    /// The RDATA in uncompressed wire format, already checked with the
    /// type's wire parser.
    pub rdata: &'b [u8],
    /// The line the entry starts on (1-based).
    pub line: u32,
}

impl<'b> ZoneRecord<'b> {
    /// The typed record data (see [`RData::parse`]).
    #[inline]
    pub fn data(&self) -> Result<RData<'b>> {
        RData::parse(self.rtype, self.class, WireReader::new(self.rdata))
    }
}

impl fmt::Display for ZoneRecord<'_> {
    /// Zone-file style: `owner ttl class type rdata`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_record(
            f,
            self.name.as_name(),
            self.ttl,
            self.class,
            self.rtype,
            self.rdata,
        )
    }
}

/// Writes `owner ttl class type rdata`, the RDATA in its type's
/// presentation format or the generic RFC 3597 form.
pub(super) fn write_record(
    f: &mut fmt::Formatter<'_>,
    owner: Name<'_>,
    ttl: u32,
    class: Class,
    rtype: Rtype,
    rdata: &[u8],
) -> fmt::Result {
    write!(f, "{owner} {ttl} {class} {rtype} ")?;
    match RData::parse(rtype, class, WireReader::new(rdata)) {
        Ok(d) => fmt::Display::fmt(&d, f),
        Err(_) => crate::text::fmt_generic_rdata(f, rdata),
    }
}

/// An `$INCLUDE <file-name> [<domain-name>]` directive (RFC 1035 §5.1).
///
/// [`ZoneReader::next_entry`] reports it for the caller to process: read
/// the named file and parse it with a reader whose origin is
/// [`origin`](Self::origin); afterwards the including file continues with
/// its own origin. [`Records`](super::Records) does this through an
/// [`IncludeResolver`](super::IncludeResolver).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Include<'a> {
    /// The file name as written (decode escapes with
    /// [`Token::unescape`]).
    pub path: Token<'a>,
    /// The origin for the included file: the directive's domain name, or
    /// the current origin.
    pub origin: NameBuf,
    /// The line of the directive (1-based).
    pub line: u32,
    /// The column of the directive (1-based).
    pub column: u32,
}

/// One entry of a master file, as returned by
/// [`ZoneReader::next_entry`].
///
/// More kinds of entries may be reported in future versions.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Entry<'a, 'b> {
    /// A resource record.
    Record(ZoneRecord<'b>),
    /// An `$INCLUDE` directive.
    Include(Include<'a>),
}

/// An error in a master file, with its position.
///
/// The column counts characters (not bytes) from 1; it points at the
/// offending token where there is one, otherwise at the start of the
/// entry.
///
/// It converts into the plain [`Error`] (dropping the position) with `?`,
/// and reports that error as its [`source`](core::error::Error::source).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ZoneError {
    error: Error,
    line: u32,
    column: u32,
    #[cfg(feature = "alloc")]
    file: Option<alloc::string::String>,
}

impl ZoneError {
    /// An error at a position.
    pub const fn new(error: Error, line: u32, column: u32) -> Self {
        ZoneError {
            error,
            line,
            column,
            #[cfg(feature = "alloc")]
            file: None,
        }
    }

    /// What went wrong.
    #[inline]
    pub const fn error(&self) -> Error {
        self.error
    }

    /// The line (1-based).
    #[inline]
    pub const fn line(&self) -> u32 {
        self.line
    }

    /// The column (1-based, in characters).
    #[inline]
    pub const fn column(&self) -> u32 {
        self.column
    }

    /// The included file the error is in, as named by its `$INCLUDE`
    /// directive (`None` for the top-level text).
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn file(&self) -> Option<&str> {
        self.file.as_deref()
    }

    /// Sets [`file`](Self::file).
    #[cfg(feature = "alloc")]
    pub(super) fn in_file(mut self, file: &str) -> Self {
        self.file = Some(file.into());
        self
    }
}

impl fmt::Display for ZoneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(feature = "alloc")]
        if let Some(file) = &self.file {
            write!(f, "{file}: ")?;
        }
        write!(
            f,
            "line {}, column {}: {}",
            self.line, self.column, self.error
        )
    }
}

impl core::error::Error for ZoneError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl From<ZoneError> for Error {
    #[inline]
    fn from(e: ZoneError) -> Error {
        e.error
    }
}

/// A `$GENERATE` directive in progress.
#[derive(Clone, Copy, Debug)]
struct Generate {
    range: Range,
    /// The next iterator value.
    next: u32,
    /// Byte range of the owner template.
    lhs: (usize, usize),
    /// Byte range of the RDATA template (quotes included).
    rhs: (usize, usize),
    rtype: Rtype,
    class: Class,
    ttl: u32,
    /// The directive's position.
    pos: Pos,
}

/// The parser state between entries (plain data: the include driver
/// suspends and resumes readers through it).
#[derive(Clone, Debug)]
pub(super) struct State {
    cur: Cursor,
    origin: NameBuf,
    owner: Option<NameBuf>,
    /// `$TTL` (RFC 2308 §4).
    default_ttl: Option<u32>,
    /// The last explicit TTL (RFC 1035 §5.1).
    last_ttl: Option<u32>,
    /// The class of the previous record.
    class: Class,
    generate: Option<Generate>,
}

impl State {
    /// The state at the start of a file.
    pub(super) const fn new() -> Self {
        State {
            cur: Cursor::START,
            origin: NameBuf::root(),
            owner: None,
            default_ttl: None,
            last_ttl: None,
            class: Class::IN,
            generate: None,
        }
    }

    /// The state an included file starts with (RFC 1035 §5.1): this one's
    /// defaults and current owner, the given origin.
    #[cfg(feature = "alloc")]
    pub(super) fn child(&self, origin: NameBuf) -> Self {
        State {
            cur: Cursor::START,
            origin,
            owner: self.owner.clone(),
            default_ttl: self.default_ttl,
            last_ttl: self.last_ttl,
            class: self.class,
            generate: None,
        }
    }
}

/// Streaming master-file parser (RFC 1035 §5) over text in memory; see
/// the [module docs](super) for the syntax.
///
/// Nothing is allocated: owner names are inline and each record's RDATA is
/// written to the buffer passed to [`next_record`](Self::next_record) /
/// [`next_entry`](Self::next_entry) (65535 bytes always suffice). After an
/// error the reader skips to the next entry, so it can be called again to
/// find further errors.
///
/// ```
/// use dnsbox::zone::ZoneReader;
/// use dnsbox::Error;
///
/// let mut zone = ZoneReader::new("a 60 IN A 192.0.2.1\nb 60 IN A 192.0.2.256\nc 60 IN TXT hi\n")
///     .with_origin(&"example.".parse::<dnsbox::NameBuf>()?);
/// let mut buf = [0u8; 512];
/// assert_eq!(zone.next_record(&mut buf)?.unwrap().name.to_string(), "a.example.");
/// let err = zone.next_record(&mut buf).unwrap_err();
/// assert_eq!((err.error(), err.line(), err.column()), (Error::InvalidText, 2, 11));
/// assert_eq!(zone.next_record(&mut buf)?.unwrap().name.to_string(), "c.example.");
/// assert!(zone.next_record(&mut buf)?.is_none());
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Debug)]
pub struct ZoneReader<'a> {
    input: &'a [u8],
    st: State,
}

impl<'a> ZoneReader<'a> {
    /// A reader over master-file text, with the root as origin, no
    /// default TTL and class IN for records that name none.
    #[inline]
    pub fn new(text: &'a str) -> Self {
        ZoneReader::from_bytes(text.as_bytes())
    }

    /// Like [`new`](Self::new), for text that is not necessarily UTF-8.
    #[inline]
    pub const fn from_bytes(text: &'a [u8]) -> Self {
        ZoneReader {
            input: text,
            st: State::new(),
        }
    }

    /// Resumes parsing `input` from a saved state.
    #[cfg(feature = "alloc")]
    pub(super) const fn resume(input: &'a [u8], st: State) -> Self {
        ZoneReader { input, st }
    }

    /// The state, for [`resume`](Self::resume).
    #[cfg(feature = "alloc")]
    pub(super) fn into_state(self) -> State {
        self.st
    }

    /// The state.
    #[cfg(feature = "alloc")]
    pub(super) const fn state(&self) -> &State {
        &self.st
    }

    /// Sets the initial origin, as if the text started with `$ORIGIN`.
    #[inline]
    pub fn with_origin(mut self, origin: impl ToName) -> Self {
        self.st.origin = origin.to_name().to_buf();
        self
    }

    /// Sets the default TTL, as if the text started with `$TTL`
    /// (RFC 2308 §4).
    #[inline]
    pub fn with_default_ttl(mut self, ttl: u32) -> Self {
        self.st.default_ttl = Some(ttl);
        self
    }

    /// Sets the class used until a record names one (IN by default).
    #[inline]
    pub fn with_class(mut self, class: Class) -> Self {
        self.st.class = class;
        self
    }

    /// The current origin (`$ORIGIN`).
    #[inline]
    pub fn origin(&self) -> Name<'_> {
        self.st.origin.as_name()
    }

    /// The current default TTL (`$TTL`), if any.
    #[inline]
    pub const fn default_ttl(&self) -> Option<u32> {
        self.st.default_ttl
    }

    /// The line the reader is on (1-based).
    #[inline]
    pub const fn line(&self) -> u32 {
        self.st.cur.pos.line
    }

    /// Reads the next resource record into `buf` (which receives the
    /// RDATA), handling `$ORIGIN`, `$TTL` and `$GENERATE` on the way.
    /// Returns `Ok(None)` at the end of the text.
    ///
    /// `$INCLUDE` fails with [`Error::BadInclude`]; use
    /// [`next_entry`](Self::next_entry) or
    /// [`records`](Self::records) with a resolver to follow it. RDATA
    /// that does not fit in `buf` fails with [`Error::BufferTooSmall`].
    pub fn next_record<'b>(
        &mut self,
        buf: &'b mut [u8],
    ) -> core::result::Result<Option<ZoneRecord<'b>>, ZoneError> {
        match self.next_entry(buf)? {
            None => Ok(None),
            Some(Entry::Record(r)) => Ok(Some(r)),
            Some(Entry::Include(i)) => Err(ZoneError::new(Error::BadInclude, i.line, i.column)),
        }
    }

    /// Reads the next entry: a resource record (RDATA written to `buf`)
    /// or an `$INCLUDE` directive. Other directives are applied on the
    /// way; blank and comment-only lines are skipped. Returns `Ok(None)` at
    /// the end of the text.
    pub fn next_entry<'b>(
        &mut self,
        buf: &'b mut [u8],
    ) -> core::result::Result<Option<Entry<'a, 'b>>, ZoneError> {
        let input = self.input;
        loop {
            if self.st.generate.is_some() {
                return self.generated(buf).map(|r| Some(Entry::Record(r)));
            }
            let start = self.st.cur;
            if start.pos.offset >= input.len() {
                return Ok(None);
            }
            // An entry starting with a blank has no owner field (RFC 1035
            // §5.1: the previous owner is reused).
            let owner_field = input
                .get(start.pos.offset)
                .is_some_and(|&c| !is_blank(c) && !matches!(c, b'\n' | b';' | b'(' | b')'));
            let mut s = Scanner::entry(input, start, Name::ROOT);
            let first = match s.peek() {
                Ok(Some(t)) => t,
                Ok(None) => {
                    // Blank or comment-only line.
                    let _ = s.next_token();
                    self.st.cur = s.cursor();
                    if self.st.cur == start {
                        return Ok(None);
                    }
                    continue;
                }
                Err(e) => return Err(self.fail(s, e)),
            };
            if owner_field && !first.is_quoted() && first.as_bytes().first() == Some(&b'$') {
                let _ = s.next_token();
                match self.directive(first, &mut s) {
                    Ok(None) => continue,
                    Ok(Some(include)) => return Ok(Some(Entry::Include(include))),
                    // A `$GENERATE` without a TTL: the whole directive.
                    Err(Error::MissingTtl) => {
                        self.st.cur = resync(input, s);
                        return Err(self.error_at(Error::MissingTtl, start.pos));
                    }
                    Err(e) => return Err(self.fail(s, e)),
                }
            }
            return self
                .record(s, owner_field, buf)
                .map(|r| Some(Entry::Record(r)));
        }
    }

    /// Follows `$INCLUDE` directives through `resolver` while iterating;
    /// see [`Records`](super::Records). Without a resolver
    /// ([`Records::with_includes`](super::Records::with_includes)),
    /// `$INCLUDE` is an error.
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn records(self) -> super::Records<'a, super::NoIncludes> {
        super::Records::new(self)
    }

    /// Converts a position to a [`ZoneError`].
    fn error_at(&self, error: Error, pos: Pos) -> ZoneError {
        ZoneError::new(error, pos.line, pos.column(self.input))
    }

    /// Reports `error` at the scanner's last token and skips the rest of
    /// the entry.
    fn fail(&mut self, s: Scanner<'_>, error: Error) -> ZoneError {
        let pos = s.last_pos();
        self.st.cur = resync(self.input, s);
        self.error_at(error, pos)
    }

    /// Applies a directive whose name is `name`; `$INCLUDE` is returned.
    fn directive(&mut self, name: Token<'a>, s: &mut Scanner<'a>) -> Result<Option<Include<'a>>> {
        let name = name.as_bytes();
        if name.eq_ignore_ascii_case(b"$ORIGIN") {
            // A relative origin is relative to the current one.
            let origin = resolve_name(s.word()?.as_bytes(), self.st.origin.as_name())?;
            s.finish()?;
            self.st.origin = origin;
            Ok(None)
        } else if name.eq_ignore_ascii_case(b"$TTL") {
            let ttl = parse_ttl(s.word()?.as_bytes())?;
            s.finish()?;
            self.st.default_ttl = Some(ttl);
            Ok(None)
        } else if name.eq_ignore_ascii_case(b"$INCLUDE") {
            let pos = self.st.cur.pos;
            let path = s.token()?;
            let origin = match s.next_token()? {
                Some(t) if !t.is_quoted() => resolve_name(t.as_bytes(), self.st.origin.as_name())?,
                Some(_) => return Err(Error::InvalidText),
                None => self.st.origin.clone(),
            };
            s.finish()?;
            Ok(Some(Include {
                path,
                origin,
                line: pos.line,
                column: pos.column(self.input),
            }))
        } else if name.eq_ignore_ascii_case(b"$GENERATE") {
            self.start_generate(s)?;
            Ok(None)
        } else {
            Err(Error::UnknownMnemonic)
        }
        .inspect(|_| self.st.cur = s.cursor())
    }

    /// Parses `$GENERATE range lhs [ttl] [class] type rhs`.
    fn start_generate(&mut self, s: &mut Scanner<'a>) -> Result<()> {
        let pos = self.st.cur.pos;
        let range = Range::parse(s.word()?.as_bytes())?;
        let lhs = s.word()?;
        let at = s.last_pos().offset;
        let lhs = (at, at + lhs.as_bytes().len());
        let (ttl, class, rtype) = fields(s)?;
        let rhs = s.token()?;
        let at = s.last_pos().offset;
        let quotes = if rhs.is_quoted() { 2 } else { 0 };
        let rhs = (at, at + rhs.as_bytes().len() + quotes);
        s.finish()?;
        let ttl = match ttl {
            Some(ttl) => {
                self.st.last_ttl = Some(ttl);
                ttl
            }
            None => self
                .st
                .default_ttl
                .or(self.st.last_ttl)
                .ok_or(Error::MissingTtl)?,
        };
        let class = class.unwrap_or(self.st.class);
        self.st.class = class;
        self.st.generate = Some(Generate {
            range,
            next: range.start,
            lhs,
            rhs,
            rtype,
            class,
            ttl,
            pos,
        });
        Ok(())
    }

    /// The next record of the `$GENERATE` in progress.
    fn generated<'b>(
        &mut self,
        buf: &'b mut [u8],
    ) -> core::result::Result<ZoneRecord<'b>, ZoneError> {
        let Some(mut g) = self.st.generate else {
            return Err(ZoneError::new(Error::InvalidText, self.line(), 1));
        };
        let value = g.next;
        self.st.generate = g.range.after(value).map(|next| {
            g.next = next;
            g
        });
        generate_one(self.input, self.st.origin.as_name(), &g, value, buf).map_err(|e| {
            self.st.generate = None;
            self.error_at(e, g.pos)
        })
    }

    /// Parses a resource-record entry.
    fn record<'b>(
        &mut self,
        mut s: Scanner<'a>,
        owner_field: bool,
        buf: &'b mut [u8],
    ) -> core::result::Result<ZoneRecord<'b>, ZoneError> {
        let entry = self.st.cur.pos;
        let owner = if owner_field {
            let t = match s.word() {
                Ok(t) => t,
                Err(e) => return Err(self.fail(s, e)),
            };
            match resolve_name(t.as_bytes(), self.st.origin.as_name()) {
                // The owner sticks even if the rest of the entry is bad, so
                // that following blank-owner lines get the intended owner.
                Ok(owner) => {
                    self.st.owner = Some(owner.clone());
                    owner
                }
                Err(e) => return Err(self.fail(s, e)),
            }
        } else {
            match &self.st.owner {
                Some(owner) => owner.clone(),
                None => return Err(self.fail(s, Error::InvalidText)),
            }
        };
        let (ttl, class, rtype) = match fields(&mut s) {
            Ok(f) => f,
            Err(e) => return Err(self.fail(s, e)),
        };
        let class = class.unwrap_or(self.st.class);
        let type_pos = s.last_pos();
        let mut w = WireWriter::new(buf);
        let mut rs = Scanner::entry(self.input, s.cursor(), self.st.origin.as_name());
        let rdata_start = rs.last_pos();
        if let Err(e) = RData::parse_text(rtype, class, &mut rs, &mut w) {
            // Errors before the first RDATA token (no RDATA, no text
            // format) point at the type.
            let pos = match rs.last_pos() {
                p if p == rdata_start => type_pos,
                p => p,
            };
            self.st.cur = resync(self.input, rs);
            return Err(self.error_at(e, pos));
        }
        self.st.cur = rs.cursor();
        let rdata: &'b [u8] = w.into_written();
        let ttl_given = ttl.is_some();
        let ttl = match ttl.or(self.st.default_ttl) {
            Some(t) => t,
            None => match self.st.last_ttl {
                Some(t) => t,
                // No TTL anywhere: like BIND, use the SOA's MINIMUM field
                // (which then also applies to later records).
                None if rtype == Rtype::SOA => match rdata.last_chunk::<4>() {
                    Some(min) => u32::from_be_bytes(*min),
                    None => return Err(self.error_at(Error::MissingTtl, entry)),
                },
                None => return Err(self.error_at(Error::MissingTtl, entry)),
            },
        };
        if self.st.default_ttl.is_none() || ttl_given {
            self.st.last_ttl = Some(ttl);
        }
        self.st.class = class;
        Ok(ZoneRecord {
            name: owner,
            ttl,
            class,
            rtype,
            rdata,
            line: entry.line,
        })
    }
}

/// Produces the record of iteration `value` of `$GENERATE` `g`.
fn generate_one<'b>(
    input: &[u8],
    origin: Name<'_>,
    g: &Generate,
    value: u32,
    buf: &'b mut [u8],
) -> Result<ZoneRecord<'b>> {
    let template = |(a, b): (usize, usize)| input.get(a..b).unwrap_or(&[]);
    let mut text = [0u8; generate::TEXT_MAX];
    let n = generate::substitute(template(g.lhs), value, &mut text)?;
    let owner = resolve_name(text.get(..n).unwrap_or(&[]), origin)?;
    let n = generate::substitute(template(g.rhs), value, &mut text)?;
    let mut s = Scanner::from_bytes(text.get(..n).unwrap_or(&[])).with_origin(origin);
    let mut w = WireWriter::new(buf);
    RData::parse_text(g.rtype, g.class, &mut s, &mut w)?;
    Ok(ZoneRecord {
        name: owner,
        ttl: g.ttl,
        class: g.class,
        rtype: g.rtype,
        rdata: w.into_written(),
        line: g.pos.line,
    })
}

/// Reads `[TTL] [class] type` (TTL and class in either order).
fn fields(s: &mut Scanner<'_>) -> Result<(Option<u32>, Option<Class>, Rtype)> {
    let mut ttl = None;
    let mut class = None;
    loop {
        let t = s.word()?;
        let raw = t.as_bytes();
        if ttl.is_none() && raw.first().is_some_and(u8::is_ascii_digit) {
            ttl = Some(parse_ttl(raw)?);
            continue;
        }
        let text = t.as_str()?;
        if class.is_none()
            && let Ok(c) = text.parse::<Class>()
        {
            class = Some(c);
            continue;
        }
        return Ok((ttl, class, text.parse()?));
    }
}

/// Skips the rest of the entry `s` is in (or, after a lexical error, the
/// rest of the line) and returns where the next entry starts.
fn resync(input: &[u8], mut s: Scanner<'_>) -> Cursor {
    if !s.lex_failed() {
        while let Ok(Some(_)) = s.next_token() {}
    }
    let mut cur = s.cursor();
    if s.lex_failed() {
        lexer::skip_line(input, &mut cur);
    }
    cur
}
