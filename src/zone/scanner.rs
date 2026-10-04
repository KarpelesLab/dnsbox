//! [`Scanner`]: reading the RDATA fields of one master-file entry
//! (RFC 1035 §5.1), with the shared field parsers every record type's
//! [`ParseRdataText`](crate::rdata::ParseRdataText) implementation uses.

use core::net::{Ipv4Addr, Ipv6Addr};
use core::str::FromStr;

use super::lexer::{self, Cursor, Lexeme, Pos};
use crate::dnssec::Timestamp;
use crate::name::{MAX_NAME_LEN, Name, NameBuf};
use crate::util::{base32hex, base64};
use crate::wire::{Composer, NameEncoding, OutBuf};
use crate::{Error, Result, Rtype};

/// One token of presentation-format text: a contiguous run of characters
/// or a quoted string (RFC 1035 §5.1).
///
/// The bytes are as written, escapes (`\X`, `\DDD`) not yet decoded; a
/// quoted string's surrounding quotes are not included. Decode with
/// [`unescape`](Self::unescape) (character-strings) or let the
/// [`Scanner`] methods interpret the token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token<'a> {
    raw: &'a [u8],
    quoted: bool,
}

impl<'a> Token<'a> {
    /// The token as written (escapes not decoded, quotes stripped).
    #[inline]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.raw
    }

    /// Whether the token was a quoted string. Quoting is only meaningful
    /// for `<character-string>`s; numbers, names and mnemonics are never
    /// quoted.
    #[inline]
    pub const fn is_quoted(&self) -> bool {
        self.quoted
    }

    /// The token as UTF-8 text, or [`Error::InvalidText`].
    #[inline]
    pub fn as_str(&self) -> Result<&'a str> {
        core::str::from_utf8(self.raw).map_err(|_| Error::InvalidText)
    }

    /// Whether the token is unquoted and equals `s`, ASCII
    /// case-insensitively (for mnemonics such as `TCP` or `\#`).
    #[inline]
    pub fn is(&self, s: &str) -> bool {
        !self.quoted && self.raw.eq_ignore_ascii_case(s.as_bytes())
    }

    /// Decodes the escapes (RFC 1035 §5.1: `\DDD` is the octet with
    /// decimal value DDD, `\X` is X), as for a `<character-string>`.
    #[inline]
    pub const fn unescape(&self) -> Unescape<'a> {
        Unescape(self.raw)
    }

    /// The token as an unsigned decimal number of at most `max`
    /// (unquoted, digits only), or [`Error::InvalidText`].
    fn number(&self, max: u64) -> Result<u64> {
        if self.quoted {
            return Err(Error::InvalidText);
        }
        parse_decimal(self.raw)
            .filter(|&v| v <= max)
            .ok_or(Error::InvalidText)
    }

    /// The token as an 8-bit unsigned decimal number.
    #[inline]
    pub fn u8(&self) -> Result<u8> {
        self.number(u8::MAX.into()).map(|v| v as u8)
    }

    /// The token as a 16-bit unsigned decimal number.
    #[inline]
    pub fn u16(&self) -> Result<u16> {
        self.number(u16::MAX.into()).map(|v| v as u16)
    }

    /// The token as a 32-bit unsigned decimal number.
    #[inline]
    pub fn u32(&self) -> Result<u32> {
        self.number(u32::MAX.into()).map(|v| v as u32)
    }
}

/// Iterator over the decoded octets of a [`Token`] (RFC 1035 §5.1
/// escapes); yields [`Error::InvalidText`] once for a malformed escape
/// (`\DDD` above 255, fewer than three digits, or a trailing backslash).
#[derive(Clone, Debug)]
pub struct Unescape<'a>(&'a [u8]);

impl Iterator for Unescape<'_> {
    type Item = Result<u8>;

    fn next(&mut self) -> Option<Result<u8>> {
        let (&c, rest) = self.0.split_first()?;
        if c != b'\\' {
            self.0 = rest;
            return Some(Ok(c));
        }
        let (byte, used) = match rest {
            [a, b, c, ..] if a.is_ascii_digit() => {
                if !b.is_ascii_digit() || !c.is_ascii_digit() {
                    return self.fail();
                }
                let v = u16::from(a - b'0') * 100 + u16::from(b - b'0') * 10 + u16::from(c - b'0');
                match u8::try_from(v) {
                    Ok(v) => (v, 3),
                    Err(_) => return self.fail(),
                }
            }
            [a, ..] if a.is_ascii_digit() => return self.fail(),
            [x, ..] => (*x, 1),
            [] => return self.fail(),
        };
        self.0 = rest.get(used..).unwrap_or(&[]);
        Some(Ok(byte))
    }
}

impl core::iter::FusedIterator for Unescape<'_> {}

impl<'a> Unescape<'a> {
    /// Decodes the escapes in `text` (as written, quotes removed).
    #[inline]
    pub const fn new(text: &'a [u8]) -> Self {
        Unescape(text)
    }
}

impl Unescape<'_> {
    /// Reports a bad escape once, then ends.
    fn fail(&mut self) -> Option<Result<u8>> {
        self.0 = &[];
        Some(Err(Error::InvalidText))
    }
}

/// Reads the fields of one presentation-format RDATA (RFC 1035 §5.1):
/// the token source handed to
/// [`ParseRdataText`](crate::rdata::ParseRdataText) implementations.
///
/// Tokens are separated by blanks; parentheses let an entry span lines;
/// `;` starts a comment; `"..."` quotes a `<character-string>`; `\X` and
/// `\DDD` escape characters. Relative domain names are completed with the
/// scanner's origin and `@` stands for the origin itself (RFC 1035 §5.1).
///
/// A scanner from [`Scanner::new`] reads standalone RDATA text, where
/// newlines are just blanks; the [`ZoneReader`](super::ZoneReader) hands
/// out scanners that stop at the end of the current master-file entry.
/// Scanning allocates nothing, and `Scanner` is cheap to clone, so a
/// parser can look ahead or make a second pass over the remaining tokens.
///
/// The field methods take the next token and fail with
/// [`Error::UnexpectedEof`] if there is none, and with
/// [`Error::InvalidText`] (or a more specific error) if it is malformed.
///
/// ```
/// use dnsbox::zone::Scanner;
/// use dnsbox::{Composer, NameBuf, NameEncoding, WireWriter};
///
/// let origin: NameBuf = "example.com".parse()?;
/// let mut s = Scanner::new("10 mail ; the exchange").with_origin(origin.as_name());
/// let mut buf = [0u8; 64];
/// let mut w = WireWriter::new(&mut buf);
/// w.put_u16(s.u16()?)?;
/// s.name_into(&mut w, NameEncoding::Compressible)?;
/// s.finish()?;
/// assert_eq!(w.written(), b"\x00\x0a\x04mail\x07example\x03com\x00");
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Debug)]
pub struct Scanner<'a> {
    input: &'a [u8],
    cur: Cursor,
    origin: Name<'a>,
    /// Start of the last token returned, or where lexing failed.
    last: Pos,
    /// The end of the entry (or a lexing error) has been reached.
    end: bool,
    /// Newlines are blanks (standalone RDATA text).
    multiline: bool,
    /// Lexing failed (the reader must resynchronise on the next line).
    lex_error: bool,
}

impl<'a> Scanner<'a> {
    /// A scanner over standalone presentation-format RDATA (e.g.
    /// `"10 mail.example.com."`). Newlines count as blanks; relative names
    /// are completed with the root (set another origin with
    /// [`with_origin`](Self::with_origin)).
    #[inline]
    pub fn new(text: &'a str) -> Self {
        Scanner::from_bytes(text.as_bytes())
    }

    /// Like [`new`](Self::new), for text that is not necessarily UTF-8
    /// (escapes are the portable way to write other octets).
    #[inline]
    pub fn from_bytes(text: &'a [u8]) -> Self {
        Scanner {
            input: text,
            cur: Cursor::START,
            origin: Name::ROOT,
            last: lexer::Pos::START,
            end: false,
            multiline: true,
            lex_error: false,
        }
    }

    /// A scanner over the master-file entry starting at `cur`.
    pub(crate) fn entry(input: &'a [u8], cur: Cursor, origin: Name<'a>) -> Self {
        Scanner {
            input,
            cur,
            origin,
            last: cur.pos,
            end: false,
            multiline: false,
            lex_error: false,
        }
    }

    /// Sets the origin that relative names are completed with
    /// (`$ORIGIN`, RFC 1035 §5.1).
    #[inline]
    pub fn with_origin(mut self, origin: Name<'a>) -> Self {
        self.origin = origin;
        self
    }

    /// The origin relative names are completed with.
    #[inline]
    pub fn origin(&self) -> Name<'a> {
        self.origin
    }

    /// The lexer position after the tokens read so far.
    #[inline]
    pub(crate) fn cursor(&self) -> Cursor {
        self.cur
    }

    /// Where the last token started (or lexing failed): the position
    /// reported with errors.
    #[inline]
    pub(crate) fn last_pos(&self) -> Pos {
        self.last
    }

    /// Whether lexing failed (so the entry's end is unknown).
    #[inline]
    pub(crate) fn lex_failed(&self) -> bool {
        self.lex_error
    }

    /// The next token of the entry, or `None` at its end.
    ///
    /// Fails with [`Error::InvalidText`] on a lexical error: an unbalanced
    /// parenthesis, an unterminated quoted string, or a trailing backslash.
    pub fn next_token(&mut self) -> Result<Option<Token<'a>>> {
        if self.end {
            return Ok(None);
        }
        match lexer::next(self.input, &mut self.cur, self.multiline) {
            Ok(Lexeme::Token { start, end, quoted }) => {
                self.last = start;
                let range = if quoted {
                    start.offset + 1..end.saturating_sub(1)
                } else {
                    start.offset..end
                };
                Ok(Some(Token {
                    raw: self.input.get(range).unwrap_or(&[]),
                    quoted,
                }))
            }
            Ok(Lexeme::EndOfEntry | Lexeme::EndOfInput) => {
                self.end = true;
                Ok(None)
            }
            Err((e, pos)) => {
                self.end = true;
                self.lex_error = true;
                self.last = pos;
                Err(e)
            }
        }
    }

    /// The next token without consuming it.
    ///
    /// A lexical error is reported as by
    /// [`next_token`](Self::next_token), and ends the entry.
    #[inline]
    pub fn peek(&mut self) -> Result<Option<Token<'a>>> {
        let mut ahead = self.clone();
        let res = ahead.next_token();
        if res.is_err() {
            *self = ahead;
        }
        res
    }

    /// Whether all tokens of the entry have been read.
    #[inline]
    pub fn is_at_end(&mut self) -> Result<bool> {
        self.peek().map(|t| t.is_none())
    }

    /// The next token; [`Error::UnexpectedEof`] if there is none.
    #[inline]
    pub fn token(&mut self) -> Result<Token<'a>> {
        self.next_token()?.ok_or(Error::UnexpectedEof)
    }

    /// The next token, which must not be quoted (numbers, names,
    /// mnemonics, encoded binary data).
    #[inline]
    pub fn word(&mut self) -> Result<Token<'a>> {
        let t = self.token()?;
        if t.quoted {
            return Err(Error::InvalidText);
        }
        Ok(t)
    }

    /// Checks that no tokens are left ([`Error::InvalidText`] otherwise).
    #[inline]
    pub fn finish(&mut self) -> Result<()> {
        match self.next_token()? {
            Some(_) => Err(Error::InvalidText),
            None => Ok(()),
        }
    }

    /// An 8-bit unsigned decimal number.
    #[inline]
    pub fn u8(&mut self) -> Result<u8> {
        self.word()?.u8()
    }

    /// A 16-bit unsigned decimal number.
    #[inline]
    pub fn u16(&mut self) -> Result<u16> {
        self.word()?.u16()
    }

    /// A 32-bit unsigned decimal number.
    #[inline]
    pub fn u32(&mut self) -> Result<u32> {
        self.word()?.u32()
    }

    /// A time value in seconds, as a plain number or with BIND-style unit
    /// suffixes (`1h30m`, `2w`; see [`parse_ttl`]): TTLs and the SOA
    /// timers.
    #[inline]
    pub fn ttl(&mut self) -> Result<u32> {
        parse_ttl(self.word()?.raw)
    }

    /// A DNSSEC timestamp (RFC 4034 §3.2): `YYYYMMDDHHmmSS` in UTC or a
    /// decimal number of seconds since the epoch; see
    /// [`Timestamp`](crate::dnssec::Timestamp).
    #[inline]
    pub fn timestamp(&mut self) -> Result<u32> {
        Ok(self.word()?.as_str()?.parse::<Timestamp>()?.get())
    }

    /// A value parsed with its [`FromStr`] implementation, e.g. a record
    /// type or class mnemonic (`MX`, `TYPE65534`), a DNSSEC algorithm, ...
    #[inline]
    pub fn parse<T: FromStr<Err = Error>>(&mut self) -> Result<T> {
        self.word()?.as_str()?.parse()
    }

    /// An IPv4 address in dotted-decimal form (RFC 1035 §3.4.1).
    #[inline]
    pub fn ipv4(&mut self) -> Result<Ipv4Addr> {
        self.word()?
            .as_str()?
            .parse()
            .map_err(|_| Error::InvalidText)
    }

    /// An IPv6 address in RFC 4291 §2.2 text form.
    #[inline]
    pub fn ipv6(&mut self) -> Result<Ipv6Addr> {
        self.word()?
            .as_str()?
            .parse()
            .map_err(|_| Error::InvalidText)
    }

    /// A domain name: absolute if it ends with an unescaped dot, otherwise
    /// relative to the origin; `@` is the origin (RFC 1035 §5.1).
    #[inline]
    pub fn name(&mut self) -> Result<NameBuf> {
        let t = self.word()?;
        resolve_name(t.raw, self.origin)
    }

    /// Reads a domain name ([`name`](Self::name)) and writes it with
    /// `encoding` (the [`NameEncoding`] the record type's RFC mandates).
    #[inline]
    pub fn name_into<C: Composer + ?Sized>(
        &mut self,
        out: &mut C,
        encoding: NameEncoding,
    ) -> Result<()> {
        let name = self.name()?;
        out.put_name(name.as_name(), encoding)
    }

    /// Reads one `<character-string>` (quoted or not, RFC 1035 §5.1) and
    /// writes it with its length octet; [`Error::CharStringTooLong`] if it
    /// decodes to more than 255 octets.
    #[inline]
    pub fn char_string_into<C: Composer + ?Sized>(&mut self, out: &mut C) -> Result<()> {
        let t = self.token()?;
        put_char_string(t, out)
    }

    /// Reads all remaining tokens as `<character-string>`s (at least one),
    /// writing each with its length octet (TXT, SPF, ...).
    pub fn char_strings_into<C: Composer + ?Sized>(&mut self, out: &mut C) -> Result<()> {
        put_char_string(self.token()?, out)?;
        while let Some(t) = self.next_token()? {
            put_char_string(t, out)?;
        }
        Ok(())
    }

    /// Reads one token of hexadecimal digits (either case) and writes the
    /// octets; returns how many.
    pub fn hex_into<C: Composer + ?Sized>(&mut self, out: &mut C) -> Result<usize> {
        let t = self.word()?;
        let mut d = HexDecoder::default();
        d.feed(t.raw, out)?;
        d.finish()
    }

    /// Reads all remaining tokens as one hexadecimal string (zone files
    /// split long digests across tokens and lines) and writes the octets;
    /// returns how many (0 if no tokens are left).
    pub fn hex_rest_into<C: Composer + ?Sized>(&mut self, out: &mut C) -> Result<usize> {
        let mut d = HexDecoder::default();
        while let Some(t) = self.next_token()? {
            if t.quoted {
                return Err(Error::InvalidText);
            }
            d.feed(t.raw, out)?;
        }
        d.finish()
    }

    /// Reads one token of base64 (RFC 4648 §4, padded) and writes the
    /// octets; returns how many.
    pub fn base64_into<C: Composer + ?Sized>(&mut self, out: &mut C) -> Result<usize> {
        let t = self.word()?;
        let mut d = base64::Decoder::default();
        let n = feed_base64(&mut d, t.raw, out)?;
        d.finish()?;
        Ok(n)
    }

    /// Reads all remaining tokens as one base64 string (RFC 4648 §4; keys
    /// and signatures are usually split across tokens and lines) and
    /// writes the octets; returns how many (0 if no tokens are left).
    pub fn base64_rest_into<C: Composer + ?Sized>(&mut self, out: &mut C) -> Result<usize> {
        let mut d = base64::Decoder::default();
        let mut n = 0;
        while let Some(t) = self.next_token()? {
            if t.quoted {
                return Err(Error::InvalidText);
            }
            n += feed_base64(&mut d, t.raw, out)?;
        }
        d.finish()?;
        Ok(n)
    }

    /// Reads one token of unpadded base32hex (RFC 4648 §7, either case;
    /// NSEC3 hashed owner names, RFC 5155 §3.3) of at most 255 decoded
    /// octets and writes them; returns how many.
    pub fn base32hex_into<C: Composer + ?Sized>(&mut self, out: &mut C) -> Result<usize> {
        let t = self.word()?;
        let mut buf = [0u8; 255];
        let n = base32hex::decode(t.raw, &mut buf)?;
        out.put_bytes(buf.get(..n).unwrap_or(&[]))?;
        Ok(n)
    }

    /// Reads all remaining tokens as record type mnemonics (`A`, `MX`,
    /// `TYPE1234`, in any order, duplicates allowed) and writes the
    /// window-block type bitmap of NSEC, NSEC3 and CSYNC
    /// (RFC 4034 §4.1.2). No tokens give an empty bitmap.
    pub fn type_bitmap_into<C: Composer + ?Sized>(&mut self, out: &mut C) -> Result<()> {
        // One bit per type: 8 KiB, so the work is linear in the tokens.
        let mut bits = [[0u8; 32]; 256];
        while let Some(t) = self.next_token()? {
            if t.quoted {
                return Err(Error::InvalidText);
            }
            let rtype: Rtype = t.as_str()?.parse()?;
            let [hi, lo] = rtype.get().to_be_bytes();
            if let Some(window) = bits.get_mut(usize::from(hi)) {
                window[usize::from(lo / 8)] |= 0x80 >> (lo % 8);
            }
        }
        for (window, map) in (0u8..=255).zip(bits.iter()) {
            let Some(len) = map.iter().rposition(|&b| b != 0).map(|p| p + 1) else {
                continue;
            };
            out.put_u8(window)?;
            out.put_u8(len as u8)?;
            out.put_bytes(map.get(..len).unwrap_or(&[]))?;
        }
        Ok(())
    }

    /// If the next token is `\#`, reads the RFC 3597 §5 generic RDATA
    /// that follows (`\# <length> <hex>...`), writes it and returns
    /// `true`; otherwise reads nothing and returns `false`.
    pub(crate) fn generic_into<B: OutBuf + ?Sized>(&mut self, out: &mut B) -> Result<bool> {
        match self.peek()? {
            Some(t) if t.is("\\#") => {}
            _ => return Ok(false),
        }
        self.next_token()?;
        let len = self.u16()?;
        if self.hex_rest_into(out)? != usize::from(len) {
            return Err(Error::InvalidText);
        }
        Ok(true)
    }
}

/// Parses a plain unsigned decimal number (no sign, no blanks).
fn parse_decimal(digits: &[u8]) -> Option<u64> {
    if digits.is_empty() {
        return None;
    }
    digits.iter().try_fold(0u64, |v, &d| {
        if !d.is_ascii_digit() {
            return None;
        }
        v.checked_mul(10)?.checked_add(u64::from(d - b'0'))
    })
}

/// Parses a TTL (or another time value in seconds) as written in master
/// files: a plain decimal number of seconds, or BIND-style units — one or
/// more `<number><unit>` groups with units `s`, `m`, `h`, `d` and `w`
/// (either case), e.g. `1h30m` (5400) or `1W` (604800). The total must
/// fit in 32 bits ([`Error::InvalidText`] otherwise).
///
/// RFC 2181 §8 restricts TTLs to 0–2147483647; larger values are
/// accepted here and left to the caller (they read as 0).
///
/// ```
/// use dnsbox::zone::parse_ttl;
///
/// assert_eq!(parse_ttl(b"3600")?, 3600);
/// assert_eq!(parse_ttl(b"1h30m")?, 5400);
/// assert_eq!(parse_ttl(b"2D")?, 172_800);
/// assert!(parse_ttl(b"1h30").is_err());
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn parse_ttl(text: &[u8]) -> Result<u32> {
    let mut total: u32 = 0;
    let mut number: Option<u32> = None;
    let mut units = false;
    for &c in text {
        if c.is_ascii_digit() {
            let v = number
                .unwrap_or(0)
                .checked_mul(10)
                .and_then(|v| v.checked_add(u32::from(c - b'0')))
                .ok_or(Error::InvalidText)?;
            number = Some(v);
            continue;
        }
        let unit = match c.to_ascii_lowercase() {
            b's' => 1,
            b'm' => 60,
            b'h' => 3600,
            b'd' => 86_400,
            b'w' => 604_800,
            _ => return Err(Error::InvalidText),
        };
        let v = number.take().ok_or(Error::InvalidText)?;
        total = v
            .checked_mul(unit)
            .and_then(|v| total.checked_add(v))
            .ok_or(Error::InvalidText)?;
        units = true;
    }
    match (number, units) {
        (Some(v), false) => Ok(v),
        (None, true) => Ok(total),
        _ => Err(Error::InvalidText),
    }
}

/// Whether a name as written ends with an unescaped dot (is absolute).
fn is_absolute(raw: &[u8]) -> bool {
    let mut i = 0;
    let mut dot = false;
    while let Some(&c) = raw.get(i) {
        if c == b'\\' {
            dot = false;
            i += if raw.get(i + 1).is_some_and(u8::is_ascii_digit) {
                4
            } else {
                2
            };
        } else {
            dot = c == b'.';
            i += 1;
        }
    }
    dot
}

/// Resolves a name as written in a master file against `origin`
/// (RFC 1035 §5.1): `@` is the origin, a name ending in an unescaped dot
/// is absolute, anything else is relative to the origin.
pub(crate) fn resolve_name(raw: &[u8], origin: Name<'_>) -> Result<NameBuf> {
    if raw == b"@" {
        return Ok(origin.to_buf());
    }
    let name = NameBuf::from_text(raw)?;
    if is_absolute(raw) || origin.is_root() {
        return Ok(name);
    }
    let rel = name.as_wire();
    let rel = rel.get(..rel.len().saturating_sub(1)).unwrap_or(&[]);
    let mut flat = [0u8; MAX_NAME_LEN];
    let n = origin.flatten(&mut flat);
    let total = rel.len() + n;
    if total > MAX_NAME_LEN {
        return Err(Error::NameTooLong);
    }
    let mut buf = [0u8; MAX_NAME_LEN];
    buf.get_mut(..rel.len())
        .ok_or(Error::NameTooLong)?
        .copy_from_slice(rel);
    buf.get_mut(rel.len()..total)
        .ok_or(Error::NameTooLong)?
        .copy_from_slice(flat.get(..n).unwrap_or(&[]));
    NameBuf::from_wire(buf.get(..total).unwrap_or(&[]))
}

/// Writes a token as a `<character-string>`.
fn put_char_string<C: Composer + ?Sized>(t: Token<'_>, out: &mut C) -> Result<()> {
    let mut buf = [0u8; 255];
    let mut n = 0;
    for b in t.unescape() {
        *buf.get_mut(n).ok_or(Error::CharStringTooLong)? = b?;
        n += 1;
    }
    out.put_char_string(buf.get(..n).unwrap_or(&[]))
}

/// Feeds base64 text to `d`, writing completed octets; returns how many.
fn feed_base64<C: Composer + ?Sized>(
    d: &mut base64::Decoder,
    text: &[u8],
    out: &mut C,
) -> Result<usize> {
    let mut n = 0;
    for &c in text {
        let (bytes, len) = d.push(c)?;
        if len > 0 {
            out.put_bytes(bytes.get(..len).unwrap_or(&[]))?;
            n += len;
        }
    }
    Ok(n)
}

/// Incremental hexadecimal decoder (digits may be split across tokens).
#[derive(Default)]
struct HexDecoder {
    high: Option<u8>,
    count: usize,
}

impl HexDecoder {
    fn feed<C: Composer + ?Sized>(&mut self, text: &[u8], out: &mut C) -> Result<()> {
        for &c in text {
            let v = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => return Err(Error::InvalidText),
            };
            match self.high.take() {
                None => self.high = Some(v),
                Some(h) => {
                    out.put_u8(h << 4 | v)?;
                    self.count += 1;
                }
            }
        }
        Ok(())
    }

    fn finish(&self) -> Result<usize> {
        if self.high.is_some() {
            return Err(Error::InvalidText);
        }
        Ok(self.count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WireWriter;
    use std::vec::Vec;

    /// Runs `f` on a scanner over `text` and returns what it wrote.
    fn scan(
        text: &str,
        f: impl FnOnce(&mut Scanner<'_>, &mut WireWriter<'_>) -> Result<()>,
    ) -> Result<Vec<u8>> {
        let origin: NameBuf = "example.com".parse().unwrap();
        let mut s = Scanner::new(text).with_origin(origin.as_name());
        let mut buf = std::vec![0u8; 65536];
        let mut out = WireWriter::new(&mut buf);
        f(&mut s, &mut out)?;
        s.finish()?;
        Ok(out.written().to_vec())
    }

    #[test]
    fn numbers_and_ttls() {
        let mut s = Scanner::new("0 255 256 65535 65536 4294967295 4294967296 -1 1x \"1\"");
        assert_eq!(s.u8(), Ok(0));
        assert_eq!(s.u8(), Ok(255));
        assert_eq!(s.u8(), Err(Error::InvalidText));
        assert_eq!(s.u16(), Ok(65535));
        assert_eq!(s.u16(), Err(Error::InvalidText));
        assert_eq!(s.u32(), Ok(u32::MAX));
        assert_eq!(s.u32(), Err(Error::InvalidText));
        assert_eq!(s.u32(), Err(Error::InvalidText));
        assert_eq!(s.u32(), Err(Error::InvalidText));
        assert_eq!(s.u32(), Err(Error::InvalidText));
        assert_eq!(s.u32(), Err(Error::UnexpectedEof));
        assert_eq!(parse_decimal(b"99999999999999999999999"), None);

        for (text, v) in [
            ("0", 0),
            ("86400", 86400),
            ("1s", 1),
            ("1m", 60),
            ("1H", 3600),
            ("1d", 86400),
            ("1w", 604_800),
            ("1h30m", 5400),
            ("1w2d3h4m5s", 788_645),
            ("1d1d", 172_800),
            ("4294967295", u32::MAX),
        ] {
            assert_eq!(parse_ttl(text.as_bytes()), Ok(v), "{text}");
        }
        for bad in ["", "h", "1h30", "1x", "-1", "4294967296", "7102w", "1 h"] {
            assert_eq!(parse_ttl(bad.as_bytes()), Err(Error::InvalidText), "{bad}");
        }
        let mut s = Scanner::new("2h 20240101000000 1700000000 2024");
        assert_eq!(s.ttl(), Ok(7200));
        assert_eq!(s.timestamp(), Ok(1_704_067_200));
        assert_eq!(s.timestamp(), Ok(1_700_000_000));
        assert_eq!(s.timestamp(), Ok(2024));
    }

    #[test]
    fn names() {
        let n = |text: &str| scan(text, |s, o| s.name_into(o, NameEncoding::Plain));
        assert_eq!(n("www").unwrap(), b"\x03www\x07example\x03com\x00");
        assert_eq!(n("www.").unwrap(), b"\x03www\x00");
        assert_eq!(n("@").unwrap(), b"\x07example\x03com\x00");
        assert_eq!(n(".").unwrap(), b"\x00");
        assert_eq!(n("a\\.b").unwrap(), b"\x03a.b\x07example\x03com\x00");
        assert_eq!(n("a\\.").unwrap(), b"\x02a.\x07example\x03com\x00");
        assert_eq!(n("a\\\\.").unwrap(), b"\x02a\\\x00");
        assert_eq!(n("a\\046").unwrap(), b"\x02a.\x07example\x03com\x00");
        assert_eq!(n("a.\\046").unwrap(), b"\x01a\x01.\x07example\x03com\x00");
        assert_eq!(n("\"quoted\""), Err(Error::InvalidText));
        assert_eq!(n("a..b"), Err(Error::EmptyLabel));
        assert_eq!(n(""), Err(Error::UnexpectedEof));
        // 250 octets relative + 13 for the origin is too long.
        let long = std::format!("{0}.{0}.{0}.{0}.a", "x".repeat(60));
        assert_eq!(n(&long), Err(Error::NameTooLong));
        assert!(n(&std::format!("{long}.")).is_ok());
        assert_eq!(
            resolve_name(b"a", Name::ROOT).unwrap().as_wire(),
            b"\x01a\x00"
        );
        assert!(is_absolute(b"a\\\\."));
        assert!(!is_absolute(b"a\\046"));
        assert!(!is_absolute(b"a\\."));
    }

    #[test]
    fn char_strings() {
        let cs = |text: &str| scan(text, |s, o| s.char_strings_into(o));
        assert_eq!(
            cs(r#""hello world" plain "" "a\"b\\c" \065\066 "\255""#).unwrap(),
            b"\x0bhello world\x05plain\x00\x05a\"b\\c\x02AB\x01\xff"
        );
        assert_eq!(cs(""), Err(Error::UnexpectedEof));
        assert_eq!(cs("\\256"), Err(Error::InvalidText));
        assert_eq!(cs("\\12"), Err(Error::InvalidText));
        assert_eq!(cs("\\1a3"), Err(Error::InvalidText));
        let long = "x".repeat(256);
        assert_eq!(cs(&long), Err(Error::CharStringTooLong));
        assert_eq!(cs(&long[1..]).unwrap().len(), 256);
        // Multi-line quoted strings and parentheses.
        assert_eq!(cs("( \"a\nb\"\n c )").unwrap(), b"\x03a\nb\x01c");
        let t = Token {
            raw: b"\\",
            quoted: false,
        };
        assert_eq!(t.unescape().collect::<Vec<_>>(), [Err(Error::InvalidText)]);
    }

    #[test]
    fn encodings() {
        let hex = |text: &str| scan(text, |s, o| s.hex_rest_into(o).map(drop));
        assert_eq!(hex("0aFf 1 2").unwrap(), [0x0a, 0xff, 0x12]);
        assert_eq!(hex("").unwrap(), []);
        assert_eq!(hex("abc"), Err(Error::InvalidText));
        assert_eq!(hex("0g"), Err(Error::InvalidText));
        assert_eq!(hex("\"00\""), Err(Error::InvalidText));
        let hex1 = |text: &str| scan(text, |s, o| s.hex_into(o).map(drop));
        assert_eq!(hex1("0102").unwrap(), [1, 2]);
        assert_eq!(hex1("01 02"), Err(Error::InvalidText));

        let b64 = |text: &str| scan(text, |s, o| s.base64_rest_into(o).map(drop));
        assert_eq!(b64("Zm9v YmFy").unwrap(), b"foobar");
        assert_eq!(b64("Zm9 vYmE=").unwrap(), b"fooba");
        assert_eq!(b64("( Zm9v\n Yg== )").unwrap(), b"foob");
        assert_eq!(b64("Zm9"), Err(Error::InvalidText));
        assert_eq!(b64("Zg== Zg=="), Err(Error::InvalidText));
        let b64one = |text: &str| scan(text, |s, o| s.base64_into(o).map(drop));
        assert_eq!(b64one("Zm9vYmFy").unwrap(), b"foobar");
        assert_eq!(b64one("Zm9v YmFy"), Err(Error::InvalidText));

        let b32 = |text: &str| scan(text, |s, o| s.base32hex_into(o).map(drop));
        assert_eq!(b32("cpnmuoj1e8").unwrap(), b"foobar");
        assert_eq!(b32("CPNMUOJ1E9"), Err(Error::InvalidText));
        assert_eq!(b32(&"0".repeat(416)), Err(Error::InvalidText));
    }

    #[test]
    fn type_bitmaps() {
        let bm = |text: &str| scan(text, |s, o| s.type_bitmap_into(o));
        // RFC 4034 §4.3: "A MX RRSIG NSEC TYPE1234".
        let mut want = b"\x00\x06\x40\x01\x00\x00\x00\x03\x04\x1b".to_vec();
        want.extend_from_slice(&[0; 26]);
        want.push(0x20);
        assert_eq!(bm("A MX RRSIG NSEC TYPE1234").unwrap(), want);
        assert_eq!(bm("TYPE1234 nsec rrsig mx a A").unwrap(), want);
        assert_eq!(bm("").unwrap(), []);
        assert_eq!(
            bm("TYPE65535").unwrap(),
            b"\xff\x20"
                .iter()
                .copied()
                .chain([0; 31])
                .chain([1])
                .collect::<Vec<_>>()
        );
        assert_eq!(bm("BOGUS"), Err(Error::UnknownMnemonic));
        assert_eq!(bm("\"A\""), Err(Error::InvalidText));
    }

    #[test]
    fn generic() {
        let g = |text: &str| {
            scan(text, |s, o| {
                assert!(s.generic_into(o)?);
                Ok(())
            })
        };
        assert_eq!(g("\\# 0").unwrap(), []);
        assert_eq!(g("\\# 4 0A000001").unwrap(), [10, 0, 0, 1]);
        assert_eq!(g("\\# 4 ( 0A00\n 0001 )").unwrap(), [10, 0, 0, 1]);
        assert_eq!(g("\\# 3 0A000001"), Err(Error::InvalidText));
        assert_eq!(g("\\# 5 0A000001"), Err(Error::InvalidText));
        assert_eq!(g("\\#"), Err(Error::UnexpectedEof));
        assert_eq!(g("\\# x"), Err(Error::InvalidText));
        let mut s = Scanner::new("\"\\#\" 0");
        let mut buf = [0u8; 4];
        assert_eq!(s.generic_into(&mut WireWriter::new(&mut buf)), Ok(false));
    }

    #[test]
    fn tokens() {
        let mut s = Scanner::new("a \"b c\" ; comment\n d");
        assert!(!s.is_at_end().unwrap());
        assert_eq!(s.peek().unwrap().map(|t| t.as_bytes()), Some(&b"a"[..]));
        let a = s.word().unwrap();
        assert!(a.is("A") && !a.is_quoted() && a.as_str() == Ok("a"));
        assert_eq!(s.word(), Err(Error::InvalidText));
        assert_eq!(s.finish(), Err(Error::InvalidText));
        assert_eq!(s.next_token(), Ok(None));
        let mut s = Scanner::from_bytes(b"\xff");
        assert_eq!(s.token().unwrap().as_str(), Err(Error::InvalidText));
        let mut s = Scanner::new("x )");
        assert!(s.word().is_ok());
        assert_eq!(s.next_token(), Err(Error::InvalidText));
        assert!(s.lex_failed());
        assert_eq!(s.next_token(), Ok(None));
        let mut s = Scanner::new("1.2.3.4 ::1 1.2.3 MX");
        assert_eq!(s.ipv4(), Ok(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(s.ipv6(), Ok(Ipv6Addr::LOCALHOST));
        assert_eq!(s.ipv4(), Err(Error::InvalidText));
        assert_eq!(s.parse::<Rtype>(), Ok(Rtype::MX));
        let _ = WireWriter::new(&mut []);
    }
}
