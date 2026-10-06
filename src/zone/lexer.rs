//! The master-file tokenizer (RFC 1035 §5.1): blanks, `;` comments,
//! parentheses spanning lines, quoted strings and backslash escapes.
//!
//! The lexer is a pure function over the input and a small `Copy` cursor,
//! so scanners can be cloned to look ahead or re-scan, and the zone reader
//! can keep its position as plain integers between calls.

use crate::Error;

/// Deepest parenthesis nesting accepted (RFC 1035 §5.1 defines one level;
/// a few more are tolerated, without unbounded state).
const MAX_PAREN: u8 = 16;

/// A position in the input: byte offset plus the line it is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Pos {
    /// Byte offset.
    pub(crate) offset: usize,
    /// 1-based line number.
    pub(crate) line: u32,
    /// Byte offset of the start of `line`.
    pub(crate) line_start: usize,
}

impl Pos {
    /// The start of an input.
    pub(crate) const START: Pos = Pos {
        offset: 0,
        line: 1,
        line_start: 0,
    };

    /// 1-based column of the position, counted in characters (UTF-8
    /// continuation bytes do not count).
    pub(crate) fn column(&self, input: &[u8]) -> u32 {
        let text = input.get(self.line_start..self.offset).unwrap_or(&[]);
        let chars = text.iter().filter(|&&b| b & 0xc0 != 0x80).count();
        u32::try_from(chars).unwrap_or(u32::MAX).saturating_add(1)
    }

    /// Moves past a newline at `offset`.
    fn newline(&mut self, offset: usize) {
        self.line = self.line.saturating_add(1);
        self.line_start = offset + 1;
    }
}

/// Lexer state: the position and the parenthesis depth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Cursor {
    pub(crate) pos: Pos,
    pub(crate) paren: u8,
}

impl Cursor {
    /// The start of an input.
    pub(crate) const START: Cursor = Cursor {
        pos: Pos::START,
        paren: 0,
    };
}

/// Length limits on lines and tokens ([`ZoneLimits`](super::ZoneLimits)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Limits {
    /// The most octets on one line.
    pub(crate) line: usize,
    /// The most octets in one token.
    pub(crate) token: usize,
}

impl Limits {
    /// No limits (standalone RDATA text).
    pub(crate) const NONE: Limits = Limits {
        line: usize::MAX,
        token: usize::MAX,
    };

    /// The error for a line ending at `end` (exclusive) that started at
    /// `pos.line_start`, if it is too long: reported at the first octet
    /// beyond the limit.
    fn check_line(&self, pos: Pos, end: usize) -> core::result::Result<(), (Error, Pos)> {
        if end.saturating_sub(pos.line_start) > self.line {
            let offset = pos.line_start.saturating_add(self.line);
            return Err((Error::LimitExceeded, Pos { offset, ..pos }));
        }
        Ok(())
    }
}

/// One lexical item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lexeme {
    /// A token: `start` is its first character (the opening quote of a
    /// quoted string), `end` the offset just past it.
    Token {
        start: Pos,
        end: usize,
        quoted: bool,
    },
    /// A newline outside parentheses: the end of an entry (consumed).
    EndOfEntry,
    /// The end of the input (outside parentheses).
    EndOfInput,
}

/// Blank characters separating tokens (the newline is handled apart).
pub(crate) const fn is_blank(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | 0x0b | 0x0c)
}

/// Reads the next lexeme at `cur`, advancing it. With `multiline`, a
/// newline never ends the entry (standalone RDATA text).
///
/// On error the cursor is left where it was and the error position is
/// returned: an unbalanced parenthesis, a quote or escape cut off by the
/// end of the input, or parentheses nested too deeply
/// ([`Error::InvalidText`]), or a line or token longer than `limits`
/// ([`Error::LimitExceeded`]). Line lengths are checked as the lexer
/// passes each newline, and for the current line at the end of the
/// lexeme, so no line is ever scanned twice.
pub(crate) fn next(
    input: &[u8],
    cur: &mut Cursor,
    multiline: bool,
    limits: Limits,
) -> core::result::Result<Lexeme, (Error, Pos)> {
    let mut c2 = *cur;
    let res = lex(input, &mut c2, multiline, limits);
    if let Ok(Lexeme::Token { start, end, .. }) = res
        && end.saturating_sub(start.offset) > limits.token
    {
        return Err((Error::LimitExceeded, start));
    }
    if res.is_ok() {
        // The line the lexeme ends on, so far.
        limits.check_line(c2.pos, c2.pos.offset)?;
        *cur = c2;
    }
    res
}

fn lex(
    input: &[u8],
    cur: &mut Cursor,
    multiline: bool,
    limits: Limits,
) -> core::result::Result<Lexeme, (Error, Pos)> {
    loop {
        let i = cur.pos.offset;
        let Some(&c) = input.get(i) else {
            if cur.paren > 0 {
                return Err((Error::InvalidText, cur.pos));
            }
            return Ok(Lexeme::EndOfInput);
        };
        match c {
            b'\n' => {
                limits.check_line(cur.pos, i)?;
                cur.pos.offset = i + 1;
                cur.pos.newline(i);
                if cur.paren == 0 && !multiline {
                    return Ok(Lexeme::EndOfEntry);
                }
            }
            c if is_blank(c) => cur.pos.offset = i + 1,
            b';' => {
                let rest = input.get(i..).unwrap_or(&[]);
                let len = rest.iter().position(|&c| c == b'\n').unwrap_or(rest.len());
                cur.pos.offset = i + len;
            }
            b'(' => {
                if cur.paren >= MAX_PAREN {
                    return Err((Error::InvalidText, cur.pos));
                }
                cur.paren += 1;
                cur.pos.offset = i + 1;
            }
            b')' => {
                if cur.paren == 0 {
                    return Err((Error::InvalidText, cur.pos));
                }
                cur.paren -= 1;
                cur.pos.offset = i + 1;
            }
            b'"' => return quoted(input, cur, limits),
            _ => return word(input, cur, limits),
        }
    }
}

/// A quoted string, from the opening quote at the cursor to the matching
/// closing one. Newlines inside are part of the string.
fn quoted(
    input: &[u8],
    cur: &mut Cursor,
    limits: Limits,
) -> core::result::Result<Lexeme, (Error, Pos)> {
    let start = cur.pos;
    let mut pos = start;
    let mut j = start.offset + 1;
    loop {
        match input.get(j) {
            None => return Err((Error::InvalidText, start)),
            Some(b'"') => break,
            Some(b'\\') => {
                match input.get(j + 1) {
                    None => return Err((Error::InvalidText, start)),
                    Some(b'\n') => {
                        limits.check_line(pos, j + 1)?;
                        pos.newline(j + 1);
                    }
                    Some(_) => {}
                }
                j += 2;
            }
            Some(b'\n') => {
                limits.check_line(pos, j)?;
                pos.newline(j);
                j += 1;
            }
            Some(_) => j += 1,
        }
    }
    cur.pos.line = pos.line;
    cur.pos.line_start = pos.line_start;
    cur.pos.offset = j + 1;
    Ok(Lexeme::Token {
        start,
        end: j + 1,
        quoted: true,
    })
}

/// A contiguous token: everything up to a blank, newline, parenthesis or
/// comment. A backslash escapes the next character, and a quote inside the
/// token groups up to the next quote on the same line (as in SVCB
/// `key="a b"` values, RFC 9460 Appendix A); an unescaped newline before
/// it is an error.
fn word(
    input: &[u8],
    cur: &mut Cursor,
    limits: Limits,
) -> core::result::Result<Lexeme, (Error, Pos)> {
    let start = cur.pos;
    let mut pos = start;
    let mut j = start.offset;
    let mut in_quote = false;
    loop {
        match input.get(j) {
            None if in_quote => return Err((Error::InvalidText, start)),
            None => break,
            Some(b'\\') => {
                match input.get(j + 1) {
                    None => return Err((Error::InvalidText, start)),
                    Some(b'\n') => {
                        limits.check_line(pos, j + 1)?;
                        pos.newline(j + 1);
                    }
                    Some(_) => {}
                }
                j += 2;
            }
            Some(b'"') => {
                in_quote = !in_quote;
                j += 1;
            }
            // The grouping ends with the line: a stray quote must not fold
            // the following lines (whole records) into this token. RFC 1035
            // §5.1 only lets a string that *starts* with a quote span lines.
            Some(b'\n') if in_quote => return Err((Error::InvalidText, start)),
            Some(&c) if !in_quote && (is_blank(c) || matches!(c, b'\n' | b'(' | b')' | b';')) => {
                break;
            }
            Some(_) => j += 1,
        }
    }
    cur.pos.line = pos.line;
    cur.pos.line_start = pos.line_start;
    cur.pos.offset = j;
    Ok(Lexeme::Token {
        start,
        end: j,
        quoted: false,
    })
}

/// Skips to the start of the next line, ignoring syntax (error recovery).
/// Always makes progress unless already at the end of the input.
pub(crate) fn skip_line(input: &[u8], cur: &mut Cursor) {
    let from = cur.pos.offset.min(input.len());
    let rest = input.get(from..).unwrap_or(&[]);
    match rest.iter().position(|&c| c == b'\n') {
        Some(n) => {
            cur.pos.offset = from + n + 1;
            cur.pos.newline(from + n);
        }
        None => cur.pos.offset = input.len(),
    }
    cur.paren = 0;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    type Lexed<'s> = Vec<(&'s str, u32, u32)>;

    /// Lexes everything, returning token texts (`|` for entry ends) with
    /// their line and column.
    fn lex_all(input: &str, multiline: bool) -> Result<Lexed<'_>, (Error, u32, u32)> {
        let b = input.as_bytes();
        let mut cur = Cursor::START;
        let mut out = Vec::new();
        loop {
            match next(b, &mut cur, multiline, Limits::NONE) {
                Ok(Lexeme::Token { start, end, .. }) => {
                    out.push((&input[start.offset..end], start.line, start.column(b)));
                }
                Ok(Lexeme::EndOfEntry) => out.push(("|", 0, 0)),
                Ok(Lexeme::EndOfInput) => return Ok(out),
                Err((e, p)) => return Err((e, p.line, p.column(b))),
            }
        }
    }

    #[test]
    fn tokens_and_positions() {
        let toks = lex_all(
            "a  b;c\n  \"q \\\" x\" ( d\n e ) f\nk=\"x y\"z \\( \\\n\n",
            false,
        )
        .unwrap();
        let texts: Vec<&str> = toks.iter().map(|t| t.0).collect();
        assert_eq!(
            texts,
            [
                "a",
                "b",
                "|",
                "\"q \\\" x\"",
                "d",
                "e",
                "f",
                "|",
                "k=\"x y\"z",
                "\\(",
                "\\\n",
                "|"
            ]
        );
        assert_eq!(toks[1], ("b", 1, 4));
        assert_eq!(toks[5], ("e", 3, 2));
        assert_eq!(toks[8], ("k=\"x y\"z", 4, 1));
        // In multiline mode newlines never end the entry.
        let toks = lex_all("a\nb\n", true).unwrap();
        assert_eq!(toks.len(), 2);
        // A newline inside a quoted string is counted.
        let toks = lex_all("\"a\nb\" c", false).unwrap();
        assert_eq!(toks[1], ("c", 2, 4));
    }

    #[test]
    fn errors() {
        assert_eq!(lex_all("a )", false), Err((Error::InvalidText, 1, 3)));
        assert_eq!(lex_all("a ( b", false), Err((Error::InvalidText, 1, 6)));
        assert_eq!(lex_all("x \"abc", false), Err((Error::InvalidText, 1, 3)));
        assert_eq!(lex_all("x a\\", false), Err((Error::InvalidText, 1, 3)));
        assert_eq!(lex_all("x \"a\\", false), Err((Error::InvalidText, 1, 3)));
        assert_eq!(lex_all("k=\"ab", false), Err((Error::InvalidText, 1, 1)));
        // A quote inside a token groups up to the end of the line at most:
        // a stray one must not swallow the lines after it.
        assert_eq!(
            lex_all("k=\"ab\ncd\" x", false),
            Err((Error::InvalidText, 1, 1))
        );
        assert_eq!(
            lex_all("x 27\"\nwww A 1\ntv 55\"", true),
            Err((Error::InvalidText, 1, 3))
        );
        // An escaped newline is still part of the token.
        assert_eq!(
            lex_all("k=\"a\\\nb\" c", false),
            Ok(std::vec![("k=\"a\\\nb\"", 1, 1), ("c", 2, 4)])
        );
        let deep = "(".repeat(usize::from(MAX_PAREN) + 1);
        assert!(lex_all(&deep, false).is_err());
        // Columns count characters, not bytes.
        assert_eq!(lex_all("é )", false), Err((Error::InvalidText, 1, 3)));
    }

    #[test]
    fn skipping() {
        let input = b"bad ( line\nnext";
        let mut cur = Cursor::START;
        cur.paren = 1;
        skip_line(input, &mut cur);
        assert_eq!((cur.pos.offset, cur.pos.line, cur.paren), (11, 2, 0));
        assert_eq!(cur.pos.line_start, 11);
        skip_line(input, &mut cur);
        assert_eq!(cur.pos.offset, input.len());
    }
}
