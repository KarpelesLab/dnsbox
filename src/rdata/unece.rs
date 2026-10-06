//! UNECE and ISO record data: values coded by registries that external
//! standards organizations maintain
//! (draft-woodcock-faltstrom-external-registry-rrtypes-01; IANA "Resource
//! Record (RR) TYPEs").
//!
//! Both types share one wire layout and one value grammar (§2.3), read by
//! [`RegistryValue`]. The format is the one of an Internet-Draft still in
//! progress, and may change.

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::text::{Hex, fmt_quoted, fmt_token};
use crate::wire::{Composer, OutBuf, WireReader};
use crate::zone::{Scanner, Token};
use crate::{Error, Result, Rtype};

/// The meaning of the Value field of [`Unece`] and [`Iso`] records
/// (draft-woodcock-faltstrom-external-registry-rrtypes-01 §2.3).
///
/// The field is US-ASCII text in a grammar that has exactly one form per
/// number: an optional `-`, a decimal number without leading zeros or
/// trailing fractional zeros, and an optional precision in parentheses
/// (`2400000(50000)`, `780000(?)`); `?` alone says that a quantity exists
/// but is unknown to the issuer, and an empty field (`-` in presentation
/// format) that none applies. A value outside the grammar must be shown
/// uninterpreted, not rejected ([`Uninterpreted`](Self::Uninterpreted)).
/// Numbers are kept as text: they have arbitrary precision.
///
/// The draft may change this grammar, so the enum may grow.
///
/// ```
/// use dnsbox::rdata::{Precision, RegistryValue};
///
/// assert_eq!(RegistryValue::parse(b""), RegistryValue::NotApplicable);
/// assert_eq!(RegistryValue::parse(b"?"), RegistryValue::Unknown);
/// assert_eq!(
///     RegistryValue::parse(b"2400000(50000)"),
///     RegistryValue::Quantity { number: "2400000", precision: Some(Precision::Known("50000")) },
/// );
/// assert_eq!(
///     RegistryValue::parse(b"-18"),
///     RegistryValue::Quantity { number: "-18", precision: None },
/// );
/// // Leading zeros are outside the grammar.
/// assert_eq!(RegistryValue::parse(b"018"), RegistryValue::Uninterpreted(b"018"));
/// assert_eq!(RegistryValue::parse(b"780000(?)").to_string(), "780000(?)");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RegistryValue<'a> {
    /// No quantity applies to the code: the empty field, `-` in
    /// presentation format.
    NotApplicable,
    /// A quantity applies but the issuer does not know it: `?`.
    Unknown,
    /// A quantity, in the units or terms of the code.
    Quantity {
        /// The number in decimal, possibly negative and fractional
        /// (`-18`, `0.25`).
        number: &'a str,
        /// The precision (plus or minus, in the same units), if given.
        precision: Option<Precision<'a>>,
    },
    /// A value outside the grammar, to be shown as is.
    Uninterpreted(&'a [u8]),
}

/// The precision of a [`RegistryValue::Quantity`]
/// (draft-woodcock-faltstrom-external-registry-rrtypes-01 §2.3).
///
/// ```
/// use dnsbox::rdata::{Precision, RegistryValue};
///
/// let RegistryValue::Quantity { precision, .. } = RegistryValue::parse(b"780000(?)") else {
///     panic!("not a quantity");
/// };
/// assert_eq!(precision, Some(Precision::Unknown));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Precision<'a> {
    /// Plus or minus this non-negative decimal number.
    Known(&'a str),
    /// Unknown precision: `(?)`.
    Unknown,
}

/// The end of a fractional part (`*DIGIT %x31-39`) starting at `start`.
fn frac_end(s: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while s.get(i).is_some_and(u8::is_ascii_digit) {
        i += 1;
    }
    (i > start && s.get(i - 1) != Some(&b'0')).then_some(i)
}

/// The length of the number at the start of `s`: `"0" / ["-"] posnum`
/// when `signed`, `"0" / posnum` otherwise (§2.3).
fn number_len(s: &[u8], signed: bool) -> Option<usize> {
    let negative = signed && s.first() == Some(&b'-');
    let mut i = usize::from(negative);
    match s.get(i)? {
        b'0' => {
            i += 1;
            if s.get(i) == Some(&b'.') {
                i = frac_end(s, i + 1)?;
            } else if negative {
                // Negative zero has no representation.
                return None;
            }
        }
        b'1'..=b'9' => {
            i += 1;
            while s.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
            if s.get(i) == Some(&b'.') {
                i = frac_end(s, i + 1)?;
            }
        }
        _ => return None,
    }
    Some(i)
}

impl<'a> RegistryValue<'a> {
    /// Reads a Value field (its octets, without the length octet)
    /// against the grammar of
    /// draft-woodcock-faltstrom-external-registry-rrtypes-01 §2.3. Never
    /// fails: a value outside the grammar is
    /// [`Uninterpreted`](Self::Uninterpreted).
    ///
    /// ```
    /// use dnsbox::rdata::RegistryValue;
    ///
    /// assert!(matches!(RegistryValue::parse(b"0.5"), RegistryValue::Quantity { .. }));
    /// assert!(matches!(RegistryValue::parse(b"-0"), RegistryValue::Uninterpreted(_)));
    /// ```
    #[must_use]
    pub fn parse(value: &'a [u8]) -> Self {
        match value {
            [] => RegistryValue::NotApplicable,
            b"?" => RegistryValue::Unknown,
            _ => Self::quantity(value).unwrap_or(RegistryValue::Uninterpreted(value)),
        }
    }

    /// `quantity = ( "0" / ["-"] posnum ) [precision]`, or `None`.
    fn quantity(value: &'a [u8]) -> Option<Self> {
        let n = number_len(value, true)?;
        let number = core::str::from_utf8(value.get(..n)?).ok()?;
        let precision = match value.get(n..)? {
            [] => None,
            [b'(', b'?', b')'] => Some(Precision::Unknown),
            [b'(', inner @ .., b')'] if number_len(inner, false)? == inner.len() => {
                Some(Precision::Known(core::str::from_utf8(inner).ok()?))
            }
            _ => return None,
        };
        Some(RegistryValue::Quantity { number, precision })
    }
}

/// Writes a Value field in presentation format: `-` when empty, else the
/// octets as one token (§2.3).
fn fmt_value<W: fmt::Write + ?Sized>(w: &mut W, value: &[u8]) -> fmt::Result {
    match value {
        [] => w.write_str("-"),
        // Not a valid field (§2.3), but keep it apart from the empty one.
        b"-" => w.write_str("\\-"),
        _ => fmt_token(w, value),
    }
}

impl fmt::Display for RegistryValue<'_> {
    /// The presentation form of the field: `-`, `?`, the number with its
    /// precision, or the uninterpreted octets (escaped as needed).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            RegistryValue::NotApplicable => f.write_str("-"),
            RegistryValue::Unknown => f.write_str("?"),
            RegistryValue::Quantity { number, precision } => {
                f.write_str(number)?;
                match precision {
                    None => Ok(()),
                    Some(Precision::Unknown) => f.write_str("(?)"),
                    Some(Precision::Known(p)) => write!(f, "({p})"),
                }
            }
            RegistryValue::Uninterpreted(v) => fmt_value(f, v),
        }
    }
}

/// The four fields: discriminator (Recommendation or Standard), value,
/// code and descriptor.
type Fields<'a> = (&'a [u8], &'a [u8], &'a [u8], &'a [u8]);

/// Checks the length-prefixed fields: a non-empty discriminator and code,
/// all three fitting their length octet, and a value that is not the
/// octet `-` (§2.3, §3.1, §4.1).
const fn check(discriminator: &[u8], value: &[u8], code: &[u8]) -> Result<()> {
    if discriminator.is_empty()
        || discriminator.len() > 255
        || value.len() > 255
        || matches!(value, [b'-'])
        || code.is_empty()
        || code.len() > 255
    {
        return Err(Error::InvalidRdata);
    }
    Ok(())
}

/// Reads the fields; the reader is left alone on error.
fn parse_fields<'a>(rdata: &mut WireReader<'a>) -> Result<Fields<'a>> {
    let mut r = *rdata;
    let discriminator = r.read_char_string()?.as_bytes();
    let value = r.read_char_string()?.as_bytes();
    let code = r.read_char_string()?.as_bytes();
    check(discriminator, value, code)?;
    let descriptor = r.read_rest();
    *rdata = r;
    Ok((discriminator, value, code, descriptor))
}

/// Writes the fields after checking them.
fn compose_fields<C: Composer + ?Sized>(c: &mut C, (d, v, code, desc): Fields<'_>) -> Result<()> {
    check(d, v, code)?;
    c.put_char_string(d)?;
    c.put_char_string(v)?;
    c.put_char_string(code)?;
    c.put_bytes(desc)
}

/// `<discriminator> <value> <code> ["<descriptor>"]`, or the RFC 3597
/// generic form when the descriptor is too long for a
/// `<character-string>` (§3.2, §4.2).
fn fmt_fields(f: &mut fmt::Formatter<'_>, (d, v, code, desc): Fields<'_>) -> fmt::Result {
    if desc.len() > 255 {
        let len = 3 + d.len() + v.len() + code.len() + desc.len();
        // Each field is at most 255 octets (`check`); `as u8` keeps the
        // display total even for a value built by hand.
        return write!(
            f,
            "\\# {len} {}{}{}{}{}{}{}",
            Hex(&[d.len() as u8]),
            Hex(d),
            Hex(&[v.len() as u8]),
            Hex(v),
            Hex(&[code.len() as u8]),
            Hex(code),
            Hex(desc)
        );
    }
    fmt_token(f, d)?;
    f.write_str(" ")?;
    fmt_value(f, v)?;
    f.write_str(" ")?;
    fmt_token(f, code)?;
    if !desc.is_empty() {
        f.write_str(" ")?;
        fmt_quoted(f, desc)?;
    }
    Ok(())
}

/// Writes a token's decoded octets with a length octet in front.
fn put_prefixed<B: OutBuf + ?Sized>(t: Token<'_>, out: &mut B) -> Result<()> {
    let at = out.pos();
    out.put_u8(0)?;
    let mut n = 0usize;
    for b in t.unescape() {
        out.put_u8(b?)?;
        n += 1;
    }
    let n = u8::try_from(n).map_err(|_| Error::InvalidRdata)?;
    out.patch(at, &[n])
}

/// Reads `<discriminator> <value> <code> ["<descriptor>"]` (§3.2, §4.2),
/// the value possibly quoted.
fn parse_text_fields<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
    put_prefixed(s.word()?, out)?;
    // Quoting lets a value with a precision keep its parentheses, which
    // otherwise group lines (RFC 1035 §5.1); `-` must be unquoted.
    let value = s.token()?;
    if value.is("-") {
        out.put_u8(0)?;
    } else {
        put_prefixed(value, out)?;
    }
    put_prefixed(s.word()?, out)?;
    // The descriptor is one <character-string>, without its length octet.
    if let Some(t) = s.next_token()? {
        for (i, b) in t.unescape().enumerate() {
            if i == 255 {
                return Err(Error::CharStringTooLong);
            }
            out.put_u8(b?)?;
        }
    }
    Ok(())
}

/// `UNECE` record data: a value coded by a registry of the UNECE
/// Recommendations series (UN/CEFACT code lists: units of measure,
/// UN/LOCODE locations, package types, ...).
///
/// Specified by draft-woodcock-faltstrom-external-registry-rrtypes-01 §3,
/// an Internet-Draft still in progress, so **the format may change**. The
/// RDATA is the Recommendation token (`20` for Recommendation No. 20), the
/// value (see [`RegistryValue`]) and the code, each with a length octet,
/// then the descriptor (UTF-8 free text, the rest of the RDATA). Empty
/// Recommendation or code fields and a value of `-` are rejected with
/// [`Error::InvalidRdata`]; unknown Recommendations, codes and values
/// outside the grammar are kept as they are, as the draft requires.
///
/// The presentation format is `<rec> <value> <code> ["<descriptor>"]`,
/// with an empty value written `-` and the descriptor as a quoted string.
/// A descriptor over 255 octets (which issuers must not publish, but
/// receivers must accept) has no presentation form: such RDATA is
/// displayed in the RFC 3597 generic form.
///
/// The draft writes a value with a precision as `2400000(50000)`, but in
/// master files parentheses group lines (RFC 1035 §5.1): that text reads
/// as the two tokens `2400000` and `50000`, as in BIND, and shifts the
/// fields that follow. Write the parentheses escaped
/// (`2400000\(50000\)`, which `Display` prints) or quote the value
/// (`"2400000(50000)"`).
///
/// ```
/// use dnsbox::rdata::{ParseRdataText, RegistryValue, Unece};
///
/// // draft-woodcock-faltstrom-external-registry-rrtypes-01 §3.4.
/// let mut buf = [0u8; 64];
/// let unece = Unece::from_text(r#"20 -18 CEL "cold-chain storage temperature""#, &mut buf)?;
/// assert_eq!(unece.recommendation, b"20");
/// assert_eq!(unece.code, b"CEL");
/// assert_eq!(unece.descriptor, b"cold-chain storage temperature");
/// assert_eq!(
///     unece.value_kind(),
///     RegistryValue::Quantity { number: "-18", precision: None }
/// );
/// assert_eq!(unece.to_string(), r#"20 -18 CEL "cold-chain storage temperature""#);
///
/// let mut buf = [0u8; 64];
/// let unece = Unece::from_text("16 - JPTYO", &mut buf)?;
/// assert_eq!(unece, Unece::new(b"16", b"", b"JPTYO", b"")?);
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Unece<'a> {
    /// The Recommendation token naming the code list, without
    /// "Recommendation No." (`16`, `20`, `3bis`; §3.1), compared octet for
    /// octet.
    pub recommendation: &'a [u8],
    /// The value, empty when not applicable (§2.3); see
    /// [`value_kind`](Self::value_kind).
    pub value: &'a [u8],
    /// The code, verbatim from the Recommendation's code list (§3.1).
    pub code: &'a [u8],
    /// Free text describing what the datum is about, possibly empty
    /// (UTF-8; a display hint, never machine semantics, §2.2, §6).
    /// Untrusted: `Display` writes control and non-ASCII octets as `\DDD`.
    pub descriptor: &'a [u8],
}

impl<'a> Unece<'a> {
    /// Builds UNECE data, checking the fields (§3.1).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRdata`] for an empty Recommendation or code, any of
    /// the three over 255 octets, or a value of `-` (the empty value is
    /// the only encoding of "not applicable", §2.3).
    ///
    /// ```
    /// use dnsbox::Error;
    /// use dnsbox::rdata::Unece;
    ///
    /// let unece = Unece::new(b"20", b"640", b"H18", b"protected wetland area")?;
    /// assert_eq!(unece.to_string(), r#"20 640 H18 "protected wetland area""#);
    /// assert_eq!(Unece::new(b"20", b"-", b"H18", b""), Err(Error::InvalidRdata));
    /// assert_eq!(Unece::new(b"", b"", b"H18", b""), Err(Error::InvalidRdata));
    /// # Ok::<(), Error>(())
    /// ```
    pub const fn new(
        recommendation: &'a [u8],
        value: &'a [u8],
        code: &'a [u8],
        descriptor: &'a [u8],
    ) -> Result<Self> {
        if let Err(e) = check(recommendation, value, code) {
            return Err(e);
        }
        Ok(Unece {
            recommendation,
            value,
            code,
            descriptor,
        })
    }

    /// The value read against the grammar of §2.3.
    ///
    /// ```
    /// use dnsbox::rdata::{RegistryValue, Unece};
    ///
    /// let unece = Unece::new(b"20", b"?", b"P1", b"moisture content, assay pending")?;
    /// assert_eq!(unece.value_kind(), RegistryValue::Unknown);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn value_kind(&self) -> RegistryValue<'a> {
        RegistryValue::parse(self.value)
    }

    fn fields(&self) -> Fields<'a> {
        (self.recommendation, self.value, self.code, self.descriptor)
    }
}

impl ParseRdataText for Unece<'_> {
    /// `<rec> <value> <code> ["<descriptor>"]`
    /// (draft-woodcock-faltstrom-external-registry-rrtypes-01 §3.2): the
    /// first three as unquoted tokens, `-` for an empty value, and the
    /// descriptor as one `<character-string>`, quoted or not.
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        parse_text_fields(s, out)
    }
}

impl<'a> ParseRdata<'a> for Unece<'a> {
    const RTYPE: Rtype = Rtype::UNECE;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        let (recommendation, value, code, descriptor) = parse_fields(rdata)?;
        Ok(Unece {
            recommendation,
            value,
            code,
            descriptor,
        })
    }
}

impl ComposeRdata for Unece<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::UNECE
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        compose_fields(c, self.fields())
    }
}

impl fmt::Display for Unece<'_> {
    /// `rec value code "descriptor"` (§3.2), the descriptor omitted when
    /// empty.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_fields(f, self.fields())
    }
}

/// `ISO` record data: a value coded by a registry defined in an ISO
/// standard (country, subdivision, currency and language codes, ...).
///
/// Specified by draft-woodcock-faltstrom-external-registry-rrtypes-01 §4,
/// an Internet-Draft still in progress, so **the format may change**. The
/// RDATA is the standard token (`3166-1` for ISO 3166-1, `TR_24028` for
/// ISO/IEC TR 24028), the value (see [`RegistryValue`]) and the code, each
/// with a length octet, then the descriptor (UTF-8 free text, the rest of
/// the RDATA). Empty standard or code fields and a value of `-` are
/// rejected with [`Error::InvalidRdata`]; unknown standards, codes and
/// values outside the grammar are kept as they are, as the draft requires.
///
/// The presentation format is `<standard> <value> <code>
/// ["<descriptor>"]`, with an empty value written `-` and the descriptor
/// as a quoted string. A descriptor over 255 octets (which issuers must
/// not publish, but receivers must accept) has no presentation form: such
/// RDATA is displayed in the RFC 3597 generic form.
///
/// The draft writes a value with a precision as `2400000(50000)`, but in
/// master files parentheses group lines (RFC 1035 §5.1): that text reads
/// as the two tokens `2400000` and `50000`, as in BIND, and shifts the
/// fields that follow. Write the parentheses escaped
/// (`2400000\(50000\)`, which `Display` prints) or quote the value
/// (`"2400000(50000)"`).
///
/// ```
/// use dnsbox::rdata::{Iso, ParseRdataText, Precision, RegistryValue};
///
/// // draft-woodcock-faltstrom-external-registry-rrtypes-01 §4.4.
/// let mut buf = [0u8; 64];
/// let iso = Iso::from_text(r#"4217 2400000\(50000\) EUR "insured value, hull and machinery""#, &mut buf)?;
/// assert_eq!((iso.standard, iso.code), (&b"4217"[..], &b"EUR"[..]));
/// assert_eq!(
///     iso.value_kind(),
///     RegistryValue::Quantity { number: "2400000", precision: Some(Precision::Known("50000")) }
/// );
///
/// let mut buf = [0u8; 64];
/// let iso = Iso::from_text(r#"3166-2 - US-CA "state of incorporation""#, &mut buf)?;
/// assert_eq!(iso.value_kind(), RegistryValue::NotApplicable);
/// assert_eq!(iso.to_string(), r#"3166-2 - US-CA "state of incorporation""#);
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Iso<'a> {
    /// The standard token naming the code list, without "ISO" or
    /// "ISO/IEC" (`639`, `3166-1`, `4217`, `Guide_2`; §4.1), compared
    /// octet for octet.
    pub standard: &'a [u8],
    /// The value, empty when not applicable (§2.3); see
    /// [`value_kind`](Self::value_kind).
    pub value: &'a [u8],
    /// The code, verbatim from the standard's code list (§4.1).
    pub code: &'a [u8],
    /// Free text describing what the datum is about, possibly empty
    /// (UTF-8; a display hint, never machine semantics, §2.2, §6).
    /// Untrusted: `Display` writes control and non-ASCII octets as `\DDD`.
    pub descriptor: &'a [u8],
}

impl<'a> Iso<'a> {
    /// Builds ISO data, checking the fields (§4.1).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRdata`] for an empty standard or code, any of the
    /// three over 255 octets, or a value of `-` (the empty value is the
    /// only encoding of "not applicable", §2.3).
    ///
    /// ```
    /// use dnsbox::Error;
    /// use dnsbox::rdata::Iso;
    ///
    /// let iso = Iso::new(b"639", b"", b"ar", b"working language")?;
    /// assert_eq!(iso.to_string(), r#"639 - ar "working language""#);
    /// assert_eq!(Iso::new(b"639", b"", b"", b""), Err(Error::InvalidRdata));
    /// # Ok::<(), Error>(())
    /// ```
    pub const fn new(
        standard: &'a [u8],
        value: &'a [u8],
        code: &'a [u8],
        descriptor: &'a [u8],
    ) -> Result<Self> {
        if let Err(e) = check(standard, value, code) {
            return Err(e);
        }
        Ok(Iso {
            standard,
            value,
            code,
            descriptor,
        })
    }

    /// The value read against the grammar of §2.3.
    ///
    /// ```
    /// use dnsbox::rdata::{Iso, Precision, RegistryValue};
    ///
    /// let iso = Iso::new(b"4217", b"780000(?)", b"CHF", b"")?;
    /// assert_eq!(
    ///     iso.value_kind(),
    ///     RegistryValue::Quantity { number: "780000", precision: Some(Precision::Unknown) }
    /// );
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn value_kind(&self) -> RegistryValue<'a> {
        RegistryValue::parse(self.value)
    }

    fn fields(&self) -> Fields<'a> {
        (self.standard, self.value, self.code, self.descriptor)
    }
}

impl ParseRdataText for Iso<'_> {
    /// `<standard> <value> <code> ["<descriptor>"]`
    /// (draft-woodcock-faltstrom-external-registry-rrtypes-01 §4.2): the
    /// first three as unquoted tokens, `-` for an empty value, and the
    /// descriptor as one `<character-string>`, quoted or not.
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        parse_text_fields(s, out)
    }
}

impl<'a> ParseRdata<'a> for Iso<'a> {
    const RTYPE: Rtype = Rtype::ISO;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        let (standard, value, code, descriptor) = parse_fields(rdata)?;
        Ok(Iso {
            standard,
            value,
            code,
            descriptor,
        })
    }
}

impl ComposeRdata for Iso<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::ISO
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        compose_fields(c, self.fields())
    }
}

impl fmt::Display for Iso<'_> {
    /// `standard value code "descriptor"` (§4.2), the descriptor omitted
    /// when empty.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_fields(f, self.fields())
    }
}

#[cfg(test)]
mod tests {
    use super::{Iso, Precision, RegistryValue, Unece};
    use crate::rdata::{ComposeRdata, RData};
    use crate::rdata::tests::{compose, parse, round_trip, text_error, text_parse, text_round_trip};
    use crate::wire::WireWriter;
    use crate::{Class, Error, Rtype};
    use std::string::ToString;
    use std::vec::Vec;

    /// The wire form of the fields.
    fn wire(d: &[u8], v: &[u8], code: &[u8], desc: &[u8]) -> Vec<u8> {
        let mut w = Vec::new();
        for f in [d, v, code] {
            w.push(f.len() as u8);
            w.extend_from_slice(f);
        }
        w.extend_from_slice(desc);
        w
    }

    /// draft-woodcock-faltstrom-external-registry-rrtypes-01 §3.4 and §4.4,
    /// as (type, presentation, fields); the parentheses of the precisions
    /// are escaped (see `precision_in_master_files`).
    const EXAMPLES: &[(Rtype, &str, [&str; 4])] = &[
        (Rtype::UNECE, r#"16 - JPTYO "place of inspection""#, ["16", "", "JPTYO", "place of inspection"]),
        (Rtype::UNECE, r#"16 - KENBO "distribution hub""#, ["16", "", "KENBO", "distribution hub"]),
        (Rtype::UNECE, r#"19 - 1 "mode: maritime""#, ["19", "", "1", "mode: maritime"]),
        (Rtype::UNECE, r#"19 - 4 "mode: air""#, ["19", "", "4", "mode: air"]),
        (Rtype::UNECE, r#"20 640 H18 "protected wetland area""#, ["20", "640", "H18", "protected wetland area"]),
        (Rtype::UNECE, r#"20 12500 MTQ "reservoir volume""#, ["20", "12500", "MTQ", "reservoir volume"]),
        (Rtype::UNECE, r#"20 5 MGM "active ingredient per dose""#, ["20", "5", "MGM", "active ingredient per dose"]),
        (Rtype::UNECE, r#"20 8500 E22 "container capacity, TEU""#, ["20", "8500", "E22", "container capacity, TEU"]),
        (Rtype::UNECE, r#"20 -18 CEL "cold-chain storage temperature""#, ["20", "-18", "CEL", "cold-chain storage temperature"]),
        (Rtype::UNECE, r#"20 90 DAY "shelf life""#, ["20", "90", "DAY", "shelf life"]),
        (Rtype::UNECE, r#"20 24 MON "warranty period""#, ["20", "24", "MON", "warranty period"]),
        (Rtype::UNECE, r#"20 230 VLT "supply voltage""#, ["20", "230", "VLT", "supply voltage"]),
        (Rtype::UNECE, r#"20 11 KWT "charger output""#, ["20", "11", "KWT", "charger output"]),
        (Rtype::UNECE, r#"20 ? P1 "moisture content, assay pending""#, ["20", "?", "P1", "moisture content, assay pending"]),
        (Rtype::UNECE, r#"21 12 PX "pallets""#, ["21", "12", "PX", "pallets"]),
        (Rtype::UNECE, r#"21 2 CR "crates, artworks on loan""#, ["21", "2", "CR", "crates, artworks on loan"]),
        (Rtype::UNECE, r#"21 3 RL "reels, fibre-optic cable""#, ["21", "3", "RL", "reels, fibre-optic cable"]),
        (Rtype::UNECE, r#"21 2 PO "diplomatic pouches""#, ["21", "2", "PO", "diplomatic pouches"]),
        (Rtype::UNECE, r#"24 - 219 "status: delivery pending""#, ["24", "", "219", "status: delivery pending"]),
        (Rtype::ISO, r#"639 - ar "working language""#, ["639", "", "ar", "working language"]),
        (Rtype::ISO, r#"639 - yue "crew lingua franca""#, ["639", "", "yue", "crew lingua franca"]),
        (Rtype::ISO, r#"3166-1 - QA "flag state""#, ["3166-1", "", "QA", "flag state"]),
        (Rtype::ISO, r#"3166-2 - US-CA "state of incorporation""#, ["3166-2", "", "US-CA", "state of incorporation"]),
        (Rtype::ISO, r#"4217 125000 USD "declared cargo value""#, ["4217", "125000", "USD", "declared cargo value"]),
        (Rtype::ISO, r#"4217 2400000\(50000\) EUR "insured value, hull and machinery""#, ["4217", "2400000(50000)", "EUR", "insured value, hull and machinery"]),
        (Rtype::ISO, r#"4217 780000\(?\) CHF "salvage award, assessment ongoing""#, ["4217", "780000(?)", "CHF", "salvage award, assessment ongoing"]),
        (Rtype::ISO, r#"4217 ? ZAR "customs value pending appraisal""#, ["4217", "?", "ZAR", "customs value pending appraisal"]),
    ];

    #[test]
    fn draft_examples() {
        for &(t, text, [d, v, code, desc]) in EXAMPLES {
            let w = wire(d.as_bytes(), v.as_bytes(), code.as_bytes(), desc.as_bytes());
            text_round_trip(t, text, &w, text);
            // Every example value is in the grammar.
            let kind = RegistryValue::parse(v.as_bytes());
            assert!(!matches!(kind, RegistryValue::Uninterpreted(_)), "{v}");
            assert_eq!(kind.to_string(), if v.is_empty() { "-" } else { v });
        }
    }

    #[test]
    fn wire_forms() {
        // No descriptor.
        round_trip(Rtype::UNECE, &wire(b"16", b"", b"JPTYO", b""), "16 - JPTYO");
        round_trip(Rtype::ISO, &wire(b"639", b"", b"ar", b""), "639 - ar");
        // Unknown tokens, codes and values are carried (§2.2), escaped
        // where they would not read back as one token.
        round_trip(Rtype::UNECE, &wire(b"3bis", b"0.50", b"X", b""), "3bis 0.50 X");
        round_trip(
            Rtype::ISO,
            &wire(b"TR 24028", b"1;2", b"a\"b", b"\xc3\xa9t\xc3\xa9 \"x\""),
            r#"TR\03224028 1\;2 a\"b "\195\169t\195\169 \"x\"""#,
        );
        round_trip(Rtype::ISO, &wire(b"(", b"@", b"$", b"\\"), r#"\( \@ \$ "\\""#);
        // Long fields.
        let long = [b'A'; 255];
        let w = wire(&long, &long, &long, &long);
        let shown = round_trip(Rtype::ISO, &w, &std::format!(
            "{0} {0} {0} \"{0}\"",
            "A".repeat(255)
        ));
        assert_eq!(text_parse(Rtype::ISO, &shown), Ok(w));
        // Descriptors over 255 octets are carried (§3.1: receivers MUST
        // NOT reject them) and shown in the generic form.
        let w = wire(b"20", b"5", b"MGM", &[b'x'; 256]);
        let shown = round_trip(Rtype::UNECE, &w, &std::format!(
            "\\# {} 023230013503{}{}",
            w.len(),
            "4D474D",
            "78".repeat(256)
        ));
        assert_eq!(text_parse(Rtype::UNECE, &shown), Ok(w));

        let w = wire(b"20", b"8500", b"E22", b"TEU");
        let RData::Unece(u) = parse(Rtype::UNECE, Class::IN, &w).unwrap() else {
            panic!("not UNECE");
        };
        assert_eq!(u, Unece::new(b"20", b"8500", b"E22", b"TEU").unwrap());
        assert_eq!(u.value_kind(), RegistryValue::Quantity { number: "8500", precision: None });
        assert_eq!(compose(&u), w);
        let w = wire(b"639", b"", b"ar", b"");
        let RData::Iso(i) = parse(Rtype::ISO, Class::CH, &w).unwrap() else {
            panic!("not ISO");
        };
        assert_eq!(i.value_kind(), RegistryValue::NotApplicable);
        assert_eq!(compose(&i), wire(b"639", b"", b"ar", b""));
    }

    #[test]
    fn malformed() {
        for t in [Rtype::UNECE, Rtype::ISO] {
            for (w, err) in [
                // Empty discriminator or code (§3.1, §4.1: MUST be nonzero).
                (wire(b"", b"", b"X", b""), Error::InvalidRdata),
                (wire(b"20", b"", b"", b""), Error::InvalidRdata),
                // §2.3: the value MUST NOT be the octet "-".
                (wire(b"20", b"-", b"X", b""), Error::InvalidRdata),
                (std::vec![], Error::UnexpectedEof),
                (b"\x0220".to_vec(), Error::UnexpectedEof),
                (b"\x0220\x00".to_vec(), Error::UnexpectedEof),
                (b"\x0220\x00\x03MG".to_vec(), Error::UnexpectedEof),
                (b"\x0320".to_vec(), Error::UnexpectedEof),
            ] {
                assert_eq!(parse(t, Class::IN, &w), Err(err), "{t} {w:02x?}");
            }
        }
        // Composing invalid fields fails without writing.
        let long = [b'1'; 256];
        for bad in [
            Unece { recommendation: b"", value: b"", code: b"X", descriptor: b"" },
            Unece { recommendation: b"20", value: b"-", code: b"X", descriptor: b"" },
            Unece { recommendation: b"20", value: &long, code: b"X", descriptor: b"" },
            Unece { recommendation: &long, value: b"", code: b"X", descriptor: b"" },
            Unece { recommendation: b"20", value: b"", code: &long, descriptor: b"" },
        ] {
            let mut buf = [0u8; 600];
            let mut w = WireWriter::new(&mut buf);
            assert_eq!(bad.compose_rdata(&mut w), Err(Error::InvalidRdata));
            assert!(w.as_bytes().is_empty());
        }
        assert_eq!(Iso::new(&long, b"", b"X", b""), Err(Error::InvalidRdata));
        assert!(Iso::new(b"639", b"", b"ar", &[b'x'; 300]).is_ok());
    }

    #[test]
    fn text() {
        for t in [Rtype::UNECE, Rtype::ISO] {
            // The descriptor may be unquoted, empty or absent.
            text_round_trip(t, "20 5 MGM dose", &wire(b"20", b"5", b"MGM", b"dose"), r#"20 5 MGM "dose""#);
            text_round_trip(t, r#"20 5 MGM """#, &wire(b"20", b"5", b"MGM", b""), "20 5 MGM");
            text_round_trip(
                t,
                r#"( 3166-1 - QA ; flag
                   "flag state" )"#,
                &wire(b"3166-1", b"", b"QA", b"flag state"),
                r#"3166-1 - QA "flag state""#,
            );
            // Escapes in every field.
            text_round_trip(
                t,
                r#"TR\03224028 \063 a\"b "\195\169""#,
                &wire(b"TR 24028", b"?", b"a\"b", b"\xc3\xa9"),
                r#"TR\03224028 ? a\"b "\195\169""#,
            );
            for (text, err) in [
                ("", Error::UnexpectedEof),
                ("20", Error::UnexpectedEof),
                ("20 5", Error::UnexpectedEof),
                (r#""20" 5 MGM"#, Error::InvalidText),
                (r#"20 5 "MGM""#, Error::InvalidText),
                ("20 5 MGM a b", Error::InvalidText),
                (r#"20 5 MGM "a"#, Error::InvalidText),
                (r"20 5 \999", Error::InvalidText),
                // An escaped "-" is the octet "-", not an empty value.
                (r"20 \- MGM", Error::InvalidRdata),
                (r"20 \045 MGM", Error::InvalidRdata),
                (r"\# 0", Error::UnexpectedEof),
            ] {
                assert_eq!(text_error(t, text), err, "{t} {text:?}");
            }
            let long = "1".repeat(256);
            assert_eq!(text_error(t, &std::format!("{long} - X")), Error::InvalidRdata);
            assert_eq!(text_error(t, &std::format!("20 {long} X")), Error::InvalidRdata);
            assert_eq!(text_error(t, &std::format!("20 - {long}")), Error::InvalidRdata);
            assert_eq!(text_error(t, &std::format!("20 - X {long}")), Error::CharStringTooLong);
            assert_eq!(
                text_parse(t, &std::format!("20 - X \"{}\"", "y".repeat(255))),
                Ok(wire(b"20", b"", b"X", &[b'y'; 255]))
            );
        }
    }

    #[test]
    fn precision_in_master_files() {
        let w = wire(b"4217", b"2400000(50000)", b"EUR", b"");
        // Escaped (as displayed) or quoted, the value keeps its parentheses.
        text_round_trip(Rtype::ISO, r"4217 2400000\(50000\) EUR", &w, r"4217 2400000\(50000\) EUR");
        text_round_trip(Rtype::ISO, r#"4217 "2400000(50000)" EUR"#, &w, r"4217 2400000\(50000\) EUR");
        text_round_trip(
            Rtype::UNECE,
            r#"20 "5" MGM"#,
            &wire(b"20", b"5", b"MGM", b""),
            "20 5 MGM",
        );
        // As the draft writes it, the parentheses group lines (RFC 1035
        // §5.1, as in BIND): the precision becomes the code.
        assert_eq!(
            text_parse(Rtype::ISO, "4217 2400000(50000) EUR"),
            Ok(wire(b"4217", b"2400000", b"50000", b"EUR"))
        );
        assert_eq!(
            text_error(Rtype::ISO, r#"4217 2400000(50000) EUR "insured value""#),
            Error::InvalidText
        );
        // A quoted "-" is the octet "-", not the empty value.
        assert_eq!(text_error(Rtype::ISO, r#"4217 "-" EUR"#), Error::InvalidRdata);
    }

    #[test]
    fn value_grammar() {
        use RegistryValue::{NotApplicable, Quantity, Uninterpreted, Unknown};
        let q = |number, precision| Quantity { number, precision };
        for (v, kind) in [
            (&b""[..], NotApplicable),
            (b"?", Unknown),
            (b"0", q("0", None)),
            (b"7", q("7", None)),
            (b"10", q("10", None)),
            (b"-18", q("-18", None)),
            (b"0.5", q("0.5", None)),
            (b"-0.05", q("-0.05", None)),
            (b"12.25", q("12.25", None)),
            (b"0(0)", q("0", Some(Precision::Known("0")))),
            (b"1(0.5)", q("1", Some(Precision::Known("0.5")))),
            (b"2400000(50000)", q("2400000", Some(Precision::Known("50000")))),
            (b"-3(?)", q("-3", Some(Precision::Unknown))),
            // One representation per number: no leading or trailing
            // zeros, no all-zero fraction, no negative zero.
            (b"00", Uninterpreted(b"00")),
            (b"01", Uninterpreted(b"01")),
            (b"1.0", Uninterpreted(b"1.0")),
            (b"1.50", Uninterpreted(b"1.50")),
            (b"0.0", Uninterpreted(b"0.0")),
            (b"-0", Uninterpreted(b"-0")),
            (b"-0.0", Uninterpreted(b"-0.0")),
            (b"1.", Uninterpreted(b"1.")),
            (b".5", Uninterpreted(b".5")),
            (b"+1", Uninterpreted(b"+1")),
            (b"--1", Uninterpreted(b"--1")),
            (b"-", Uninterpreted(b"-")),
            (b"1e3", Uninterpreted(b"1e3")),
            (b"1 ", Uninterpreted(b"1 ")),
            // Precision: unsigned, and not attached to "?".
            (b"1(-1)", Uninterpreted(b"1(-1)")),
            (b"1(01)", Uninterpreted(b"1(01)")),
            (b"1()", Uninterpreted(b"1()")),
            (b"1(", Uninterpreted(b"1(")),
            (b"1(2", Uninterpreted(b"1(2")),
            (b"1(2))", Uninterpreted(b"1(2))")),
            (b"1(2)(3)", Uninterpreted(b"1(2)(3)")),
            (b"?(1)", Uninterpreted(b"?(1)")),
            (b"??", Uninterpreted(b"??")),
            (b"(1)", Uninterpreted(b"(1)")),
        ] {
            assert_eq!(RegistryValue::parse(v), kind, "{v:?}");
        }
        assert_eq!(RegistryValue::Uninterpreted(b"-").to_string(), r"\-");
        assert_eq!(RegistryValue::Uninterpreted(b"a b").to_string(), r"a\032b");
        assert_eq!(RegistryValue::NotApplicable.to_string(), "-");
        assert_eq!(RegistryValue::parse(b"1(0.5)").to_string(), "1(0.5)");
    }

}
