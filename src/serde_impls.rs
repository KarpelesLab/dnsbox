//! `serde` support (feature `serde`) for the types that need no allocation:
//! the protocol-number newtypes, names and the header flags. The owned
//! message types are in `owned::serde_impl` (features `serde` + `alloc`).
//!
//! Conventions, chosen so that serialized data is readable where a human
//! may look at it and compact elsewhere:
//!
//! - **Protocol numbers** (every `open_enum!` registry such as [`Rtype`],
//!   [`Class`], [`OptionCode`](crate::edns::OptionCode),
//!   [`Algorithm`](crate::dnssec::Algorithm), plus [`Opcode`] and
//!   [`Rcode`]): in human-readable formats (JSON, YAML, TOML, ...) the
//!   presentation mnemonic, or the RFC 3597 §5 generic form for
//!   unregistered values (`"MX"`, `"TYPE65534"`, `"CLASS42"`); integers
//!   are accepted too when deserializing. In binary formats, the integer.
//! - **Names** ([`Name`], [`NameBuf`]): always the presentation string with
//!   escapes and a trailing dot (RFC 1035 §5.1, RFC 4343 §2.1).
//! - **[`Flags`]**: in human-readable formats a struct of the header bits
//!   with the opcode and header RCODE as mnemonics (RFC 1035 §4.1.1); in
//!   binary formats the raw 16-bit word.

use core::fmt;
use core::str::FromStr;

use serde::de::{self, Deserializer, Unexpected, Visitor};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::name::{Name, NameBuf};
use crate::{Flags, Opcode, Rcode};

#[cfg(doc)]
use crate::{Class, Rtype};

/// Serializes a protocol number: `Display` (mnemonic or generic form) in
/// human-readable formats, the integer otherwise.
pub(crate) fn serialize_open<S, T, I>(s: S, value: &T, raw: I) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: fmt::Display + ?Sized,
    I: Serialize,
{
    if s.is_human_readable() {
        s.collect_str(value)
    } else {
        raw.serialize(s)
    }
}

/// Deserializes a protocol number: a string (`parse`) or an integer
/// (`from_int`) in human-readable formats, the integer `I` otherwise.
pub(crate) fn deserialize_open<'de, D, T, I>(
    d: D,
    expecting: &'static str,
    parse: fn(&str) -> Option<T>,
    from_int: fn(u64) -> Option<T>,
) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    I: Deserialize<'de> + Into<u64>,
{
    if d.is_human_readable() {
        d.deserialize_any(OpenVisitor {
            expecting,
            parse,
            from_int,
        })
    } else {
        let v: u64 = I::deserialize(d)?.into();
        from_int(v).ok_or_else(|| de::Error::invalid_value(Unexpected::Unsigned(v), &expecting))
    }
}

/// Visitor for [`deserialize_open`].
struct OpenVisitor<T> {
    expecting: &'static str,
    parse: fn(&str) -> Option<T>,
    from_int: fn(u64) -> Option<T>,
}

impl<T> Visitor<'_> for OpenVisitor<T> {
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.expecting)
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<T, E> {
        (self.parse)(v).ok_or_else(|| E::invalid_value(Unexpected::Str(v), &self))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<T, E> {
        (self.from_int)(v).ok_or_else(|| E::invalid_value(Unexpected::Unsigned(v), &self))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<T, E> {
        match u64::try_from(v) {
            Ok(u) => self.visit_u64(u),
            Err(_) => Err(E::invalid_value(Unexpected::Signed(v), &self)),
        }
    }
}

/// `FromStr`-based parser for [`deserialize_open`].
pub(crate) fn parse_from_str<T: FromStr>(s: &str) -> Option<T> {
    s.parse().ok()
}

// --- Names -------------------------------------------------------------------

impl Serialize for Name<'_> {
    /// The presentation form (`"www.example.com."`).
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl Serialize for NameBuf {
    /// The presentation form (`"www.example.com."`).
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for NameBuf {
    /// Parses the presentation form (escapes allowed, trailing dot
    /// optional: names are absolute).
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = NameBuf;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a domain name in presentation format")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<NameBuf, E> {
                v.parse()
                    .map_err(|e| E::custom(format_args!("invalid domain name {v:?}: {e}")))
            }
        }
        d.deserialize_str(V)
    }
}

// --- Opcode and Rcode ----------------------------------------------------------

/// Parses an opcode mnemonic or `OPCODE<n>` (ASCII-case-insensitively).
fn parse_opcode(s: &str) -> Option<Opcode> {
    if let Some(op) = (0..16)
        .map(Opcode::new)
        .find(|op| op.name().is_some_and(|n| n.eq_ignore_ascii_case(s)))
    {
        return Some(op);
    }
    let digits = crate::macros::generic_digits(s, "OPCODE")??;
    opcode_from_int(digits.parse().ok()?)
}

fn opcode_from_int(v: u64) -> Option<Opcode> {
    u8::try_from(v).ok().filter(|&v| v < 16).map(Opcode::new)
}

/// Parses an RCODE mnemonic or `RCODE<n>` (ASCII-case-insensitively).
fn parse_rcode(s: &str) -> Option<Rcode> {
    // Every assigned mnemonic is below 32.
    if let Some(rc) = (0..32)
        .map(Rcode::new)
        .find(|rc| rc.name().is_some_and(|n| n.eq_ignore_ascii_case(s)))
    {
        return Some(rc);
    }
    let digits = crate::macros::generic_digits(s, "RCODE")??;
    rcode_from_int(digits.parse().ok()?)
}

fn rcode_from_int(v: u64) -> Option<Rcode> {
    u16::try_from(v).ok().filter(|&v| v < 4096).map(Rcode::new)
}

impl Serialize for Opcode {
    /// `"QUERY"`, `"UPDATE"`, `"OPCODE3"`; the number in binary formats.
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serialize_open(s, self, self.get())
    }
}

impl<'de> Deserialize<'de> for Opcode {
    /// A mnemonic, `OPCODE<n>` or a number below 16.
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        deserialize_open::<D, Opcode, u8>(
            d,
            "an opcode mnemonic or number below 16",
            parse_opcode,
            opcode_from_int,
        )
    }
}

impl Serialize for Rcode {
    /// `"NOERROR"`, `"NXDOMAIN"`, `"RCODE12"`; the number in binary formats.
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serialize_open(s, self, self.get())
    }
}

impl<'de> Deserialize<'de> for Rcode {
    /// A mnemonic, `RCODE<n>` or a number below 4096 (12 bits, RFC 6891
    /// §6.1.3).
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        deserialize_open::<D, Rcode, u16>(
            d,
            "an RCODE mnemonic or number below 4096",
            parse_rcode,
            rcode_from_int,
        )
    }
}

// --- Flags ---------------------------------------------------------------------

/// Human-readable form of [`Flags`].
#[derive(Serialize, Deserialize)]
#[serde(rename = "Flags")]
struct FlagsRepr {
    #[serde(default)]
    qr: bool,
    #[serde(default = "default_opcode")]
    opcode: Opcode,
    #[serde(default)]
    aa: bool,
    #[serde(default)]
    tc: bool,
    #[serde(default)]
    rd: bool,
    #[serde(default)]
    ra: bool,
    #[serde(default)]
    z: bool,
    #[serde(default)]
    ad: bool,
    #[serde(default)]
    cd: bool,
    #[serde(default = "default_rcode")]
    rcode: Rcode,
}

fn default_opcode() -> Opcode {
    Opcode::QUERY
}

fn default_rcode() -> Rcode {
    Rcode::NOERROR
}

impl Serialize for Flags {
    /// Human-readable formats: `{"qr": true, "opcode": "QUERY", "aa":
    /// false, "tc": false, "rd": true, "ra": true, "z": false, "ad": false,
    /// "cd": false, "rcode": "NOERROR"}`. Binary formats: the raw word.
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if !s.is_human_readable() {
            return self.bits().serialize(s);
        }
        FlagsRepr {
            qr: self.qr(),
            opcode: self.opcode(),
            aa: self.aa(),
            tc: self.tc(),
            rd: self.rd(),
            ra: self.ra(),
            z: self.z(),
            ad: self.ad(),
            cd: self.cd(),
            rcode: self.rcode(),
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for Flags {
    /// The form [`Serialize`] writes; missing bits default to clear, the
    /// opcode to QUERY and the RCODE to NOERROR. The header RCODE has 4
    /// bits: larger values belong in the OPT record (RFC 6891 §6.1.3) and
    /// are rejected.
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if !d.is_human_readable() {
            return u16::deserialize(d).map(Flags::from_bits);
        }
        let r = FlagsRepr::deserialize(d)?;
        if r.rcode.get() > 15 {
            return Err(de::Error::invalid_value(
                Unexpected::Unsigned(r.rcode.get().into()),
                &"a header RCODE below 16",
            ));
        }
        Ok(Flags::default()
            .with_qr(r.qr)
            .with_opcode(r.opcode)
            .with_aa(r.aa)
            .with_tc(r.tc)
            .with_rd(r.rd)
            .with_ra(r.ra)
            .with_z(r.z)
            .with_ad(r.ad)
            .with_cd(r.cd)
            .with_rcode(r.rcode))
    }
}
