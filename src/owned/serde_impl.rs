//! `serde` support for the owned types (features `serde` + `alloc`); the
//! layout is documented on the [`owned`](crate::owned#serde) module.

use alloc::vec::Vec;
use core::fmt;

use serde::de::{self, Deserializer, SeqAccess, Unexpected, Visitor};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use super::{MAX_RDATA_LEN, OwnedMessage, OwnedQuestion, OwnedRData, OwnedRecord};
use crate::name::NameBuf;
use crate::{Class, Flags, Rtype};

/// RDATA bytes, serialized in the generic form or as bytes.
struct RdataRef<'a>(&'a [u8]);

/// `Display` of RDATA in the RFC 3597 §5 generic form.
struct Generic<'a>(&'a [u8]);

impl fmt::Display for Generic<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::text::fmt_generic_rdata(f, self.0)
    }
}

impl Serialize for RdataRef<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(&Generic(self.0))
        } else {
            s.serialize_bytes(self.0)
        }
    }
}

/// Deserialized RDATA bytes.
struct RdataBuf(Vec<u8>);

/// Parses the RFC 3597 §5 generic form: `\#`, the length in decimal, then
/// the data in hexadecimal, possibly split by whitespace (absent for a
/// length of 0).
fn parse_generic(s: &str) -> Option<Vec<u8>> {
    let mut words = s.split_ascii_whitespace();
    if words.next()? != "\\#" {
        return None;
    }
    let len = words.next()?;
    if len.is_empty() || !len.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let len: usize = len.parse().ok()?;
    if len > MAX_RDATA_LEN {
        return None;
    }
    let mut out = Vec::with_capacity(len);
    let mut high = None;
    for b in words.flat_map(str::bytes) {
        let nibble = (b as char).to_digit(16)? as u8;
        match high.take() {
            None => high = Some(nibble),
            Some(h) => {
                if out.len() == len {
                    return None;
                }
                out.push((h << 4) | nibble);
            }
        }
    }
    (high.is_none() && out.len() == len).then_some(out)
}

impl<'de> Deserialize<'de> for RdataBuf {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = RdataBuf;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("RDATA as `\\# <length> <hex>` (RFC 3597 §5) or bytes")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<RdataBuf, E> {
                parse_generic(v)
                    .map(RdataBuf)
                    .ok_or_else(|| E::invalid_value(Unexpected::Str(v), &self))
            }

            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<RdataBuf, E> {
                if v.len() > MAX_RDATA_LEN {
                    return Err(E::invalid_length(v.len(), &"at most 65535 octets"));
                }
                Ok(RdataBuf(v.to_vec()))
            }

            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<RdataBuf, E> {
                if v.len() > MAX_RDATA_LEN {
                    return Err(E::invalid_length(v.len(), &"at most 65535 octets"));
                }
                Ok(RdataBuf(v))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<RdataBuf, A::Error> {
                let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(MAX_RDATA_LEN));
                while let Some(b) = seq.next_element::<u8>()? {
                    if out.len() == MAX_RDATA_LEN {
                        return Err(de::Error::invalid_length(
                            out.len() + 1,
                            &"at most 65535 octets",
                        ));
                    }
                    out.push(b);
                }
                Ok(RdataBuf(out))
            }
        }
        if d.is_human_readable() {
            d.deserialize_str(V)
        } else {
            d.deserialize_bytes(V)
        }
    }
}

/// Builds validated RDATA for a deserialized record.
fn rdata<E: de::Error>(rtype: Rtype, class: Class, data: &[u8]) -> Result<OwnedRData, E> {
    OwnedRData::from_wire(rtype, class, data)
        .map_err(|e| E::custom(format_args!("invalid {rtype} RDATA: {e}")))
}

// --- OwnedRData ----------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename = "OwnedRData")]
struct RDataSer<'a> {
    #[serde(rename = "type")]
    rtype: Rtype,
    rdata: RdataRef<'a>,
}

#[derive(Deserialize)]
#[serde(rename = "OwnedRData")]
struct RDataDe {
    #[serde(rename = "type")]
    rtype: Rtype,
    rdata: RdataBuf,
}

impl Serialize for OwnedRData {
    /// `{"type": "MX", "rdata": "\\# 20 000A04..."}`; see the [module
    /// documentation](crate::owned#serde).
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        RDataSer {
            rtype: self.rtype,
            rdata: RdataRef(&self.data),
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for OwnedRData {
    /// Checked as [`OwnedRData::from_wire`] does for class ANY: typed
    /// formats must be valid unless the data is empty.
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let r = RDataDe::deserialize(d)?;
        rdata(r.rtype, Class::ANY, &r.rdata.0)
    }
}

// --- OwnedQuestion -------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename = "OwnedQuestion")]
struct QuestionSer<'a> {
    name: &'a NameBuf,
    #[serde(rename = "type")]
    qtype: Rtype,
    class: Class,
}

#[derive(Deserialize)]
#[serde(rename = "OwnedQuestion")]
struct QuestionDe {
    name: NameBuf,
    #[serde(rename = "type")]
    qtype: Rtype,
    class: Class,
}

impl Serialize for OwnedQuestion {
    /// `{"name": "example.com.", "type": "A", "class": "IN"}`.
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        QuestionSer {
            name: &self.name,
            qtype: self.qtype,
            class: self.qclass,
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for OwnedQuestion {
    /// The form [`Serialize`] writes.
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let q = QuestionDe::deserialize(d)?;
        Ok(OwnedQuestion {
            name: q.name,
            qtype: q.qtype,
            qclass: q.class,
        })
    }
}

// --- OwnedRecord ---------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename = "OwnedRecord")]
struct RecordSer<'a> {
    name: &'a NameBuf,
    #[serde(rename = "type")]
    rtype: Rtype,
    class: Class,
    ttl: u32,
    rdata: RdataRef<'a>,
}

#[derive(Deserialize)]
#[serde(rename = "OwnedRecord")]
struct RecordDe {
    name: NameBuf,
    #[serde(rename = "type")]
    rtype: Rtype,
    class: Class,
    ttl: u32,
    rdata: RdataBuf,
}

impl Serialize for OwnedRecord {
    /// `{"name": "example.com.", "type": "A", "class": "IN", "ttl": 3600,
    /// "rdata": "\\# 4 5DB8D822"}`; see the [module documentation](crate::owned#serde).
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        RecordSer {
            name: &self.name,
            rtype: self.rtype(),
            class: self.class,
            ttl: self.ttl,
            rdata: RdataRef(self.rdata.as_bytes()),
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for OwnedRecord {
    /// The form [`Serialize`] writes. The RDATA is checked as
    /// [`OwnedRData::from_wire`] does for the record's type and class.
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let r = RecordDe::deserialize(d)?;
        Ok(OwnedRecord {
            rdata: rdata(r.rtype, r.class, &r.rdata.0)?,
            name: r.name,
            class: r.class,
            ttl: r.ttl,
        })
    }
}

// --- OwnedMessage --------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename = "OwnedMessage")]
struct MessageSer<'a> {
    id: u16,
    flags: Flags,
    questions: &'a [OwnedQuestion],
    answers: &'a [OwnedRecord],
    authority: &'a [OwnedRecord],
    additional: &'a [OwnedRecord],
}

#[derive(Deserialize)]
#[serde(rename = "OwnedMessage")]
struct MessageDe {
    id: u16,
    flags: Flags,
    #[serde(default)]
    questions: Vec<OwnedQuestion>,
    #[serde(default)]
    answers: Vec<OwnedRecord>,
    #[serde(default)]
    authority: Vec<OwnedRecord>,
    #[serde(default)]
    additional: Vec<OwnedRecord>,
}

impl Serialize for OwnedMessage {
    /// `{"id": 4660, "flags": {...}, "questions": [...], "answers": [...],
    /// "authority": [...], "additional": [...]}`.
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        MessageSer {
            id: self.id,
            flags: self.flags,
            questions: &self.questions,
            answers: &self.answers,
            authority: &self.authority,
            additional: &self.additional,
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for OwnedMessage {
    /// The form [`Serialize`] writes; missing sections are empty.
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let m = MessageDe::deserialize(d)?;
        Ok(OwnedMessage {
            id: m.id,
            flags: m.flags,
            questions: m.questions,
            answers: m.answers,
            authority: m.authority,
            additional: m.additional,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_form() {
        assert_eq!(parse_generic("\\# 0"), Some(Vec::new()));
        assert_eq!(parse_generic("  \\#  0  "), Some(Vec::new()));
        assert_eq!(parse_generic("\\# 3 0a0B 0c"), Some(std::vec![10, 11, 12]));
        assert_eq!(
            parse_generic("\\# 3 0 a 0 b 0 c"),
            Some(std::vec![10, 11, 12])
        );
        for bad in [
            "",
            "\\#",
            "# 1 00",
            "\\# 1",
            "\\# 1 0",
            "\\# 1 0000",
            "\\# 2 00",
            "\\# +1 00",
            "\\# -1 00",
            "\\# x 00",
            "\\# 1 0g",
            "\\# 65536 00",
            "\\# 99999999999999999999999 00",
            "\\#1 00",
        ] {
            assert_eq!(parse_generic(bad), None, "{bad:?}");
        }
        let mut s = std::string::String::from("\\# 65535 ");
        s.push_str(&"ab".repeat(65535));
        assert_eq!(parse_generic(&s).map(|v| v.len()), Some(65535));
    }
}
