//! `serde` support for the owned types (features `serde` + `alloc`); the
//! layout is documented on the [`owned`](crate::owned#serde) module.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use serde::de::{self, Deserializer, SeqAccess, Visitor};
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

/// Deserialized RDATA: a presentation-format or RFC 3597 §5 generic
/// string (human-readable formats), or the wire bytes.
enum RdataBuf {
    /// Text, parsed once the record type and class are known.
    Text(String),
    /// Uncompressed wire bytes.
    Wire(Vec<u8>),
}

impl<'de> Deserialize<'de> for RdataBuf {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = RdataBuf;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(
                    "RDATA in presentation format, as `\\# <length> <hex>` (RFC 3597 §5) or bytes",
                )
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<RdataBuf, E> {
                Ok(RdataBuf::Text(v.into()))
            }

            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<RdataBuf, E> {
                if v.len() > MAX_RDATA_LEN {
                    return Err(E::invalid_length(v.len(), &"at most 65535 octets"));
                }
                Ok(RdataBuf::Wire(v.to_vec()))
            }

            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<RdataBuf, E> {
                if v.len() > MAX_RDATA_LEN {
                    return Err(E::invalid_length(v.len(), &"at most 65535 octets"));
                }
                Ok(RdataBuf::Wire(v))
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
                Ok(RdataBuf::Wire(out))
            }
        }
        if d.is_human_readable() {
            d.deserialize_str(V)
        } else {
            d.deserialize_bytes(V)
        }
    }
}

/// Builds validated RDATA for a deserialized record: text through
/// [`OwnedRData::from_text`], bytes through [`OwnedRData::from_wire`].
fn rdata<E: de::Error>(rtype: Rtype, class: Class, data: &RdataBuf) -> Result<OwnedRData, E> {
    match data {
        RdataBuf::Text(t) => OwnedRData::from_text(rtype, class, t),
        RdataBuf::Wire(w) => OwnedRData::from_wire(rtype, class, w),
    }
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
    /// Accepted when [`OwnedRData::from_wire`] (or `from_text`) accepts it
    /// for some class, since the class is not part of this form: typed
    /// formats must be valid for class ANY unless the data is empty, except
    /// for types defined only for class IN (A, AAAA, SVCB, ...), whose data
    /// in another class is opaque (RFC 3597) and may be anything.
    /// [`OwnedRData::parse`] checks it for a given class.
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let r = RDataDe::deserialize(d)?;
        rdata(r.rtype, Class::ANY, &r.rdata).or_else(|e| {
            // What Serialize writes for class-specific data held for a
            // class other than IN (CH stands for any of them).
            rdata::<D::Error>(r.rtype, Class::CH, &r.rdata).map_err(|_| e)
        })
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
            rdata: RdataRef(self.rdata.as_wire()),
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
            rdata: rdata(r.rtype, r.class, &r.rdata)?,
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
    questions: Section<OwnedQuestion>,
    #[serde(default)]
    answers: Section<OwnedRecord>,
    #[serde(default)]
    authority: Section<OwnedRecord>,
    #[serde(default)]
    additional: Section<OwnedRecord>,
}

/// The most entries of a section: its header count is 16-bit (RFC 1035
/// §4.1.1).
const MAX_SECTION: usize = u16::MAX as usize;

/// A deserialized message section, refused as soon as it holds more than
/// [`MAX_SECTION`] entries.
struct Section<T>(Vec<T>);

impl<T> Default for Section<T> {
    fn default() -> Self {
        Section(Vec::new())
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Section<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for V<T> {
            type Value = Section<T>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a sequence of at most 65535 entries")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Section<T>, A::Error> {
                // The size hint is the input's claim: trust it only a little.
                let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(256));
                while let Some(entry) = seq.next_element()? {
                    if out.len() == MAX_SECTION {
                        return Err(de::Error::invalid_length(out.len() + 1, &self));
                    }
                    out.push(entry);
                }
                Ok(Section(out))
            }
        }
        d.deserialize_seq(V(PhantomData))
    }
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
    /// The form [`Serialize`] writes; missing sections are empty, and a
    /// section of more than 65535 entries is an error.
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let m = MessageDe::deserialize(d)?;
        Ok(OwnedMessage {
            id: m.id,
            flags: m.flags,
            questions: m.questions.0,
            answers: m.answers.0,
            authority: m.authority.0,
            additional: m.additional.0,
        })
    }
}
