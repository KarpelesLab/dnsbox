//! Appending pre-encoded resource records (RFC 1035 §4.1.3).

use super::MessageBuilder;
use crate::Result;
use crate::message::{Record, Section};
use crate::wire::{OutBuf, WireReader};

impl<B: OutBuf> MessageBuilder<B> {
    /// Appends resource records given in wire format — one or more
    /// complete records (owner, TYPE, CLASS, TTL, RDLENGTH, RDATA) back to
    /// back, as kept by a cache or zone store — to `section`. Returns the
    /// number of records added.
    ///
    /// Each record is validated and re-encoded like
    /// [`copy_record`](Self::copy_record): the owner name and the names in
    /// RFC 1035 RDATA are compressed against this message, and RDATA of
    /// types without a typed implementation is copied verbatim
    /// (RFC 3597 §4). Compression pointers inside `raw` are allowed and
    /// resolve against `raw` itself. `raw` must hold whole records only.
    ///
    /// The call is atomic: on any error nothing is added. To use it with
    /// the truncation policy, wrap it in
    /// [`push_rrset_with`](Self::push_rrset_with).
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedEof`](crate::Error::UnexpectedEof) if `raw` ends
    /// inside a record, the parse error of a malformed record, or any
    /// error of [`push_record`](Self::push_record).
    ///
    /// ```
    /// use dnsbox::{Message, MessageBuilder, NameBuf, Rtype, Class, Section};
    ///
    /// // www.example.com. 300 IN A 192.0.2.1, stored uncompressed.
    /// let stored = b"\x03www\x07example\x03com\x00\x00\x01\x00\x01\
    ///                \x00\x00\x01\x2c\x00\x04\xc0\x00\x02\x01";
    /// let name: NameBuf = "www.example.com".parse()?;
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::query(&mut buf, 1, &name, Rtype::A, Class::IN)?;
    /// assert_eq!(b.push_raw_records(Section::Answer, stored)?, 1);
    /// let wire = b.finish();
    /// // The owner was compressed against the question.
    /// assert_eq!(wire.len(), 12 + 21 + 2 + 10 + 4);
    /// Message::parse_validated(wire)?;
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn push_raw_records(&mut self, section: Section, raw: &[u8]) -> Result<usize> {
        let cp = self.checkpoint();
        let mut r = WireReader::new(raw);
        let mut count = 0;
        // Every record is at least 11 bytes, so this loop is bounded by
        // raw.len() / 11 iterations.
        while !r.is_empty() {
            let res = Record::parse(&mut r).and_then(|rr| self.copy_record(section, &rr));
            if let Err(e) = res {
                self.rollback(cp);
                return Err(e);
            }
            count += 1;
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::{Outcome, Truncation};
    use crate::message::Message;
    use crate::name::NameBuf;
    use crate::rdata::{Mx, Ns};
    use crate::{Class, Error, Rtype};
    use std::string::ToString;
    use std::vec::Vec;

    fn name(s: &str) -> NameBuf {
        s.parse().unwrap()
    }

    /// Encodes records uncompressed into a standalone buffer.
    fn stored() -> Vec<u8> {
        let mut v = Vec::new();
        let mut put = |owner: &str, rtype: Rtype, rdata: &[u8]| {
            v.extend_from_slice(name(owner).as_wire());
            v.extend_from_slice(&rtype.get().to_be_bytes());
            v.extend_from_slice(&[0, 1, 0, 0, 0x0e, 0x10]);
            v.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            v.extend_from_slice(rdata);
        };
        put("example.com", Rtype::NS, b"\x02ns\x07example\x03com\x00");
        put(
            "example.com",
            Rtype::MX,
            b"\x00\x0a\x04mail\x07example\x03com\x00",
        );
        put("example.com", Rtype::new(65280), b"\xde\xad");
        v
    }

    #[test]
    fn raw_records_are_recompressed() {
        let raw = stored();
        let mut buf = [0u8; 512];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.push_question(name("example.com"), Rtype::ANY, Class::IN)
            .unwrap();
        assert_eq!(b.push_raw_records(Section::Answer, &raw).unwrap(), 3);
        let wire = b.finish();
        assert!(wire.len() < 12 + 17 + raw.len());
        let msg = Message::parse_validated(wire).unwrap();
        let text: Vec<_> = msg.answers().map(|r| r.unwrap().to_string()).collect();
        assert_eq!(
            text,
            [
                "example.com. 3600 IN NS ns.example.com.",
                "example.com. 3600 IN MX 10 mail.example.com.",
                "example.com. 3600 IN TYPE65280 \\# 2 DEAD",
            ]
        );
    }

    #[test]
    fn raw_with_internal_pointers() {
        // A stored record that uses a pointer into itself is decoded
        // relative to the stored buffer and re-encoded correctly.
        let raw = b"\x07example\x03com\x00\x00\x02\x00\x01\x00\x00\x00\x3c\x00\x05\x02ns\xc0\x00";
        let mut buf = [0u8; 512];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.push_answer(
            name("other.test"),
            Class::IN,
            0,
            &Mx {
                preference: 0,
                exchange: name("x.test").as_name(),
            },
        )
        .unwrap();
        assert_eq!(b.push_raw_records(Section::Answer, raw).unwrap(), 1);
        let msg = Message::parse_validated(b.finish()).unwrap();
        let rr = msg.answers().nth(1).unwrap().unwrap();
        assert_eq!(
            rr.data_as::<Ns>().unwrap().nsdname.to_string(),
            "ns.example.com."
        );
    }

    #[test]
    fn raw_errors_are_atomic() {
        let raw = stored();
        let mut buf = [0u8; 512];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.push_question(name("example.com"), Rtype::ANY, Class::IN)
            .unwrap();
        let before = b.as_bytes().to_vec();
        let start = b.checkpoint();
        // Every cut of the stored records except at record boundaries
        // fails cleanly and leaves nothing behind.
        let boundaries = [0, 39, 39 + 43, raw.len()];
        assert_eq!(raw.len(), 39 + 43 + 25);
        for end in 0..=raw.len() {
            let res = b.push_raw_records(Section::Answer, &raw[..end]);
            if let Some(n) = boundaries.iter().position(|&x| x == end) {
                assert_eq!(res, Ok(n));
                b.rollback(start);
            } else {
                assert!(res.is_err(), "end {end}");
            }
            assert_eq!(b.as_bytes(), &before[..]);
        }
        // Forward pointer, bad label type, bad typed RDATA (A of 3 bytes).
        for bad in [
            &b"\xc0\x05\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00"[..],
            &b"\x40\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00"[..],
            &b"\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x03\x01\x02\x03"[..],
        ] {
            assert!(b.push_raw_records(Section::Answer, bad).is_err());
            assert_eq!(b.as_bytes(), &before[..]);
        }
        // Does not fit.
        b.set_limit(before.len() + 20);
        assert_eq!(
            b.push_raw_records(Section::Answer, &raw),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(b.as_bytes(), &before[..]);
        // With the truncation policy.
        b.set_truncation(Truncation::SetTc);
        let out = b
            .push_rrset_with(Section::Answer, |b| {
                b.push_raw_records(Section::Answer, &raw).map(drop)
            })
            .unwrap();
        assert_eq!(out, Outcome::Truncated);
        assert_eq!(b.len(), before.len());
        assert!(b.header().flags.tc());
    }
}
