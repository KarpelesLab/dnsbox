//! NAPTR record data (RFC 3403 §4.1).

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::charstr::CharStr;
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, WireReader};
use crate::{Result, Rtype};

/// `NAPTR` record data: a Naming Authority Pointer, one rule of a Dynamic
/// Delegation Discovery System application (RFC 3403 §4.1).
///
/// RFC 3403 §4.1 says the replacement name is not compressed, but RFC 3597
/// §4 lists NAPTR among the types whose RDATA names receivers should
/// decompress, so a compressed replacement is accepted when parsing. It is
/// always written uncompressed, and lowercased in canonical form
/// (RFC 4034 §6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Naptr<'a> {
    /// Order in which records must be processed; lower first
    /// (RFC 3403 §4.1 "ORDER").
    pub order: u16,
    /// Preference among records of equal order; lower first
    /// (RFC 3403 §4.1 "PREFERENCE").
    pub preference: u16,
    /// Application-specific flags, e.g. `S`, `A`, `U`, `P`
    /// (RFC 3403 §4.1 "FLAGS").
    pub flags: CharStr<'a>,
    /// Service parameters, e.g. `E2U+sip` (RFC 3403 §4.1 "SERVICES").
    pub services: CharStr<'a>,
    /// Substitution expression applied to the client's string
    /// (RFC 3403 §4.1 "REGEXP"); empty when `replacement` is used.
    pub regexp: CharStr<'a>,
    /// Next domain name to query; `.` when `regexp` is used
    /// (RFC 3403 §4.1 "REPLACEMENT").
    pub replacement: Name<'a>,
}

impl<'a> ParseRdata<'a> for Naptr<'a> {
    const RTYPE: Rtype = Rtype::NAPTR;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        Ok(Naptr {
            order: rdata.read_u16()?,
            preference: rdata.read_u16()?,
            flags: rdata.read_char_string()?,
            services: rdata.read_char_string()?,
            regexp: rdata.read_char_string()?,
            // RFC 3597 §4 lists NAPTR among the types receivers decompress.
            replacement: rdata.read_name()?,
        })
    }
}

impl ComposeRdata for Naptr<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::NAPTR
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_u16(self.order)?;
        c.put_u16(self.preference)?;
        self.flags.compose(c)?;
        self.services.compose(c)?;
        self.regexp.compose(c)?;
        // Never compressed (RFC 3403 §4.1), lowercased in canonical form
        // (RFC 4034 §6.2).
        c.put_name(self.replacement, NameEncoding::Lowercase)
    }
}

impl fmt::Display for Naptr<'_> {
    /// `order preference "flags" "services" "regexp" replacement`
    /// (RFC 3403 §4.1, §6).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {}",
            self.order,
            self.preference,
            self.flags,
            self.services,
            self.regexp,
            self.replacement
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdata::tests::{compose, parse, round_trip};
    use crate::{Class, Error, Message, RData};
    use std::string::ToString;
    use std::vec::Vec;

    /// Encodes NAPTR RDATA from its parts.
    fn wire(order: u16, pref: u16, strings: [&[u8]; 3], replacement: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&order.to_be_bytes());
        v.extend_from_slice(&pref.to_be_bytes());
        for s in strings {
            v.push(s.len() as u8);
            v.extend_from_slice(s);
        }
        v.extend_from_slice(replacement);
        v
    }

    #[test]
    fn rfc3403_examples() {
        // RFC 3403 §6.1:
        //   IN NAPTR 100 10 "" "" "/urn:cid:.+@([^\.]+\.)(.*)$/\2/i" .
        // (in zone-file text the backslashes of the regexp are escaped).
        round_trip(
            Rtype::NAPTR,
            &wire(
                100,
                10,
                [b"", b"", br"/urn:cid:.+@([^\.]+\.)(.*)$/\2/i"],
                b"\x00",
            ),
            r#"100 10 "" "" "/urn:cid:.+@([^\\.]+\\.)(.*)$/\\2/i" ."#,
        );
        // RFC 3403 §6.1 (second step):
        //   IN NAPTR 100 50 "a" "z3950+N2L+N2C" "" cidserver.example.com.
        round_trip(
            Rtype::NAPTR,
            &wire(
                100,
                50,
                [b"a", b"z3950+N2L+N2C", b""],
                b"\x09cidserver\x07example\x03com\x00",
            ),
            r#"100 50 "a" "z3950+N2L+N2C" "" cidserver.example.com."#,
        );
        // RFC 3403 §6.2:
        //   IN NAPTR 100 10 "u" "E2U+sip" "!^.*$!sip:information@foo.se!i" .
        round_trip(
            Rtype::NAPTR,
            &wire(
                100,
                10,
                [b"u", b"E2U+sip", b"!^.*$!sip:information@foo.se!i"],
                b"\x00",
            ),
            r#"100 10 "u" "E2U+sip" "!^.*$!sip:information@foo.se!i" ."#,
        );
        // An "s" rule pointing at SRV records (RFC 3403 §4.1 flags).
        round_trip(
            Rtype::NAPTR,
            &wire(
                100,
                100,
                [b"s", b"http+I2R", b""],
                b"\x05_http\x04_tcp\x07foo\x2dbar\x03com\x00",
            ),
            r#"100 100 "s" "http+I2R" "" _http._tcp.foo-bar.com."#,
        );
    }

    #[test]
    fn malformed() {
        let good = wire(1, 2, [b"a", b"b", b"c"], b"\x00");
        // Every truncation fails.
        for end in 0..good.len() {
            assert!(parse(Rtype::NAPTR, Class::IN, &good[..end]).is_err());
        }
        // A string length running past the RDATA.
        assert_eq!(
            parse(Rtype::NAPTR, Class::IN, b"\x00\x01\x00\x02\x05ab"),
            Err(Error::UnexpectedEof)
        );
        // Trailing bytes after the replacement.
        let mut long = good.clone();
        long.push(0);
        assert_eq!(
            parse(Rtype::NAPTR, Class::IN, &long),
            Err(Error::TrailingData)
        );
    }

    #[test]
    fn compressed_replacement_is_accepted_and_expanded() {
        // Response for example.com NAPTR with the replacement
        // "sip" + pointer to the question name.
        let mut msg = b"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\
                        \x07example\x03com\x00\x00\x23\x00\x01\
                        \xc0\x0c\x00\x23\x00\x01\x00\x00\x0e\x10"
            .to_vec();
        let rdata = wire(10, 20, [b"s", b"SIP+D2U", b""], b"\x04_sip\xc0\x0c");
        msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        msg.extend_from_slice(&rdata);
        let msg = Message::parse_validated(&msg).unwrap();
        let rr = msg.answers().next().unwrap().unwrap();
        let RData::Naptr(n) = rr.data().unwrap() else {
            panic!("not NAPTR")
        };
        assert_eq!(n.replacement.to_string(), "_sip.example.com.");
        assert_eq!(
            compose(&n),
            wire(10, 20, [b"s", b"SIP+D2U", b""], b"\x04_sip\x07example\x03com\x00")
        );
    }

}
