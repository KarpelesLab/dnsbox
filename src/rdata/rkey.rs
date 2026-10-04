//! RKEY record data (draft-reid-dnsext-rkey-00).

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::dnssec::Algorithm;
use crate::text::Base64;
use crate::wire::{Composer, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Result, Rtype};

/// `RKEY` record data: a resource-record encryption key, with the
/// DNSKEY layout (draft-reid-dnsext-rkey-00). Never standardised.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Rkey<'a> {
    /// Flags (none defined; zero in practice).
    pub flags: u16,
    /// Protocol (as in DNSKEY, RFC 4034 §2.1.2).
    pub protocol: u8,
    /// DNSSEC algorithm (RFC 4034 §2.1.3).
    pub algorithm: Algorithm,
    /// The public key.
    pub public_key: &'a [u8],
}

impl ParseRdataText for Rkey<'_> {
    /// `flags protocol algorithm [base64-key]`, as DNSKEY (RFC 4034
    /// §2.2): decimal flags and protocol, the algorithm as a number or
    /// mnemonic, then the key in base64, possibly split by blanks (BIND
    /// requires a key; the wire format allows none, so this does too).
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        out.put_u16(s.u16()?)?;
        out.put_u8(s.u8()?)?;
        out.put_u8(s.parse::<Algorithm>()?.get())?;
        s.base64_rest_into(out).map(drop)
    }
}

impl<'a> ParseRdata<'a> for Rkey<'a> {
    const RTYPE: Rtype = Rtype::RKEY;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        let [f0, f1, protocol, algorithm] = rdata.read_array()?;
        Ok(Rkey {
            flags: u16::from_be_bytes([f0, f1]),
            protocol,
            algorithm: Algorithm::new(algorithm),
            public_key: rdata.read_rest(),
        })
    }
}

impl ComposeRdata for Rkey<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::RKEY
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_u16(self.flags)?;
        c.put_u8(self.protocol)?;
        c.put_u8(self.algorithm.get())?;
        c.put_bytes(self.public_key)
    }
}

impl fmt::Display for Rkey<'_> {
    /// `flags protocol algorithm base64-key`, as DNSKEY (RFC 4034 §2.2).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.flags, self.protocol, self.algorithm.get())?;
        if !self.public_key.is_empty() {
            write!(f, " {}", Base64(self.public_key))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::rdata::tests::{parse, round_trip, text_error, text_round_trip};
    use crate::{Class, Error, Rtype};

    #[test]
    fn round_trips() {
        // RKEY 0 1 7 AQID (named-rrchecker).
        round_trip(Rtype::RKEY, b"\x00\x00\x01\x07\x01\x02\x03", "0 1 7 AQID");
        round_trip(Rtype::RKEY, b"\x00\x00\x03\x07", "0 3 7");
        assert_eq!(
            parse(Rtype::RKEY, Class::IN, b"\x00\x00\x01"),
            Err(Error::UnexpectedEof)
        );
    }

    #[test]
    fn text() {
        // named-rrchecker.
        text_round_trip(
            Rtype::RKEY,
            "0 1 7 AQID",
            b"\x00\x00\x01\x07\x01\x02\x03",
            "0 1 7 AQID",
        );
        text_round_trip(
            Rtype::RKEY,
            "256 3 RSASHA256 ( AQ\n ID )",
            b"\x01\x00\x03\x08\x01\x02\x03",
            "256 3 8 AQID",
        );
        text_round_trip(Rtype::RKEY, "0 3 7", b"\x00\x00\x03\x07", "0 3 7");
        for (text, err) in [
            ("0 1 NOSUCHALG AQID", Error::InvalidText),
            ("65536 1 7 AQID", Error::InvalidText),
            ("0 256 7 AQID", Error::InvalidText),
            ("0 1 7 AQI", Error::InvalidText),
            ("0 1", Error::UnexpectedEof),
        ] {
            assert_eq!(text_error(Rtype::RKEY, text), err, "{text:?}");
        }
    }
}
