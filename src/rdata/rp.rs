//! RP record data (RFC 1183 §2.2).

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, WireReader};
use crate::{Result, Rtype};

/// `RP` record data: the responsible person for a domain
/// (RFC 1183 §2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Rp<'a> {
    /// The mailbox of the responsible person, encoded as a domain name
    /// (`.` if none).
    pub mbox: Name<'a>,
    /// A domain name with TXT records about the person (`.` if none).
    pub txt: Name<'a>,
}

impl<'a> ParseRdata<'a> for Rp<'a> {
    const RTYPE: Rtype = Rtype::RP;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        // RFC 3597 §4 lists RP among the types receivers decompress.
        Ok(Rp {
            mbox: rdata.read_name()?,
            txt: rdata.read_name()?,
        })
    }
}

impl ComposeRdata for Rp<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::RP
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        // Never compressed by senders (RFC 3597 §4), lowercased in canonical
        // form (RFC 4034 §6.2).
        c.put_name(self.mbox, NameEncoding::Lowercase)?;
        c.put_name(self.txt, NameEncoding::Lowercase)
    }
}

impl fmt::Display for Rp<'_> {
    /// `mbox-dname txt-dname` (RFC 1183 §2.2).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.mbox, self.txt)
    }
}

#[cfg(test)]
mod tests {
    use crate::rdata::tests::{compose, parse, round_trip};
    use crate::rdata::{RData, Rp};
    use crate::wire::{Canonical, WireWriter};
    use crate::{Class, ComposeRdata, Error, Rtype};
    use std::string::ToString;

    #[test]
    fn rfc1183_example() {
        // RP root.sri-nic.arpa. nic.arpa. (named-rrchecker).
        round_trip(
            Rtype::RP,
            b"\x04root\x07sri-nic\x04arpa\x00\x03nic\x04arpa\x00",
            "root.sri-nic.arpa. nic.arpa.",
        );
        round_trip(Rtype::RP, b"\x00\x00", ". .");
    }

    #[test]
    fn decompresses_and_lowercases() {
        // RFC 3597 §4: RP names may be compressed on receipt.
        let msg = b"\x03Foo\x00\x01x\xc0\x00\xc0\x00";
        let mut r = crate::WireReader::with_range(msg, 5, msg.len()).unwrap();
        let rp: Rp<'_> = crate::rdata::ParseRdata::parse_rdata(&mut r).unwrap();
        assert!(r.is_empty());
        assert_eq!(rp.mbox.to_string(), "x.Foo.");
        assert_eq!(compose(&rp), b"\x01x\x03Foo\x00\x03Foo\x00");
        let mut buf = [0u8; 32];
        let mut w = WireWriter::new(&mut buf);
        rp.compose_rdata(&mut Canonical::new(&mut w)).unwrap();
        assert_eq!(w.written(), b"\x01x\x03foo\x00\x03foo\x00");
        assert!(matches!(
            parse(Rtype::RP, Class::IN, b"\x00\x00").unwrap(),
            RData::Rp(_)
        ));
        assert_eq!(
            parse(Rtype::RP, Class::IN, b"\x00"),
            Err(Error::UnexpectedEof)
        );
    }
}
