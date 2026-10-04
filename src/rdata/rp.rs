//! RP record data (RFC 1183 §2.2).

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Result, Rtype};

/// `RP` record data: the responsible person for a domain
/// (RFC 1183 §2.2).
///
/// ```
/// use dnsbox::rdata::{ParseRdataText, Rp};
///
/// // RFC 1183 §2.2.
/// let mut buf = [0u8; 64];
/// let rp = Rp::from_text("louie.trantor.umd.edu. LAM1.people.umd.edu.", &mut buf)?;
/// assert_eq!(rp.mbox.to_string(), "louie.trantor.umd.edu.");
/// assert_eq!(rp.txt.to_string(), "LAM1.people.umd.edu.");
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Rp<'a> {
    /// The mailbox of the responsible person, encoded as a domain name
    /// (`.` if none).
    pub mbox: Name<'a>,
    /// A domain name with TXT records about the person (`.` if none).
    pub txt: Name<'a>,
}

impl ParseRdataText for Rp<'_> {
    /// `<mbox-dname> <txt-dname>` (RFC 1183 §2.2): two domain names,
    /// relative to the origin unless they end in a dot; `.` for none.
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        s.name_into(out, NameEncoding::Lowercase)?;
        s.name_into(out, NameEncoding::Lowercase)
    }
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
    use crate::rdata::tests::{compose, parse, round_trip, text_error, text_round_trip};
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
        assert_eq!(w.as_bytes(), b"\x01x\x03foo\x00\x03foo\x00");
        assert!(matches!(
            parse(Rtype::RP, Class::IN, b"\x00\x00").unwrap(),
            RData::Rp(_)
        ));
        assert_eq!(
            parse(Rtype::RP, Class::IN, b"\x00"),
            Err(Error::UnexpectedEof)
        );
    }

    #[test]
    fn text() {
        // RFC 1183 §2.2 examples (case preserved; `.` for "no TXT").
        text_round_trip(
            Rtype::RP,
            "louie.trantor.umd.edu.  LAM1.people.umd.edu.",
            b"\x05louie\x07trantor\x03umd\x03edu\x00\x04LAM1\x06people\x03umd\x03edu\x00",
            "louie.trantor.umd.edu. LAM1.people.umd.edu.",
        );
        text_round_trip(
            Rtype::RP,
            "louie.trantor.umd.edu. .",
            b"\x05louie\x07trantor\x03umd\x03edu\x00\x00",
            "louie.trantor.umd.edu. .",
        );
        // Relative names and `@` use the origin.
        text_round_trip(
            Rtype::RP,
            "( hostmaster\n @ )",
            b"\x0ahostmaster\x07example\x00\x07example\x00",
            "hostmaster.example. example.",
        );
        text_round_trip(Rtype::RP, ". .", b"\x00\x00", ". .");
    }

    #[test]
    fn text_malformed() {
        for (text, err) in [
            ("", Error::UnexpectedEof),
            ("a.", Error::UnexpectedEof),
            ("a. b. c.", Error::InvalidText),
            ("\"a.\" b.", Error::InvalidText),
            ("a..b. c.", Error::EmptyLabel),
        ] {
            assert_eq!(text_error(Rtype::RP, text), err, "{text:?}");
        }
    }
}
