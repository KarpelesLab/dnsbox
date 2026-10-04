//! SSHFP record data (RFC 4255, RFC 6594, RFC 7479, RFC 8709) and its
//! algorithm and fingerprint-type registries.

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::wire::{Composer, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Error, Result, Rtype};

open_enum! {
    /// An SSHFP public key algorithm number (RFC 4255 §3.1.1, IANA "SSHFP
    /// RR Types for public key algorithms").
    ///
    /// The presentation format of SSHFP uses the bare number.
    pub struct SshfpAlgorithm(u8), generic "";
    /// RSA (RFC 4255).
    RSA = 1 => "RSA",
    /// DSA (RFC 4255).
    DSA = 2 => "DSA",
    /// ECDSA (RFC 6594).
    ECDSA = 3 => "ECDSA",
    /// Ed25519 (RFC 7479).
    ED25519 = 4 => "Ed25519",
    /// Ed448 (RFC 8709).
    ED448 = 6 => "Ed448",
}

open_enum! {
    /// An SSHFP fingerprint type (RFC 4255 §3.1.2, IANA "SSHFP RR types
    /// for fingerprint types").
    ///
    /// The presentation format of SSHFP uses the bare number.
    pub struct SshfpFpType(u8), generic "";
    /// SHA-1 (RFC 4255).
    SHA1 = 1 => "SHA-1",
    /// SHA-256 (RFC 6594).
    SHA256 = 2 => "SHA-256",
}

/// `SSHFP` record data: an SSH host key fingerprint (RFC 4255 §3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Sshfp<'a> {
    /// Algorithm of the public key (RFC 4255 §3.1.1).
    pub algorithm: SshfpAlgorithm,
    /// Message-digest algorithm of the fingerprint (RFC 4255 §3.1.2).
    pub fp_type: SshfpFpType,
    /// The fingerprint: the rest of the RDATA (RFC 4255 §3.1.3).
    pub fingerprint: &'a [u8],
}

impl<'a> Sshfp<'a> {
    /// Builds SSHFP data from its fields (RFC 4255 §3.1).
    #[inline]
    pub const fn new(
        algorithm: SshfpAlgorithm,
        fp_type: SshfpFpType,
        fingerprint: &'a [u8],
    ) -> Self {
        Sshfp {
            algorithm,
            fp_type,
            fingerprint,
        }
    }
}

impl ParseRdataText for Sshfp<'_> {
    /// `<algorithm> <fp-type> <fingerprint>` (RFC 4255 §3.2): two decimal
    /// numbers and the fingerprint in hexadecimal, which may be split
    /// across blanks and lines. At least one octet is required (an empty
    /// fingerprint has only the generic form, as in BIND).
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        out.put_u8(s.u8()?)?;
        out.put_u8(s.u8()?)?;
        if s.hex_rest_into(out)? == 0 {
            return Err(Error::UnexpectedEof);
        }
        Ok(())
    }
}

impl<'a> ParseRdata<'a> for Sshfp<'a> {
    const RTYPE: Rtype = Rtype::SSHFP;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        Ok(Sshfp {
            algorithm: SshfpAlgorithm::new(rdata.read_u8()?),
            fp_type: SshfpFpType::new(rdata.read_u8()?),
            fingerprint: rdata.read_rest(),
        })
    }
}

impl ComposeRdata for Sshfp<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::SSHFP
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_u8(self.algorithm.get())?;
        c.put_u8(self.fp_type.get())?;
        c.put_bytes(self.fingerprint)
    }
}

impl fmt::Display for Sshfp<'_> {
    /// `algorithm fp-type fingerprint-hex` (RFC 4255 §3.2). An empty
    /// fingerprint has no such form and is written in the generic RFC 3597
    /// §5 form instead.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.fingerprint.is_empty() {
            return crate::text::fmt_generic_rdata(
                f,
                &[self.algorithm.get(), self.fp_type.get()],
            );
        }
        write!(
            f,
            "{} {} {}",
            self.algorithm.get(),
            self.fp_type.get(),
            crate::text::Hex(self.fingerprint)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Class;
    use crate::rdata::tests::{compose, parse, round_trip, text_error, text_round_trip};
    use crate::testutil::hex;
    use std::string::ToString;

    #[test]
    fn rfc4255_example() {
        // RFC 4255 §3.3:
        //   host.example.  SSHFP 2 1 123456789abcdef67890123456789abcdef67890
        let mut wire = std::vec![2, 1];
        wire.extend(hex("123456789abcdef67890123456789abcdef67890"));
        round_trip(
            Rtype::SSHFP,
            &wire,
            "2 1 123456789ABCDEF67890123456789ABCDEF67890",
        );
        let Ok(crate::RData::Sshfp(s)) = parse(Rtype::SSHFP, Class::IN, &wire) else {
            panic!("not SSHFP")
        };
        assert_eq!(s.algorithm, SshfpAlgorithm::DSA);
        assert_eq!(s.fp_type, SshfpFpType::SHA1);
        assert_eq!(s.fingerprint.len(), 20);
    }

    #[test]
    fn rfc6594_sha256() {
        // An ECDSA key with a SHA-256 fingerprint (values from RFC 6594).
        let fp = hex("821eb6c1c98d9cc827ab7f456304c0f14785b7008d9e8646a8519de80849afc7");
        let s = Sshfp::new(SshfpAlgorithm::ECDSA, SshfpFpType::SHA256, &fp);
        let wire = compose(&s);
        assert_eq!(&wire[..2], [3, 2]);
        round_trip(
            Rtype::SSHFP,
            &wire,
            "3 2 821EB6C1C98D9CC827AB7F456304C0F14785B7008D9E8646A8519DE80849AFC7",
        );
    }

    #[test]
    fn registries_and_edge_cases() {
        assert_eq!(SshfpAlgorithm::ED25519.get(), 4);
        assert_eq!(SshfpAlgorithm::ED448.to_string(), "Ed448");
        assert_eq!("sha-256".parse(), Ok(SshfpFpType::SHA256));
        assert_eq!(SshfpFpType::new(9).to_string(), "9");
        // Unknown numbers round-trip and display as numbers.
        round_trip(Rtype::SSHFP, b"\x09\x07\xab", "9 7 AB");
        // No fingerprint: generic form.
        round_trip(Rtype::SSHFP, b"\x01\x01", "\\# 2 0101");
        assert_eq!(parse(Rtype::SSHFP, Class::IN, b"\x01"), Err(Error::UnexpectedEof));
    }

    #[test]
    fn text() {
        // RFC 4255 §3.3:
        //   host.example.  SSHFP 2 1 123456789abcdef67890123456789abcdef67890
        let mut wire = std::vec![2, 1];
        wire.extend(hex("123456789abcdef67890123456789abcdef67890"));
        text_round_trip(
            Rtype::SSHFP,
            "2 1 123456789abcdef67890123456789abcdef67890",
            &wire,
            "2 1 123456789ABCDEF67890123456789ABCDEF67890",
        );
        // RFC 6594 §3: an ECDSA key with a SHA-256 fingerprint, split
        // across lines as zone files do (RFC 4255 §3.2).
        let mut wire = std::vec![3, 2];
        wire.extend(hex(
            "821eb6c1c98d9cc827ab7f456304c0f14785b7008d9e8646a8519de80849afc7",
        ));
        text_round_trip(
            Rtype::SSHFP,
            "3 2 (\n 821eb6c1c98d9cc827ab7f456304c0f1\n 4785b7008d9e8646a8519de80849afc7 )",
            &wire,
            "3 2 821EB6C1C98D9CC827AB7F456304C0F14785B7008D9E8646A8519DE80849AFC7",
        );
        // RFC 7479 §3 (Ed25519, SHA-256), split at odd digit counts.
        let mut wire = std::vec![4, 2];
        wire.extend(hex(
            "a87f1b687ac0e57d2a081a2f282672334d90ed316d2b818ca9580ea384d92401",
        ));
        text_round_trip(
            Rtype::SSHFP,
            "4 2 ( a87f1b687ac0e57d2a081a2f2826723\n 34d90ed316d2b818ca9580ea384d924\n 01 )",
            &wire,
            "4 2 A87F1B687AC0E57D2A081A2F282672334D90ED316D2B818CA9580EA384D92401",
        );
        // Unassigned numbers round-trip; digits may be split anywhere.
        text_round_trip(Rtype::SSHFP, "255 9 0 0 a B", b"\xff\x09\x00\xab", "255 9 00AB");
    }

    #[test]
    fn text_malformed() {
        for (text, err) in [
            ("", Error::UnexpectedEof),
            ("2", Error::UnexpectedEof),
            // No fingerprint: only the generic form can express it.
            ("2 1", Error::UnexpectedEof),
            ("256 1 00", Error::InvalidText),
            ("2 -1 00", Error::InvalidText),
            // SSHFP numbers have no mnemonics in the presentation format.
            ("RSA 1 00", Error::InvalidText),
            ("2 1 0", Error::InvalidText),
            ("2 1 0g", Error::InvalidText),
            ("2 1 \"00\"", Error::InvalidText),
        ] {
            assert_eq!(text_error(Rtype::SSHFP, text), err, "{text:?}");
        }
    }
}
