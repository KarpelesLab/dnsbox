//! DS (RFC 4034 §5), CDS (RFC 7344 §3.1, RFC 8078), DLV (RFC 4431) and TA
//! (DNSSEC Trust Authorities) record data, which share one wire format:
//! key tag, algorithm, digest type and digest.

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::dnssec::{Algorithm, DigestType};
use crate::text::Hex;
use crate::wire::{Composer, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Result, Rtype};

/// Defines a DS-shaped record-data view.
macro_rules! ds_like {
    ($(#[$doc:meta])* $ty:ident, $rt:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $ty<'a> {
            /// Key tag of the referenced DNSKEY (RFC 4034 §5.1.1).
            pub key_tag: u16,
            /// Algorithm of the referenced DNSKEY (RFC 4034 §5.1.2).
            pub algorithm: Algorithm,
            /// Digest algorithm (RFC 4034 §5.1.3).
            pub digest_type: DigestType,
            /// Digest of the owner name and DNSKEY RDATA (RFC 4034 §5.1.4).
            pub digest: &'a [u8],
        }

        impl<'a> $ty<'a> {
            /// Builds the record data.
            #[inline]
            #[must_use]
            pub const fn new(key_tag: u16, algorithm: Algorithm, digest_type: DigestType, digest: &'a [u8]) -> Self {
                $ty { key_tag, algorithm, digest_type, digest }
            }
        }

        impl ParseRdataText for $ty<'_> {
            /// `<key tag> <algorithm> <digest type> <digest>` (RFC 4034
            /// §5.3): the algorithm as a number or a mnemonic, the digest
            /// type as a number (or a mnemonic such as `SHA-256`), the
            /// digest in hexadecimal, possibly split into several tokens.
            fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
                out.put_u16(s.u16()?)?;
                out.put_u8(s.parse::<Algorithm>()?.get())?;
                out.put_u8(s.parse::<DigestType>()?.get())?;
                s.hex_rest_into(out)?;
                Ok(())
            }
        }

        impl<'a> ParseRdata<'a> for $ty<'a> {
            const RTYPE: Rtype = Rtype::$rt;

            fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
                Ok($ty {
                    key_tag: rdata.read_u16()?,
                    algorithm: Algorithm::new(rdata.read_u8()?),
                    digest_type: DigestType::new(rdata.read_u8()?),
                    digest: rdata.read_rest(),
                })
            }
        }

        impl ComposeRdata for $ty<'_> {
            fn rtype(&self) -> Rtype {
                Rtype::$rt
            }

            fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
                c.put_u16(self.key_tag)?;
                c.put_u8(self.algorithm.get())?;
                c.put_u8(self.digest_type.get())?;
                c.put_bytes(self.digest)
            }
        }

        impl fmt::Display for $ty<'_> {
            /// `key-tag algorithm digest-type hex-digest` (RFC 4034 §5.3),
            /// with numeric algorithm and digest type.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    f,
                    "{} {} {}",
                    self.key_tag,
                    self.algorithm.get(),
                    self.digest_type.get()
                )?;
                if !self.digest.is_empty() {
                    write!(f, " {}", Hex(self.digest))?;
                }
                Ok(())
            }
        }
    };
}

ds_like! {
    /// `DS` record data: a delegation signer, the parent-side hash of a
    /// child zone's DNSKEY (RFC 4034 §5).
    ///
    /// Use [`dnssec::ds_digest_input`](crate::dnssec::ds_digest_input) to
    /// build the digested data, or, with the `dnssec-digest` feature,
    /// [`dnssec::DsDigest`](crate::dnssec) to compute and check digests.
    ///
    /// ```
    /// use dnsbox::dnssec::{Algorithm, DigestType};
    /// use dnsbox::rdata::{Ds, ParseRdataText};
    ///
    /// // The digest may be split into several tokens.
    /// let mut buf = [0u8; 64];
    /// let ds = Ds::from_text(
    ///     "3613 15 2 3aa5ab37efce57f737fc1627013fee07 bdf241bd10f3b1964ab55c78e79a304b",
    ///     &mut buf,
    /// )?;
    /// assert_eq!((ds.key_tag, ds.algorithm, ds.digest_type), (3613, Algorithm::ED25519, DigestType::SHA256));
    /// assert_eq!(ds.digest.len(), 32);
    /// assert_eq!(
    ///     ds.to_string(),
    ///     "3613 15 2 3AA5AB37EFCE57F737FC1627013FEE07BDF241BD10F3B1964AB55C78E79A304B"
    /// );
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    Ds, DS
}

ds_like! {
    /// `CDS` record data: a child's DS published for the parent
    /// (RFC 7344 §3.1). [`Cds::DELETE`] is the RFC 8078 §4 "remove the DS
    /// RRset" form.
    ///
    /// ```
    /// use dnsbox::rdata::{Cds, ParseRdataText};
    ///
    /// let mut buf = [0u8; 8];
    /// let cds = Cds::from_text("0 0 0 00", &mut buf)?;
    /// assert!(cds.is_delete());
    /// assert_eq!(cds, Cds::DELETE);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    Cds, CDS
}

ds_like! {
    /// `DLV` record data: a DNSSEC lookaside validation record (RFC 4431),
    /// in the DS format. Historic (RFC 8749).
    ///
    /// ```
    /// use dnsbox::rdata::{Dlv, ParseRdataText};
    ///
    /// let mut buf = [0u8; 32];
    /// let dlv = Dlv::from_text("12345 8 1 0123456789ABCDEF0123456789ABCDEF01234567", &mut buf)?;
    /// assert_eq!(dlv.digest.len(), 20);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    Dlv, DLV
}

ds_like! {
    /// `TA` record data: a DNSSEC trust authority (IANA, Weiler 2005), in
    /// the DS format.
    ///
    /// ```
    /// use dnsbox::rdata::{ParseRdataText, Ta};
    ///
    /// let mut buf = [0u8; 64];
    /// let ta = Ta::from_text("20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D", &mut buf)?;
    /// assert_eq!(ta.key_tag, 20326);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    Ta, TA
}

impl Cds<'_> {
    /// The CDS "delete" record `0 0 0 00` asking the parent to remove the
    /// DS RRset (RFC 8078 §4).
    pub const DELETE: Cds<'static> = Cds {
        key_tag: 0,
        algorithm: Algorithm::DELETE,
        digest_type: DigestType::new(0),
        digest: &[0],
    };

    /// Whether this is the RFC 8078 §4 delete form (key tag, algorithm and
    /// digest type 0, digest a single zero octet).
    #[inline]
    #[must_use]
    pub const fn is_delete(&self) -> bool {
        self.key_tag == 0
            && self.algorithm.get() == 0
            && self.digest_type.get() == 0
            && matches!(self.digest, [0])
    }
}

impl<'a> From<Ds<'a>> for Cds<'a> {
    fn from(d: Ds<'a>) -> Self {
        Cds::new(d.key_tag, d.algorithm, d.digest_type, d.digest)
    }
}

impl<'a> From<Cds<'a>> for Ds<'a> {
    fn from(d: Cds<'a>) -> Self {
        Ds::new(d.key_tag, d.algorithm, d.digest_type, d.digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdata::RData;
    use crate::rdata::tests::{parse, round_trip, text_error, text_parse, text_round_trip};
    use crate::testutil::hex;
    use crate::{Class, Error};
    use std::string::ToString;

    #[test]
    fn rfc4034_example() {
        // RFC 4034 §5.4: dskey.example.com. DS 60485 5 1 2BB183AF...
        let mut wire = hex("ec45 05 01");
        wire.extend(hex("2bb183af5f22588179a53b0a98631fad1a292118"));
        round_trip(
            Rtype::DS,
            &wire,
            "60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118",
        );
        for t in [Rtype::CDS, Rtype::DLV, Rtype::TA] {
            round_trip(t, &wire, "60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118");
        }
        let RData::Ds(ds) = parse(Rtype::DS, Class::IN, &wire).unwrap() else {
            panic!()
        };
        assert_eq!(ds.key_tag, 60485);
        assert_eq!(ds.digest_type, DigestType::SHA1);
        assert_eq!(ds.digest.len(), 20);
        let cds: Cds<'_> = ds.into();
        assert_eq!(Ds::from(cds), ds);
        assert!(!cds.is_delete());
    }

    #[test]
    fn cds_delete() {
        // RFC 8078 §4.
        round_trip(Rtype::CDS, b"\x00\x00\x00\x00\x00", "0 0 0 00");
        let RData::Cds(d) = parse(Rtype::CDS, Class::IN, b"\x00\x00\x00\x00\x00").unwrap() else {
            panic!()
        };
        assert!(d.is_delete());
        assert_eq!(d, Cds::DELETE);
        assert!(!Cds::new(0, Algorithm::DELETE, DigestType::new(0), &[]).is_delete());
        assert!(!Cds::new(0, Algorithm::DELETE, DigestType::SHA1, &[0]).is_delete());
    }

    #[test]
    fn text() {
        // RFC 4034 §5.4, as printed there.
        let mut wire = hex("ec45 05 01");
        wire.extend(hex("2bb183af5f22588179a53b0a98631fad1a292118"));
        let display = "60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118";
        for t in [Rtype::DS, Rtype::CDS, Rtype::DLV, Rtype::TA] {
            text_round_trip(
                t,
                "60485 5 1 ( 2BB183AF5F22588179A53B0A\n 98631FAD1A292118 )",
                &wire,
                display,
            );
            // Mnemonics for the algorithm (RFC 4034 §5.3) and, as BIND
            // accepts, the digest type; lowercase hex.
            assert_eq!(
                text_parse(t, "60485 RSASHA1 SHA-1 2bb183af5f22588179a53b0a98631fad1a292118")
                    .as_deref(),
                Ok(&wire[..])
            );
        }
        // RFC 8080 §6.1: the DS of the Ed25519 example key, SHA-256.
        let mut wire = hex("0e1d 0f 02");
        wire.extend(hex("3aa5ab37efce57f737fc1627013fee07bdf241bd10f3b1964ab55c78e79a304b"));
        text_round_trip(
            Rtype::DS,
            "3613 15 2 3aa5ab37efce57f737fc1627013fee07 bdf241bd10f3b1964ab55c78e79a304b",
            &wire,
            "3613 15 2 3AA5AB37EFCE57F737FC1627013FEE07BDF241BD10F3B1964AB55C78E79A304B",
        );
        // RFC 8078 §4: the CDS delete form.
        text_round_trip(Rtype::CDS, "0 0 0 00", b"\x00\x00\x00\x00\x00", "0 0 0 00");
        // No digest (allowed on the wire, so displayed and parsed back).
        text_round_trip(Rtype::DS, "1 8 2", b"\x00\x01\x08\x02", "1 8 2");
    }

    #[test]
    fn text_malformed() {
        for t in [Rtype::DS, Rtype::CDS, Rtype::DLV, Rtype::TA] {
            assert_eq!(text_error(t, "60485 5"), Error::UnexpectedEof);
            assert_eq!(text_error(t, "65536 5 1 00"), Error::InvalidText);
            assert_eq!(text_error(t, "1 256 1 00"), Error::InvalidText);
            assert_eq!(text_error(t, "1 5 256 00"), Error::InvalidText);
            assert_eq!(text_error(t, "1 5 SHA-512 00"), Error::InvalidText);
            // Odd number of digits, a non-hex digit, a quoted digest.
            assert_eq!(text_error(t, "1 5 1 2BB"), Error::InvalidText);
            assert_eq!(text_error(t, "1 5 1 2B B"), Error::InvalidText);
            assert_eq!(text_error(t, "1 5 1 2G"), Error::InvalidText);
            assert_eq!(text_error(t, "1 5 1 \"2B\""), Error::InvalidText);
        }
    }

    #[test]
    fn malformed() {
        for t in [Rtype::DS, Rtype::CDS, Rtype::DLV, Rtype::TA] {
            assert_eq!(parse(t, Class::IN, b"\x00\x01\x08"), Err(Error::UnexpectedEof));
            // An empty digest parses (the wire format allows it).
            let d = parse(t, Class::IN, b"\x00\x01\x08\x02").unwrap();
            assert_eq!(d.to_string(), "1 8 2");
        }
    }
}
