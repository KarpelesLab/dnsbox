//! DS (RFC 4034 §5), CDS (RFC 7344 §3.1, RFC 8078), DLV (RFC 4431) and TA
//! (DNSSEC Trust Authorities) record data, which share one wire format:
//! key tag, algorithm, digest type and digest.

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::dnssec::{Algorithm, DigestType};
use crate::text::Hex;
use crate::wire::{Composer, WireReader};
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
            pub const fn new(key_tag: u16, algorithm: Algorithm, digest_type: DigestType, digest: &'a [u8]) -> Self {
                $ty { key_tag, algorithm, digest_type, digest }
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
    Ds, DS
}

ds_like! {
    /// `CDS` record data: a child's DS published for the parent
    /// (RFC 7344 §3.1). [`Cds::DELETE`] is the RFC 8078 §4 "remove the DS
    /// RRset" form.
    Cds, CDS
}

ds_like! {
    /// `DLV` record data: a DNSSEC lookaside validation record (RFC 4431),
    /// in the DS format. Historic (RFC 8749).
    Dlv, DLV
}

ds_like! {
    /// `TA` record data: a DNSSEC trust authority (IANA, Weiler 2005), in
    /// the DS format.
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
    use crate::rdata::tests::{parse, round_trip};
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
    fn malformed() {
        for t in [Rtype::DS, Rtype::CDS, Rtype::DLV, Rtype::TA] {
            assert_eq!(parse(t, Class::IN, b"\x00\x01\x08"), Err(Error::UnexpectedEof));
            // An empty digest parses (the wire format allows it).
            let d = parse(t, Class::IN, b"\x00\x01\x08\x02").unwrap();
            assert_eq!(d.to_string(), "1 8 2");
        }
    }
}
