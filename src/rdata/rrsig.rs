//! RRSIG (RFC 4034 §3) and SIG (RFC 2535 §4.1, RFC 2931 §3) record data,
//! which share one wire format.

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::dnssec::{Algorithm, Timestamp};
use crate::name::Name;
use crate::text::Base64;
use crate::wire::{Composer, NameEncoding, WireReader};
use crate::{Result, Rtype};

/// Defines an RRSIG-shaped record-data view.
macro_rules! rrsig_like {
    ($(#[$doc:meta])* $ty:ident, $rt:ident, $read:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $ty<'a> {
            /// The type of the RRset covered by the signature (RFC 4034 §3.1.1).
            pub type_covered: Rtype,
            /// The signing algorithm (RFC 4034 §3.1.2).
            pub algorithm: Algorithm,
            /// The number of labels in the original owner name, not counting
            /// the root or a leading wildcard label (RFC 4034 §3.1.3).
            pub labels: u8,
            /// The TTL of the covered RRset in the zone (RFC 4034 §3.1.4).
            pub original_ttl: u32,
            /// End of the validity period, seconds since 1970 modulo 2^32
            /// (RFC 4034 §3.1.5).
            pub expiration: u32,
            /// Start of the validity period, seconds since 1970 modulo 2^32
            /// (RFC 4034 §3.1.5).
            pub inception: u32,
            /// Key tag of the signing DNSKEY (RFC 4034 §3.1.6).
            pub key_tag: u16,
            /// The owner name of the signing DNSKEY: the zone apex
            /// (RFC 4034 §3.1.7).
            pub signer_name: Name<'a>,
            /// The signature (RFC 4034 §3.1.8).
            pub signature: &'a [u8],
        }

        impl<'a> ParseRdata<'a> for $ty<'a> {
            const RTYPE: Rtype = Rtype::$rt;

            fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
                Ok($ty {
                    type_covered: Rtype::new(rdata.read_u16()?),
                    algorithm: Algorithm::new(rdata.read_u8()?),
                    labels: rdata.read_u8()?,
                    original_ttl: rdata.read_u32()?,
                    expiration: rdata.read_u32()?,
                    inception: rdata.read_u32()?,
                    key_tag: rdata.read_u16()?,
                    signer_name: rdata.$read()?,
                    signature: rdata.read_rest(),
                })
            }
        }

        impl<'a> $ty<'a> {
            /// Writes the RDATA without the signature field — the prefix of
            /// the signed data (RFC 4034 §3.1.8.1, RFC 2931 §3.1). Wrap `c`
            /// in [`Canonical`](crate::wire::Canonical) to lowercase the
            /// signer's name as the signature requires.
            pub fn compose_unsigned<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
                c.put_u16(self.type_covered.get())?;
                c.put_u8(self.algorithm.get())?;
                c.put_u8(self.labels)?;
                c.put_u32(self.original_ttl)?;
                c.put_u32(self.expiration)?;
                c.put_u32(self.inception)?;
                c.put_u16(self.key_tag)?;
                // Never compressed (RFC 4034 §3.1.7), lowercased in canonical
                // form (RFC 4034 §6.2, RFC 6840 §5.1).
                c.put_name(self.signer_name, NameEncoding::Lowercase)
            }

            /// The same record data with another signature (e.g. a template
            /// from [`ZoneKey::rrsig_template`](crate::dnssec::ZoneKey::rrsig_template)
            /// completed after signing).
            #[inline]
            pub const fn with_signature<'s>(&self, signature: &'s [u8]) -> $ty<'s>
            where
                'a: 's,
            {
                $ty {
                    type_covered: self.type_covered,
                    algorithm: self.algorithm,
                    labels: self.labels,
                    original_ttl: self.original_ttl,
                    expiration: self.expiration,
                    inception: self.inception,
                    key_tag: self.key_tag,
                    signer_name: self.signer_name,
                    signature,
                }
            }
        }

        impl ComposeRdata for $ty<'_> {
            fn rtype(&self) -> Rtype {
                Rtype::$rt
            }

            fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
                self.compose_unsigned(c)?;
                c.put_bytes(self.signature)
            }
        }

        impl fmt::Display for $ty<'_> {
            /// `type algorithm labels ttl expiration inception key-tag
            /// signer signature` (RFC 4034 §3.2), with `YYYYMMDDHHmmSS`
            /// times and a numeric algorithm.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    f,
                    "{} {} {} {} {} {} {} {}",
                    self.type_covered,
                    self.algorithm.get(),
                    self.labels,
                    self.original_ttl,
                    Timestamp::new(self.expiration),
                    Timestamp::new(self.inception),
                    self.key_tag,
                    self.signer_name,
                )?;
                if !self.signature.is_empty() {
                    write!(f, " {}", Base64(self.signature))?;
                }
                Ok(())
            }
        }
    };
}

rrsig_like! {
    /// `RRSIG` record data: a DNSSEC signature over an RRset (RFC 4034 §3).
    ///
    /// The signer's name is never compressed (RFC 4034 §3.1.7). See
    /// [`crate::dnssec`] for signed-data construction and validation.
    Rrsig, RRSIG, read_name_uncompressed
}

rrsig_like! {
    /// `SIG` record data: the RFC 2535 signature, used today for SIG(0)
    /// transaction signatures (RFC 2931). Its signer's name may be
    /// compressed on receipt (RFC 3597 §4).
    Sig, SIG, read_name
}

impl<'a> From<Rrsig<'a>> for Sig<'a> {
    fn from(s: Rrsig<'a>) -> Self {
        let Rrsig {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer_name,
            signature,
        } = s;
        Sig {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer_name,
            signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdata::RData;
    use crate::rdata::tests::{parse, round_trip};
    use crate::testutil::hex;
    use crate::wire::{Canonical, WireWriter};
    use crate::{Class, Error};
    use std::string::ToString;

    /// RFC 4034 §3.3: the example RRSIG over host.example.com. A.
    pub(crate) fn rfc4034_rrsig() -> std::vec::Vec<u8> {
        let mut w = hex("0001 05 03 00015180 3e7c9dd7 3e5510d7 0a52");
        w.extend(b"\x07example\x03com\x00");
        w.extend(hex(
            "a090755ba58d1affa576f4375831b4310920e481218d18a9f164eb3d81afd3b8
             75d3c75428631e0cf2a28d50875f70c329d7dbfafea807dc1fba1dc34c95d401
             f23f334ce63bfcf3f1b5b44739e5f0eded18d6b33f040a911376d173d757a9f0
             c1fa1798941bb0b36b2df9062790fa7f0166f2737eea907378341fb12dc0a77a",
        ));
        w
    }

    #[test]
    fn rfc4034_example() {
        let wire = rfc4034_rrsig();
        let text = round_trip(
            Rtype::RRSIG,
            &wire,
            "A 5 3 86400 20030322173103 20030220173103 2642 example.com. \
             oJB1W6WNGv+ldvQ3WDG0MQkg5IEhjRip8WTrPYGv07h108dUKGMeDPKijVCHX3DDKdfb+v6o\
             B9wfuh3DTJXUAfI/M0zmO/zz8bW0Rznl8O3tGNazPwQKkRN20XPXV6nwwfoXmJQbsLNrLfkG\
             J5D6fwFm8nN+6pBzeDQfsS3Ap3o=",
        );
        round_trip(Rtype::SIG, &wire, &text);
        let RData::Rrsig(r) = parse(Rtype::RRSIG, Class::IN, &wire).unwrap() else {
            panic!()
        };
        assert_eq!(r.type_covered, Rtype::A);
        assert_eq!(r.algorithm, Algorithm::RSASHA1);
        assert_eq!((r.labels, r.original_ttl, r.key_tag), (3, 86400, 2642));
        let sig: Sig<'_> = r.into();
        assert_eq!(sig.signature, r.signature);

        // compose_unsigned + Canonical lowercases the signer's name.
        let upper = crate::NameBuf::from_text(b"EXAMPLE.com").unwrap();
        let r2 = Rrsig {
            signer_name: upper.as_name(),
            ..r
        };
        let mut buf = [0u8; 64];
        let mut w = WireWriter::new(&mut buf);
        r2.compose_unsigned(&mut Canonical::new(&mut w)).unwrap();
        assert_eq!(w.written(), &wire[..31]);
        let empty = r.with_signature(&[]);
        assert_eq!(empty.signature, b"");
        assert!(empty.to_string().ends_with(" example.com."));
    }

    #[test]
    fn names() {
        // RRSIG's signer name must not be compressed; SIG's may be.
        let mut wire = hex("0001 05 03 00015180 3e7c9dd7 3e5510d7 0a52");
        wire.extend(b"\xc0\x00\x01");
        assert_eq!(
            parse(Rtype::RRSIG, Class::IN, &wire),
            Err(Error::UnexpectedPointer)
        );
        // A backward pointer (here to the zero octet at offset 0, the root).
        let RData::Sig(sig) = parse(Rtype::SIG, Class::IN, &wire).unwrap() else {
            panic!()
        };
        assert!(sig.signer_name.is_root());
        // A forward pointer.
        wire[19] = 0x7f;
        assert_eq!(parse(Rtype::SIG, Class::IN, &wire), Err(Error::BadPointer));
        assert_eq!(
            parse(Rtype::RRSIG, Class::IN, &wire[..17]),
            Err(Error::UnexpectedEof)
        );
    }
}
