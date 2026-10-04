//! DNSKEY (RFC 4034 §2), CDNSKEY (RFC 7344 §3.2, RFC 8078) and KEY
//! (RFC 2535 §3.1, RFC 3445, RFC 2931) record data, which share one wire
//! format: flags, protocol, algorithm and public key.

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::dnssec::{Algorithm, key_tag};
use crate::text::Base64;
use crate::wire::{Composer, WireReader};
use crate::{Result, Rtype};

/// Defines a DNSKEY-shaped record-data view.
macro_rules! dnskey_like {
    ($(#[$doc:meta])* $ty:ident, $rt:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $ty<'a> {
            /// The flags field.
            pub flags: u16,
            /// The protocol field; always 3 in DNSSEC (RFC 4034 §2.1.2).
            pub protocol: u8,
            /// The public key's cryptographic algorithm (RFC 4034 §2.1.3).
            pub algorithm: Algorithm,
            /// The public key material, in the algorithm-specific format
            /// (RFC 4034 §2.1.4; e.g. RFC 3110 for RSA).
            pub public_key: &'a [u8],
        }

        impl<'a> $ty<'a> {
            /// Builds the record data.
            #[inline]
            pub const fn new(flags: u16, protocol: u8, algorithm: Algorithm, public_key: &'a [u8]) -> Self {
                $ty { flags, protocol, algorithm, public_key }
            }

            /// The key tag (RFC 4034 Appendix B, including the RSA/MD5
            /// special case of §B.1).
            #[inline]
            pub fn key_tag(&self) -> u16 {
                key_tag(self.flags, self.protocol, self.algorithm, self.public_key)
            }

            /// The RDATA length in octets.
            #[inline]
            pub const fn rdata_len(&self) -> usize {
                4 + self.public_key.len()
            }
        }

        impl super::ParseRdataText for $ty<'_> {}

        impl<'a> ParseRdata<'a> for $ty<'a> {
            const RTYPE: Rtype = Rtype::$rt;

            fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
                Ok($ty {
                    flags: rdata.read_u16()?,
                    protocol: rdata.read_u8()?,
                    algorithm: Algorithm::new(rdata.read_u8()?),
                    public_key: rdata.read_rest(),
                })
            }
        }

        impl ComposeRdata for $ty<'_> {
            fn rtype(&self) -> Rtype {
                Rtype::$rt
            }

            fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
                c.put_u16(self.flags)?;
                c.put_u8(self.protocol)?;
                c.put_u8(self.algorithm.get())?;
                c.put_bytes(self.public_key)
            }
        }

        impl fmt::Display for $ty<'_> {
            /// `flags protocol algorithm base64-key` (RFC 4034 §2.2), with
            /// the algorithm as a number.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{} {} {}", self.flags, self.protocol, self.algorithm.get())?;
                if !self.public_key.is_empty() {
                    write!(f, " {}", Base64(self.public_key))?;
                }
                Ok(())
            }
        }
    };
}

dnskey_like! {
    /// `DNSKEY` record data: a zone's public key (RFC 4034 §2).
    ///
    /// ```
    /// use dnsbox::dnssec::Algorithm;
    /// use dnsbox::rdata::Dnskey;
    ///
    /// let key = Dnskey::new(Dnskey::ZONE | Dnskey::SEP, 3, Algorithm::ED25519, &[0; 32]);
    /// assert!(key.is_zone_key() && key.is_sep() && !key.is_revoked());
    /// assert_eq!(key.to_string(), "257 3 15 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    /// ```
    Dnskey, DNSKEY
}

dnskey_like! {
    /// `CDNSKEY` record data: a child's DNSKEY published for the parent
    /// (RFC 7344 §3.2). [`Cdnskey::DELETE`] is the RFC 8078 §4 "remove the
    /// DS RRset" form.
    Cdnskey, CDNSKEY
}

dnskey_like! {
    /// `KEY` record data: a public key for SIG(0) and other non-zone uses
    /// (RFC 2535 §3.1, restricted by RFC 3445; RFC 2931). The flags are
    /// the RFC 2535 §3.1.2 key flags.
    Key, KEY
}

impl Dnskey<'_> {
    /// The Zone Key flag (bit 7, RFC 4034 §2.1.1).
    pub const ZONE: u16 = 0x0100;
    /// The REVOKE flag (bit 8, RFC 5011 §2.1).
    pub const REVOKE: u16 = 0x0080;
    /// The Secure Entry Point flag (bit 15, RFC 4034 §2.1.1, RFC 3757).
    pub const SEP: u16 = 0x0001;

    /// Whether the Zone Key flag is set: only such keys may verify RRSIGs
    /// (RFC 4034 §2.1.1).
    #[inline]
    pub const fn is_zone_key(&self) -> bool {
        self.flags & Self::ZONE != 0
    }

    /// Whether the Secure Entry Point flag is set (a key-signing key by
    /// convention, RFC 4034 §2.1.1).
    #[inline]
    pub const fn is_sep(&self) -> bool {
        self.flags & Self::SEP != 0
    }

    /// Whether the REVOKE flag is set (RFC 5011 §2.1).
    #[inline]
    pub const fn is_revoked(&self) -> bool {
        self.flags & Self::REVOKE != 0
    }
}

impl Cdnskey<'_> {
    /// The CDNSKEY "delete" record `0 3 0 AA==` asking the parent to
    /// remove the DS RRset (RFC 8078 §4).
    pub const DELETE: Cdnskey<'static> = Cdnskey {
        flags: 0,
        protocol: 3,
        algorithm: Algorithm::DELETE,
        public_key: &[0],
    };

    /// Whether this is the RFC 8078 §4 delete form (flags 0, protocol 3,
    /// algorithm 0, public key a single zero octet).
    #[inline]
    pub const fn is_delete(&self) -> bool {
        self.flags == 0
            && self.protocol == 3
            && self.algorithm.get() == 0
            && matches!(self.public_key, [0])
    }
}

impl<'a> From<Dnskey<'a>> for Cdnskey<'a> {
    fn from(k: Dnskey<'a>) -> Self {
        Cdnskey::new(k.flags, k.protocol, k.algorithm, k.public_key)
    }
}

impl<'a> From<Cdnskey<'a>> for Dnskey<'a> {
    fn from(k: Cdnskey<'a>) -> Self {
        Dnskey::new(k.flags, k.protocol, k.algorithm, k.public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdata::RData;
    use crate::rdata::tests::{parse, round_trip};
    use crate::testutil::hex;
    use crate::dnssec::testvec::RFC4034_KEY;
    use crate::{Class, Error};


    #[test]
    fn rfc4034_example() {
        let wire = hex(RFC4034_KEY);
        let s = round_trip(
            Rtype::DNSKEY,
            &wire,
            "256 3 5 AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8nokfzj31GajIQKY+5CptLr3buXA10hWqTkF7H6RfoRqXQeogmMHfpftf6zMv1LyBUgia7za6ZEzOJBOztyvhjL742iU/TpPSEDhm2SNKLijfUppn1UaNvv4w==",
        );
        assert!(s.starts_with("256 3 5 AQPSKmyn"));
        let RData::Dnskey(key) = parse(Rtype::DNSKEY, Class::IN, &wire).unwrap() else {
            panic!()
        };
        assert_eq!(key.key_tag(), 2642);
        assert!(key.is_zone_key() && !key.is_sep() && !key.is_revoked());
        assert_eq!(key.algorithm, Algorithm::RSASHA1);
        assert_eq!(key.rdata_len(), wire.len());
    }

    #[test]
    fn cdnskey_and_key() {
        let wire = hex(RFC4034_KEY);
        round_trip(Rtype::CDNSKEY, &wire, &round_trip(Rtype::DNSKEY, &wire, "256 3 5 AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8nokfzj31GajIQKY+5CptLr3buXA10hWqTkF7H6RfoRqXQeogmMHfpftf6zMv1LyBUgia7za6ZEzOJBOztyvhjL742iU/TpPSEDhm2SNKLijfUppn1UaNvv4w=="));
        round_trip(Rtype::KEY, &wire[..6], "256 3 5 AQM=");
        // KEY with the NOKEY flags has no key material (RFC 2535 §3.1.2).
        round_trip(Rtype::KEY, b"\xc2\x00\x03\x05", "49664 3 5");

        // RFC 8078 §4 delete form.
        round_trip(Rtype::CDNSKEY, b"\x00\x00\x03\x00\x00", "0 3 0 AA==");
        let RData::Cdnskey(d) = parse(Rtype::CDNSKEY, Class::IN, b"\x00\x00\x03\x00\x00").unwrap()
        else {
            panic!()
        };
        assert!(d.is_delete());
        assert_eq!(d, Cdnskey::DELETE);
        let k: Dnskey<'_> = d.into();
        assert_eq!(Cdnskey::from(k), d);
        assert!(!Cdnskey::new(0, 3, Algorithm::DELETE, &[1]).is_delete());
        assert!(!Cdnskey::new(0, 3, Algorithm::DELETE, &[0, 0]).is_delete());
        assert!(!Cdnskey::new(256, 3, Algorithm::DELETE, &[0]).is_delete());
    }

    #[test]
    fn malformed() {
        for t in [Rtype::DNSKEY, Rtype::CDNSKEY, Rtype::KEY] {
            assert_eq!(parse(t, Class::IN, b"\x01\x00\x03"), Err(Error::UnexpectedEof));
            assert!(parse(t, Class::IN, b"\x01\x00\x03\x08").is_ok());
        }
    }
}
