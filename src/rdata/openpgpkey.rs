//! OPENPGPKEY record data (RFC 7929 §2).

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::wire::{Composer, WireReader};
use crate::{Result, Rtype};

/// `OPENPGPKEY` record data: an OpenPGP Transferable Public Key in binary
/// form (RFC 7929 §2.1, RFC 4880 §11.1).
///
/// The key is not interpreted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Openpgpkey<'a> {
    /// The binary OpenPGP key: the whole RDATA (RFC 7929 §2.1).
    pub key: &'a [u8],
}

impl<'a> Openpgpkey<'a> {
    /// Wraps a binary OpenPGP key (RFC 7929 §2.1).
    #[inline]
    pub const fn new(key: &'a [u8]) -> Self {
        Openpgpkey { key }
    }
}

impl<'a> ParseRdata<'a> for Openpgpkey<'a> {
    const RTYPE: Rtype = Rtype::OPENPGPKEY;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        Ok(Openpgpkey {
            key: rdata.read_rest(),
        })
    }
}

impl ComposeRdata for Openpgpkey<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::OPENPGPKEY
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_bytes(self.key)
    }
}

impl fmt::Display for Openpgpkey<'_> {
    /// The key in base64 (RFC 7929 §2.3). An empty key has no such form and
    /// is written in the generic RFC 3597 §5 form (`\# 0`) instead.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.key.is_empty() {
            return crate::text::fmt_generic_rdata(f, self.key);
        }
        fmt::Display::fmt(&crate::text::Base64(self.key), f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdata::tests::{compose, parse, round_trip};
    use crate::testutil::hex;
    use crate::{Class, RData};

    #[test]
    fn rfc7929_shape() {
        // The start of an OpenPGP public-key packet (RFC 4880 §5.5.2):
        // old-format tag 6, two-octet length, version 4, creation time,
        // algorithm 22 (EdDSA). RFC 7929 §2.3 presents it as base64.
        let wire = hex("98330457f7e7bc16");
        round_trip(Rtype::OPENPGPKEY, &wire, "mDMEV/fnvBY=");
        let Ok(RData::Openpgpkey(k)) = parse(Rtype::OPENPGPKEY, Class::IN, &wire) else {
            panic!("not OPENPGPKEY")
        };
        assert_eq!(k, Openpgpkey::new(&wire));
        assert_eq!(compose(&k), wire);
    }

    #[test]
    fn empty_key_uses_generic_form() {
        // Only representable in class IN as the generic form.
        assert_eq!(compose(&Openpgpkey::new(b"")), b"");
        assert_eq!(
            std::string::ToString::to_string(&Openpgpkey::new(b"")),
            "\\# 0"
        );
        round_trip(Rtype::OPENPGPKEY, b"\x01", "AQ==");
    }
}
