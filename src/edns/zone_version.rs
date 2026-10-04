//! ZONEVERSION option (RFC 9660).

use core::fmt;

use super::{ComposeOption, OptionCode, ParseOption};
use crate::text::Hex;
use crate::wire::{Composer, WireReader};
use crate::{Error, Result};

// The complete IANA registry as of 2026-10-04.
open_enum! {
    /// A ZONEVERSION TYPE value (RFC 9660 §6.2; IANA "ZONEVERSION TYPE
    /// Values" registry). Unregistered values display as bare numbers.
    ///
    /// ```
    /// use dnsbox::edns::ZoneVersionType;
    ///
    /// assert_eq!(ZoneVersionType::SOA_SERIAL.to_string(), "SOA-SERIAL");
    /// assert_eq!(ZoneVersionType::new(250).to_string(), "250");
    /// assert!(ZoneVersionType::new(250).is_private_use());
    /// ```
    pub struct ZoneVersionType(u8) in dnsbox::edns, generic "";
    /// The zone's SOA serial number (RFC 9660 §4).
    SOA_SERIAL = 0 => "SOA-SERIAL",
}

impl ZoneVersionType {
    /// Whether the value lies in the private-use range 246–254
    /// (RFC 9660 §6.2).
    #[inline]
    #[must_use]
    pub const fn is_private_use(self) -> bool {
        self.0 >= 246 && self.0 <= 254
    }
}

/// `ZONEVERSION` option: the version of the zone a response was generated
/// from (RFC 9660 §2.1).
///
/// Queries carry it empty ([`ZoneVersion::Request`]). A response carries
/// LABELCOUNT, TYPE and VERSION; a one-byte value, or an SOA-SERIAL
/// version that is not exactly 4 bytes (§4), fails with
/// [`Error::InvalidOption`].
///
/// ```
/// use dnsbox::edns::{Opt, ZoneVersion};
///
/// // Serial 2024010101 of a zone two labels up from the QNAME.
/// let serial = 2_024_010_101u32.to_be_bytes();
/// let zv = ZoneVersion::soa_serial(2, &serial);
/// assert_eq!(zv.serial(), Some(2_024_010_101));
/// assert_eq!(zv.to_string(), "ZONEVERSION=2,SOA-SERIAL,2024010101");
///
/// let opt = Opt::new(b"\x00\x13\x00\x00")?;
/// assert_eq!(opt.get::<ZoneVersion>().expect("present")?, ZoneVersion::Request);
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ZoneVersion<'a> {
    /// The empty option sent in queries.
    Request,
    /// The version data sent in responses.
    Version {
        /// Number of labels of the zone name, counted from the right of
        /// the QNAME, root excluded (§2.1).
        label_count: u8,
        /// Format and meaning of `version`.
        version_type: ZoneVersionType,
        /// Opaque version data.
        version: &'a [u8],
    },
}

impl<'a> ZoneVersion<'a> {
    /// A response option for an SOA serial number (RFC 9660 §4). The
    /// version bytes borrow from `serial`.
    #[inline]
    #[must_use]
    pub const fn soa_serial(label_count: u8, serial: &'a [u8; 4]) -> Self {
        ZoneVersion::Version {
            label_count,
            version_type: ZoneVersionType::SOA_SERIAL,
            version: serial,
        }
    }

    /// The SOA serial number, for an SOA-SERIAL response.
    pub fn serial(&self) -> Option<u32> {
        match *self {
            ZoneVersion::Version {
                version_type: ZoneVersionType::SOA_SERIAL,
                version,
                ..
            } => version.try_into().ok().map(u32::from_be_bytes),
            _ => None,
        }
    }
}

impl<'a> ParseOption<'a> for ZoneVersion<'a> {
    const CODE: OptionCode = OptionCode::ZONEVERSION;

    fn parse_option(data: &mut WireReader<'a>) -> Result<Self> {
        if data.is_empty() {
            return Ok(ZoneVersion::Request);
        }
        if data.remaining() < 2 {
            return Err(Error::InvalidOption);
        }
        let mut r = *data;
        let label_count = r.read_u8()?;
        let version_type = ZoneVersionType::new(r.read_u8()?);
        let version = r.read_rest();
        if version_type == ZoneVersionType::SOA_SERIAL && version.len() != 4 {
            return Err(Error::InvalidOption);
        }
        *data = r;
        Ok(ZoneVersion::Version {
            label_count,
            version_type,
            version,
        })
    }
}

impl ComposeOption for ZoneVersion<'_> {
    #[inline]
    fn code(&self) -> OptionCode {
        OptionCode::ZONEVERSION
    }

    fn compose_option<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        match *self {
            ZoneVersion::Request => Ok(()),
            ZoneVersion::Version {
                label_count,
                version_type,
                version,
            } => {
                c.put_u8(label_count)?;
                c.put_u8(version_type.get())?;
                c.put_bytes(version)
            }
        }
    }
}

impl fmt::Display for ZoneVersion<'_> {
    /// `ZONEVERSION` for a request; `ZONEVERSION=<labels>,<type>,<version>`
    /// otherwise, with the SOA serial in decimal (RFC 9660 §4.1) and other
    /// versions in hex.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ZONEVERSION")?;
        if let ZoneVersion::Version {
            label_count,
            version_type,
            version,
        } = *self
        {
            write!(f, "={label_count},{version_type},")?;
            match self.serial() {
                Some(serial) => write!(f, "{serial}")?,
                None => write!(f, "{}", Hex(version))?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edns::tests::{parse, round_trip};

    #[test]
    fn zone_version() {
        round_trip(OptionCode::ZONEVERSION, b"", "ZONEVERSION");
        // RFC 9660 §5 example: example.com serial 2023073001.
        round_trip(
            OptionCode::ZONEVERSION,
            b"\x02\x00\x78\x95\xa4\xe9",
            "ZONEVERSION=2,SOA-SERIAL,2023073001",
        );
        // a.ns.nic.cz for nic.cz (captured October 2026).
        round_trip(
            OptionCode::ZONEVERSION,
            b"\x02\x00\x6a\xc2\x07\xda",
            "ZONEVERSION=2,SOA-SERIAL,1791100890",
        );
        round_trip(
            OptionCode::ZONEVERSION,
            b"\x01\xf6\xde\xad\xbe\xef\x01",
            "ZONEVERSION=1,246,DEADBEEF01",
        );
        round_trip(OptionCode::ZONEVERSION, b"\x00\x07", "ZONEVERSION=0,7,");
        for bad in [&b"\x01"[..], b"\x01\x00\x00\x00\x00", b"\x01\x00\x00\x00\x00\x00\x00"] {
            assert_eq!(parse(OptionCode::ZONEVERSION, bad), Err(Error::InvalidOption));
        }
        let serial = 7u32.to_be_bytes();
        let z = ZoneVersion::soa_serial(1, &serial);
        assert_eq!(z.serial(), Some(7));
        assert_eq!(ZoneVersion::Request.serial(), None);
        assert!(ZoneVersionType::new(250).is_private_use());
        assert!(!ZoneVersionType::SOA_SERIAL.is_private_use());
    }
}
