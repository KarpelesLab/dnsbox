//! DSYNC record data (RFC 9859 §2): where a child zone's operator sends
//! generalized notifications (CDS/CDNSKEY or CSYNC changes) to its parent.

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Result, Rtype};

// IANA "DSYNC: Location of Synchronization Endpoints"
// (https://www.iana.org/assignments/dns-parameters), as of 2026-10.
// Scheme 0 is the null scheme (no mnemonic), 128-255 are private use.
open_enum! {
    /// A DSYNC notification scheme (RFC 9859 §2.1, §6.2, IANA "DSYNC:
    /// Location of Synchronization Endpoints"): how the target is
    /// contacted. Presented by its mnemonic if assigned, otherwise as a
    /// decimal number (§2.2).
    ///
    /// ```
    /// use dnsbox::rdata::DsyncScheme;
    ///
    /// assert_eq!(DsyncScheme::NOTIFY.get(), 1);
    /// assert_eq!(DsyncScheme::NOTIFY.to_string(), "NOTIFY");
    /// assert_eq!(DsyncScheme::new(200).to_string(), "200");
    /// assert_eq!("notify".parse::<DsyncScheme>()?, DsyncScheme::NOTIFY);
    /// assert_eq!("3".parse::<DsyncScheme>()?, DsyncScheme::new(3));
    /// assert!(DsyncScheme::new(0).is_null());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub struct DsyncScheme(u8) in dnsbox::rdata, generic "";
    /// A DNS NOTIFY message to the target, over conventional DNS
    /// transport (RFC 9859 §2.3, §4).
    NOTIFY = 1 => "NOTIFY",
}

impl DsyncScheme {
    /// The null scheme (0): consumers ignore records with it (RFC 9859
    /// §2.1).
    pub const NULL: DsyncScheme = DsyncScheme::new(0);

    /// Whether this is the null scheme, which consumers ignore (RFC 9859
    /// §2.1).
    #[inline]
    #[must_use]
    pub const fn is_null(self) -> bool {
        self.get() == 0
    }

    /// Whether the value is in the private-use range 128–255 (RFC 9859
    /// §6.2).
    #[inline]
    #[must_use]
    pub const fn is_private_use(self) -> bool {
        self.get() >= 128
    }
}

/// `DSYNC` record data: a notification endpoint for delegation maintenance
/// (RFC 9859 §2).
///
/// A parent publishes DSYNC records under `_dsync` (§3); a child's
/// operator looks them up (§4.1) and sends a NOTIFY for the record type
/// that changed to `target`, port `port` (§4.2). Records whose scheme is
/// the null scheme or whose port is 0 are ignored by consumers (§2.1).
///
/// ```
/// use dnsbox::rdata::{Dsync, DsyncScheme, ParseRdataText};
/// use dnsbox::Rtype;
///
/// // RFC 9859 §2.3.
/// let mut buf = [0u8; 64];
/// let dsync = Dsync::from_text("CDS NOTIFY 5359 cds-scanner.example.net.", &mut buf)?;
/// assert_eq!(dsync.rrtype, Rtype::CDS);
/// assert_eq!(dsync.scheme, DsyncScheme::NOTIFY);
/// assert_eq!(dsync.port, 5359);
/// assert_eq!(dsync.target.to_string(), "cds-scanner.example.net.");
/// assert!(dsync.is_usable());
/// assert_eq!(dsync.to_string(), "CDS NOTIFY 5359 cds-scanner.example.net.");
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Dsync<'a> {
    /// The type of generalized notification this endpoint is for (CDS for
    /// CDS/CDNSKEY changes, CSYNC).
    pub rrtype: Rtype,
    /// How to contact the target.
    pub scheme: DsyncScheme,
    /// The transport port on the target.
    pub port: u16,
    /// The host receiving the notifications (uncompressed on the wire).
    pub target: Name<'a>,
}

impl Dsync<'_> {
    /// Whether consumers may use this record: neither the null scheme nor
    /// port 0, which RFC 9859 §2.1 says are ignored.
    #[inline]
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        !self.scheme.is_null() && self.port != 0
    }
}

impl ParseRdataText for Dsync<'_> {
    /// `RRtype Scheme Port Target` (RFC 9859 §2.2): the RRtype as a
    /// mnemonic or `TYPEnnn` (a bare number is accepted too, as BIND
    /// does), the scheme as a mnemonic or a decimal number, the port in
    /// decimal and the target as a domain name.
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        let rrtype = s.word()?;
        let rrtype = if rrtype.as_bytes().first().is_some_and(u8::is_ascii_digit) {
            rrtype.u16()?
        } else {
            rrtype.as_str()?.parse::<Rtype>()?.get()
        };
        out.put_u16(rrtype)?;
        out.put_u8(s.parse::<DsyncScheme>()?.get())?;
        out.put_u16(s.u16()?)?;
        s.name_into(out, NameEncoding::Plain)
    }
}

impl<'a> ParseRdata<'a> for Dsync<'a> {
    const RTYPE: Rtype = Rtype::DSYNC;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        let mut r = *rdata;
        let rrtype = Rtype::new(r.read_u16()?);
        let scheme = DsyncScheme::new(r.read_u8()?);
        let port = r.read_u16()?;
        // "The fully-qualified, uncompressed domain name" (§2.1).
        let target = r.read_name_uncompressed()?;
        *rdata = r;
        Ok(Dsync {
            rrtype,
            scheme,
            port,
            target,
        })
    }
}

impl ComposeRdata for Dsync<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::DSYNC
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_u16(self.rrtype.get())?;
        c.put_u8(self.scheme.get())?;
        c.put_u16(self.port)?;
        // Never compressed, and not in the RFC 4034 §6.2 lowercasing list.
        c.put_name(self.target, NameEncoding::Plain)
    }
}

impl fmt::Display for Dsync<'_> {
    /// `RRtype Scheme Port Target` (RFC 9859 §2.2).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.rrtype, self.scheme, self.port, self.target
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{Dsync, DsyncScheme};
    use crate::name::NameBuf;
    use crate::rdata::RData;
    use crate::rdata::tests::{compose, parse, round_trip, text_error, text_parse, text_round_trip};
    use crate::testutil::hex;
    use crate::{Class, Error, Rtype};

    #[test]
    fn rfc9859_examples() {
        // RFC 9859 §2.3; wire as dnspython 2.8 writes it
        // (tests/corpus/dnspython/rdata.txt).
        let cds = hex("003b0114ef0b6364732d7363616e6e6572076578616d706c65036e657400");
        text_round_trip(
            Rtype::DSYNC,
            "CDS NOTIFY 5359 cds-scanner.example.net.",
            &cds,
            "CDS NOTIFY 5359 cds-scanner.example.net.",
        );
        assert_eq!(
            text_parse(Rtype::DSYNC, "CDS 1 5359 cds-scanner.example.net.").as_deref(),
            Ok(&cds[..])
        );
        text_round_trip(
            Rtype::DSYNC,
            "CSYNC NOTIFY 5360 csync-scanner.example.net.",
            b"\x00\x3e\x01\x14\xf0\x0dcsync-scanner\x07example\x03net\x00",
            "CSYNC NOTIFY 5360 csync-scanner.example.net.",
        );
        // §3.2, relative to the origin `example.`.
        text_round_trip(
            Rtype::DSYNC,
            "CDS NOTIFY 5300 rr-endpoint",
            b"\x00\x3b\x01\x14\xb4\x0brr-endpoint\x07example\x00",
            "CDS NOTIFY 5300 rr-endpoint.example.",
        );
    }

    #[test]
    fn fields() {
        let target: NameBuf = "cds-scanner.example.net".parse().unwrap();
        let d = Dsync {
            rrtype: Rtype::CDS,
            scheme: DsyncScheme::NOTIFY,
            port: 5359,
            target: target.as_name(),
        };
        let wire = compose(&d);
        assert_eq!(
            parse(Rtype::DSYNC, Class::IN, &wire),
            Ok(RData::Dsync(d))
        );
        assert!(d.is_usable());
        assert!(!Dsync { port: 0, ..d }.is_usable());
        assert!(!Dsync { scheme: DsyncScheme::NULL, ..d }.is_usable());
        assert!(DsyncScheme::new(128).is_private_use() && !DsyncScheme::NOTIFY.is_private_use());
        // Unknown types and schemes display numerically.
        round_trip(Rtype::DSYNC, b"\x03\xe8\x03\x00\x00\x00", "TYPE1000 3 0 .");
        round_trip(Rtype::DSYNC, b"\xfa\x00\xff\xff\xff\x00", "TYPE64000 255 65535 .");
        round_trip(Rtype::DSYNC, b"\x00\x00\x00\x00\x00\x00", "TYPE0 0 0 .");
    }

    #[test]
    fn malformed() {
        for (wire, err) in [
            (&b""[..], Error::UnexpectedEof),
            (b"\x00\x3b\x01\x14", Error::UnexpectedEof),
            (b"\x00\x3b\x01\x14\xef", Error::UnexpectedEof),
            (b"\x00\x3b\x01\x14\xef\x01a", Error::UnexpectedEof),
            (b"\x00\x3b\x01\x14\xef\x00\x00", Error::TrailingData),
            // "uncompressed" (§2.1).
            (b"\x00\x3b\x01\x14\xef\xc0\x00", Error::UnexpectedPointer),
        ] {
            assert_eq!(parse(Rtype::DSYNC, Class::IN, wire), Err(err), "{wire:02x?}");
        }
    }

    #[test]
    fn text() {
        // BIND's text tests (lib/dns/tests/rdata_test.c).
        text_round_trip(
            Rtype::DSYNC,
            "CDS NOTIFY 0 example.com.",
            b"\x00\x3b\x01\x00\x00\x07example\x03com\x00",
            "CDS NOTIFY 0 example.com.",
        );
        text_round_trip(
            Rtype::DSYNC,
            "cds 3 0 example.com.",
            b"\x00\x3b\x03\x00\x00\x07example\x03com\x00",
            "CDS 3 0 example.com.",
        );
        text_round_trip(
            Rtype::DSYNC,
            "TYPE1000 notify 0 example.com.",
            b"\x03\xe8\x01\x00\x00\x07example\x03com\x00",
            "TYPE1000 NOTIFY 0 example.com.",
        );
        text_round_trip(
            Rtype::DSYNC,
            "TYPE64000 255 65535 example.com.",
            b"\xfa\x00\xff\xff\xff\x07example\x03com\x00",
            "TYPE64000 255 65535 example.com.",
        );
        // A bare type number (BIND), parentheses.
        text_round_trip(
            Rtype::DSYNC,
            "( 62 1\n 53 @ )",
            b"\x00\x3e\x01\x00\x35\x07example\x00",
            "CSYNC NOTIFY 53 example.",
        );
        for (text, err) in [
            ("", Error::UnexpectedEof),
            ("CDS", Error::UnexpectedEof),
            ("CDS NOTIFY", Error::UnexpectedEof),
            ("CDS NOTIFY 53", Error::UnexpectedEof),
            ("INVALID 255 65535 example.com.", Error::UnknownMnemonic),
            ("TYPE1000 256 65535 example.com.", Error::InvalidText),
            ("TYPE1000 3 65536 example.com.", Error::InvalidText),
            ("TYPE1000 UNKNOWN 65535 example.com.", Error::InvalidText),
            ("65536 1 53 example.com.", Error::InvalidText),
            ("TYPE65536 1 53 example.com.", Error::InvalidText),
            ("\"CDS\" 1 53 example.com.", Error::InvalidText),
            ("CDS 1 53 example.com. extra", Error::InvalidText),
        ] {
            assert_eq!(text_error(Rtype::DSYNC, text), err, "{text:?}");
        }
    }
}
