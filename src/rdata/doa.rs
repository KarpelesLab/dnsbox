//! DOA record data: Digital Object Architecture objects
//! (draft-durand-doa-over-dns-03 §3; IANA "Resource Record (RR) TYPEs").

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::charstr::CharStr;
use crate::text::{Base64, fmt_quoted};
use crate::wire::{Composer, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Error, Result, Rtype};

/// `DOA` record data: a Digital Object Architecture object, or a reference
/// to one (draft-durand-doa-over-dns-03 §3.1).
///
/// The format is the one IANA's registration points to, as BIND
/// implements it.
///
/// ```
/// use dnsbox::rdata::{Doa, ParseRdataText};
///
/// let mut buf = [0u8; 64];
/// let doa = Doa::from_text(r#"0 1 2 "" aHR0cHM6Ly93d3cuaXNjLm9yZy8="#, &mut buf)?;
/// assert_eq!((doa.enterprise, doa.doa_type, doa.location), (0, 1, Doa::LOCATION_URI));
/// assert!(doa.media_type.as_bytes().is_empty());
/// assert_eq!(doa.data, b"https://www.isc.org/");
/// assert_eq!(doa.to_string(), r#"0 1 2 "" aHR0cHM6Ly93d3cuaXNjLm9yZy8="#);
///
/// // Empty data is written `-`.
/// let mut buf = [0u8; 64];
/// let doa = Doa::from_text(r#"0 0 1 "text/plain" -"#, &mut buf)?;
/// assert!(doa.data.is_empty());
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Doa<'a> {
    /// DOA-ENTERPRISE: an IANA Private Enterprise Number qualifying
    /// [`doa_type`](Self::doa_type), or 0 for none (§3.1.1).
    pub enterprise: u32,
    /// DOA-TYPE: the semantic type of the object (§3.1.1).
    pub doa_type: u32,
    /// DOA-LOCATION: how to interpret [`data`](Self::data) (§3.1.2;
    /// [`Doa::LOCATION_LOCAL`], [`Doa::LOCATION_URI`],
    /// [`Doa::LOCATION_HDL`]). Unknown values must be kept and the data
    /// treated as opaque.
    pub location: u8,
    /// DOA-MEDIA-TYPE: the Internet media type of the object, possibly
    /// empty (§3.1.3).
    pub media_type: CharStr<'a>,
    /// DOA-DATA: the object, or where to get it (§3.1.4); the rest of the
    /// RDATA.
    pub data: &'a [u8],
}

impl Doa<'_> {
    /// DOA-LOCATION 1: the data is the object itself (§3.1.2).
    pub const LOCATION_LOCAL: u8 = 1;
    /// DOA-LOCATION 2: the data is a UTF-8 URI of the object (§3.1.2).
    pub const LOCATION_URI: u8 = 2;
    /// DOA-LOCATION 3: the data is a UTF-8 Handle System handle of the
    /// object (§3.1.2, RFC 3650).
    pub const LOCATION_HDL: u8 = 3;
}

impl ParseRdataText for Doa<'_> {
    /// `<enterprise> <type> <location> <media-type> <data>`
    /// (draft-durand-doa-over-dns-03 §3.3): decimal numbers, the media
    /// type as one `<character-string>` (quoted or not), and the data in
    /// base64, possibly split by blanks, or `-` when empty.
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        out.put_u32(s.u32()?)?;
        out.put_u32(s.u32()?)?;
        out.put_u8(s.u8()?)?;
        s.char_string_into(out)?;
        match s.peek()? {
            None => Err(Error::UnexpectedEof),
            Some(t) if t.is("-") => s.next_token().map(drop),
            Some(_) => s.base64_rest_into(out).map(drop),
        }
    }
}

impl<'a> ParseRdata<'a> for Doa<'a> {
    const RTYPE: Rtype = Rtype::DOA;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        let mut r = *rdata;
        let enterprise = r.read_u32()?;
        let doa_type = r.read_u32()?;
        let location = r.read_u8()?;
        let media_type = r.read_char_string()?;
        let data = r.read_rest();
        *rdata = r;
        Ok(Doa {
            enterprise,
            doa_type,
            location,
            media_type,
            data,
        })
    }
}

impl ComposeRdata for Doa<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::DOA
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_u32(self.enterprise)?;
        c.put_u32(self.doa_type)?;
        c.put_u8(self.location)?;
        c.put_char_string(self.media_type.as_bytes())?;
        c.put_bytes(self.data)
    }
}

impl fmt::Display for Doa<'_> {
    /// `enterprise type location "media-type" data`
    /// (draft-durand-doa-over-dns-03 §3.3), the data in base64 or `-` when
    /// empty.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {} ", self.enterprise, self.doa_type, self.location)?;
        fmt_quoted(f, self.media_type.as_bytes())?;
        if self.data.is_empty() {
            f.write_str(" -")
        } else {
            write!(f, " {}", Base64(self.data))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Doa;
    use crate::charstr::CharStr;
    use crate::rdata::RData;
    use crate::rdata::tests::{compose, parse, round_trip, text_error, text_parse, text_round_trip};
    use crate::{Class, Error, Rtype};
    use std::vec::Vec;

    // A 40x25 GIF, the "DOA-DATA over 255 octets" example of BIND's
    // lib/dns/tests/rdata_test.c.
    const GIF: &str = "R0lGODlhKAAZAOMCAGZmZgBmmf///zOZzMz//5nM/zNmmWbM\
        /5nMzMzMzACZ/////////////////////yH5BAEKAA8ALAAA\
        AAAoABkAAATH8IFJK5U2a4337F5ogRkpnoCJrly7PrCKyh8c\
        3HgAhzT35MDbbtO7/IJIHbGiOiaTxVTpSVWWLqNq1UVyapNS\
        1wd3OAxug0LhnCubcVhsxysQnOt4ATpvvzHlFzl1AwODhWeF\
        AgRpen5/UhheAYMFdUB4SFcpGEGGdQeCAqBBLTuSk30EeXd9\
        pEsAbKGxjHqDSE0Sp6ixN4N1BJmbc7lIhmsBich1awPAjkY1\
        SZR8bJWrz382SGqIBQQFQd4IsUTaX+ceuudPEQA7";

    fn wire(head: &[u8], media: &[u8], data: &[u8]) -> Vec<u8> {
        let mut w = head.to_vec();
        w.push(media.len() as u8);
        w.extend_from_slice(media);
        w.extend_from_slice(data);
        w
    }

    #[test]
    fn bind_vectors() {
        // BIND's text tests (lib/dns/tests/rdata_test.c).
        let head = [0, 0, 0, 0, 0, 0, 0, 0, 1];
        text_round_trip(
            Rtype::DOA,
            r#"0 0 1 "text/plain" Zm9v"#,
            &wire(&head, b"text/plain", b"foo"),
            r#"0 0 1 "text/plain" Zm9v"#,
        );
        text_round_trip(
            Rtype::DOA,
            r#"0 0 1 "text/plain" Zm 9v"#,
            &wire(&head, b"text/plain", b"foo"),
            r#"0 0 1 "text/plain" Zm9v"#,
        );
        text_round_trip(
            Rtype::DOA,
            "0 0 1 text/plain Zm9v",
            &wire(&head, b"text/plain", b"foo"),
            r#"0 0 1 "text/plain" Zm9v"#,
        );
        text_round_trip(
            Rtype::DOA,
            r#"0 0 1 "text/plain" -"#,
            &wire(&head, b"text/plain", b""),
            r#"0 0 1 "text/plain" -"#,
        );
        text_round_trip(
            Rtype::DOA,
            r#"0 0 100 "text/plain" Zm9v"#,
            &wire(&[0, 0, 0, 0, 0, 0, 0, 0, 100], b"text/plain", b"foo"),
            r#"0 0 100 "text/plain" Zm9v"#,
        );
        text_round_trip(
            Rtype::DOA,
            r#"0 0 1 "" -"#,
            &wire(&head, b"", b""),
            r#"0 0 1 "" -"#,
        );
        text_round_trip(
            Rtype::DOA,
            r#"0 0 1 "plain text" Zm9v"#,
            &wire(&head, b"plain text", b"foo"),
            r#"0 0 1 "plain text" Zm9v"#,
        );
        let gif = crate::util::base64::decode(GIF.as_bytes(), &mut [0u8; 512][..]).unwrap();
        assert!(gif > 255);
        let text = std::format!(r#"1234567890 1234567890 1 "image/gif" {GIF}"#);
        let w = text_parse(Rtype::DOA, &text).unwrap();
        assert_eq!(&w[..9], &[0x49, 0x96, 0x02, 0xd2, 0x49, 0x96, 0x02, 0xd2, 1]);
        assert_eq!(w.len(), 9 + 10 + gif);
        text_round_trip(Rtype::DOA, &text, &w, &text);
    }

    #[test]
    fn wire_forms() {
        // BIND's wire tests.
        let head = [0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x01];
        round_trip(Rtype::DOA, &wire(&head, b"", b""), r#"305419896 305419896 1 "" -"#);
        round_trip(Rtype::DOA, &wire(&head, b"foo", b""), r#"305419896 305419896 1 "foo" -"#);
        let w = wire(&head, b"foo", b"bar");
        round_trip(Rtype::DOA, &w, r#"305419896 305419896 1 "foo" YmFy"#);
        let RData::Doa(d) = parse(Rtype::DOA, Class::IN, &w).unwrap() else {
            panic!("not DOA")
        };
        assert_eq!(
            d,
            Doa {
                enterprise: 0x1234_5678,
                doa_type: 0x1234_5678,
                location: Doa::LOCATION_LOCAL,
                media_type: CharStr::new(b"foo").unwrap(),
                data: b"bar",
            }
        );
        assert_eq!(compose(&d), w);
        for (bad, err) in [
            (&head[..], Error::UnexpectedEof),
            (&[0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x01, 0xff][..], Error::UnexpectedEof),
            (&[0; 8][..], Error::UnexpectedEof),
        ] {
            assert_eq!(parse(Rtype::DOA, Class::IN, bad), Err(err), "{bad:02x?}");
        }
    }

    #[test]
    fn text_malformed() {
        for (text, err) in [
            (r#"0 0 1 "text/plain" "Zm9v""#, Error::InvalidText),
            (r#"0 0 1 "text/plain" "-""#, Error::InvalidText),
            (r#"0 0 1 "text/plain""#, Error::UnexpectedEof),
            (r#"0 0 256 "text/plain" ZM9v"#, Error::InvalidText),
            ("1234567890 1234567890 1", Error::UnexpectedEof),
            (r#"1234567890 1234567890 1 "image/gif" R0lGODl"#, Error::InvalidText),
            (r#"4294967296 0 1 "" -"#, Error::InvalidText),
            (r#"0 0 1 "" - Zm9v"#, Error::InvalidText),
            (r#"0 0 1 "" Zm9v -"#, Error::InvalidText),
        ] {
            assert_eq!(text_error(Rtype::DOA, text), err, "{text:?}");
        }
        let long = std::format!("0 0 1 {} -", "x".repeat(256));
        assert_eq!(text_error(Rtype::DOA, &long), Error::CharStringTooLong);
    }
}
