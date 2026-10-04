//! TSIG record data (RFC 8945 §4.2) and the TSIG error registry.
//!
//! The signing and verification logic lives in [`crate::tsig`]; this module
//! is only the wire format.

use core::fmt;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::name::Name;
use crate::text::Base64;
use crate::util::base64;
use crate::wire::{Composer, NameEncoding, OutBuf, WireReader};
use crate::zone::{Scanner, Token};
use crate::{Error, Rcode, Result, Rtype};

open_enum! {
    /// A TSIG / TKEY error code: the 16-bit "Error" field of TSIG RDATA
    /// (RFC 8945 §4.2, §8), drawn from the IANA "DNS RCODEs" registry.
    ///
    /// Unlike the header [`Rcode`], value 16 is presented as `BADSIG` (its
    /// meaning in TSIG); `BADVERS` is accepted as an alias.
    pub struct TsigRcode(u16), generic "RCODE", aliases { "BADVERS" => BADSIG };
    /// No error (RFC 1035).
    NOERROR = 0 => "NOERROR",
    /// Format error (RFC 1035).
    FORMERR = 1 => "FORMERR",
    /// Server failure (RFC 1035).
    SERVFAIL = 2 => "SERVFAIL",
    /// Non-existent domain (RFC 1035).
    NXDOMAIN = 3 => "NXDOMAIN",
    /// Not implemented (RFC 1035).
    NOTIMP = 4 => "NOTIMP",
    /// Query refused (RFC 1035).
    REFUSED = 5 => "REFUSED",
    /// Name exists when it should not (RFC 2136).
    YXDOMAIN = 6 => "YXDOMAIN",
    /// RRset exists when it should not (RFC 2136).
    YXRRSET = 7 => "YXRRSET",
    /// RRset that should exist does not (RFC 2136).
    NXRRSET = 8 => "NXRRSET",
    /// Not authoritative / not authorized (RFC 2136, RFC 8945).
    NOTAUTH = 9 => "NOTAUTH",
    /// Name not contained in zone (RFC 2136).
    NOTZONE = 10 => "NOTZONE",
    /// DSO-TYPE not implemented (RFC 8490).
    DSOTYPENI = 11 => "DSOTYPENI",
    /// TSIG signature failure (RFC 8945). Also BADVERS (RFC 6891) in OPT.
    BADSIG = 16 => "BADSIG",
    /// Key not recognized (RFC 8945).
    BADKEY = 17 => "BADKEY",
    /// Signature out of time window (RFC 8945).
    BADTIME = 18 => "BADTIME",
    /// Bad TKEY mode (RFC 2930).
    BADMODE = 19 => "BADMODE",
    /// Duplicate key name (RFC 2930).
    BADNAME = 20 => "BADNAME",
    /// Algorithm not supported (RFC 2930).
    BADALG = 21 => "BADALG",
    /// Bad truncation (RFC 8945).
    BADTRUNC = 22 => "BADTRUNC",
    /// Bad or missing server cookie (RFC 7873).
    BADCOOKIE = 23 => "BADCOOKIE",
}

impl From<Rcode> for TsigRcode {
    #[inline]
    fn from(r: Rcode) -> Self {
        TsigRcode::new(r.get())
    }
}

impl From<TsigRcode> for Rcode {
    /// Keeps the low 12 bits (the extended RCODE range).
    #[inline]
    fn from(r: TsigRcode) -> Self {
        Rcode::new(r.get())
    }
}

/// The largest value of the 48-bit Time Signed field (RFC 8945 §4.2).
pub const MAX_TIME_SIGNED: u64 = (1 << 48) - 1;

/// `TSIG` record data: a transaction signature (RFC 8945 §4.2).
///
/// TSIG is a meta-RR: it is the last record of the additional section,
/// with CLASS ANY and TTL 0, and its owner name is the key name. Use
/// [`crate::tsig`] to sign and verify messages.
///
/// ```text
/// Algorithm Name | Time Signed (48) | Fudge | MAC Size | MAC |
/// Original ID | Error | Other Len | Other Data
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Tsig<'a> {
    /// The MAC algorithm, as a domain name (e.g. `hmac-sha256.`).
    pub algorithm: Name<'a>,
    /// Signing time, seconds since the UNIX epoch (48 bits).
    pub time_signed: u64,
    /// Permitted clock skew, in seconds.
    pub fudge: u16,
    /// The MAC (possibly truncated; empty in unsigned error responses).
    pub mac: &'a [u8],
    /// The message ID the MAC was computed with.
    pub original_id: u16,
    /// TSIG error code.
    pub error: TsigRcode,
    /// Other data: the server's 48-bit time in BADTIME responses.
    pub other: &'a [u8],
}

impl ParseRdataText for Tsig<'_> {
    /// `<algorithm> <time signed> <fudge> <MAC size> [<MAC>] <original ID>
    /// <error> <other len> [<other data>]`, the layout BIND and `dig`
    /// use (TSIG has no zone-file form; RFC 8945 §4.2 gives the fields).
    /// The MAC and other data are base64 of exactly the stated size,
    /// possibly split into several tokens, and absent when the size is 0;
    /// the error is a mnemonic (`BADTIME`), `RCODEnnn` or a number.
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        s.name_into(out, NameEncoding::Plain)?;
        out.put_u48(time_signed(s.word()?)?)?;
        out.put_u16(s.u16()?)?;
        sized_base64_into(s, out)?;
        out.put_u16(s.u16()?)?;
        let error = s.word()?;
        let error = if error.as_bytes().first().is_some_and(u8::is_ascii_digit) {
            error.u16()?
        } else {
            error.as_str()?.parse::<TsigRcode>()?.get()
        };
        out.put_u16(error)?;
        sized_base64_into(s, out)
    }
}

/// A 48-bit decimal number of seconds (the TSIG Time Signed field,
/// RFC 8945 §4.2).
fn time_signed(t: Token<'_>) -> Result<u64> {
    let digits = t.as_bytes();
    if digits.is_empty() || digits.len() > 15 || !digits.iter().all(u8::is_ascii_digit) {
        return Err(Error::InvalidText);
    }
    let v = digits
        .iter()
        .fold(0u64, |v, &d| v * 10 + u64::from(d - b'0'));
    if v > MAX_TIME_SIGNED {
        return Err(Error::InvalidText);
    }
    Ok(v)
}

/// Reads a 16-bit size and then base64 tokens decoding to exactly that
/// many octets (none for size 0), and writes the size and the octets (a
/// TSIG MAC or other data, RFC 8945 §4.2).
fn sized_base64_into<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
    let size = s.u16()?;
    out.put_u16(size)?;
    let size = usize::from(size);
    let mut d = base64::Decoder::default();
    let mut n = 0;
    while n < size || d.finish().is_err() {
        for &c in s.word()?.as_bytes() {
            let (bytes, len) = d.push(c)?;
            out.put_bytes(bytes.get(..len).unwrap_or(&[]))?;
            n += len;
        }
        if n > size {
            return Err(Error::InvalidText);
        }
    }
    Ok(())
}

impl<'a> ParseRdata<'a> for Tsig<'a> {
    const RTYPE: Rtype = Rtype::TSIG;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        // RFC 3597 §4 does not list TSIG: its algorithm name is never
        // compressed (and RFC 8945 §4.3.3 requires canonical form).
        let algorithm = rdata.read_name_uncompressed()?;
        let time_signed = rdata.read_u48()?;
        let fudge = rdata.read_u16()?;
        let mac_len = rdata.read_u16()?;
        let mac = rdata.read_bytes(mac_len as usize)?;
        let original_id = rdata.read_u16()?;
        let error = TsigRcode::new(rdata.read_u16()?);
        let other_len = rdata.read_u16()?;
        let other = rdata.read_bytes(other_len as usize)?;
        Ok(Tsig {
            algorithm,
            time_signed,
            fudge,
            mac,
            original_id,
            error,
            other,
        })
    }
}

impl ComposeRdata for Tsig<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::TSIG
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        if self.time_signed > MAX_TIME_SIGNED {
            return Err(Error::InvalidRdata);
        }
        let mac_len = u16::try_from(self.mac.len()).map_err(|_| Error::InvalidRdata)?;
        let other_len = u16::try_from(self.other.len()).map_err(|_| Error::InvalidRdata)?;
        c.put_name(self.algorithm, NameEncoding::Plain)?;
        c.put_u48(self.time_signed)?;
        c.put_u16(self.fudge)?;
        c.put_u16(mac_len)?;
        c.put_bytes(self.mac)?;
        c.put_u16(self.original_id)?;
        c.put_u16(self.error.get())?;
        c.put_u16(other_len)?;
        c.put_bytes(self.other)
    }
}

impl fmt::Display for Tsig<'_> {
    /// `algorithm time-signed fudge mac-size [mac] original-id error
    /// other-len [other]`, with the MAC and other data in base64 (the
    /// layout used by BIND and `dig`; TSIG has no zone-file form).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.algorithm,
            self.time_signed,
            self.fudge,
            self.mac.len()
        )?;
        if !self.mac.is_empty() {
            write!(f, " {}", Base64(self.mac))?;
        }
        write!(
            f,
            " {} {} {}",
            self.original_id,
            self.error,
            self.other.len()
        )?;
        if !self.other.is_empty() {
            write!(f, " {}", Base64(self.other))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Class;
    use crate::rdata::RData;
    use crate::rdata::tests::{compose, parse, round_trip, text_error, text_parse, text_round_trip};
    use std::string::ToString;

    // TSIG RDATA of a `dig -y hmac-sha256:tsig-key:...` query captured from
    // BIND 9.18 (tests/data/named/query-sha256.query.bin).
    const BIND_QUERY_TSIG: &str = "0b686d61632d7368613235360000006ac2152b012c0020\
        61c9b97683ff7290ebd4c9b2dd5b4d6cea8248388dce58c7e81c02dba2257244c9cc00000000";

    #[test]
    fn bind_capture() {
        let wire = crate::testutil::hex(BIND_QUERY_TSIG);
        round_trip(
            Rtype::TSIG,
            &wire,
            "hmac-sha256. 1791104299 300 32 Ycm5doP/cpDr1Mmy3VtNbOqCSDiNzljH6BwC26IlckQ= \
             51660 NOERROR 0",
        );
    }

    #[test]
    fn badtime_with_other_data() {
        // BADTIME response TSIG from BIND: MAC present, other = server time.
        let wire = crate::testutil::hex(
            "0b686d61632d7368613235360000006ac211f5012c0020\
             39365547cb1f4a70394cdc8766f80153c0173d4503d134926f8b9d1a746b348c\
             42420012000600006ac215dd",
        );
        let s = round_trip(Rtype::TSIG, &wire, "hmac-sha256. 1791103477 300 32 OTZVR8sfSnA5TNyHZvgBU8AXPUUD0TSSb4udGnRrNIw= 16962 BADTIME 6 AABqwhXd");
        assert!(s.contains("BADTIME"));
        let RData::Tsig(t) = parse(Rtype::TSIG, Class::ANY, &wire).unwrap() else {
            panic!("not TSIG");
        };
        assert_eq!(t.error, TsigRcode::BADTIME);
        assert_eq!(t.other, &[0, 0, 0x6a, 0xc2, 0x15, 0xdd]);
    }

    #[test]
    fn unsigned_error() {
        // BADKEY response: MAC size 0.
        let wire = crate::testutil::hex(
            "0b686d61632d7368613235360000006ac2152b012c0000a57600110000",
        );
        round_trip(
            Rtype::TSIG,
            &wire,
            "hmac-sha256. 1791104299 300 0 42358 BADKEY 0",
        );
    }

    #[test]
    fn text() {
        // The BIND captures above, in the form `dig` prints.
        let wire = crate::testutil::hex(BIND_QUERY_TSIG);
        let shown = "hmac-sha256. 1791104299 300 32 Ycm5doP/cpDr1Mmy3VtNbOqCSDiNzljH6BwC26IlckQ= \
                     51660 NOERROR 0";
        text_round_trip(Rtype::TSIG, shown, &wire, shown);
        // The MAC split into tokens, the error as a number, a relative
        // algorithm name (origin `example.`).
        let mut rel = wire.clone();
        rel.splice(12..13, *b"\x07example\x00");
        assert_eq!(
            text_parse(
                Rtype::TSIG,
                "hmac-sha256 1791104299 300 32 Ycm5doP/cpDr1Mmy3VtN bOqCSDiNzljH6BwC26IlckQ= \
                 51660 0 0"
            )
            .as_deref(),
            Ok(&rel[..])
        );
        let wire = crate::testutil::hex(
            "0b686d61632d7368613235360000006ac211f5012c0020\
             39365547cb1f4a70394cdc8766f80153c0173d4503d134926f8b9d1a746b348c\
             42420012000600006ac215dd",
        );
        let shown = "hmac-sha256. 1791103477 300 32 OTZVR8sfSnA5TNyHZvgBU8AXPUUD0TSSb4udGnRrNIw= \
                     16962 BADTIME 6 AABqwhXd";
        text_round_trip(Rtype::TSIG, shown, &wire, shown);
        assert_eq!(
            text_parse(Rtype::TSIG, &shown.replace("BADTIME", "18")).as_deref(),
            Ok(&wire[..])
        );
        assert_eq!(
            text_parse(Rtype::TSIG, &shown.replace("BADTIME", "rcode18")).as_deref(),
            Ok(&wire[..])
        );
        // The largest time, an unregistered error.
        let wire = crate::testutil::hex("00ffffffffffff0000000000000fa00000");
        text_round_trip(
            Rtype::TSIG,
            ". 281474976710655 0 0 0 4000 0",
            &wire,
            ". 281474976710655 0 0 0 RCODE4000 0",
        );
    }

    #[test]
    fn text_malformed() {
        let ok = "hmac-sha256. 1 300 2 AAA= 7 NOERROR 1 AA==";
        assert!(text_parse(Rtype::TSIG, ok).is_ok());
        for (from, to, err) in [
            (" 1 300", " 281474976710656 300", Error::InvalidText),
            (" 1 300", " 1000000000000000 300", Error::InvalidText),
            (" 1 300", " -1 300", Error::InvalidText),
            (" 300 ", " 65536 ", Error::InvalidText),
            // MAC size and data disagree.
            (" 2 AAA=", " 3 AAA=", Error::InvalidText),
            (" 2 AAA=", " 1 AAA=", Error::InvalidText),
            (" 2 AAA=", " 2 AAAA", Error::InvalidText),
            (" 2 AAA=", " 2 AA", Error::InvalidText),
            (" 2 AAA=", " 2 A*A=", Error::InvalidText),
            (" NOERROR", " NOSUCHERROR", Error::UnknownMnemonic),
            (" NOERROR", " 65536", Error::InvalidText),
            (" 1 AA==", " 2 AA==", Error::UnexpectedEof),
            (" 1 AA==", " 1 \"AA==\"", Error::InvalidText),
            (" 1 AA==", " 0 AA==", Error::InvalidText),
        ] {
            let bad = ok.replacen(from, to, 1);
            assert_eq!(text_error(Rtype::TSIG, &bad), err, "{bad}");
        }
        assert_eq!(text_error(Rtype::TSIG, "hmac-sha256. 1 300"), Error::UnexpectedEof);
    }

    #[test]
    fn malformed() {
        let wire = crate::testutil::hex(BIND_QUERY_TSIG);
        // MAC size larger than the RDATA.
        let mut bad = wire.clone();
        bad[21] = 0xff;
        assert_eq!(
            parse(Rtype::TSIG, Class::ANY, &bad),
            Err(Error::UnexpectedEof)
        );
        // Trailing byte.
        let mut long = wire.clone();
        long.push(0);
        assert_eq!(
            parse(Rtype::TSIG, Class::ANY, &long),
            Err(Error::TrailingData)
        );
        // Compressed algorithm name.
        assert_eq!(
            parse(Rtype::TSIG, Class::ANY, b"\xc0\x00"),
            Err(Error::UnexpectedPointer)
        );
        // Empty TSIG RDATA in class ANY is still parsed (TSIG is a meta type).
        assert_eq!(
            parse(Rtype::TSIG, Class::ANY, b""),
            Err(Error::UnexpectedEof)
        );
    }

    #[test]
    fn compose_limits() {
        let mac = [0u8; 70000];
        let t = Tsig {
            algorithm: Name::ROOT,
            time_signed: 0,
            fudge: 0,
            mac: &mac,
            original_id: 0,
            error: TsigRcode::NOERROR,
            other: &[],
        };
        let mut out = std::vec![0u8; 80000];
        let mut w = crate::WireWriter::new(&mut out);
        assert_eq!(t.compose_rdata(&mut w), Err(Error::InvalidRdata));
        let t = Tsig {
            mac: &[],
            time_signed: MAX_TIME_SIGNED + 1,
            ..t
        };
        assert_eq!(t.compose_rdata(&mut w), Err(Error::InvalidRdata));
        let t = Tsig {
            time_signed: MAX_TIME_SIGNED,
            ..t
        };
        assert_eq!(compose(&t).len(), 1 + 6 + 2 + 2 + 2 + 2 + 2);
    }

    #[test]
    fn rcodes() {
        assert_eq!(TsigRcode::new(16).to_string(), "BADSIG");
        assert_eq!("badvers".parse(), Ok(TsigRcode::BADSIG));
        assert_eq!(TsigRcode::new(4000).to_string(), "RCODE4000");
        assert_eq!(Rcode::from(TsigRcode::BADKEY).get(), 17);
        assert_eq!(TsigRcode::from(Rcode::NOTAUTH), TsigRcode::NOTAUTH);
    }
}
