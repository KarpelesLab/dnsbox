//! TKEY record data (RFC 2930 §2) and the TKEY mode registry.
//!
//! The message shapes of a key exchange (TKEY queries and responses) are
//! in [`crate::tkey`]; this module is only the wire format.

use core::fmt;

use super::tsig::{sized_base64_into, tsig_error_code};
use super::{ComposeRdata, ParseRdata, ParseRdataText, TsigRcode};
use crate::name::Name;
use crate::text::Base64;
use crate::wire::{Composer, NameEncoding, OutBuf, WireReader};
use crate::zone::Scanner;
use crate::{Error, Result, Rtype};

// RFC 2930 §2.5 (IANA "TKEY Modes", same values). The registry has no
// mnemonics; the ones below are descriptive only, and the presentation
// format uses the number.
open_enum! {
    /// A TKEY mode (RFC 2930 §2.5): the key agreement scheme or purpose of
    /// a TKEY message. Values 0 and 65535 are reserved.
    ///
    /// ```
    /// use dnsbox::rdata::TkeyMode;
    ///
    /// assert_eq!(TkeyMode::GSSAPI.get(), 3);
    /// assert_eq!(TkeyMode::KEY_DELETION.to_string(), "KEY-DELETION");
    /// assert_eq!("gss-api".parse::<TkeyMode>()?, TkeyMode::GSSAPI);
    /// assert_eq!("2".parse::<TkeyMode>()?, TkeyMode::DIFFIE_HELLMAN);
    /// assert_eq!(TkeyMode::new(7).to_string(), "7");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub struct TkeyMode(u16) in dnsbox::rdata, generic "";
    /// Server assignment: the server sends keying material encrypted
    /// under the resolver's KEY (RFC 2930 §4.4).
    SERVER_ASSIGNMENT = 1 => "SERVER-ASSIGNMENT",
    /// Diffie-Hellman exchange (RFC 2930 §4.1).
    DIFFIE_HELLMAN = 2 => "DIFFIE-HELLMAN",
    /// GSS-API negotiation (RFC 2930 §4.3, RFC 3645).
    GSSAPI = 3 => "GSS-API",
    /// Resolver assignment: the resolver sends keying material encrypted
    /// under the server's KEY (RFC 2930 §4.5).
    RESOLVER_ASSIGNMENT = 4 => "RESOLVER-ASSIGNMENT",
    /// Key deletion (RFC 2930 §4.2).
    KEY_DELETION = 5 => "KEY-DELETION",
}

/// `TKEY` record data: a transaction key establishment message (RFC 2930
/// §2).
///
/// TKEY is a meta-RR: its owner name is the key name, its CLASS should be
/// ANY and its TTL zero (§2, §2.2); it travels in the additional section
/// of a query and the answer section of the response (§4). See
/// [`crate::tkey`] for building and reading those messages.
///
/// ```text
/// Algorithm | Inception | Expiration | Mode | Error |
/// Key Size | Key Data | Other Size | Other Data
/// ```
///
/// TKEY has no zone-file form. Its text is BIND's, with the sizes written
/// before the base64 data (which is absent when the size is 0); dnspython's
/// form, without the sizes, is read too:
///
/// ```
/// use dnsbox::rdata::{ParseRdataText, Tkey, TkeyMode, TsigRcode};
///
/// let mut buf = [0u8; 64];
/// let tkey = Tkey::from_text("gss-tsig. 1700000000 1700003600 3 NOERROR 3 AAEC 0", &mut buf)?;
/// assert_eq!(tkey.algorithm.to_string(), "gss-tsig.");
/// assert_eq!((tkey.inception, tkey.expiration), (1_700_000_000, 1_700_003_600));
/// assert_eq!(tkey.mode, TkeyMode::GSSAPI);
/// assert_eq!(tkey.error, TsigRcode::NOERROR);
/// assert_eq!(tkey.key, [0, 1, 2]);
/// assert!(tkey.other.is_empty());
/// assert!(tkey.is_valid_at(1_700_000_100));
/// assert_eq!(tkey.to_string(), "gss-tsig. 1700000000 1700003600 3 NOERROR 3 AAEC 0");
///
/// // dnspython writes the same record without the sizes.
/// let mut buf2 = [0u8; 64];
/// assert_eq!(Tkey::from_text("gss-tsig. 1700000000 1700003600 3 0 AAEC", &mut buf2)?, tkey);
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Tkey<'a> {
    /// The algorithm the agreed key is for, as a domain name with the
    /// meaning of the TSIG algorithm field (e.g. `gss-tsig.`,
    /// `hmac-sha256.`; §2.3).
    pub algorithm: Name<'a>,
    /// Start of the key's validity, seconds since the UNIX epoch modulo
    /// 2³² (RFC 1982 serial arithmetic, §2.4).
    pub inception: u32,
    /// End of the key's validity, as [`inception`](Self::inception).
    pub expiration: u32,
    /// The key agreement scheme or purpose of the message (§2.5).
    pub mode: TkeyMode,
    /// The error code: an extended RCODE (§2.6), from the TSIG error
    /// registry (BADMODE, BADNAME, BADALG, ...).
    pub error: TsigRcode,
    /// The key exchange data; its meaning depends on the mode (§2.7).
    pub key: &'a [u8],
    /// Other data, undefined by RFC 2930 (§2.8).
    pub other: &'a [u8],
}

impl<'a> Tkey<'a> {
    /// TKEY data with the given algorithm, validity, mode and key exchange
    /// data, no error and no other data.
    ///
    /// ```
    /// use dnsbox::NameBuf;
    /// use dnsbox::rdata::{Tkey, TkeyMode, TsigRcode};
    ///
    /// let alg: NameBuf = "gss-tsig".parse()?;
    /// let token = [0x60, 0x82]; // a GSS-API token
    /// let tkey = Tkey::new(alg.as_name(), 1_700_000_000, 1_700_086_400, TkeyMode::GSSAPI, &token);
    /// assert_eq!(tkey.error, TsigRcode::NOERROR);
    /// assert_eq!(tkey.to_string(), "gss-tsig. 1700000000 1700086400 3 NOERROR 2 YII= 0");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub const fn new(
        algorithm: Name<'a>,
        inception: u32,
        expiration: u32,
        mode: TkeyMode,
        key: &'a [u8],
    ) -> Self {
        Tkey {
            algorithm,
            inception,
            expiration,
            mode,
            error: TsigRcode::NOERROR,
            key,
            other: &[],
        }
    }

    /// The same data with `error` and no key or other data: the TKEY of an
    /// error response (§2.6, §4).
    ///
    /// ```
    /// use dnsbox::NameBuf;
    /// use dnsbox::rdata::{Tkey, TkeyMode, TsigRcode};
    ///
    /// let alg: NameBuf = "hmac-sha256".parse()?;
    /// let query = Tkey::new(alg.as_name(), 0, 3600, TkeyMode::new(9), &[1, 2, 3]);
    /// let refusal = query.with_error(TsigRcode::BADMODE);
    /// assert_eq!(refusal.to_string(), "hmac-sha256. 0 3600 9 BADMODE 0 0");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub const fn with_error(self, error: TsigRcode) -> Self {
        Tkey {
            error,
            key: &[],
            other: &[],
            ..self
        }
    }

    /// Whether `now` (seconds since the UNIX epoch, modulo 2³²) lies within
    /// `[inception, expiration]` in RFC 1982 serial arithmetic (§2.4).
    /// GSS-API mode ignores these times (§4.3); the caller decides whether
    /// they matter.
    #[must_use]
    pub const fn is_valid_at(&self, now: u32) -> bool {
        crate::dnssec::check_validity(self.inception, self.expiration, now).is_ok()
    }
}

impl ParseRdataText for Tkey<'_> {
    /// `<algorithm> <inception> <expiration> <mode> <error>` followed by
    /// the key and other data in either of the two forms in use (TKEY has
    /// no zone-file form; RFC 2930 §2 gives the fields):
    ///
    /// - BIND's (what `Display` writes): `<key size> [<key data>] <other
    ///   size> [<other data>]`, the data base64 of exactly the stated
    ///   size, possibly split into several tokens, and absent when the
    ///   size is 0;
    /// - dnspython's: `[<key data> [<other data>]]`, the key one base64
    ///   token, the other data base64 over the remaining tokens.
    ///
    /// The times are decimal seconds (or `YYYYMMDDHHmmSS`), the mode a
    /// number or a [`TkeyMode`] mnemonic, the error a mnemonic
    /// (`BADMODE`), `RCODEnnn` or a number. Text that reads both ways
    /// (possible only when the base64 tokens are all digits, as in
    /// `0000 0000`) is read as BIND's form.
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        s.name_into(out, NameEncoding::Plain)?;
        out.put_u32(s.timestamp()?)?;
        out.put_u32(s.timestamp()?)?;
        out.put_u16(s.parse::<TkeyMode>()?.get())?;
        out.put_u16(tsig_error_code(s)?)?;
        let (start, saved) = (out.as_bytes().len(), s.clone());
        let bind = sized_base64_into(s, out)
            .and_then(|()| sized_base64_into(s, out))
            .and_then(|()| match s.is_at_end()? {
                true => Ok(()),
                false => Err(Error::InvalidText),
            });
        let Err(bind_error) = bind else {
            return Ok(());
        };
        // BIND's form starts with a decimal size; report its error when
        // the text looks like it and does not read as dnspython's either.
        let sized = saved
            .clone()
            .next_token()
            .ok()
            .flatten()
            .is_some_and(|t| !t.is_quoted() && t.as_bytes().iter().all(u8::is_ascii_digit));
        *s = saved;
        out.truncate(start);
        unsized_base64_into(s, out).map_err(|e| if sized { bind_error } else { e })
    }
}

/// dnspython's key and other data: one base64 token, then base64 over
/// the remaining tokens, each written after its 16-bit size; nothing at
/// all for empty key and other data.
fn unsized_base64_into<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
    for rest in [false, true] {
        let at = out.as_bytes().len();
        out.put_u16(0)?;
        let n = if rest {
            s.base64_rest_into(out)?
        } else if s.is_at_end()? {
            0
        } else {
            s.base64_into(out)?
        };
        let n = u16::try_from(n).map_err(|_| Error::InvalidText)?;
        out.patch(at, &n.to_be_bytes())?;
    }
    Ok(())
}

impl<'a> ParseRdata<'a> for Tkey<'a> {
    const RTYPE: Rtype = Rtype::TKEY;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        let mut r = *rdata;
        // RFC 3597 §4 does not list TKEY: its algorithm name is never
        // compressed (BIND does not decompress it either).
        let algorithm = r.read_name_uncompressed()?;
        let inception = r.read_u32()?;
        let expiration = r.read_u32()?;
        let mode = TkeyMode::new(r.read_u16()?);
        let error = TsigRcode::new(r.read_u16()?);
        let key_len = r.read_u16()?;
        let key = r.read_bytes(usize::from(key_len))?;
        let other_len = r.read_u16()?;
        let other = r.read_bytes(usize::from(other_len))?;
        *rdata = r;
        Ok(Tkey {
            algorithm,
            inception,
            expiration,
            mode,
            error,
            key,
            other,
        })
    }
}

impl ComposeRdata for Tkey<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::TKEY
    }

    /// # Errors
    ///
    /// [`Error::InvalidRdata`] if the key or other data is longer than
    /// 65535 octets, and [`Error::BufferTooSmall`] if `c` is full.
    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        let key_len = u16::try_from(self.key.len()).map_err(|_| Error::InvalidRdata)?;
        let other_len = u16::try_from(self.other.len()).map_err(|_| Error::InvalidRdata)?;
        c.put_name(self.algorithm, NameEncoding::Plain)?;
        c.put_u32(self.inception)?;
        c.put_u32(self.expiration)?;
        c.put_u16(self.mode.get())?;
        c.put_u16(self.error.get())?;
        c.put_u16(key_len)?;
        c.put_bytes(self.key)?;
        c.put_u16(other_len)?;
        c.put_bytes(self.other)
    }
}

impl fmt::Display for Tkey<'_> {
    /// `algorithm inception expiration mode error key-size [key]
    /// other-size [other]`, with the times and the mode as decimal
    /// numbers and the data in base64 (BIND's layout; TKEY has no
    /// zone-file form).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {}",
            self.algorithm,
            self.inception,
            self.expiration,
            self.mode.get(),
            self.error,
            self.key.len()
        )?;
        if !self.key.is_empty() {
            write!(f, " {}", Base64(self.key))?;
        }
        write!(f, " {}", self.other.len())?;
        if !self.other.is_empty() {
            write!(f, " {}", Base64(self.other))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Tkey, TkeyMode};
    use crate::name::{Name, NameBuf};
    use crate::rdata::tests::{compose, parse, round_trip, text_error, text_parse, text_round_trip};
    use crate::rdata::{ComposeRdata, RData, TsigRcode};
    use crate::testutil::hex;
    use crate::{Class, Error, Rtype, WireWriter};
    use std::string::ToString;

    // dnspython 2.8's wire form of `gss-tsig. 1791104299 1791107899 3 0
    // AAEC` and `hmac-sha256. 1791104299 1791107899 2 17 AAEC AQID`
    // (tests/corpus/dnspython/rdata.txt).
    const GSS: &str = "086773732d74736967006ac2152b6ac2233b0003000000030001020000";
    const DH: &str = "0b686d61632d736861323536006ac2152b6ac2233b0002001100030001020003010203";

    #[test]
    fn dnspython_vectors() {
        text_round_trip(
            Rtype::TKEY,
            "gss-tsig. 1791104299 1791107899 3 NOERROR 3 AAEC 0",
            &hex(GSS),
            "gss-tsig. 1791104299 1791107899 3 NOERROR 3 AAEC 0",
        );
        text_round_trip(
            Rtype::TKEY,
            "hmac-sha256. 1791104299 1791107899 2 17 3 AAEC 3 AQID",
            &hex(DH),
            "hmac-sha256. 1791104299 1791107899 2 BADKEY 3 AAEC 3 AQID",
        );
        let wire = hex(DH);
        let RData::Tkey(t) = parse(Rtype::TKEY, Class::ANY, &wire).unwrap() else {
            panic!("not TKEY")
        };
        let alg: NameBuf = "hmac-sha256".parse().unwrap();
        assert_eq!(
            t,
            Tkey {
                algorithm: alg.as_name(),
                inception: 1_791_104_299,
                expiration: 1_791_107_899,
                mode: TkeyMode::DIFFIE_HELLMAN,
                error: TsigRcode::BADKEY,
                key: &[0, 1, 2],
                other: &[1, 2, 3],
            }
        );
        assert_eq!(compose(&t), wire);
    }

    #[test]
    fn constructors_and_validity() {
        let alg: NameBuf = "gss-tsig".parse().unwrap();
        let t = Tkey::new(alg.as_name(), 1_791_104_299, 1_791_107_899, TkeyMode::GSSAPI, &[0, 1, 2]);
        assert_eq!(compose(&t), hex(GSS));
        let e = t.with_error(TsigRcode::BADNAME);
        assert_eq!((e.error, e.key, e.other), (TsigRcode::BADNAME, &[][..], &[][..]));
        assert_eq!(e.to_string(), "gss-tsig. 1791104299 1791107899 3 BADNAME 0 0");
        assert!(t.is_valid_at(1_791_104_299) && t.is_valid_at(1_791_107_899));
        assert!(!t.is_valid_at(1_791_104_298) && !t.is_valid_at(1_791_107_900));
        // Serial arithmetic (§2.4): a window across the 2^32 wrap.
        let w = Tkey { inception: u32::MAX - 10, expiration: 10, ..t };
        assert!(w.is_valid_at(0) && w.is_valid_at(u32::MAX) && !w.is_valid_at(11));
        // Expiration before inception: never valid.
        assert!(!Tkey { inception: 10, expiration: 5, ..t }.is_valid_at(7));
        assert_eq!(TkeyMode::new(0).to_string(), "0");
        assert_eq!(TkeyMode::all().count(), 5);
    }

    #[test]
    fn empty_and_large_data() {
        round_trip(Rtype::TKEY, &hex("0000000000000000000000000000000000"), ". 0 0 0 NOERROR 0 0");
        round_trip(
            Rtype::TKEY,
            &hex("00ffffffffffffffffffff0fa0000000020102"),
            ". 4294967295 4294967295 65535 RCODE4000 0 2 AQI=",
        );
        // Composing data that does not fit the 16-bit sizes fails cleanly.
        let big = std::vec![0u8; 70000];
        let t = Tkey::new(Name::ROOT, 0, 0, TkeyMode::GSSAPI, &big);
        let mut buf = std::vec![0u8; 80000];
        let mut w = WireWriter::new(&mut buf);
        assert_eq!(t.compose_rdata(&mut w), Err(Error::InvalidRdata));
        let t = Tkey { key: &[], other: &big, ..t };
        assert_eq!(t.compose_rdata(&mut w), Err(Error::InvalidRdata));
        assert!(w.as_bytes().is_empty());
    }

    #[test]
    fn malformed() {
        let wire = hex(DH);
        // Every truncation fails (round_trip also checks this).
        for end in 0..wire.len() {
            assert_eq!(
                parse(Rtype::TKEY, Class::ANY, &wire[..end]),
                Err(Error::UnexpectedEof),
                "{end}"
            );
        }
        let mut long = wire.clone();
        long.push(0);
        assert_eq!(parse(Rtype::TKEY, Class::ANY, &long), Err(Error::TrailingData));
        // Key size beyond the RDATA.
        let mut bad = wire.clone();
        bad[25] = 0x10;
        assert_eq!(parse(Rtype::TKEY, Class::ANY, &bad), Err(Error::UnexpectedEof));
        // The algorithm name is never compressed.
        assert_eq!(
            parse(Rtype::TKEY, Class::ANY, b"\xc0\x00"),
            Err(Error::UnexpectedPointer)
        );
        // TKEY is a meta type: empty RDATA in class ANY is still parsed
        // (and rejected), not taken for an UPDATE deletion.
        assert_eq!(parse(Rtype::TKEY, Class::ANY, b""), Err(Error::UnexpectedEof));
    }

    #[test]
    fn dnspython_form() {
        // dnspython 2.8 writes the key and other data without their sizes
        // (`to_text`: `"%s %u %u %u %u %s"` and the other data if any) and
        // reads them back as one base64 token and the remaining ones.
        text_round_trip(
            Rtype::TKEY,
            "gss-tsig. 1791104299 1791107899 3 0 AAEC",
            &hex(GSS),
            "gss-tsig. 1791104299 1791107899 3 NOERROR 3 AAEC 0",
        );
        text_round_trip(
            Rtype::TKEY,
            "hmac-sha256. 1791104299 1791107899 2 17 AAEC AQID",
            &hex(DH),
            "hmac-sha256. 1791104299 1791107899 2 BADKEY 3 AAEC 3 AQID",
        );
        // The other data split over several tokens.
        assert_eq!(
            text_parse(Rtype::TKEY, "hmac-sha256. 1791104299 1791107899 2 17 AAEC AQ ID").as_deref(),
            Ok(&hex(DH)[..])
        );
        // Without key data (dnspython writes a trailing blank then, and
        // cannot read it back; dnsbox reads it as empty key and other
        // data).
        let empty = "gss-tsig. 1791104299 1791107899 3 BADKEY 0 0";
        assert_eq!(
            text_parse(Rtype::TKEY, "gss-tsig. 1791104299 1791107899 3 17 "),
            text_parse(Rtype::TKEY, empty)
        );
        // A key of digits only that is not a size BIND's form can use.
        let digits = text_parse(Rtype::TKEY, "gss-tsig. 1 2 3 0 12345678").unwrap();
        assert_eq!(digits.get(22..), Some(&[0, 6, 0xd7, 0x6d, 0xf8, 0xe7, 0xae, 0xfc, 0, 0][..]));
        // Ambiguous text reads as BIND's form: two sizes of 0, not two
        // three-octet values.
        let both = text_parse(Rtype::TKEY, "gss-tsig. 1 2 3 0 0000 0000").unwrap();
        assert_eq!(both, text_parse(Rtype::TKEY, "gss-tsig. 1 2 3 0 0 0").unwrap());
        // BIND's form with data left over is not taken for dnspython's.
        assert_eq!(text_error(Rtype::TKEY, "gss-tsig. 1 2 3 0 0 0 AA=="), Error::InvalidText);
    }

    #[test]
    fn text() {
        // Relative algorithm (origin `example.`), split base64, mnemonics
        // for the mode and the error, date-form times.
        let mut rel = hex(DH);
        rel.splice(12..13, *b"\x07example\x00");
        assert_eq!(
            text_parse(
                Rtype::TKEY,
                "hmac-sha256 ( 20261004085819 20261004095819\n diffie-hellman BADKEY 3 AA EC 3 AQID )"
            )
            .as_deref(),
            Ok(&rel[..])
        );
        assert_eq!(
            text_parse(Rtype::TKEY, "gss-tsig. 1791104299 1791107899 3 rcode0 3 AAEC 0").as_deref(),
            Ok(&hex(GSS)[..])
        );
        let ok = "gss-tsig. 1 2 3 NOERROR 2 AAA= 1 AA==";
        assert!(text_parse(Rtype::TKEY, ok).is_ok());
        for (from, to, err) in [
            (" 1 2 ", " 4294967296 2 ", Error::InvalidText),
            (" 1 2 ", " -1 2 ", Error::InvalidText),
            (" 3 NOERROR", " 65536 NOERROR", Error::InvalidText),
            (" 3 NOERROR", " DH NOERROR", Error::InvalidText),
            (" NOERROR", " NOSUCHERROR", Error::UnknownMnemonic),
            (" NOERROR", " 65536", Error::InvalidText),
            // Sizes and data disagree.
            (" 2 AAA=", " 3 AAA=", Error::InvalidText),
            (" 2 AAA=", " 1 AAA=", Error::InvalidText),
            (" 2 AAA=", " 2 AA", Error::InvalidText),
            (" 2 AAA=", " 2 A*A=", Error::InvalidText),
            (" 1 AA==", " 2 AA==", Error::UnexpectedEof),
            (" 1 AA==", " 0 AA==", Error::InvalidText),
            (" 1 AA==", " 1 \"AA==\"", Error::InvalidText),
            (" 1 AA==", "", Error::UnexpectedEof),
            // Neither BIND's form nor dnspython's: the error of the form
            // the text starts like.
            (" 2 AAA= 1 AA==", " AAE", Error::InvalidText),
            (" 2 AAA= 1 AA==", " 2 AAA= 1", Error::UnexpectedEof),
            (" 2 AAA= 1 AA==", " AAEC AQI", Error::InvalidText),
            (" 2 AAA= 1 AA==", " \"AAEC\"", Error::InvalidText),
        ] {
            let bad = ok.replacen(from, to, 1);
            assert_eq!(text_error(Rtype::TKEY, &bad), err, "{bad}");
        }
        assert_eq!(text_error(Rtype::TKEY, "gss-tsig. 1 2"), Error::UnexpectedEof);
        assert_eq!(text_error(Rtype::TKEY, "gss-tsig. 1 2 3"), Error::UnexpectedEof);
        // The generic form (RFC 3597 §5) works too.
        assert_eq!(
            text_parse(Rtype::TKEY, &std::format!("\\# 29 {GSS}")).as_deref(),
            Ok(&hex(GSS)[..])
        );
    }
}
