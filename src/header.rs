//! The fixed 12-byte DNS message header (RFC 1035 §4.1.1).
//!
//! ```text
//!                                 1  1  1  1  1  1
//!   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                      ID                       |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                    QDCOUNT                    |
//! |                    ANCOUNT                    |
//! |                    NSCOUNT                    |
//! |                    ARCOUNT                    |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! ```

use core::fmt;

use crate::{Error, Result};

/// A DNS operation code (4 bits on the wire).
///
/// This is an open newtype rather than an enum so that unassigned values
/// round-trip unchanged.
///
/// Its text form is the IANA mnemonic (`QUERY`, `UPDATE`) or `OPCODE<n>`
/// for unassigned values; [`FromStr`](core::str::FromStr) parses both back.
/// The default is [`QUERY`](Self::QUERY).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Opcode(u8);

impl Opcode {
    /// Standard query (RFC 1035).
    pub const QUERY: Opcode = Opcode(0);
    /// Inverse query (RFC 1035, obsoleted by RFC 3425).
    pub const IQUERY: Opcode = Opcode(1);
    /// Server status request (RFC 1035).
    pub const STATUS: Opcode = Opcode(2);
    /// Zone change notification (RFC 1996).
    pub const NOTIFY: Opcode = Opcode(4);
    /// Dynamic update (RFC 2136).
    pub const UPDATE: Opcode = Opcode(5);
    /// DNS Stateful Operations (RFC 8490).
    pub const DSO: Opcode = Opcode(6);

    /// Builds an opcode from its numeric value, keeping the low 4 bits.
    #[inline]
    #[must_use]
    pub const fn new(value: u8) -> Self {
        Opcode(value & 0x0f)
    }

    /// The numeric value of this opcode.
    #[inline]
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    /// The IANA mnemonic for this opcode, if it is assigned.
    #[must_use]
    pub const fn mnemonic(self) -> Option<&'static str> {
        Some(match self.0 {
            0 => "QUERY",
            1 => "IQUERY",
            2 => "STATUS",
            4 => "NOTIFY",
            5 => "UPDATE",
            6 => "DSO",
            _ => return None,
        })
    }

    /// Looks up an assigned mnemonic, ASCII-case-insensitively. Does not
    /// accept the generic `OPCODE<n>` form; [`FromStr`](core::str::FromStr)
    /// does.
    pub fn from_mnemonic(s: &str) -> Option<Self> {
        (0..16)
            .map(Opcode)
            .find(|op| op.mnemonic().is_some_and(|m| m.eq_ignore_ascii_case(s)))
    }
}

impl core::str::FromStr for Opcode {
    type Err = Error;

    /// Parses a mnemonic or the generic form `OPCODE<n>` (`n` below 16),
    /// ASCII-case-insensitively: [`Error::UnknownMnemonic`] for an unknown
    /// word, [`Error::InvalidText`] for a bad number.
    fn from_str(s: &str) -> Result<Self> {
        if let Some(op) = Self::from_mnemonic(s) {
            return Ok(op);
        }
        match crate::macros::generic_digits(s, "OPCODE") {
            Some(Some(digits)) => match digits.parse::<u8>() {
                Ok(v) if v < 16 => Ok(Opcode(v)),
                _ => Err(Error::InvalidText),
            },
            Some(None) => Err(Error::InvalidText),
            None => Err(Error::UnknownMnemonic),
        }
    }
}

impl fmt::Debug for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.mnemonic() {
            Some(m) => f.write_str(m),
            None => write!(f, "OPCODE{}", self.0),
        }
    }
}

/// A DNS response code.
///
/// The header carries only the low 4 bits; EDNS(0) (RFC 6891) extends this to
/// 12 bits using the OPT record, which is why the value is stored as `u16`.
///
/// Its text form is the IANA mnemonic (`NOERROR`, `NXDOMAIN`) or
/// `RCODE<n>` for unassigned values; [`FromStr`](core::str::FromStr)
/// parses both back. The default is [`NOERROR`](Self::NOERROR).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Rcode(u16);

impl Rcode {
    /// No error (RFC 1035).
    pub const NOERROR: Rcode = Rcode(0);
    /// Format error (RFC 1035).
    pub const FORMERR: Rcode = Rcode(1);
    /// Server failure (RFC 1035).
    pub const SERVFAIL: Rcode = Rcode(2);
    /// Non-existent domain (RFC 1035).
    pub const NXDOMAIN: Rcode = Rcode(3);
    /// Not implemented (RFC 1035).
    pub const NOTIMP: Rcode = Rcode(4);
    /// Query refused (RFC 1035).
    pub const REFUSED: Rcode = Rcode(5);
    /// Name exists when it should not (RFC 2136).
    pub const YXDOMAIN: Rcode = Rcode(6);
    /// RR set exists when it should not (RFC 2136).
    pub const YXRRSET: Rcode = Rcode(7);
    /// RR set that should exist does not (RFC 2136).
    pub const NXRRSET: Rcode = Rcode(8);
    /// Server not authoritative for zone / not authorized (RFC 2136, RFC 8945).
    pub const NOTAUTH: Rcode = Rcode(9);
    /// Name not contained in zone (RFC 2136).
    pub const NOTZONE: Rcode = Rcode(10);
    /// DSO-TYPE not implemented (RFC 8490).
    pub const DSOTYPENI: Rcode = Rcode(11);
    /// Bad OPT version (RFC 6891). Shares value 16 with BADSIG (RFC 8945).
    pub const BADVERS: Rcode = Rcode(16);
    /// Bad or missing server cookie (RFC 7873).
    pub const BADCOOKIE: Rcode = Rcode(23);

    /// Builds a response code from its numeric value, keeping the low 12 bits.
    #[inline]
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Rcode(value & 0x0fff)
    }

    /// Combines the 4-bit header RCODE with the 8-bit EDNS extended RCODE.
    #[inline]
    #[must_use]
    pub const fn from_parts(header: u8, extended: u8) -> Self {
        Rcode(((extended as u16) << 4) | (header as u16 & 0x0f))
    }

    /// The numeric value of this response code.
    #[inline]
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }

    /// The low 4 bits, as carried in the message header.
    #[inline]
    #[must_use]
    pub const fn header_bits(self) -> u8 {
        (self.0 & 0x0f) as u8
    }

    /// The high 8 bits, as carried in the EDNS OPT record's TTL field.
    #[inline]
    #[must_use]
    pub const fn extended_bits(self) -> u8 {
        (self.0 >> 4) as u8
    }

    /// The IANA mnemonic for this response code, if it is assigned.
    #[must_use]
    pub const fn mnemonic(self) -> Option<&'static str> {
        Some(match self.0 {
            0 => "NOERROR",
            1 => "FORMERR",
            2 => "SERVFAIL",
            3 => "NXDOMAIN",
            4 => "NOTIMP",
            5 => "REFUSED",
            6 => "YXDOMAIN",
            7 => "YXRRSET",
            8 => "NXRRSET",
            9 => "NOTAUTH",
            10 => "NOTZONE",
            11 => "DSOTYPENI",
            16 => "BADVERS",
            23 => "BADCOOKIE",
            _ => return None,
        })
    }

    /// Looks up an assigned mnemonic, ASCII-case-insensitively. Does not
    /// accept the generic `RCODE<n>` form; [`FromStr`](core::str::FromStr)
    /// does.
    pub fn from_mnemonic(s: &str) -> Option<Self> {
        // Every assigned mnemonic is below 32.
        (0..32)
            .map(Rcode)
            .find(|rc| rc.mnemonic().is_some_and(|m| m.eq_ignore_ascii_case(s)))
    }
}

impl core::str::FromStr for Rcode {
    type Err = Error;

    /// Parses a mnemonic or the generic form `RCODE<n>` (`n` below 4096,
    /// RFC 6891 §6.1.3), ASCII-case-insensitively:
    /// [`Error::UnknownMnemonic`] for an unknown word,
    /// [`Error::InvalidText`] for a bad number.
    fn from_str(s: &str) -> Result<Self> {
        if let Some(rc) = Self::from_mnemonic(s) {
            return Ok(rc);
        }
        match crate::macros::generic_digits(s, "RCODE") {
            Some(Some(digits)) => match digits.parse::<u16>() {
                Ok(v) if v < 4096 => Ok(Rcode(v)),
                _ => Err(Error::InvalidText),
            },
            Some(None) => Err(Error::InvalidText),
            None => Err(Error::UnknownMnemonic),
        }
    }
}

impl fmt::Debug for Rcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Rcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.mnemonic() {
            Some(m) => f.write_str(m),
            None => write!(f, "RCODE{}", self.0),
        }
    }
}

/// The second 16-bit word of the header: QR, opcode, flag bits and RCODE.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Flags(u16);

macro_rules! flag_bit {
    ($(#[$doc:meta])* $get:ident, $set:ident, $bit:expr) => {
        $(#[$doc])*
        #[inline]
        #[must_use]
        pub const fn $get(self) -> bool {
            self.0 & (1 << $bit) != 0
        }

        #[doc = concat!("Returns a copy with the `", stringify!($get), "` bit set to `value`.")]
        #[inline]
        #[must_use]
        pub const fn $set(self, value: bool) -> Self {
            if value {
                Flags(self.0 | (1 << $bit))
            } else {
                Flags(self.0 & !(1 << $bit))
            }
        }
    };
}

impl Flags {
    /// Wraps a raw 16-bit flags word.
    #[inline]
    #[must_use]
    pub const fn from_bits(bits: u16) -> Self {
        Flags(bits)
    }

    /// The raw 16-bit flags word.
    #[inline]
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    flag_bit!(
        /// QR: `true` for a response, `false` for a query.
        qr, with_qr, 15
    );
    flag_bit!(
        /// AA: authoritative answer.
        aa, with_aa, 10
    );
    flag_bit!(
        /// TC: the message was truncated.
        tc, with_tc, 9
    );
    flag_bit!(
        /// RD: recursion desired.
        rd, with_rd, 8
    );
    flag_bit!(
        /// RA: recursion available.
        ra, with_ra, 7
    );
    flag_bit!(
        /// Z: reserved, must be zero.
        z, with_z, 6
    );
    flag_bit!(
        /// AD: authentic data (RFC 4035).
        ad, with_ad, 5
    );
    flag_bit!(
        /// CD: checking disabled (RFC 4035).
        cd, with_cd, 4
    );

    /// The operation code.
    #[inline]
    #[must_use]
    pub const fn opcode(self) -> Opcode {
        Opcode::new((self.0 >> 11) as u8)
    }

    /// Returns a copy with the opcode replaced.
    #[inline]
    #[must_use]
    pub const fn with_opcode(self, opcode: Opcode) -> Self {
        Flags((self.0 & !0x7800) | ((opcode.get() as u16) << 11))
    }

    /// The 4-bit header response code. Combine with the EDNS extended RCODE
    /// via [`Rcode::from_parts`] for the full value.
    #[inline]
    #[must_use]
    pub const fn rcode(self) -> Rcode {
        Rcode::new(self.0 & 0x000f)
    }

    /// Returns a copy with the header RCODE replaced by the low 4 bits of
    /// `rcode`. The extended bits must be carried in an OPT record.
    #[inline]
    #[must_use]
    pub const fn with_rcode(self, rcode: Rcode) -> Self {
        Flags((self.0 & !0x000f) | rcode.header_bits() as u16)
    }
}

impl fmt::Debug for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Flags({} {}", self.opcode(), self.rcode())?;
        for (set, name) in [
            (self.qr(), "qr"),
            (self.aa(), "aa"),
            (self.tc(), "tc"),
            (self.rd(), "rd"),
            (self.ra(), "ra"),
            (self.z(), "z"),
            (self.ad(), "ad"),
            (self.cd(), "cd"),
        ] {
            if set {
                write!(f, " {name}")?;
            }
        }
        f.write_str(")")
    }
}

/// The fixed DNS message header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Header {
    /// Transaction ID, echoed by the responder.
    pub id: u16,
    /// QR, opcode, flag bits and header RCODE.
    pub flags: Flags,
    /// Number of entries in the question section.
    pub qdcount: u16,
    /// Number of records in the answer section.
    pub ancount: u16,
    /// Number of records in the authority section.
    pub nscount: u16,
    /// Number of records in the additional section.
    pub arcount: u16,
}

impl Header {
    /// Size of the header on the wire, in bytes.
    pub const LEN: usize = 12;

    /// Parses a header from the first 12 bytes of `buf`.
    pub const fn parse(buf: &[u8]) -> Result<Self> {
        let [a, b, c, d, e, f, g, h, i, j, k, l, ..] = *buf else {
            return Err(Error::UnexpectedEof);
        };
        Ok(Header {
            id: u16::from_be_bytes([a, b]),
            flags: Flags(u16::from_be_bytes([c, d])),
            qdcount: u16::from_be_bytes([e, f]),
            ancount: u16::from_be_bytes([g, h]),
            nscount: u16::from_be_bytes([i, j]),
            arcount: u16::from_be_bytes([k, l]),
        })
    }

    /// Encodes the header into its 12-byte wire form.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; Self::LEN] {
        let [a, b] = self.id.to_be_bytes();
        let [c, d] = self.flags.0.to_be_bytes();
        let [e, f] = self.qdcount.to_be_bytes();
        let [g, h] = self.ancount.to_be_bytes();
        let [i, j] = self.nscount.to_be_bytes();
        let [k, l] = self.arcount.to_be_bytes();
        [a, b, c, d, e, f, g, h, i, j, k, l]
    }

    /// Writes the header into the first 12 bytes of `out`.
    pub fn write(&self, out: &mut [u8]) -> Result<()> {
        let dst = out.get_mut(..Self::LEN).ok_or(Error::BufferTooSmall)?;
        dst.copy_from_slice(&self.to_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Header of a `dig example.com A` query: id 0x1234, RD set, one question,
    // one additional (the OPT record).
    const QUERY: [u8; 12] = [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    #[test]
    fn parse_query_header() {
        let h = Header::parse(&QUERY).unwrap();
        assert_eq!(h.id, 0x1234);
        assert!(!h.flags.qr());
        assert!(h.flags.rd());
        assert_eq!(h.flags.opcode(), Opcode::QUERY);
        assert_eq!(h.flags.rcode(), Rcode::NOERROR);
        assert_eq!((h.qdcount, h.ancount, h.nscount, h.arcount), (1, 0, 0, 1));
    }

    #[test]
    fn round_trip() {
        let h = Header::parse(&QUERY).unwrap();
        assert_eq!(h.to_bytes(), QUERY);
        let mut out = [0u8; 16];
        h.write(&mut out).unwrap();
        assert_eq!(&out[..12], &QUERY);
    }

    #[test]
    fn short_input() {
        assert_eq!(Header::parse(&QUERY[..11]), Err(Error::UnexpectedEof));
        assert_eq!(
            Header::default().write(&mut [0u8; 11]),
            Err(Error::BufferTooSmall)
        );
    }

    #[test]
    fn flag_setters() {
        let f = Flags::default()
            .with_qr(true)
            .with_aa(true)
            .with_opcode(Opcode::UPDATE)
            .with_rcode(Rcode::NXDOMAIN);
        assert!(f.qr() && f.aa() && !f.tc() && !f.rd());
        assert_eq!(f.opcode(), Opcode::UPDATE);
        assert_eq!(f.rcode(), Rcode::NXDOMAIN);
        assert_eq!(f.bits(), 0xac03);
        assert!(!f.with_aa(false).aa());
    }

    #[test]
    fn mnemonics() {
        use std::string::ToString;
        for v in 0..16 {
            let op = Opcode::new(v);
            assert_eq!(op.to_string().parse(), Ok(op));
        }
        for v in [0, 3, 11, 16, 23, 24, 4095] {
            let rc = Rcode::new(v);
            assert_eq!(rc.to_string().parse(), Ok(rc));
        }
        assert_eq!("update".parse(), Ok(Opcode::UPDATE));
        assert_eq!(Opcode::from_mnemonic("Notify"), Some(Opcode::NOTIFY));
        assert_eq!(Opcode::from_mnemonic("OPCODE4"), None);
        assert_eq!("opcode15".parse(), Ok(Opcode::new(15)));
        assert_eq!("OPCODE16".parse::<Opcode>(), Err(Error::InvalidText));
        assert_eq!("OPCODE".parse::<Opcode>(), Err(Error::InvalidText));
        assert_eq!("FOO".parse::<Opcode>(), Err(Error::UnknownMnemonic));
        assert_eq!("nxdomain".parse(), Ok(Rcode::NXDOMAIN));
        assert_eq!("RCODE4095".parse(), Ok(Rcode::new(4095)));
        assert_eq!("RCODE4096".parse::<Rcode>(), Err(Error::InvalidText));
        assert_eq!("RCODE-1".parse::<Rcode>(), Err(Error::InvalidText));
        assert_eq!("BADSIG".parse::<Rcode>(), Err(Error::UnknownMnemonic));
        assert_eq!(Rcode::new(12).mnemonic(), None);
        assert_eq!(Opcode::default(), Opcode::QUERY);
        assert_eq!(Rcode::default(), Rcode::NOERROR);
    }

    #[test]
    fn extended_rcode() {
        let r = Rcode::BADCOOKIE;
        assert_eq!(Rcode::from_parts(r.header_bits(), r.extended_bits()), r);
        assert_eq!((r.header_bits(), r.extended_bits()), (7, 1));
    }
}
