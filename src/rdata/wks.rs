//! WKS record data (RFC 1035 §3.4.2).

use core::fmt;
use core::net::Ipv4Addr;

use super::{ComposeRdata, ParseRdata, ParseRdataText};
use crate::wire::{Composer, OutBuf, WireReader};
use crate::zone::{Scanner, Token};
use crate::{Class, Error, Result, Rtype};

/// `WKS` record data: well-known services offered by a host
/// (RFC 1035 §3.4.2). Class IN only. Deprecated in practice (RFC 1123
/// §2.2).
///
/// ```
/// use dnsbox::rdata::{ParseRdataText, Wks};
///
/// // Protocols and services by name or number.
/// let mut buf = [0u8; 16];
/// let wks = Wks::from_text("10.0.0.1 tcp ( smtp 37 )", &mut buf)?;
/// assert_eq!(wks.protocol, 6);
/// assert_eq!(wks.ports().collect::<Vec<_>>(), [25, 37]);
/// assert_eq!(wks.to_string(), "10.0.0.1 6 25 37");
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Wks<'a> {
    /// The host address.
    pub address: Ipv4Addr,
    /// IP protocol number (6 = TCP, 17 = UDP).
    pub protocol: u8,
    /// Port bitmap: bit *n* (MSB-first) set means port *n* is offered.
    pub bitmap: &'a [u8],
}

impl<'a> Wks<'a> {
    /// Iterates over the ports set in the bitmap, ascending.
    pub fn ports(&self) -> impl Iterator<Item = u16> + 'a {
        let bitmap = self.bitmap;
        bitmap.iter().enumerate().flat_map(|(i, &byte)| {
            (0..8u16).filter_map(move |bit| {
                let port = u16::try_from(i * 8).ok()?.checked_add(bit)?;
                (byte & (0x80 >> bit) != 0).then_some(port)
            })
        })
    }
}

impl<'a> ParseRdata<'a> for Wks<'a> {
    const RTYPE: Rtype = Rtype::WKS;
    const CLASS: Option<Class> = Some(Class::IN);

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        Ok(Wks {
            address: Ipv4Addr::from(rdata.read_array::<4>()?),
            protocol: rdata.read_u8()?,
            bitmap: rdata.read_rest(),
        })
    }
}

impl ComposeRdata for Wks<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::WKS
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_bytes(&self.address.octets())?;
        c.put_u8(self.protocol)?;
        c.put_bytes(self.bitmap)
    }
}

impl fmt::Display for Wks<'_> {
    /// `address protocol port...`, with numeric protocol and ports.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.address, self.protocol)?;
        for port in self.ports() {
            write!(f, " {port}")?;
        }
        Ok(())
    }
}

/// Protocol mnemonics accepted in WKS text (IANA "Assigned Internet
/// Protocol Numbers"; BIND asks the system's protocol database).
const PROTOCOLS: &[(&str, u8)] = &[("ICMP", 1), ("IGMP", 2), ("TCP", 6), ("UDP", 17)];

/// Service names accepted in WKS text (IANA "Service Name and Transport
/// Protocol Port Number Registry"; BIND asks the system's services
/// database).
const SERVICES: &[(&str, u16)] = &[
    ("echo", 7),
    ("discard", 9),
    ("daytime", 13),
    ("ftp-data", 20),
    ("ftp", 21),
    ("ssh", 22),
    ("telnet", 23),
    ("smtp", 25),
    ("time", 37),
    ("whois", 43),
    ("nicname", 43),
    ("domain", 53),
    ("tftp", 69),
    ("gopher", 70),
    ("finger", 79),
    ("http", 80),
    ("www", 80),
    ("kerberos", 88),
    ("pop3", 110),
    ("sunrpc", 111),
    ("auth", 113),
    ("nntp", 119),
    ("ntp", 123),
    ("imap", 143),
    ("snmp", 161),
    ("ldap", 389),
    ("https", 443),
    ("submission", 587),
];

/// A number, or a mnemonic from `table` (case-insensitively).
fn lookup<'t, T: Copy>(
    t: Token<'t>,
    table: &[(&str, T)],
    number: fn(&Token<'t>) -> Result<T>,
) -> Result<T> {
    if t.as_bytes().first().is_some_and(u8::is_ascii_digit) {
        return number(&t);
    }
    table
        .iter()
        .find(|(name, _)| t.is(name))
        .map(|&(_, v)| v)
        .ok_or(Error::UnknownMnemonic)
}

impl ParseRdataText for Wks<'_> {
    /// `<address> <protocol> <service>...` (RFC 1035 §3.4.2; RFC 1010
    /// mnemonics): the protocol and the services are numbers or common
    /// mnemonics (`TCP`, `UDP`; `smtp`, `domain`, ...), the services in
    /// any order, possibly none.
    fn parse_text<B: OutBuf + ?Sized>(s: &mut Scanner<'_>, out: &mut B) -> Result<()> {
        out.put_bytes(&s.ipv4()?.octets())?;
        out.put_u8(lookup(s.word()?, PROTOCOLS, Token::u8)?)?;
        // One bit per port: the work is linear in the number of tokens.
        let mut bitmap = [0u8; 8192];
        let mut len = 0;
        while let Some(t) = s.next_token()? {
            if t.is_quoted() {
                return Err(Error::InvalidText);
            }
            let port = usize::from(lookup(t, SERVICES, Token::u16)?);
            if let Some(byte) = bitmap.get_mut(port / 8) {
                *byte |= 0x80 >> (port % 8);
            }
            len = len.max(port / 8 + 1);
        }
        out.put_bytes(bitmap.get(..len).unwrap_or(&[]))
    }
}

#[cfg(test)]
mod tests {
    use crate::rdata::tests::{text_error, text_parse, text_round_trip};
    use crate::{Error, Rtype};

    #[test]
    fn text() {
        // RFC 1035 §3.4.2 / BIND style.
        text_round_trip(
            Rtype::WKS,
            "10.0.0.1 tcp ( smtp 37 )",
            &[10, 0, 0, 1, 6, 0x00, 0x00, 0x00, 0x40, 0x04],
            "10.0.0.1 6 25 37",
        );
        text_round_trip(Rtype::WKS, "192.0.2.1 17", &[192, 0, 2, 1, 17], "192.0.2.1 17");
        text_round_trip(
            Rtype::WKS,
            "192.0.2.1 UDP 1023 domain 0 DOMAIN",
            &{
                let mut w = std::vec![192, 0, 2, 1, 17];
                w.resize(5 + 128, 0);
                w[5] = 0x80;
                w[5 + 6] = 0x04;
                w[5 + 127] = 0x01;
                w
            },
            "192.0.2.1 17 0 53 1023",
        );
        let top = text_parse(Rtype::WKS, "192.0.2.1 6 65535").unwrap();
        assert_eq!((top.len(), top.last()), (5 + 8192, Some(&0x01)));
        assert_eq!(text_error(Rtype::WKS, "10.0.0.1 xtp 25"), Error::UnknownMnemonic);
        assert_eq!(text_error(Rtype::WKS, "10.0.0.1 6 bogus"), Error::UnknownMnemonic);
        assert_eq!(text_error(Rtype::WKS, "10.0.0.1 6 65536"), Error::InvalidText);
        assert_eq!(text_error(Rtype::WKS, "10.0.0.1 256 25"), Error::InvalidText);
        assert_eq!(text_error(Rtype::WKS, "10.0.0.1 6 \"25\""), Error::InvalidText);
        assert_eq!(text_error(Rtype::WKS, "10.0.0.1"), Error::UnexpectedEof);
    }
}
