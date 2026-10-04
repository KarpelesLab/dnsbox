//! DNS Cookies (RFC 7873) and interoperable server cookies (RFC 9018).

use core::fmt;
use core::net::IpAddr;

use super::{ComposeOption, OptionCode, ParseOption};
use crate::text::Hex;
use crate::wire::{Composer, WireReader};
use crate::{Error, Result};

/// `COOKIE` option: a client cookie, optionally followed by a server
/// cookie (RFC 7873 §4).
///
/// The client cookie is 8 bytes; the server cookie, when present, is 8 to
/// 32 bytes. Any other length is malformed (RFC 7873 §5.2.2) and fails with
/// [`Error::InvalidOption`].
///
/// ```
/// use dnsbox::edns::Cookie;
///
/// let c = Cookie::client_only([0x24, 0x64, 0xc4, 0xab, 0xcf, 0x10, 0xc9, 0x57]);
/// assert_eq!(c.server(), None);
/// assert_eq!(c.to_string(), "COOKIE=2464C4ABCF10C957");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Cookie<'a> {
    client: [u8; 8],
    server: &'a [u8],
}

impl<'a> Cookie<'a> {
    /// Length of the client cookie (RFC 7873 §4.1).
    pub const CLIENT_LEN: usize = 8;
    /// Smallest server cookie (RFC 7873 §4.2).
    pub const MIN_SERVER_LEN: usize = 8;
    /// Largest server cookie (RFC 7873 §4.2).
    pub const MAX_SERVER_LEN: usize = 32;

    /// A cookie with only the client part, as sent before a server cookie
    /// is known (RFC 7873 §5.1).
    #[inline]
    #[must_use]
    pub const fn client_only(client: [u8; 8]) -> Self {
        Cookie { client, server: &[] }
    }

    /// A client cookie and a server cookie, as a client echoes them once
    /// it has learned the server cookie (RFC 7873 §5.3).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidOption`] unless `server` is empty (no server
    /// cookie) or 8 to 32 bytes long.
    ///
    /// ```
    /// use dnsbox::edns::Cookie;
    ///
    /// let c = Cookie::new([1; 8], &[2; 16])?;
    /// assert_eq!(c.server(), Some(&[2u8; 16][..]));
    /// assert!(Cookie::new([1; 8], &[2; 4]).is_err());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub const fn new(client: [u8; 8], server: &'a [u8]) -> Result<Self> {
        let len = server.len();
        if len != 0 && (len < Self::MIN_SERVER_LEN || len > Self::MAX_SERVER_LEN) {
            return Err(Error::InvalidOption);
        }
        Ok(Cookie { client, server })
    }

    /// The client cookie.
    #[inline]
    #[must_use]
    pub const fn client(&self) -> [u8; 8] {
        self.client
    }

    /// The server cookie, if present.
    #[inline]
    #[must_use]
    pub const fn server(&self) -> Option<&'a [u8]> {
        if self.server.is_empty() {
            None
        } else {
            Some(self.server)
        }
    }

    /// The server cookie decoded as an RFC 9018 [`ServerCookie`]: `Some`
    /// only if it is exactly 16 bytes (RFC 9018 §4.4 requires the 24-byte
    /// option length for verification) and of version 1.
    #[must_use]
    pub fn server_cookie_v1(&self) -> Option<ServerCookie> {
        ServerCookie::from_bytes(self.server)
            .ok()
            .filter(|s| s.version == ServerCookie::VERSION)
    }
}

impl<'a> ParseOption<'a> for Cookie<'a> {
    const CODE: OptionCode = OptionCode::COOKIE;

    fn parse_option(data: &mut WireReader<'a>) -> Result<Self> {
        let len = data.remaining();
        if len < Self::CLIENT_LEN {
            return Err(Error::InvalidOption);
        }
        let mut r = *data;
        let client = r.read_array()?;
        let cookie = Cookie::new(client, r.read_rest())?;
        *data = r;
        Ok(cookie)
    }
}

impl ComposeOption for Cookie<'_> {
    #[inline]
    fn code(&self) -> OptionCode {
        OptionCode::COOKIE
    }

    fn compose_option<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_bytes(&self.client)?;
        c.put_bytes(self.server)
    }
}

impl fmt::Display for Cookie<'_> {
    /// `COOKIE=<client hex><server hex>`, as in `dig` output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "COOKIE={}{}", Hex(&self.client), Hex(self.server))
    }
}

/// An interoperable server cookie (RFC 9018 §4):
///
/// ```text
/// | Version (1) | Reserved (3) | Timestamp (4) | Hash (8) |
/// ```
///
/// where, for version 1, `Hash = SipHash-2-4(Client Cookie | Version |
/// Reserved | Timestamp | Client-IP, Server Secret)` (§4.4).
///
/// The hash input is built by [`hash_input`](Self::hash_input) without any
/// dependency. Computing and checking the hash needs SipHash-2-4, which
/// dnsbox takes from `purecrypto` behind the `cookie-siphash` feature
/// ([`generate`], [`verify`]).
///
/// ```
/// use dnsbox::edns::{Cookie, ServerCookie};
///
/// // A server cookie received from a server implementing RFC 9018.
/// let sc = ServerCookie::from_bytes(&[1, 0, 0, 0, 0x5c, 0xf7, 0x9f, 0x11,
///                                     0x1f, 0x81, 0x30, 0xc3, 0xee, 0xe2, 0x94, 0x80])?;
/// assert_eq!((sc.version, sc.timestamp), (1, 1559731985));
/// assert!(sc.is_fresh(1559731985 + 60));
/// assert!(!sc.is_fresh(1559731985 + 7200));
/// assert!(sc.needs_refresh(1559731985 + 1801));
/// let bytes = sc.to_bytes();
/// let c = Cookie::new([0x24, 0x64, 0xc4, 0xab, 0xcf, 0x10, 0xc9, 0x57], &bytes)?;
/// assert_eq!(c.server_cookie_v1(), Some(sc));
/// # Ok::<(), dnsbox::Error>(())
/// ```
///
#[cfg_attr(feature = "cookie-siphash", doc = "[`generate`]: Self::generate")]
#[cfg_attr(feature = "cookie-siphash", doc = "[`verify`]: Self::verify")]
#[cfg_attr(not(feature = "cookie-siphash"), doc = "[`generate`]: crate#cargo-features")]
#[cfg_attr(not(feature = "cookie-siphash"), doc = "[`verify`]: crate#cargo-features")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ServerCookie {
    /// Construction method; 1 for RFC 9018 (§4.1).
    pub version: u8,
    /// Reserved; zero when generated, but hashed as received (§4.2).
    pub reserved: [u8; 3],
    /// Seconds since the Unix epoch, modulo 2^32 (§4.3).
    pub timestamp: u32,
    /// The SipHash-2-4 output (§4.4).
    pub hash: [u8; 8],
}

impl ServerCookie {
    /// The version defined by RFC 9018 (§4.1).
    pub const VERSION: u8 = 1;
    /// Encoded length.
    pub const LEN: usize = 16;
    /// How far in the past a timestamp may be and still be accepted:
    /// one hour (RFC 9018 §4.3).
    pub const MAX_AGE: u32 = 3600;
    /// How far in the future a timestamp may be (clock skew in an anycast
    /// set): five minutes (RFC 9018 §4.3).
    pub const MAX_FUTURE: u32 = 300;
    /// Age after which a server should issue a fresh cookie: half an hour
    /// (RFC 9018 §4.3).
    pub const REFRESH_AGE: u32 = 1800;

    /// Decodes a 16-byte server cookie (any version).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidOption`] for any other length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let b: &[u8; 16] = bytes.try_into().map_err(|_| Error::InvalidOption)?;
        let [v, r0, r1, r2, t0, t1, t2, t3, h @ ..] = *b;
        Ok(ServerCookie {
            version: v,
            reserved: [r0, r1, r2],
            timestamp: u32::from_be_bytes([t0, t1, t2, t3]),
            hash: h,
        })
    }

    /// The 16-byte encoding.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; 16] {
        let [r0, r1, r2] = self.reserved;
        let [t0, t1, t2, t3] = self.timestamp.to_be_bytes();
        let h = self.hash;
        [
            self.version,
            r0,
            r1,
            r2,
            t0,
            t1,
            t2,
            t3,
            h[0],
            h[1],
            h[2],
            h[3],
            h[4],
            h[5],
            h[6],
            h[7],
        ]
    }

    /// The SipHash-2-4 input for this cookie (RFC 9018 §4.4): `Client
    /// Cookie | Version | Reserved | Timestamp | Client-IP`, 20 bytes for an
    /// IPv4 client and 32 for IPv6.
    #[must_use]
    pub fn hash_input(&self, client: &[u8; 8], client_ip: IpAddr) -> HashInput {
        let mut buf = [0u8; 32];
        buf[..8].copy_from_slice(client);
        buf[8] = self.version;
        buf[9..12].copy_from_slice(&self.reserved);
        buf[12..16].copy_from_slice(&self.timestamp.to_be_bytes());
        let len = match client_ip {
            IpAddr::V4(a) => {
                buf[16..20].copy_from_slice(&a.octets());
                20
            }
            IpAddr::V6(a) => {
                buf[16..32].copy_from_slice(&a.octets());
                32
            }
        };
        HashInput { buf, len }
    }

    /// Whether the timestamp is acceptable at time `now` (seconds since the
    /// Unix epoch, modulo 2^32): at most [`MAX_AGE`](Self::MAX_AGE) in the
    /// past and [`MAX_FUTURE`](Self::MAX_FUTURE) in the future, compared
    /// with serial number arithmetic (RFC 9018 §4.3, RFC 1982).
    #[must_use]
    pub const fn is_fresh(&self, now: u32) -> bool {
        let age = now.wrapping_sub(self.timestamp) as i32;
        if age >= 0 {
            age as u32 <= Self::MAX_AGE
        } else {
            age.unsigned_abs() <= Self::MAX_FUTURE
        }
    }

    /// Whether a server should issue a fresh cookie at time `now`: the
    /// cookie is older than [`REFRESH_AGE`](Self::REFRESH_AGE) (RFC 9018
    /// §4.3) or not [fresh](Self::is_fresh) at all.
    #[must_use]
    pub const fn needs_refresh(&self, now: u32) -> bool {
        let age = now.wrapping_sub(self.timestamp) as i32;
        !self.is_fresh(now) || age > Self::REFRESH_AGE as i32
    }
}

#[cfg(feature = "cookie-siphash")]
#[cfg_attr(docsrs, doc(cfg(feature = "cookie-siphash")))]
impl ServerCookie {
    /// Generates a version 1 server cookie for `client` (the client cookie)
    /// sent from `client_ip`, at time `now` (seconds since the Unix epoch,
    /// modulo 2^32), with the reserved bytes zeroed (RFC 9018 §4).
    ///
    /// ```
    /// use dnsbox::edns::ServerCookie;
    ///
    /// // RFC 9018 Appendix A.1.
    /// let secret = [0xe5, 0xe9, 0x73, 0xe5, 0xa6, 0xb2, 0xa4, 0x3f,
    ///               0x48, 0xe7, 0xdc, 0x84, 0x9e, 0x37, 0xbf, 0xcf];
    /// let client = [0x24, 0x64, 0xc4, 0xab, 0xcf, 0x10, 0xc9, 0x57];
    /// let ip = "198.51.100.100".parse().unwrap();
    /// let sc = ServerCookie::generate(&secret, &client, ip, 1559731985);
    /// assert_eq!(sc.hash, [0x1f, 0x81, 0x30, 0xc3, 0xee, 0xe2, 0x94, 0x80]);
    /// assert!(sc.verify(&secret, &client, ip));
    /// ```
    #[must_use]
    pub fn generate(secret: &[u8; 16], client: &[u8; 8], client_ip: IpAddr, now: u32) -> Self {
        let mut cookie = ServerCookie {
            version: Self::VERSION,
            reserved: [0; 3],
            timestamp: now,
            hash: [0; 8],
        };
        let input = cookie.hash_input(client, client_ip);
        cookie.hash = purecrypto::mac::SipHash24::compute(secret, input.as_bytes());
        cookie
    }

    /// Checks the hash of this cookie against `secret`, in constant time
    /// (RFC 9018 §4.4). The version must be 1. Check the timestamp
    /// separately with [`is_fresh`](Self::is_fresh); during a secret
    /// rollover (§5), try each valid secret.
    #[must_use]
    pub fn verify(&self, secret: &[u8; 16], client: &[u8; 8], client_ip: IpAddr) -> bool {
        if self.version != Self::VERSION {
            return false;
        }
        let input = self.hash_input(client, client_ip);
        purecrypto::mac::SipHash24::new(secret)
            .chain(input.as_bytes())
            .verify(&self.hash)
    }
}

impl fmt::Display for ServerCookie {
    /// The 16 bytes in hex.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(&self.to_bytes()), f)
    }
}

/// The SipHash-2-4 input of an RFC 9018 server cookie; see
/// [`ServerCookie::hash_input`].
///
/// ```
/// use dnsbox::edns::ServerCookie;
///
/// let sc = ServerCookie { version: 1, reserved: [0; 3], timestamp: 1_559_731_985, hash: [0; 8] };
/// let client = [0x24, 0x64, 0xc4, 0xab, 0xcf, 0x10, 0xc9, 0x57];
/// let v4 = sc.hash_input(&client, "198.51.100.100".parse().unwrap());
/// assert_eq!(v4.as_bytes().len(), 20);
/// let v6 = sc.hash_input(&client, "2001:db8::1".parse().unwrap());
/// assert_eq!(v6.as_bytes().len(), 32);
/// // Feed it to SipHash-2-4 keyed with the server secret.
/// assert_eq!(&v4.as_bytes()[..8], client);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HashInput {
    buf: [u8; 32],
    len: usize,
}

impl HashInput {
    /// The input bytes (20 or 32 of them).
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&self.buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edns::tests::{parse, round_trip};
    use crate::testutil::hex;
    use std::string::ToString;

    #[test]
    fn wire_forms() {
        round_trip(
            OptionCode::COOKIE,
            &hex("2464c4abcf10c957"),
            "COOKIE=2464C4ABCF10C957",
        );
        // ns1.isc.org response, captured October 2026.
        let s = round_trip(
            OptionCode::COOKIE,
            &hex("2464c4abcf10c957010000006ac214c3e8ecef0e76e8f243"),
            "COOKIE=2464C4ABCF10C957010000006AC214C3E8ECEF0E76E8F243",
        );
        assert!(!s.is_empty());
        // Server cookies of 8 and 32 bytes are the extremes.
        round_trip(
            OptionCode::COOKIE,
            &[7; 16],
            "COOKIE=07070707070707070707070707070707",
        );
        let mut max = std::vec![1u8; 40];
        max[39] = 2;
        round_trip(OptionCode::COOKIE, &max, &std::format!("COOKIE={}", Hex(&max)));
        // RFC 7873 §5.2.2: < 8, 9..=15 and > 40 are malformed.
        for len in (0..8).chain(9..16).chain(41..45) {
            assert_eq!(
                parse(OptionCode::COOKIE, &std::vec![0u8; len]),
                Err(Error::InvalidOption),
                "{len}"
            );
        }
    }

    #[test]
    fn accessors() {
        let raw = hex("2464c4abcf10c957010000005cf79f111f8130c3eee29480");
        let mut r = WireReader::new(&raw);
        let c = Cookie::parse_option(&mut r).unwrap();
        assert!(r.is_empty());
        assert_eq!(c.client(), raw[..8]);
        assert_eq!(c.server(), Some(&raw[8..]));
        let sc = c.server_cookie_v1().unwrap();
        assert_eq!(sc.version, 1);
        assert_eq!(sc.reserved, [0; 3]);
        assert_eq!(sc.timestamp, 1559731985);
        assert_eq!(sc.to_bytes(), raw[8..]);
        assert_eq!(sc.to_string(), "010000005CF79F111F8130C3EEE29480");
        assert_eq!(Cookie::client_only([0; 8]).server_cookie_v1(), None);
        let other_version = Cookie::new([0; 8], &[2; 16]).unwrap();
        assert_eq!(other_version.server_cookie_v1(), None);
        assert_eq!(Cookie::new([0; 8], &[1; 7]), Err(Error::InvalidOption));
        assert_eq!(Cookie::new([0; 8], &[1; 33]), Err(Error::InvalidOption));
        assert_eq!(ServerCookie::from_bytes(&[0; 15]), Err(Error::InvalidOption));
    }

    #[test]
    fn hash_input_layout() {
        let sc = ServerCookie::from_bytes(&hex("01abcdef5cf78f71a314227b6679ebf5")).unwrap();
        let client = [0xfc, 0x93, 0xfc, 0x62, 0x80, 0x7d, 0xdb, 0x86];
        let v4 = sc.hash_input(&client, "203.0.113.203".parse().unwrap());
        assert_eq!(v4.as_bytes(), hex("fc93fc62807ddb8601abcdef5cf78f71cb0071cb"));
        let v6 = sc.hash_input(&client, "2001:db8::1".parse().unwrap());
        assert_eq!(v6.as_bytes().len(), 32);
        assert_eq!(v6.as_bytes()[16..], hex("20010db8000000000000000000000001"));
    }

    #[test]
    fn freshness() {
        let mut sc = ServerCookie::from_bytes(&[1; 16]).unwrap();
        sc.timestamp = 1_000_000;
        assert!(sc.is_fresh(1_000_000) && !sc.needs_refresh(1_000_000));
        assert!(sc.is_fresh(1_000_000 + 3600) && sc.needs_refresh(1_000_000 + 3600));
        assert!(!sc.is_fresh(1_000_000 + 3601));
        assert!(sc.is_fresh(1_000_000 - 300) && !sc.needs_refresh(1_000_000 - 300));
        assert!(!sc.is_fresh(1_000_000 - 301) && sc.needs_refresh(1_000_000 - 301));
        assert!(!sc.needs_refresh(1_000_000 + 1800));
        assert!(sc.needs_refresh(1_000_000 + 1801));
        // Serial arithmetic across the 2^32 wrap (RFC 1982).
        sc.timestamp = u32::MAX - 10;
        assert!(sc.is_fresh(100));
        assert!(!sc.is_fresh(u32::MAX - 400));
    }

    /// RFC 9018 Appendix A test vectors.
    #[cfg(feature = "cookie-siphash")]
    #[test]
    fn rfc9018_vectors() {
        let secret1: [u8; 16] = hex("e5e973e5a6b2a43f48e7dc849e37bfcf").try_into().unwrap();
        let old_secret: [u8; 16] = hex("dd3bdf9344b678b185a6f5cb60fca715").try_into().unwrap();
        let new_secret: [u8; 16] = hex("445536bcd2513298075a5d379663c962").try_into().unwrap();
        struct V {
            client_ip: &'static str,
            secret: [u8; 16],
            cookie: &'static str,
        }
        let generated = [
            // A.1: learning a new server cookie.
            V {
                client_ip: "198.51.100.100",
                secret: secret1,
                cookie: "2464c4abcf10c957010000005cf79f111f8130c3eee29480",
            },
            // A.2: the same client, renewed cookie.
            V {
                client_ip: "198.51.100.100",
                secret: secret1,
                cookie: "2464c4abcf10c957010000005cf7a871d4a564a1442aca77",
            },
            // A.3: another client, renewed cookie.
            V {
                client_ip: "203.0.113.203",
                secret: secret1,
                cookie: "fc93fc62807ddb86010000005cf7a9acf73a7810aca2381e",
            },
            // A.4: IPv6 client, new secret.
            V {
                client_ip: "2001:db8:220:1:59de:d0f4:8769:82b8",
                secret: new_secret,
                cookie: "22681ab97d52c298010000005cf7c609a6bb79d16625507a",
            },
        ];
        for v in &generated {
            let raw = hex(v.cookie);
            let c = Cookie::parse_option(&mut WireReader::new(&raw)).unwrap();
            let ip: IpAddr = v.client_ip.parse().unwrap();
            let sc = c.server_cookie_v1().unwrap();
            let fresh = ServerCookie::generate(&v.secret, &c.client(), ip, sc.timestamp);
            assert_eq!(fresh, sc, "{}", v.cookie);
            assert!(sc.verify(&v.secret, &c.client(), ip));
            assert!(!sc.verify(&old_secret, &c.client(), ip));
        }
        // Received cookies that must verify as they are: A.3 has reserved
        // bytes set; A.4's was made with the old secret.
        let received = [
            V {
                client_ip: "203.0.113.203",
                secret: secret1,
                cookie: "fc93fc62807ddb8601abcdef5cf78f71a314227b6679ebf5",
            },
            V {
                client_ip: "2001:db8:220:1:59de:d0f4:8769:82b8",
                secret: old_secret,
                cookie: "22681ab97d52c298010000005cf7c57926556bd0934c72f8",
            },
        ];
        for v in &received {
            let raw = hex(v.cookie);
            let c = Cookie::parse_option(&mut WireReader::new(&raw)).unwrap();
            let ip: IpAddr = v.client_ip.parse().unwrap();
            let sc = c.server_cookie_v1().unwrap();
            assert!(sc.verify(&v.secret, &c.client(), ip), "{}", v.cookie);
            // Wrong client address, cookie or secret: rejected.
            assert!(!sc.verify(&v.secret, &c.client(), "192.0.2.1".parse().unwrap()));
            assert!(!sc.verify(&v.secret, &[0; 8], ip));
            assert!(!sc.verify(&new_secret, &c.client(), ip));
            let mut v2 = sc;
            v2.version = 2;
            assert!(!v2.verify(&v.secret, &c.client(), ip));
        }
    }
}
