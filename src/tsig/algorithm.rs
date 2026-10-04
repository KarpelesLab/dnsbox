//! The TSIG algorithm names of RFC 8945 §6.

use core::fmt;

use crate::name::Name;

/// A TSIG MAC algorithm known to dnsbox (RFC 8945 §6, IANA "TSIG Algorithm
/// Names").
///
/// TSIG identifies algorithms by domain name; the [`Tsig`](crate::rdata::Tsig)
/// record keeps whatever name it carries, so unknown algorithms still
/// round-trip. This enum only lists the algorithms dnsbox can map to a MAC
/// (GSS-TSIG, RFC 3645, needs a GSS-API context and is not included).
///
/// The `-128`/`-192`/`-256` variants are the truncated forms of RFC 4868 /
/// RFC 8945 §6: the same HMAC, with the MAC truncated to that many bits.
///
/// ```
/// use dnsbox::tsig::TsigAlgorithm;
///
/// let alg: TsigAlgorithm = "HMAC-SHA256.".parse()?;
/// assert_eq!(alg, TsigAlgorithm::HmacSha256);
/// assert_eq!((alg.digest_len(), alg.mac_len()), (32, 32));
/// assert_eq!(TsigAlgorithm::HmacSha256_128.mac_len(), 16);
/// assert_eq!(alg.to_string(), "hmac-sha256.");
/// assert_eq!(alg.as_wire(), b"\x0bhmac-sha256\x00");
/// assert_eq!(TsigAlgorithm::from_name(alg.name()), Some(alg));
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TsigAlgorithm {
    /// `HMAC-MD5.SIG-ALG.REG.INT` (RFC 8945 §6: mandatory to implement,
    /// "not recommended" for use).
    HmacMd5,
    /// `hmac-sha1` (RFC 4635).
    HmacSha1,
    /// `hmac-sha224` (RFC 4635).
    HmacSha224,
    /// `hmac-sha256` (RFC 4635; mandatory, recommended).
    HmacSha256,
    /// `hmac-sha256-128`: HMAC-SHA256 truncated to 128 bits (RFC 8945 §6).
    HmacSha256_128,
    /// `hmac-sha384` (RFC 4635).
    HmacSha384,
    /// `hmac-sha384-192`: HMAC-SHA384 truncated to 192 bits.
    HmacSha384_192,
    /// `hmac-sha512` (RFC 4635).
    HmacSha512,
    /// `hmac-sha512-256`: HMAC-SHA512 truncated to 256 bits.
    HmacSha512_256,
}

impl TsigAlgorithm {
    /// Every algorithm, in RFC 8945 §6 order.
    pub const ALL: [TsigAlgorithm; 9] = [
        TsigAlgorithm::HmacMd5,
        TsigAlgorithm::HmacSha1,
        TsigAlgorithm::HmacSha224,
        TsigAlgorithm::HmacSha256,
        TsigAlgorithm::HmacSha256_128,
        TsigAlgorithm::HmacSha384,
        TsigAlgorithm::HmacSha384_192,
        TsigAlgorithm::HmacSha512,
        TsigAlgorithm::HmacSha512_256,
    ];

    /// The algorithm name in uncompressed, lowercase wire format (the
    /// canonical form used in MAC input, RFC 8945 §4.3.3).
    #[must_use]
    pub const fn as_wire(self) -> &'static [u8] {
        match self {
            TsigAlgorithm::HmacMd5 => b"\x08hmac-md5\x07sig-alg\x03reg\x03int\x00",
            TsigAlgorithm::HmacSha1 => b"\x09hmac-sha1\x00",
            TsigAlgorithm::HmacSha224 => b"\x0bhmac-sha224\x00",
            TsigAlgorithm::HmacSha256 => b"\x0bhmac-sha256\x00",
            TsigAlgorithm::HmacSha256_128 => b"\x0fhmac-sha256-128\x00",
            TsigAlgorithm::HmacSha384 => b"\x0bhmac-sha384\x00",
            TsigAlgorithm::HmacSha384_192 => b"\x0fhmac-sha384-192\x00",
            TsigAlgorithm::HmacSha512 => b"\x0bhmac-sha512\x00",
            TsigAlgorithm::HmacSha512_256 => b"\x0fhmac-sha512-256\x00",
        }
    }

    /// The algorithm name as a [`Name`].
    #[must_use]
    pub fn name(self) -> Name<'static> {
        // The constants above are valid names; ROOT is unreachable.
        Name::from_wire(self.as_wire()).unwrap_or(Name::ROOT)
    }

    /// Looks up an algorithm by name (ASCII-case-insensitively).
    #[must_use]
    pub fn from_name(name: Name<'_>) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.name() == name)
    }

    /// Output length of the underlying HMAC, in bytes.
    #[must_use]
    pub const fn digest_len(self) -> usize {
        match self {
            TsigAlgorithm::HmacMd5 => 16,
            TsigAlgorithm::HmacSha1 => 20,
            TsigAlgorithm::HmacSha224 => 28,
            TsigAlgorithm::HmacSha256 | TsigAlgorithm::HmacSha256_128 => 32,
            TsigAlgorithm::HmacSha384 | TsigAlgorithm::HmacSha384_192 => 48,
            TsigAlgorithm::HmacSha512 | TsigAlgorithm::HmacSha512_256 => 64,
        }
    }

    /// Length of the MAC this algorithm generates: the digest length, or
    /// the truncated length for the `-128`/`-192`/`-256` variants.
    #[must_use]
    pub const fn mac_len(self) -> usize {
        match self {
            TsigAlgorithm::HmacSha256_128 => 16,
            TsigAlgorithm::HmacSha384_192 => 24,
            TsigAlgorithm::HmacSha512_256 => 32,
            other => other.digest_len(),
        }
    }
}

impl core::str::FromStr for TsigAlgorithm {
    type Err = crate::Error;

    /// Parses an algorithm name (`hmac-sha256`, `HMAC-MD5.SIG-ALG.REG.INT.`,
    /// ASCII-case-insensitively, with or without the trailing dot), the
    /// inverse of `Display`: [`Error::UnknownMnemonic`](crate::Error::UnknownMnemonic)
    /// for a name that is not one of [`ALL`](Self::ALL), the name parsing
    /// error for malformed text.
    fn from_str(s: &str) -> crate::Result<Self> {
        let name: crate::NameBuf = s.parse()?;
        Self::from_name(name.as_name()).ok_or(crate::Error::UnknownMnemonic)
    }
}

impl fmt::Display for TsigAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.name(), f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NameBuf;
    use std::string::ToString;

    #[test]
    fn names() {
        for a in TsigAlgorithm::ALL {
            let n = a.name();
            assert!(!n.is_root(), "{a:?}");
            assert_eq!(n.as_contiguous(), Some(a.as_wire()));
            assert_eq!(TsigAlgorithm::from_name(n), Some(a));
            assert!(a.mac_len() <= a.digest_len());
        }
        let upper: NameBuf = "HMAC-MD5.SIG-ALG.REG.INT".parse().unwrap();
        assert_eq!(
            TsigAlgorithm::from_name(upper.as_name()),
            Some(TsigAlgorithm::HmacMd5)
        );
        let gss: NameBuf = "gss-tsig".parse().unwrap();
        assert_eq!(TsigAlgorithm::from_name(gss.as_name()), None);
        assert_eq!(TsigAlgorithm::HmacSha256.to_string(), "hmac-sha256.");
        for a in TsigAlgorithm::ALL {
            assert_eq!(a.to_string().parse(), Ok(a));
        }
        assert_eq!("HMAC-SHA1".parse(), Ok(TsigAlgorithm::HmacSha1));
        assert_eq!(
            "gss-tsig".parse::<TsigAlgorithm>(),
            Err(crate::Error::UnknownMnemonic)
        );
        assert_eq!(
            "a..b".parse::<TsigAlgorithm>(),
            Err(crate::Error::EmptyLabel)
        );
    }
}
