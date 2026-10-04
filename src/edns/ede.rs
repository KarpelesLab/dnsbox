//! Extended DNS Errors (RFC 8914).

use core::fmt;

use super::{ComposeOption, OptionCode, ParseOption};
use crate::Result;
use crate::text::fmt_quoted;
use crate::wire::{Composer, WireReader};

// The complete IANA registry as of 2026-10-04
// (https://www.iana.org/assignments/dns-parameters/extended-dns-error-codes.csv).
open_enum! {
    /// An Extended DNS Error INFO-CODE (RFC 8914 §4; IANA "Extended DNS
    /// Error Codes" registry).
    ///
    /// Displays as the registered purpose (`Stale Answer`); unregistered
    /// codes display as the bare number.
    ///
    /// ```
    /// use dnsbox::edns::InfoCode;
    ///
    /// assert_eq!(InfoCode::DNSKEY_MISSING.get(), 9);
    /// assert_eq!(InfoCode::DNSKEY_MISSING.to_string(), "DNSKEY Missing");
    /// assert_eq!("blocked".parse(), Ok(InfoCode::BLOCKED));
    /// assert_eq!(InfoCode::new(50000).to_string(), "50000");
    /// ```
    pub struct InfoCode(u16), generic "";
    /// Other Error: none of the other codes apply (RFC 8914 §4.1).
    OTHER_ERROR = 0 => "Other Error",
    /// Unsupported DNSKEY Algorithm (RFC 8914 §4.2).
    UNSUPPORTED_DNSKEY_ALGORITHM = 1 => "Unsupported DNSKEY Algorithm",
    /// Unsupported DS Digest Type (RFC 8914 §4.3).
    UNSUPPORTED_DS_DIGEST_TYPE = 2 => "Unsupported DS Digest Type",
    /// Stale Answer, served from expired cache data (RFC 8914 §4.4,
    /// RFC 8767).
    STALE_ANSWER = 3 => "Stale Answer",
    /// Forged Answer, e.g. by policy (RFC 8914 §4.5).
    FORGED_ANSWER = 4 => "Forged Answer",
    /// DNSSEC Indeterminate (RFC 8914 §4.6).
    DNSSEC_INDETERMINATE = 5 => "DNSSEC Indeterminate",
    /// DNSSEC Bogus (RFC 8914 §4.7).
    DNSSEC_BOGUS = 6 => "DNSSEC Bogus",
    /// Signature Expired (RFC 8914 §4.8).
    SIGNATURE_EXPIRED = 7 => "Signature Expired",
    /// Signature Not Yet Valid (RFC 8914 §4.9).
    SIGNATURE_NOT_YET_VALID = 8 => "Signature Not Yet Valid",
    /// DNSKEY Missing (RFC 8914 §4.10).
    DNSKEY_MISSING = 9 => "DNSKEY Missing",
    /// RRSIGs Missing (RFC 8914 §4.11).
    RRSIGS_MISSING = 10 => "RRSIGs Missing",
    /// No Zone Key Bit Set (RFC 8914 §4.12).
    NO_ZONE_KEY_BIT_SET = 11 => "No Zone Key Bit Set",
    /// NSEC Missing (RFC 8914 §4.13).
    NSEC_MISSING = 12 => "NSEC Missing",
    /// Cached Error (RFC 8914 §4.14).
    CACHED_ERROR = 13 => "Cached Error",
    /// Not Ready (RFC 8914 §4.15).
    NOT_READY = 14 => "Not Ready",
    /// Blocked by the operator (RFC 8914 §4.16).
    BLOCKED = 15 => "Blocked",
    /// Censored by an external requirement (RFC 8914 §4.17).
    CENSORED = 16 => "Censored",
    /// Filtered at the client's request (RFC 8914 §4.18).
    FILTERED = 17 => "Filtered",
    /// Prohibited: the client is not authorized (RFC 8914 §4.19).
    PROHIBITED = 18 => "Prohibited",
    /// Stale NXDomain Answer (RFC 8914 §4.20).
    STALE_NXDOMAIN_ANSWER = 19 => "Stale NXDomain Answer",
    /// Not Authoritative (RFC 8914 §4.21).
    NOT_AUTHORITATIVE = 20 => "Not Authoritative",
    /// Not Supported (RFC 8914 §4.22).
    NOT_SUPPORTED = 21 => "Not Supported",
    /// No Reachable Authority (RFC 8914 §4.23).
    NO_REACHABLE_AUTHORITY = 22 => "No Reachable Authority",
    /// Network Error (RFC 8914 §4.24).
    NETWORK_ERROR = 23 => "Network Error",
    /// Invalid Data (RFC 8914 §4.25).
    INVALID_DATA = 24 => "Invalid Data",
    /// Signature Expired before Valid (NLnet Labs Unbound).
    SIGNATURE_EXPIRED_BEFORE_VALID = 25 => "Signature Expired before Valid",
    /// Too Early: 0-RTT data refused (RFC 9250 §4.5).
    TOO_EARLY = 26 => "Too Early",
    /// Unsupported NSEC3 Iterations Value (RFC 9276 §3.2).
    UNSUPPORTED_NSEC3_ITERATIONS_VALUE = 27 => "Unsupported NSEC3 Iterations Value",
    /// Unable to conform to policy (draft-homburg-dnsop-codcp).
    UNABLE_TO_CONFORM_TO_POLICY = 28 => "Unable to conform to policy",
    /// Synthesized (PowerDNS).
    SYNTHESIZED = 29 => "Synthesized",
    /// Invalid Query Type (RFC 9824).
    INVALID_QUERY_TYPE = 30 => "Invalid Query Type",
    /// Rate Limited (draft-muks-dns-ede-rate-limited §2).
    RATE_LIMITED = 31 => "Rate Limited",
    /// Over Quota (draft-muks-dns-ede-rate-limited §3).
    OVER_QUOTA = 32 => "Over Quota",
    /// Negative Trust Anchor (draft-farrokhi-dnsop-ede-nta).
    NEGATIVE_TRUST_ANCHOR = 33 => "Negative Trust Anchor",
    /// New Delegation Only (draft-ietf-deleg).
    NEW_DELEGATION_ONLY = 34 => "New Delegation Only",
    /// Blocked by Upstream DNS Server (RFC-ietf-dnsop-structured-dns-error).
    BLOCKED_BY_UPSTREAM = 35 => "Blocked by Upstream DNS Server",
}

impl InfoCode {
    /// Whether the code lies in the private-use range 49152–65535
    /// (RFC 8914 §5.2).
    #[inline]
    #[must_use]
    pub const fn is_private_use(self) -> bool {
        self.0 >= 49152
    }
}

/// `EDE` option: an Extended DNS Error (RFC 8914 §2).
///
/// EXTRA-TEXT is meant to be UTF-8 but is kept as raw bytes (it may also
/// carry a trailing NUL, §2); [`extra_text_str`](Self::extra_text_str)
/// gives it as text when valid. A message may carry several EDE options.
///
/// ```
/// use dnsbox::edns::{ExtendedError, InfoCode, Opt};
///
/// // EDE 18 (Prohibited) with an explanation.
/// let opt = Opt::new(b"\x00\x0f\x00\x09\x00\x12blocked")?;
/// let ede: ExtendedError<'_> = opt.get().expect("present")?;
/// assert_eq!(ede.info_code, InfoCode::PROHIBITED);
/// assert_eq!(ede.extra_text_str(), Some("blocked"));
/// assert_eq!(ede.to_string(), r#"EDE=18 (Prohibited) "blocked""#);
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ExtendedError<'a> {
    /// INFO-CODE.
    pub info_code: InfoCode,
    /// EXTRA-TEXT, possibly empty.
    pub extra_text: &'a [u8],
}

impl<'a> ExtendedError<'a> {
    /// Builds an EDE from a code and (possibly empty) text.
    #[inline]
    #[must_use]
    pub const fn new(info_code: InfoCode, extra_text: &'a [u8]) -> Self {
        ExtendedError {
            info_code,
            extra_text,
        }
    }

    /// EXTRA-TEXT as a string, if it is valid UTF-8.
    #[inline]
    #[must_use]
    pub fn extra_text_str(&self) -> Option<&'a str> {
        core::str::from_utf8(self.extra_text).ok()
    }
}

impl<'a> ParseOption<'a> for ExtendedError<'a> {
    const CODE: OptionCode = OptionCode::EDE;

    fn parse_option(data: &mut WireReader<'a>) -> Result<Self> {
        let info_code = InfoCode::new(data.read_u16()?);
        Ok(ExtendedError {
            info_code,
            extra_text: data.read_rest(),
        })
    }
}

impl ComposeOption for ExtendedError<'_> {
    #[inline]
    fn code(&self) -> OptionCode {
        OptionCode::EDE
    }

    fn compose_option<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_u16(self.info_code.get())?;
        c.put_bytes(self.extra_text)
    }
}

impl fmt::Display for ExtendedError<'_> {
    /// `EDE=<code>`, then ` (<purpose>)` for a registered code and the
    /// quoted EXTRA-TEXT if any: `EDE=9 (DNSKEY Missing) "no SEP"`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EDE={}", self.info_code.get())?;
        if let Some(m) = self.info_code.mnemonic() {
            write!(f, " ({m})")?;
        }
        if !self.extra_text.is_empty() {
            f.write_str(" ")?;
            fmt_quoted(f, self.extra_text)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use crate::edns::tests::{parse, round_trip};
    use std::string::ToString;

    #[test]
    fn ede() {
        // 1.1.1.1 answering dnssec-failed.org (captured October 2026).
        round_trip(
            OptionCode::EDE,
            b"\x00\x09no SEP matching the DS found for dnssec-failed.org.",
            "EDE=9 (DNSKEY Missing) \"no SEP matching the DS found for dnssec-failed.org.\"",
        );
        round_trip(OptionCode::EDE, b"\x00\x12", "EDE=18 (Prohibited)");
        round_trip(OptionCode::EDE, b"\xc0\x00\"\x00", "EDE=49152 \"\\\"\\000\"");
        assert_eq!(parse(OptionCode::EDE, b"\x00"), Err(Error::UnexpectedEof));
        let e = ExtendedError::new(InfoCode::STALE_ANSWER, b"stale");
        assert_eq!(e.extra_text_str(), Some("stale"));
        assert_eq!(ExtendedError::new(InfoCode::BLOCKED, b"\xff").extra_text_str(), None);
    }

    #[test]
    fn registry() {
        let all: std::vec::Vec<_> = InfoCode::all().collect();
        assert_eq!(all.len(), 36);
        for (i, (code, name)) in all.iter().enumerate() {
            assert_eq!(code.get() as usize, i);
            assert_eq!(name.parse::<InfoCode>(), Ok(*code));
            assert_eq!(code.to_string(), *name);
        }
        assert!(InfoCode::new(49152).is_private_use() && !InfoCode::new(49151).is_private_use());
        assert_eq!("24".parse(), Ok(InfoCode::INVALID_DATA));
    }
}
