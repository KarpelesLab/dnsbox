//! The SvcParamKey registry (RFC 9460 §14.3).

open_enum! {
    /// A service parameter key (RFC 9460 §2.1, §14.3; IANA "Service
    /// Parameter Keys (SvcParamKeys)").
    ///
    /// Presentation format is the registered lowercase name, or
    /// `key<number>` for any key (RFC 9460 §2.1), which is also how
    /// unregistered keys are displayed.
    pub struct SvcParamKey(u16), generic "key";
    /// Keys that clients must understand to use the record (RFC 9460 §8).
    MANDATORY = 0 => "mandatory",
    /// Additional supported ALPN protocol IDs (RFC 9460 §7.1).
    ALPN = 1 => "alpn",
    /// No support for the scheme's default ALPN set (RFC 9460 §7.1).
    NO_DEFAULT_ALPN = 2 => "no-default-alpn",
    /// Port of the alternative endpoint (RFC 9460 §7.2).
    PORT = 3 => "port",
    /// IPv4 address hints (RFC 9460 §7.3).
    IPV4HINT = 4 => "ipv4hint",
    /// TLS Encrypted ClientHello configuration list (RFC 9848).
    ECH = 5 => "ech",
    /// IPv6 address hints (RFC 9460 §7.3).
    IPV6HINT = 6 => "ipv6hint",
    /// DNS over HTTPS path template (RFC 9461 §5).
    DOHPATH = 7 => "dohpath",
    /// The service is reachable as an Oblivious HTTP target (RFC 9540 §4).
    OHTTP = 8 => "ohttp",
    /// Supported TLS named groups, in order of preference
    /// (draft-ietf-tls-key-share-prediction §3.1).
    TLS_SUPPORTED_GROUPS = 9 => "tls-supported-groups",
    /// DNS over CoAP resource path (RFC 9953 §3).
    DOCPATH = 10 => "docpath",
    /// PvD configuration available at the well-known path
    /// (draft-ietf-intarea-proxy-config §2.1).
    PVD = 11 => "pvd",
    /// Per-transport operator confidence in serving the query load
    /// (draft-johani-dnsop-svcb-oots §2).
    OOTS = 12 => "oots",
}

impl SvcParamKey {
    /// Key 65535, reserved as the "Invalid key" (RFC 9460 §14.3.2). RDATA
    /// using it is malformed: wire and presentation parsing refuse it, and
    /// [`SvcbBuilder`](super::SvcbBuilder) never writes it.
    pub const INVALID: SvcParamKey = SvcParamKey::new(65535);

    /// Whether the key is in the private-use range 65280–65534
    /// (RFC 9460 §14.3.2).
    #[inline]
    #[must_use]
    pub const fn is_private_use(self) -> bool {
        self.get() >= 65280 && self.get() <= 65534
    }
}

#[cfg(test)]
mod tests {
    use super::SvcParamKey;
    use crate::Error;
    use std::string::ToString;

    #[test]
    fn registry() {
        assert_eq!(SvcParamKey::all().count(), 13);
        for (i, (k, _)) in SvcParamKey::all().enumerate() {
            assert_eq!(usize::from(k.get()), i);
        }
        assert_eq!(SvcParamKey::ALPN.to_string(), "alpn");
        assert_eq!(SvcParamKey::new(667).to_string(), "key667");
        assert_eq!(SvcParamKey::INVALID.to_string(), "key65535");
        assert_eq!("key1".parse(), Ok(SvcParamKey::ALPN));
        assert_eq!("No-Default-ALPN".parse(), Ok(SvcParamKey::NO_DEFAULT_ALPN));
        assert_eq!("key65536".parse::<SvcParamKey>(), Err(Error::InvalidText));
        assert_eq!("key".parse::<SvcParamKey>(), Err(Error::InvalidText));
        assert_eq!("foo".parse::<SvcParamKey>(), Err(Error::UnknownMnemonic));
        assert!(SvcParamKey::new(65280).is_private_use());
        assert!(SvcParamKey::new(65534).is_private_use());
        assert!(!SvcParamKey::INVALID.is_private_use());
        assert!(!SvcParamKey::OOTS.is_private_use());
    }
}
