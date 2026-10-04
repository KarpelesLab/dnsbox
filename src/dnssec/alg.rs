//! DNSSEC protocol-number registries: security algorithms, DS digest types
//! and NSEC3 hash algorithms.

open_enum! {
    /// A DNSSEC security algorithm number (RFC 4034 §A.1, IANA "DNS
    /// Security Algorithm Numbers"), as found in DNSKEY, RRSIG, DS, KEY and
    /// SIG records.
    ///
    /// The presentation form of unregistered values is the bare number
    /// (RFC 4034 §2.2, §3.2, §5.3).
    pub struct Algorithm(u8), generic "";
    /// Delete DS / delete DNSKEY (RFC 4034 §A.1, RFC 8078 §4).
    DELETE = 0 => "DELETE",
    /// RSA/MD5 — deprecated, MUST NOT be used (RFC 6725, RFC 8624).
    RSAMD5 = 1 => "RSAMD5",
    /// Diffie-Hellman (RFC 2539).
    DH = 2 => "DH",
    /// DSA/SHA-1 (RFC 3755, RFC 2536).
    DSA = 3 => "DSA",
    /// RSA/SHA-1 (RFC 3110).
    RSASHA1 = 5 => "RSASHA1",
    /// DSA-NSEC3-SHA1 (RFC 5155 §2).
    DSA_NSEC3_SHA1 = 6 => "DSA-NSEC3-SHA1",
    /// RSASHA1-NSEC3-SHA1 (RFC 5155 §2).
    RSASHA1_NSEC3_SHA1 = 7 => "RSASHA1-NSEC3-SHA1",
    /// RSA/SHA-256 (RFC 5702).
    RSASHA256 = 8 => "RSASHA256",
    /// RSA/SHA-512 (RFC 5702).
    RSASHA512 = 10 => "RSASHA512",
    /// GOST R 34.10-2001 (RFC 5933) — deprecated (RFC 9558).
    ECC_GOST = 12 => "ECC-GOST",
    /// ECDSA Curve P-256 with SHA-256 (RFC 6605).
    ECDSAP256SHA256 = 13 => "ECDSAP256SHA256",
    /// ECDSA Curve P-384 with SHA-384 (RFC 6605).
    ECDSAP384SHA384 = 14 => "ECDSAP384SHA384",
    /// Ed25519 (RFC 8080).
    ED25519 = 15 => "ED25519",
    /// Ed448 (RFC 8080).
    ED448 = 16 => "ED448",
    /// SM2 signing with SM3 hashing (RFC 9563).
    SM2SM3 = 17 => "SM2SM3",
    /// GOST R 34.10-2012 (RFC 9558).
    ECC_GOST12 = 23 => "ECC-GOST12",
    /// Reserved for indirect keys (RFC 4034 §A.1).
    INDIRECT = 252 => "INDIRECT",
    /// Private algorithm identified by a domain name (RFC 4034 §A.1.1).
    PRIVATEDNS = 253 => "PRIVATEDNS",
    /// Private algorithm identified by an OID (RFC 4034 §A.1.1).
    PRIVATEOID = 254 => "PRIVATEOID",
}

impl Algorithm {
    /// Whether this is one of the RSA algorithms whose public key uses the
    /// RFC 3110 format (RSAMD5, RSASHA1, RSASHA1-NSEC3-SHA1, RSASHA256,
    /// RSASHA512).
    pub const fn is_rsa(self) -> bool {
        matches!(self.0, 1 | 5 | 7 | 8 | 10)
    }

    /// The size in octets of public keys of this algorithm, for the
    /// fixed-size algorithms: ECDSA (RFC 6605 §4) and EdDSA (RFC 8080 §3).
    pub const fn public_key_len(self) -> Option<usize> {
        match self.0 {
            13 => Some(64),
            14 => Some(96),
            15 => Some(32),
            16 => Some(57),
            _ => None,
        }
    }

    /// The size in octets of signatures of this algorithm, for the
    /// fixed-size algorithms: ECDSA (RFC 6605 §4) and EdDSA (RFC 8080 §4).
    pub const fn signature_len(self) -> Option<usize> {
        match self.0 {
            13 => Some(64),
            14 => Some(96),
            15 => Some(64),
            16 => Some(114),
            _ => None,
        }
    }
}

open_enum! {
    /// A DS digest type (RFC 4034 §A.2, IANA "Delegation Signer (DS)
    /// Resource Record (RR) Type Digest Algorithms"), as found in DS, CDS,
    /// DLV and TA records.
    pub struct DigestType(u8), generic "", aliases {
        "SHA1" => SHA1,
        "SHA256" => SHA256,
        "SHA384" => SHA384,
    };
    /// SHA-1 (RFC 3658, RFC 4034 §5.1.4).
    SHA1 = 1 => "SHA-1",
    /// SHA-256 (RFC 4509).
    SHA256 = 2 => "SHA-256",
    /// GOST R 34.11-94 (RFC 5933) — deprecated (RFC 9558).
    GOST = 3 => "GOST",
    /// SHA-384 (RFC 6605).
    SHA384 = 4 => "SHA-384",
    /// GOST R 34.11-2012 (RFC 9558).
    GOST12 = 5 => "GOST12",
    /// SM3 (RFC 9563).
    SM3 = 6 => "SM3",
}

impl DigestType {
    /// The digest length in octets of a registered digest type.
    pub const fn digest_len(self) -> Option<usize> {
        match self.0 {
            1 => Some(20),
            2 | 3 | 5 | 6 => Some(32),
            4 => Some(48),
            _ => None,
        }
    }
}

open_enum! {
    /// An NSEC3 hash algorithm (RFC 5155 §11, IANA "DNSSEC NSEC3 Hash
    /// Algorithms").
    pub struct Nsec3HashAlgorithm(u8), generic "", aliases { "SHA1" => SHA1 };
    /// SHA-1 (RFC 5155 §5).
    SHA1 = 1 => "SHA-1",
}

impl Nsec3HashAlgorithm {
    /// The hash length in octets of a registered algorithm.
    pub const fn hash_len(self) -> Option<usize> {
        match self.0 {
            1 => Some(20),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::ToString;

    #[test]
    fn registries() {
        assert_eq!(Algorithm::RSASHA256.get(), 8);
        assert_eq!(Algorithm::ED448.to_string(), "ED448");
        assert_eq!(Algorithm::new(200).to_string(), "200");
        assert_eq!("rsasha1-nsec3-sha1".parse(), Ok(Algorithm::RSASHA1_NSEC3_SHA1));
        assert_eq!("13".parse(), Ok(Algorithm::ECDSAP256SHA256));
        assert!(Algorithm::RSASHA512.is_rsa() && !Algorithm::ED25519.is_rsa());
        assert_eq!(Algorithm::ED25519.public_key_len(), Some(32));
        assert_eq!(Algorithm::ECDSAP384SHA384.signature_len(), Some(96));
        assert_eq!(Algorithm::RSASHA256.signature_len(), None);
        assert_eq!(Algorithm::RSASHA256.public_key_len(), None);

        assert_eq!(DigestType::SHA256.to_string(), "SHA-256");
        assert_eq!("sha384".parse(), Ok(DigestType::SHA384));
        assert_eq!("SHA-1".parse(), Ok(DigestType::SHA1));
        assert_eq!(DigestType::SHA384.digest_len(), Some(48));
        assert_eq!(DigestType::new(0).digest_len(), None);

        assert_eq!(Nsec3HashAlgorithm::SHA1.hash_len(), Some(20));
        assert_eq!(Nsec3HashAlgorithm::new(2).hash_len(), None);
        assert_eq!(Nsec3HashAlgorithm::new(2).to_string(), "2");
    }
}
