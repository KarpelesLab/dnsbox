//! Resource record TYPEs and QTYPEs (RFC 1035 §3.2.2–3.2.3, RFC 6895 §3.1).

// The complete IANA registry as of 2026-08-20
// (https://www.iana.org/assignments/dns-parameters/dns-parameters-4.csv).
open_enum! {
    /// A resource record TYPE (or QTYPE), as a 16-bit open newtype.
    ///
    /// Every value in the IANA "Resource Record (RR) TYPEs" registry has an
    /// associated constant. Unassigned values are representable and round-trip
    /// unchanged (RFC 3597); they display as `TYPEnnn`.
    ///
    /// ```
    /// use dnsbox::Rtype;
    ///
    /// assert_eq!(Rtype::AAAA.get(), 28);
    /// assert_eq!("aaaa".parse::<Rtype>(), Ok(Rtype::AAAA));
    /// assert_eq!("TYPE65534".parse::<Rtype>(), Ok(Rtype::new(65534)));
    /// assert_eq!(Rtype::new(65534).to_string(), "TYPE65534");
    /// ```
    pub struct Rtype(u16), generic "TYPE", aliases { "*" => ANY };
    /// IPv4 host address (RFC 1035 §3.4.1).
    A = 1 => "A",
    /// Authoritative name server (RFC 1035 §3.3.11).
    NS = 2 => "NS",
    /// Mail destination — obsolete, use MX (RFC 1035 §3.3.4).
    MD = 3 => "MD",
    /// Mail forwarder — obsolete, use MX (RFC 1035 §3.3.5).
    MF = 4 => "MF",
    /// Canonical name for an alias (RFC 1035 §3.3.1).
    CNAME = 5 => "CNAME",
    /// Start of a zone of authority (RFC 1035 §3.3.13).
    SOA = 6 => "SOA",
    /// Mailbox domain name — experimental (RFC 1035 §3.3.3).
    MB = 7 => "MB",
    /// Mail group member — experimental (RFC 1035 §3.3.6).
    MG = 8 => "MG",
    /// Mail rename domain name — experimental (RFC 1035 §3.3.8).
    MR = 9 => "MR",
    /// Null RR — experimental (RFC 1035 §3.3.10).
    NULL = 10 => "NULL",
    /// Well-known service description (RFC 1035 §3.4.2).
    WKS = 11 => "WKS",
    /// Domain name pointer (RFC 1035 §3.3.12).
    PTR = 12 => "PTR",
    /// Host information (RFC 1035 §3.3.2).
    HINFO = 13 => "HINFO",
    /// Mailbox or mail list information (RFC 1035 §3.3.7).
    MINFO = 14 => "MINFO",
    /// Mail exchange (RFC 1035 §3.3.9).
    MX = 15 => "MX",
    /// Text strings (RFC 1035 §3.3.14).
    TXT = 16 => "TXT",
    /// Responsible person (RFC 1183 §2.2).
    RP = 17 => "RP",
    /// AFS database location (RFC 1183 §1, RFC 5864).
    AFSDB = 18 => "AFSDB",
    /// X.25 PSDN address (RFC 1183 §3.1).
    X25 = 19 => "X25",
    /// ISDN address (RFC 1183 §3.2).
    ISDN = 20 => "ISDN",
    /// Route through (RFC 1183 §3.3).
    RT = 21 => "RT",
    /// NSAP address — deprecated (RFC 1706).
    NSAP = 22 => "NSAP",
    /// NSAP domain name pointer — deprecated (RFC 1706).
    NSAP_PTR = 23 => "NSAP-PTR",
    /// Security signature (RFC 2535, RFC 2931).
    SIG = 24 => "SIG",
    /// Security key (RFC 2535, RFC 3445).
    KEY = 25 => "KEY",
    /// X.400 mail mapping information (RFC 2163).
    PX = 26 => "PX",
    /// Geographical position (RFC 1712).
    GPOS = 27 => "GPOS",
    /// IPv6 host address (RFC 3596 §2).
    AAAA = 28 => "AAAA",
    /// Location information (RFC 1876).
    LOC = 29 => "LOC",
    /// Next domain — obsolete (RFC 2535, RFC 3755).
    NXT = 30 => "NXT",
    /// Endpoint identifier (Nimrod).
    EID = 31 => "EID",
    /// Nimrod locator.
    NIMLOC = 32 => "NIMLOC",
    /// Server selection (RFC 2782).
    SRV = 33 => "SRV",
    /// ATM address (ATM Forum AF-DANS-0152.000).
    ATMA = 34 => "ATMA",
    /// Naming authority pointer (RFC 3403).
    NAPTR = 35 => "NAPTR",
    /// Key exchanger (RFC 2230).
    KX = 36 => "KX",
    /// Certificate (RFC 4398).
    CERT = 37 => "CERT",
    /// IPv6 address with indirection — obsolete, use AAAA (RFC 2874, RFC 6563).
    A6 = 38 => "A6",
    /// Delegation name (RFC 6672).
    DNAME = 39 => "DNAME",
    /// Kitchen sink (draft-eastlake-kitchen-sink).
    SINK = 40 => "SINK",
    /// EDNS(0) option pseudo-record (RFC 6891 §6.1).
    OPT = 41 => "OPT",
    /// Address prefix list (RFC 3123).
    APL = 42 => "APL",
    /// Delegation signer (RFC 4034 §5).
    DS = 43 => "DS",
    /// SSH key fingerprint (RFC 4255).
    SSHFP = 44 => "SSHFP",
    /// IPsec keying material (RFC 4025).
    IPSECKEY = 45 => "IPSECKEY",
    /// DNSSEC signature (RFC 4034 §3).
    RRSIG = 46 => "RRSIG",
    /// Next secure (RFC 4034 §4, RFC 9077).
    NSEC = 47 => "NSEC",
    /// DNSSEC public key (RFC 4034 §2).
    DNSKEY = 48 => "DNSKEY",
    /// DHCP identifier (RFC 4701).
    DHCID = 49 => "DHCID",
    /// Hashed next secure (RFC 5155 §3, RFC 9077).
    NSEC3 = 50 => "NSEC3",
    /// NSEC3 parameters (RFC 5155 §4).
    NSEC3PARAM = 51 => "NSEC3PARAM",
    /// TLS certificate association (RFC 6698).
    TLSA = 52 => "TLSA",
    /// S/MIME certificate association (RFC 8162).
    SMIMEA = 53 => "SMIMEA",
    /// Host identity protocol (RFC 8005).
    HIP = 55 => "HIP",
    /// Zone status information.
    NINFO = 56 => "NINFO",
    /// Resource key.
    RKEY = 57 => "RKEY",
    /// Trust anchor link.
    TALINK = 58 => "TALINK",
    /// Child DS (RFC 7344).
    CDS = 59 => "CDS",
    /// Child DNSKEY (RFC 7344).
    CDNSKEY = 60 => "CDNSKEY",
    /// OpenPGP key (RFC 7929).
    OPENPGPKEY = 61 => "OPENPGPKEY",
    /// Child-to-parent synchronization (RFC 7477).
    CSYNC = 62 => "CSYNC",
    /// Message digest over zone data (RFC 8976).
    ZONEMD = 63 => "ZONEMD",
    /// General-purpose service binding (RFC 9460).
    SVCB = 64 => "SVCB",
    /// SVCB-compatible type for HTTP (RFC 9460).
    HTTPS = 65 => "HTTPS",
    /// Endpoint discovery for delegation synchronization (RFC 9859).
    DSYNC = 66 => "DSYNC",
    /// Hierarchical host identity tag (RFC 9886).
    HHIT = 67 => "HHIT",
    /// UAS broadcast remote identification (RFC 9886).
    BRID = 68 => "BRID",
    /// Value coded per a UNECE recommendation
    /// (draft-woodcock-faltstrom-external-registry-rrtypes).
    UNECE = 69 => "UNECE",
    /// Value coded per an ISO standard
    /// (draft-woodcock-faltstrom-external-registry-rrtypes).
    ISO = 70 => "ISO",
    /// Sender policy framework — use TXT instead (RFC 7208 §3.1).
    SPF = 99 => "SPF",
    /// IANA-reserved.
    UINFO = 100 => "UINFO",
    /// IANA-reserved.
    UID = 101 => "UID",
    /// IANA-reserved.
    GID = 102 => "GID",
    /// IANA-reserved.
    UNSPEC = 103 => "UNSPEC",
    /// ILNP node identifier (RFC 6742 §2.1).
    NID = 104 => "NID",
    /// ILNP 32-bit locator (RFC 6742 §2.2).
    L32 = 105 => "L32",
    /// ILNP 64-bit locator (RFC 6742 §2.3).
    L64 = 106 => "L64",
    /// ILNP locator pointer (RFC 6742 §2.4).
    LP = 107 => "LP",
    /// EUI-48 address (RFC 7043 §3).
    EUI48 = 108 => "EUI48",
    /// EUI-64 address (RFC 7043 §4).
    EUI64 = 109 => "EUI64",
    /// NXDOMAIN indicator for compact denial of existence (RFC 9824).
    NXNAME = 128 => "NXNAME",
    /// Transaction key (RFC 2930).
    TKEY = 249 => "TKEY",
    /// Transaction signature (RFC 8945).
    TSIG = 250 => "TSIG",
    /// Incremental zone transfer — QTYPE only (RFC 1995).
    IXFR = 251 => "IXFR",
    /// Full zone transfer — QTYPE only (RFC 1035, RFC 5936).
    AXFR = 252 => "AXFR",
    /// Mailbox-related RRs (MB, MG or MR) — QTYPE only (RFC 1035).
    MAILB = 253 => "MAILB",
    /// Mail agent RRs — obsolete QTYPE (RFC 1035).
    MAILA = 254 => "MAILA",
    /// Any type (`*`) — QTYPE only (RFC 1035, RFC 8482).
    ANY = 255 => "ANY",
    /// Uniform resource identifier (RFC 7553).
    URI = 256 => "URI",
    /// Certification authority authorization (RFC 8659).
    CAA = 257 => "CAA",
    /// Application visibility and control.
    AVC = 258 => "AVC",
    /// Digital object architecture (draft-durand-doa-over-dns).
    DOA = 259 => "DOA",
    /// Automatic multicast tunneling relay (RFC 8777).
    AMTRELAY = 260 => "AMTRELAY",
    /// Resolver information as key/value pairs (RFC 9606).
    RESINFO = 261 => "RESINFO",
    /// Public wallet address.
    WALLET = 262 => "WALLET",
    /// BP convergence layer adapter (draft-johnson-dns-ipn-cla).
    CLA = 263 => "CLA",
    /// BP node number (draft-johnson-dns-ipn-cla).
    IPN = 264 => "IPN",
    /// DNSSEC trust authorities.
    TA = 32768 => "TA",
    /// DNSSEC lookaside validation — obsolete (RFC 4431, RFC 8749).
    DLV = 32769 => "DLV",
}

impl Rtype {
    /// Whether this is a QTYPE that may only appear in questions: IXFR,
    /// AXFR, MAILB, MAILA and ANY (RFC 1035 §3.2.3, RFC 6895 §3.1).
    #[inline]
    pub const fn is_question_only(self) -> bool {
        matches!(self.0, 251..=255)
    }

    /// Whether this is a meta-type or QTYPE: OPT, or a value in the 128–255
    /// range (RFC 6895 §3.1; this includes NXNAME, RFC 9824 §4). Such types
    /// carry per-message data and are never cached or stored in zones.
    #[inline]
    pub const fn is_meta(self) -> bool {
        self.0 == 41 || (self.0 >= 128 && self.0 <= 255)
    }

    /// Whether this is an ordinary data type (neither meta nor QTYPE).
    #[inline]
    pub const fn is_data(self) -> bool {
        !self.is_meta() && self.0 != 0
    }

    /// Whether the value lies in the private-use range 65280–65534
    /// (RFC 6895 §3.1).
    #[inline]
    pub const fn is_private_use(self) -> bool {
        self.0 >= 0xff00 && self.0 != 0xffff
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use std::string::ToString;

    #[test]
    fn registry_is_sorted_and_unique() {
        let all: std::vec::Vec<_> = Rtype::all().collect();
        for w in all.windows(2) {
            assert!(w[0].0 < w[1].0, "{:?} / {:?}", w[0], w[1]);
        }
        for (t, m) in Rtype::all() {
            assert_eq!(Rtype::from_mnemonic(m), Some(t));
            assert_eq!(m.parse::<Rtype>(), Ok(t));
            assert_eq!(t.to_string(), m);
        }
        assert_eq!(Rtype::all().count(), 99);
    }

    #[test]
    fn text_forms() {
        assert_eq!("nsap-ptr".parse(), Ok(Rtype::NSAP_PTR));
        assert_eq!("*".parse(), Ok(Rtype::ANY));
        assert_eq!("type1".parse(), Ok(Rtype::A));
        assert_eq!("TYPE65535".parse(), Ok(Rtype::new(65535)));
        assert_eq!("TYPE65536".parse::<Rtype>(), Err(Error::InvalidText));
        assert_eq!("TYPE".parse::<Rtype>(), Err(Error::InvalidText));
        assert_eq!("TYPE+1".parse::<Rtype>(), Err(Error::InvalidText));
        assert_eq!("BOGUS".parse::<Rtype>(), Err(Error::UnknownMnemonic));
        assert_eq!("".parse::<Rtype>(), Err(Error::UnknownMnemonic));
        assert_eq!("é".parse::<Rtype>(), Err(Error::UnknownMnemonic));
        assert_eq!(Rtype::new(54).to_string(), "TYPE54");
        assert_eq!(std::format!("{:?}", Rtype::MX), "MX");
    }

    #[test]
    fn categories() {
        assert!(Rtype::AXFR.is_question_only() && Rtype::ANY.is_question_only());
        assert!(!Rtype::TSIG.is_question_only());
        assert!(Rtype::OPT.is_meta() && Rtype::TSIG.is_meta() && Rtype::ANY.is_meta());
        assert!(Rtype::NXNAME.is_meta() && !Rtype::NXNAME.is_data());
        assert!(Rtype::A.is_data() && !Rtype::new(0).is_data());
        assert!(Rtype::new(65280).is_private_use() && !Rtype::new(65535).is_private_use());
        assert_eq!(u16::from(Rtype::from(7u16)), 7);
    }
}
