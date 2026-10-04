use core::fmt;

/// Errors produced while parsing or building DNS messages.
///
/// The enum is `#[non_exhaustive]`: new variants are added as new parts of
/// the protocol are implemented. Match on the variants you care about and
/// keep a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// The input ended before a complete structure could be read. Also
    /// returned when a section count in the header promises more entries
    /// than the message contains (RFC 1035 §4.1.1).
    UnexpectedEof,
    /// The output buffer (or the configured size limit) is too small for the
    /// data being written.
    BufferTooSmall,
    /// Bytes were left over after a structure that must fill its container
    /// exactly (e.g. RDATA shorter than its RDLENGTH, RFC 1035 §3.2.1).
    TrailingData,

    /// A domain name exceeds 255 octets in wire form (RFC 1035 §2.3.4).
    NameTooLong,
    /// A label exceeds 63 octets (RFC 1035 §2.3.4).
    LabelTooLong,
    /// A presentation-format name contains an empty label (`a..b`).
    EmptyLabel,
    /// A label uses a reserved or extended label type (`0b01` / `0b10` top
    /// bits), which is rejected (RFC 6891 §5, RFC 2673 is historic).
    BadLabelType,
    /// A compression pointer points forward, at itself, or into the name it
    /// is part of (RFC 1035 §4.1.4; rejected to guarantee termination).
    BadPointer,
    /// A name follows more compression pointers than
    /// [`MAX_POINTERS`](crate::name::MAX_POINTERS).
    TooManyPointers,
    /// A compression pointer appeared where only uncompressed names are
    /// allowed (RFC 3597 §4, RFC 4034 §3.1.7).
    UnexpectedPointer,

    /// RDATA is malformed for its record type (bad length, invalid field).
    InvalidRdata,
    /// A typed RDATA parse was requested for a record of another type.
    WrongType,

    /// A DNSSEC algorithm or digest type is not supported by the crypto
    /// backend (RFC 4035 §5.2: unsupported algorithms leave data insecure).
    UnsupportedAlgorithm,
    /// A DNSSEC public or private key is malformed for its algorithm
    /// (e.g. RFC 3110 §2, RFC 6605 §4, RFC 8080 §3).
    InvalidKey,
    /// A signature, digest or MAC does not verify: DNSSEC RRSIG or DS
    /// (RFC 4035 §5.3.3), TSIG (error BADSIG, RFC 8945 §5.2.2) or SIG(0)
    /// (RFC 2931 §3.1).
    BadSignature,
    /// An RRSIG's validity period has ended (RFC 4035 §5.3.1).
    SignatureExpired,
    /// An RRSIG's validity period has not started yet (RFC 4035 §5.3.1).
    SignatureNotYetValid,
    /// An RRSIG does not match the DNSKEY it is checked against: signer
    /// name, algorithm, key tag, protocol or zone flag (RFC 4035 §5.3.1).
    KeyMismatch,
    /// An RRSIG does not cover the RRset it is checked against: type
    /// covered, labels, signer zone or record types (RFC 4035 §5.3.1).
    RrsetMismatch,

    /// Presentation-format text is malformed (bad escape, bad number, ...).
    InvalidText,
    /// A mnemonic (type, class, ...) is not recognised.
    UnknownMnemonic,
    /// A character-string exceeds 255 octets (RFC 1035 §3.3).
    CharStringTooLong,

    /// A builder section was written out of order: question → answer →
    /// authority → additional (RFC 1035 §4.1).
    SectionOrder,
    /// A section would hold more than 65535 entries.
    CountOverflow,
    /// A message exceeds 65535 octets, the most the TCP length prefix can
    /// describe (RFC 1035 §4.2.2).
    MessageTooLong,

    /// An EDNS(0) option is malformed: bad length or invalid field value
    /// (RFC 6891 §6.1.2 and the option's own RFC).
    InvalidOption,
    /// A message carries more than one OPT record (RFC 6891 §6.1.1).
    DuplicateOpt,
    /// An OPT record's owner name is not the root (RFC 6891 §6.1.2).
    OptNotRoot,

    /// A TSIG or SIG(0) record is not the last record of the additional
    /// section, or appears more than once (RFC 8945 §5.1, RFC 2931 §3).
    /// Servers answer FORMERR.
    MisplacedSignature,
    /// A TSIG MAC size is longer than the algorithm's output or shorter than
    /// the truncation floor (RFC 8945 §5.2.2.1). Servers answer FORMERR.
    BadMacSize,
    /// The TSIG key or algorithm is unknown (TSIG error BADKEY, RFC 8945
    /// §5.2.1).
    BadKey,
    /// The signature time is outside the allowed window (TSIG error
    /// BADTIME, RFC 8945 §5.2.3; SIG(0) validity period, RFC 2931 §3.1).
    BadTime,
    /// A TSIG MAC is truncated below local policy (TSIG error BADTRUNC,
    /// RFC 8945 §5.2.4).
    BadTrunc,
    /// A message that must be signed carries no TSIG, or too many unsigned
    /// messages follow each other in a TSIG stream (RFC 8945 §5.3.1, §5.4).
    Unsigned,
    /// The peer reported a TSIG error (BADKEY, BADSIG, ...) in an unsigned
    /// response; it cannot be authenticated and must be discarded
    /// (RFC 8945 §5.3.2, §5.4.1).
    TsigErrorResponse,
    /// A dynamic-update prerequisite or update RR has an invalid
    /// class/type/TTL/RDATA combination (RFC 2136 §3.2.4, §3.4.1.3), or the
    /// zone section is malformed (RFC 2136 §3.1.1). Servers answer FORMERR.
    MalformedUpdate,
    /// A zone-transfer response stream violates RFC 5936 §2.2 / RFC 1995 §4
    /// (bad SOA sequence, records after the end, question mismatch).
    MalformedXfr,
    /// A response carries an error RCODE where success was required (e.g. a
    /// refused zone transfer, RFC 5936 §2.2.1).
    ErrorResponse,
    /// A DNS Stateful Operations message is malformed: non-zero section
    /// counts, bad TLV framing or placement (RFC 8490 §5.4, §7.3).
    MalformedDso,
}

/// Shorthand for `core::result::Result<T, dnsbox::Error>`.
pub type Result<T> = core::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::UnexpectedEof => "unexpected end of input",
            Error::BufferTooSmall => "output buffer too small",
            Error::TrailingData => "trailing data",
            Error::NameTooLong => "domain name longer than 255 octets",
            Error::LabelTooLong => "label longer than 63 octets",
            Error::EmptyLabel => "empty label in domain name",
            Error::BadLabelType => "reserved or extended label type",
            Error::BadPointer => "invalid compression pointer",
            Error::TooManyPointers => "too many compression pointers",
            Error::UnexpectedPointer => "compression pointer not allowed here",
            Error::InvalidRdata => "malformed record data",
            Error::WrongType => "record type mismatch",
            Error::UnsupportedAlgorithm => "unsupported DNSSEC algorithm",
            Error::InvalidKey => "malformed DNSSEC key",
            Error::BadSignature => "signature verification failed",
            Error::SignatureExpired => "DNSSEC signature expired",
            Error::SignatureNotYetValid => "DNSSEC signature not yet valid",
            Error::KeyMismatch => "DNSSEC key does not match the signature",
            Error::RrsetMismatch => "DNSSEC signature does not cover the RRset",
            Error::InvalidText => "malformed presentation-format text",
            Error::UnknownMnemonic => "unknown mnemonic",
            Error::CharStringTooLong => "character-string longer than 255 octets",
            Error::SectionOrder => "message section written out of order",
            Error::CountOverflow => "section count overflow",
            Error::MessageTooLong => "message longer than 65535 octets",
            Error::InvalidOption => "malformed EDNS option",
            Error::DuplicateOpt => "more than one OPT record",
            Error::OptNotRoot => "OPT record owner is not the root",
            Error::MisplacedSignature => "TSIG/SIG(0) record is not last in the message",
            Error::BadMacSize => "invalid TSIG MAC size",
            Error::BadKey => "unknown TSIG key or algorithm",
            Error::BadTime => "signature time outside the allowed window",
            Error::BadTrunc => "TSIG MAC truncated below policy",
            Error::Unsigned => "message is not signed",
            Error::TsigErrorResponse => "peer reported a TSIG error in an unsigned response",
            Error::MalformedUpdate => "malformed dynamic update",
            Error::MalformedXfr => "malformed zone transfer stream",
            Error::ErrorResponse => "response carries an error RCODE",
            Error::MalformedDso => "malformed DSO message",
        })
    }
}

impl core::error::Error for Error {}
