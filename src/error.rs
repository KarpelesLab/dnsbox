use core::fmt;

/// Errors produced while parsing or building DNS messages.
///
/// dnsbox has **one error type** for everything that can fail — wire and
/// text parsing, building, DNSSEC, TSIG, SIG(0), UPDATE, XFR, DSO. It is a
/// one-byte, `Copy`, allocation-free enum, so returning it costs nothing
/// on the hot path and it works without `alloc`. The variants name what
/// was wrong rather than where: `Invalid*` for malformed input of some kind
/// ([`InvalidRdata`](Self::InvalidRdata), [`InvalidText`](Self::InvalidText),
/// [`InvalidOption`](Self::InvalidOption), [`InvalidUpdate`](Self::InvalidUpdate),
/// ...), `Bad*` for failed checks (compression pointers, signatures, and the
/// TSIG error codes of RFC 8945), the rest for specific conditions.
///
/// Two error types add context and convert into `Error` with `?`:
/// [`ZoneError`](crate::zone::ZoneError) (the position of a zone-file
/// error) and `dnssec::ZonemdFailure` (which RFC 8976 §4 check failed).
/// Outcomes that are answers rather than failures of the call — a DNSSEC
/// [`DenialStatus`](crate::dnssec::DenialStatus), a truncated
/// [`Outcome`](crate::builder::Outcome) — are ordinary return values.
///
/// The enum is `#[non_exhaustive]`: new variants are added as new parts of
/// the protocol are implemented. Match on the variants you care about and
/// keep a wildcard arm.
///
/// # Examples
///
/// Hostile or truncated input is rejected with an error, never a panic:
///
/// ```
/// use dnsbox::{Error, Message};
///
/// // A header claiming one question, but the message ends after it.
/// let wire = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
/// let msg = Message::parse(&wire)?; // only the header is checked here
/// let err = msg.questions().next().unwrap().unwrap_err();
/// assert_eq!(err, Error::UnexpectedEof);
/// assert_eq!(err.to_string(), "unexpected end of input");
///
/// // The enum is non-exhaustive: keep a wildcard arm.
/// let retry_over_tcp = match err {
///     Error::UnexpectedEof | Error::BufferTooSmall => true,
///     _ => false,
/// };
/// assert!(retry_over_tcp);
/// # Ok::<(), Error>(())
/// ```
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
    /// The record type has no type-specific presentation format (or none
    /// is implemented, or its format is not defined for the record's
    /// class): only the generic `\# <length> <hex>` form of RFC 3597 §5 is
    /// accepted.
    NoTextFormat,
    /// A zone-file record has no TTL and none can be inferred: no `$TTL`
    /// directive (RFC 2308 §4) and no earlier explicit TTL (RFC 1035 §5.1).
    MissingTtl,
    /// A zone-file `$INCLUDE` directive (RFC 1035 §5.1) could not be
    /// processed: includes are unsupported here (no resolver, or no `std`),
    /// the file was refused (outside the include directory) or failed to
    /// load.
    BadInclude,
    /// A configured work or size limit was reached before the input could
    /// be fully processed: zone-file limits
    /// ([`ZoneLimits`](crate::zone::ZoneLimits): records, `$GENERATE`
    /// size, `$INCLUDE` nesting, count and size, line, token and input
    /// length), DNSSEC validation budgets (`dnssec::ValidationBudget`,
    /// the KeyTrap bounds of CVE-2023-50387) and zone-transfer limits
    /// ([`XfrProcessor::with_max_records`](crate::xfr::XfrProcessor::with_max_records)).
    /// The input is neither accepted nor proven wrong: treat it as
    /// unusable (a validator answers SERVFAIL, as for bogus data), or
    /// raise the limit for trusted input.
    LimitExceeded,

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
    /// An OPT record outside the additional section (RFC 6891 §6.1.1).
    /// Servers answer FORMERR.
    MisplacedOpt,

    /// A TSIG or SIG(0) record is not the last record of the additional
    /// section, or appears more than once (RFC 8945 §5.1, RFC 2931 §3).
    /// Servers answer FORMERR.
    MisplacedSignature,
    /// A TSIG MAC size is longer than the algorithm's output or shorter than
    /// the truncation floor (RFC 8945 §5.2.2.1). Servers answer FORMERR.
    BadMacSize,
    /// The TSIG key or algorithm is unknown (TSIG error BADKEY, RFC 8945
    /// §5.2.1), or a TKEY exchange came with an incompatible or unusable
    /// KEY (TKEY error BADKEY, RFC 2930 §4.1, §4.5).
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
    InvalidUpdate,
    /// A zone-transfer response stream violates RFC 5936 §2.2 / RFC 1995 §4
    /// (bad SOA sequence, records after the end, question mismatch).
    InvalidXfr,
    /// A response carries an error RCODE where success was required (e.g. a
    /// refused zone transfer, RFC 5936 §2.2.1).
    ErrorResponse,
    /// A DNS Stateful Operations message is malformed: non-zero section
    /// counts, bad TLV framing or placement (RFC 8490 §5.4, §7.3).
    InvalidDso,
    /// A TKEY message breaks RFC 2930: not exactly one TKEY record, the
    /// record in the wrong section or not owned by the question name, the
    /// wrong mode, or a KEY the mode needs missing (§3, §4). Servers answer
    /// FORMERR.
    InvalidTkey,
}

/// Shorthand for `core::result::Result<T, dnsbox::Error>`.
///
/// # Examples
///
/// ```
/// use dnsbox::{NameBuf, Result};
///
/// fn parent_of(name: &str) -> Result<NameBuf> {
///     let name: NameBuf = name.parse()?;
///     Ok(name.as_name().parent().unwrap_or(name.as_name()).to_buf())
/// }
/// assert_eq!(parent_of("www.example.com")?.to_string(), "example.com.");
/// # Ok::<(), dnsbox::Error>(())
/// ```
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
            Error::NoTextFormat => {
                "no presentation format for this record type (use \\# generic form)"
            }
            Error::MissingTtl => "no TTL given and no default TTL",
            Error::BadInclude => "$INCLUDE failed",
            Error::LimitExceeded => "work or size limit exceeded",
            Error::SectionOrder => "message section written out of order",
            Error::CountOverflow => "section count overflow",
            Error::MessageTooLong => "message longer than 65535 octets",
            Error::InvalidOption => "malformed EDNS option",
            Error::DuplicateOpt => "more than one OPT record",
            Error::OptNotRoot => "OPT record owner is not the root",
            Error::MisplacedOpt => "OPT record outside the additional section",
            Error::MisplacedSignature => "TSIG/SIG(0) record is not last in the message",
            Error::BadMacSize => "invalid TSIG MAC size",
            Error::BadKey => "unknown TSIG key or algorithm",
            Error::BadTime => "signature time outside the allowed window",
            Error::BadTrunc => "TSIG MAC truncated below policy",
            Error::Unsigned => "message is not signed",
            Error::TsigErrorResponse => "peer reported a TSIG error in an unsigned response",
            Error::InvalidUpdate => "malformed dynamic update",
            Error::InvalidXfr => "malformed zone transfer stream",
            Error::ErrorResponse => "response carries an error RCODE",
            Error::InvalidDso => "malformed DSO message",
            Error::InvalidTkey => "malformed TKEY exchange",
        })
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn small_and_copy() {
        assert_eq!(core::mem::size_of::<Error>(), 1);
        assert_eq!(core::mem::size_of::<crate::Result<()>>(), 1);
    }
}
