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
            Error::InvalidText => "malformed presentation-format text",
            Error::UnknownMnemonic => "unknown mnemonic",
            Error::CharStringTooLong => "character-string longer than 255 octets",
            Error::SectionOrder => "message section written out of order",
            Error::CountOverflow => "section count overflow",
            Error::MessageTooLong => "message longer than 65535 octets",
        })
    }
}

impl core::error::Error for Error {}
