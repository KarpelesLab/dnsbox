use core::fmt;

/// Errors produced while parsing or building DNS messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// The input ended before a complete structure could be read.
    UnexpectedEof,
    /// The output buffer is too small for the data being written.
    BufferTooSmall,
}

/// Shorthand for `core::result::Result<T, dnsbox::Error>`.
pub type Result<T> = core::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::UnexpectedEof => "unexpected end of input",
            Error::BufferTooSmall => "output buffer too small",
        })
    }
}

impl core::error::Error for Error {}
