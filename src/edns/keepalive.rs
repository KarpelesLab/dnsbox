//! TCP keepalive option (RFC 7828).

use core::fmt;

use super::{ComposeOption, OptionCode, ParseOption};
use crate::wire::{Composer, WireReader};
use crate::{Error, Result};

/// `TCP-KEEPALIVE` option: the idle timeout of a TCP connection
/// (RFC 7828 §3.1).
///
/// Clients send it empty; servers send a timeout in units of 100
/// milliseconds. Any length other than 0 or 2 fails with
/// [`Error::InvalidOption`] (RFC 7828 §3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct TcpKeepalive {
    /// The idle timeout in units of 100 ms; `None` (an empty option) in
    /// queries.
    pub timeout: Option<u16>,
}

impl TcpKeepalive {
    /// The empty option a client sends (RFC 7828 §3.2.1).
    pub const REQUEST: TcpKeepalive = TcpKeepalive { timeout: None };

    /// A server's option with the given timeout, in units of 100 ms.
    #[inline]
    pub const fn new(timeout: u16) -> Self {
        TcpKeepalive {
            timeout: Some(timeout),
        }
    }

    /// The timeout in milliseconds, if present.
    #[inline]
    pub const fn timeout_millis(&self) -> Option<u32> {
        match self.timeout {
            Some(t) => Some(t as u32 * 100),
            None => None,
        }
    }
}

impl ParseOption<'_> for TcpKeepalive {
    const CODE: OptionCode = OptionCode::TCP_KEEPALIVE;

    fn parse_option(data: &mut WireReader<'_>) -> Result<Self> {
        match data.remaining() {
            0 => Ok(TcpKeepalive::REQUEST),
            2 => data.read_u16().map(TcpKeepalive::new),
            _ => Err(Error::InvalidOption),
        }
    }
}

impl ComposeOption for TcpKeepalive {
    #[inline]
    fn code(&self) -> OptionCode {
        OptionCode::TCP_KEEPALIVE
    }

    #[inline]
    fn compose_option<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        match self.timeout {
            Some(t) => c.put_u16(t),
            None => Ok(()),
        }
    }
}

impl fmt::Display for TcpKeepalive {
    /// `TCP-KEEPALIVE` or `TCP-KEEPALIVE=<timeout in 100 ms units>`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TCP-KEEPALIVE")?;
        if let Some(t) = self.timeout {
            write!(f, "={t}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edns::tests::{parse, round_trip};

    #[test]
    fn keepalive() {
        round_trip(OptionCode::TCP_KEEPALIVE, b"", "TCP-KEEPALIVE");
        round_trip(OptionCode::TCP_KEEPALIVE, b"\x02\x58", "TCP-KEEPALIVE=600");
        assert_eq!(TcpKeepalive::new(600).timeout_millis(), Some(60_000));
        assert_eq!(TcpKeepalive::REQUEST.timeout_millis(), None);
        for bad in [&b"\x01"[..], b"\x00\x00\x00"] {
            assert_eq!(parse(OptionCode::TCP_KEEPALIVE, bad), Err(Error::InvalidOption));
        }
    }
}
