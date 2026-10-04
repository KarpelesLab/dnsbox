//! EDNS EXPIRE option (RFC 7314).

use core::fmt;

use super::{ComposeOption, OptionCode, ParseOption};
use crate::wire::{Composer, WireReader};
use crate::{Error, Result};

/// `EXPIRE` option: the remaining time before a secondary's copy of a zone
/// expires (RFC 7314 §2–3).
///
/// Queries carry it empty; responses carry the expire timer in seconds.
/// Any length other than 0 or 4 fails with [`Error::InvalidOption`].
///
/// ```
/// use dnsbox::edns::{Expire, Opt};
///
/// assert_eq!(Expire::REQUEST.to_string(), "EXPIRE");
/// let opt = Opt::new(b"\x00\x09\x00\x04\x00\x09\x3a\x80")?;
/// let expire: Expire = opt.get().expect("present")?;
/// assert_eq!(expire, Expire::new(604_800)); // one week
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Expire {
    /// Seconds before the zone expires; `None` (an empty option) in
    /// queries.
    pub expire: Option<u32>,
}

impl Expire {
    /// The empty option sent in queries (RFC 7314 §2).
    pub const REQUEST: Expire = Expire { expire: None };

    /// A response option with the given timer, in seconds (RFC 7314 §3).
    #[inline]
    #[must_use]
    pub const fn new(expire: u32) -> Self {
        Expire {
            expire: Some(expire),
        }
    }
}

impl ParseOption<'_> for Expire {
    const CODE: OptionCode = OptionCode::EXPIRE;

    fn parse_option(data: &mut WireReader<'_>) -> Result<Self> {
        match data.remaining() {
            0 => Ok(Expire::REQUEST),
            4 => data.read_u32().map(Expire::new),
            _ => Err(Error::InvalidOption),
        }
    }
}

impl ComposeOption for Expire {
    #[inline]
    fn code(&self) -> OptionCode {
        OptionCode::EXPIRE
    }

    #[inline]
    fn compose_option<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        match self.expire {
            Some(e) => c.put_u32(e),
            None => Ok(()),
        }
    }
}

impl fmt::Display for Expire {
    /// `EXPIRE` or `EXPIRE=<seconds>`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EXPIRE")?;
        if let Some(e) = self.expire {
            write!(f, "={e}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edns::tests::{parse, round_trip};

    #[test]
    fn expire() {
        round_trip(OptionCode::EXPIRE, b"", "EXPIRE");
        round_trip(OptionCode::EXPIRE, b"\x00\x09\x3a\x80", "EXPIRE=604800");
        assert_eq!(Expire::new(1).expire, Some(1));
        for bad in [&b"\x00"[..], b"\x00\x00\x00", b"\x00\x00\x00\x00\x00"] {
            assert_eq!(parse(OptionCode::EXPIRE, bad), Err(Error::InvalidOption));
        }
    }
}
