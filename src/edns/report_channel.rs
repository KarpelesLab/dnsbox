//! Report-Channel option for DNS error reporting (RFC 9567).

use core::fmt;

use super::{ComposeOption, OptionCode, ParseOption};
use crate::Result;
use crate::name::Name;
use crate::wire::{Composer, NameEncoding, WireReader};

/// `REPORT-CHANNEL` option: the agent domain to which resolvers send error
/// reports for this zone (RFC 9567 §5).
///
/// The name is in uncompressed wire format and must fill the option.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReportChannel<'a> {
    /// AGENT DOMAIN.
    pub agent_domain: Name<'a>,
}

impl<'a> ReportChannel<'a> {
    /// Wraps an agent domain.
    #[inline]
    #[must_use]
    pub const fn new(agent_domain: Name<'a>) -> Self {
        ReportChannel { agent_domain }
    }
}

impl<'a> ParseOption<'a> for ReportChannel<'a> {
    const CODE: OptionCode = OptionCode::REPORT_CHANNEL;

    #[inline]
    fn parse_option(data: &mut WireReader<'a>) -> Result<Self> {
        data.read_name_uncompressed().map(ReportChannel::new)
    }
}

impl ComposeOption for ReportChannel<'_> {
    #[inline]
    fn code(&self) -> OptionCode {
        OptionCode::REPORT_CHANNEL
    }

    #[inline]
    fn compose_option<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_name(self.agent_domain, NameEncoding::Plain)
    }
}

impl fmt::Display for ReportChannel<'_> {
    /// `REPORT-CHANNEL=<agent domain>`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "REPORT-CHANNEL={}", self.agent_domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use crate::edns::tests::{parse, round_trip};

    #[test]
    fn report_channel() {
        // RFC 9567 §4.1 example agent domain.
        round_trip(
            OptionCode::REPORT_CHANNEL,
            b"\x03a01\x0cagent-domain\x07example\x00",
            "REPORT-CHANNEL=a01.agent-domain.example.",
        );
        assert_eq!(parse(OptionCode::REPORT_CHANNEL, b"\x03com"), Err(Error::UnexpectedEof));
        assert_eq!(
            parse(OptionCode::REPORT_CHANNEL, b"\x00\x00"),
            Err(Error::TrailingData)
        );
    }
}
