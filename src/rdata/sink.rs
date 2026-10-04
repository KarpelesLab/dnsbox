//! SINK record data (draft-eastlake-kitchen-sink-02).

use core::fmt;

use super::{ComposeRdata, ParseRdata};
use crate::text::Base64;
use crate::wire::{Composer, WireReader};
use crate::{Result, Rtype};

/// `SINK` record data: the "kitchen sink" for arbitrary typed data
/// (draft-eastlake-kitchen-sink-02). Never standardised.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Sink<'a> {
    /// What the data means.
    pub meaning: u8,
    /// How the data is encoded.
    pub coding: u8,
    /// Encoding detail, interpreted per `coding`.
    pub subcoding: u8,
    /// The payload.
    pub data: &'a [u8],
}

impl super::ParseRdataText for Sink<'_> {}

impl<'a> ParseRdata<'a> for Sink<'a> {
    const RTYPE: Rtype = Rtype::SINK;

    fn parse_rdata(rdata: &mut WireReader<'a>) -> Result<Self> {
        let [meaning, coding, subcoding] = rdata.read_array()?;
        Ok(Sink {
            meaning,
            coding,
            subcoding,
            data: rdata.read_rest(),
        })
    }
}

impl ComposeRdata for Sink<'_> {
    fn rtype(&self) -> Rtype {
        Rtype::SINK
    }

    fn compose_rdata<C: Composer + ?Sized>(&self, c: &mut C) -> Result<()> {
        c.put_bytes(&[self.meaning, self.coding, self.subcoding])?;
        c.put_bytes(self.data)
    }
}

impl fmt::Display for Sink<'_> {
    /// `meaning coding subcoding [base64-data]`, as BIND prints it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.meaning, self.coding, self.subcoding)?;
        if !self.data.is_empty() {
            write!(f, " {}", Base64(self.data))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::rdata::tests::{parse, round_trip};
    use crate::{Class, Error, Rtype};

    #[test]
    fn round_trips() {
        // SINK 1 2 3 AQID / SINK 1 0 0 (named-rrchecker).
        round_trip(Rtype::SINK, b"\x01\x02\x03\x01\x02\x03", "1 2 3 AQID");
        round_trip(Rtype::SINK, b"\x01\x00\x00", "1 0 0");
        assert_eq!(
            parse(Rtype::SINK, Class::IN, b"\x01\x02"),
            Err(Error::UnexpectedEof)
        );
    }
}
