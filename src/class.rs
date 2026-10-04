//! Resource record CLASSes and QCLASSes (RFC 1035 §3.2.4–3.2.5,
//! RFC 6895 §3.2).

// The IANA "DNS CLASSes" registry
// (https://www.iana.org/assignments/dns-parameters/dns-parameters-2.csv).
open_enum! {
    /// A resource record CLASS (or QCLASS), as a 16-bit open newtype.
    ///
    /// Unassigned values round-trip unchanged and display as `CLASSnnn`
    /// (RFC 3597 §5). Note that the CLASS field of an OPT pseudo-record carries
    /// the requestor's UDP payload size instead (RFC 6891 §6.1.2).
    ///
    /// ```
    /// use dnsbox::Class;
    ///
    /// assert_eq!("in".parse::<Class>(), Ok(Class::IN));
    /// assert_eq!("CLASS3".parse::<Class>(), Ok(Class::CH));
    /// assert_eq!(Class::new(42).to_string(), "CLASS42");
    /// ```
    pub struct Class(u16), generic "CLASS", aliases {
        "*" => ANY,
        "CS" => CS,
        "CHAOS" => CH,
        "HESIOD" => HS,
    };
    /// The Internet (RFC 1035 §3.2.4).
    IN = 1 => "IN",
    /// Chaos (RFC 1035 §3.2.4).
    CH = 3 => "CH",
    /// Hesiod (RFC 1035 §3.2.4).
    HS = 4 => "HS",
    /// QCLASS NONE, used by dynamic update (RFC 2136 §2.4).
    NONE = 254 => "NONE",
    /// QCLASS `*` (any class) (RFC 1035 §3.2.5).
    ANY = 255 => "ANY",
}

impl Class {
    /// CSNET — obsolete and no longer in the IANA registry (RFC 1035
    /// §3.2.4). Displays as `CLASS2`; the mnemonic `CS` is still accepted.
    pub const CS: Class = Class(2);

    /// Whether the value lies in the private-use range 65280–65534
    /// (RFC 6895 §3.2).
    #[inline]
    #[must_use]
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
    fn text_forms() {
        for c in [Class::IN, Class::CH, Class::HS, Class::NONE, Class::ANY] {
            assert_eq!(c.to_string().parse(), Ok(c));
        }
        assert_eq!("*".parse(), Ok(Class::ANY));
        assert_eq!("chaos".parse(), Ok(Class::CH));
        assert_eq!("CS".parse(), Ok(Class::CS));
        assert_eq!(Class::CS.to_string(), "CLASS2");
        assert_eq!("class65535".parse(), Ok(Class::new(65535)));
        assert_eq!("CLASS70000".parse::<Class>(), Err(Error::InvalidText));
        assert_eq!("CLASSX".parse::<Class>(), Err(Error::InvalidText));
        assert_eq!("XX".parse::<Class>(), Err(Error::UnknownMnemonic));
        assert!(Class::new(0xff00).is_private_use());
        assert_eq!(u16::from(Class::from(1u16)), 1);
        assert_eq!(std::format!("{:?}", Class::IN), "IN");
        assert_eq!(Class::all().count(), 5);
    }
}
