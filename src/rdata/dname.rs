//! DNAME record data (RFC 6672 §2.1).

super::single_name::single_name_rdata! {
    /// `DNAME` record data: redirection of a whole subtree of the name
    /// space to another domain (RFC 6672 §2.1).
    ///
    /// The target is never compressed on output and is lowercased in
    /// canonical form (RFC 6672 §2.5, RFC 4034 §6.2). Some RFC 2672-era
    /// senders compressed it, so a compressed target is accepted (and
    /// expanded) when parsing.
    Dname, DNAME, target, Lowercase, read_name
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdata::tests::{compose, parse, round_trip, text_error, text_round_trip};
    use crate::wire::{Canonical, WireWriter};
    use crate::{Class, ComposeRdata, Error, Message, NameBuf, RData, Rtype};
    use std::string::ToString;

    #[test]
    fn rfc6672_example() {
        // RFC 6672 §2.3 / §3: frobozz.example. DNAME frobozz-division.acme.example.
        round_trip(
            Rtype::DNAME,
            b"\x10frobozz-division\x04acme\x07example\x00",
            "frobozz-division.acme.example.",
        );
        // A DNAME to the root is allowed on the wire.
        round_trip(Rtype::DNAME, b"\x00", ".");
        assert_eq!(
            parse(Rtype::DNAME, Class::IN, b"\x01a\x00\x00"),
            Err(Error::TrailingData)
        );
    }

    #[test]
    fn text() {
        // RFC 6672 §2.3 / §3: "frobozz.example. DNAME
        // frobozz-division.acme.example.", and a relative target
        // (completed with the origin, `example.`).
        text_round_trip(
            Rtype::DNAME,
            "frobozz-division.acme.example.",
            b"\x10frobozz-division\x04acme\x07example\x00",
            "frobozz-division.acme.example.",
        );
        text_round_trip(
            Rtype::DNAME,
            "Frobozz-Division.acme",
            b"\x10Frobozz-Division\x04acme\x07example\x00",
            "Frobozz-Division.acme.example.",
        );
        assert_eq!(text_error(Rtype::DNAME, ""), Error::UnexpectedEof);
        assert_eq!(text_error(Rtype::DNAME, "a. b."), Error::InvalidText);
        assert_eq!(text_error(Rtype::DNAME, "\"a.\""), Error::InvalidText);
        assert_eq!(text_error(Rtype::DNAME, "a..b."), Error::EmptyLabel);
    }

    #[test]
    fn canonical_lowercase() {
        let n: NameBuf = "Acme.EXAMPLE.".parse().unwrap();
        let d = Dname::new(n.as_name());
        assert_eq!(compose(&d), b"\x04Acme\x07EXAMPLE\x00");
        let mut buf = [0u8; 32];
        let mut w = WireWriter::new(&mut buf);
        d.compose_rdata(&mut Canonical::new(&mut w)).unwrap();
        assert_eq!(w.written(), b"\x04acme\x07example\x00");
    }

    #[test]
    fn compressed_target_is_accepted() {
        // example. DNAME with target "x" + pointer to the question name.
        let msg = b"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\
                    \x07example\x00\x00\x27\x00\x01\
                    \xc0\x0c\x00\x27\x00\x01\x00\x00\x0e\x10\x00\x04\x01x\xc0\x0c";
        let msg = Message::parse_validated(msg).unwrap();
        let rr = msg.answers().next().unwrap().unwrap();
        let RData::Dname(d) = rr.data().unwrap() else {
            panic!("not DNAME")
        };
        assert_eq!(d.target.to_string(), "x.example.");
        assert_eq!(compose(&d), b"\x01x\x07example\x00");
    }
}
