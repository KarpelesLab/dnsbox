//! EDNS accessors on [`Message`].

use super::Edns;
use crate::message::Message;
use crate::{Error, Rcode, Result, Rtype};

impl<'a> Message<'a> {
    /// The message's OPT record, decoded (RFC 6891 §6.1.1), or `None` if
    /// the additional section has none.
    ///
    /// # Errors
    ///
    /// [`Error::DuplicateOpt`] if there is more than one OPT record,
    /// [`Error::OptNotRoot`] if its owner is not the root, the framing
    /// error of a truncated option, or any error met while walking the
    /// message up to and through the additional section. (RFC 6891 §7
    /// asks responders to answer such queries with FORMERR.)
    ///
    /// ```
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
    /// use dnsbox::edns::OptHeader;
    ///
    /// let name: NameBuf = "example.com".parse()?;
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::query(&mut buf, 1, &name, Rtype::A, Class::IN)?;
    /// b.push_edns(OptHeader::new(4096).with_dnssec_ok(true), &())?;
    /// let msg = Message::parse(b.finish())?;
    /// let edns = msg.edns()?.expect("OPT present");
    /// assert_eq!((edns.udp_payload_size(), edns.version()), (4096, 0));
    /// assert!(edns.dnssec_ok());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn edns(&self) -> Result<Option<Edns<'a>>> {
        let mut found = None;
        for rr in self.additional() {
            let rr = rr?;
            if rr.rtype() != Rtype::OPT {
                continue;
            }
            if found.is_some() {
                return Err(Error::DuplicateOpt);
            }
            found = Some(Edns::from_record(&rr)?);
        }
        Ok(found)
    }

    /// The full response code: the header's 4-bit RCODE combined with the
    /// OPT record's extended RCODE when there is one (RFC 6891 §6.1.3).
    ///
    /// # Errors
    ///
    /// As [`edns`](Self::edns).
    pub fn effective_rcode(&self) -> Result<Rcode> {
        let flags = self.flags();
        Ok(match self.edns()? {
            Some(edns) => edns.rcode(flags),
            None => flags.rcode(),
        })
    }
}
