//! EDNS accessors on [`Message`].

use super::Edns;
use crate::message::Message;
use crate::{Error, Rcode, Result, Rtype, Section};

impl<'a> Message<'a> {
    /// The message's OPT record, decoded (RFC 6891 §6.1.1), or `None` if
    /// the message has none. Walks every record once.
    ///
    /// # Errors
    ///
    /// [`Error::DuplicateOpt`] if there is more than one OPT record,
    /// [`Error::MisplacedOpt`] if one is in the answer or authority
    /// section, [`Error::OptNotRoot`] if its owner is not the root, the
    /// framing error of a truncated option, or any error met while walking
    /// the message. (RFC 6891 §6.1.1 and §7 ask responders to answer such
    /// queries with FORMERR.)
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
        for rr in self.records() {
            let (section, rr) = rr?;
            if rr.rtype() != Rtype::OPT {
                continue;
            }
            // RFC 6891 §6.1.1: the OPT pseudo-RR belongs in the additional
            // data section; one anywhere else is malformed, not "no EDNS".
            if section != Section::Additional {
                return Err(Error::MisplacedOpt);
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
    ///
    /// ```
    /// use dnsbox::edns::OptHeader;
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rcode, Rtype};
    ///
    /// // A response to a query with EDNS version 1: BADVERS (16) does not fit
    /// // in the 4 header bits; the rest travels in the OPT record.
    /// let name: NameBuf = "example.com".parse()?;
    /// let mut qbuf = [0u8; 512];
    /// let mut q = MessageBuilder::query(&mut qbuf, 1, &name, Rtype::A, Class::IN)?;
    /// let mut v1 = OptHeader::new(1232);
    /// v1.version = 1;
    /// q.push_edns(v1, &())?;
    /// let query = Message::parse(q.finish())?;
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// let opt = b.start_response_edns(&query, 1232)?.expect("EDNS");
    /// b.push_reserved_edns(opt, &())?;
    /// let resp = Message::parse(b.finish())?;
    /// assert_eq!(resp.flags().rcode(), Rcode::NOERROR); // the header bits alone
    /// assert_eq!(resp.effective_rcode()?, Rcode::BADVERS);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn effective_rcode(&self) -> Result<Rcode> {
        let flags = self.flags();
        Ok(match self.edns()? {
            Some(edns) => edns.rcode(flags),
            None => flags.rcode(),
        })
    }
}
