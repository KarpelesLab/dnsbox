//! Building messages with a TCP length prefix (RFC 1035 §4.2.2,
//! RFC 7766 §8).

use super::{MAX_MESSAGE_LEN, MessageBuilder};
use crate::Result;
use crate::wire::{OutBuf, WireWriter};

impl<'b> MessageBuilder<WireWriter<'b>> {
    /// Starts a message for DNS over TCP (or TLS, RFC 7858) in `buf`: the
    /// message is preceded by its 2-byte big-endian length (RFC 1035
    /// §4.2.2), kept up to date after every push, so
    /// [`finish`](Self::finish) returns a frame ready to send in a single
    /// write (as RFC 7766 §8 recommends). [`as_bytes`](Self::as_bytes) and
    /// [`len`](Self::len) still refer to the message alone.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`](crate::Error::BufferTooSmall) if `buf`
    /// cannot hold the prefix and the 12-byte header.
    ///
    /// ```
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype, tcp};
    ///
    /// let name: NameBuf = "example.com".parse()?;
    /// let mut buf = [0u8; 514];
    /// let mut b = MessageBuilder::new_tcp(&mut buf)?;
    /// b.start_query(1, &name, Rtype::A, Class::IN)?;
    /// let frame = b.finish();
    /// assert_eq!(&frame[..2], &[0, 29]);
    /// let (msg, rest) = tcp::split_frame(frame).unwrap();
    /// assert!(rest.is_empty());
    /// Message::parse_validated(msg)?;
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn new_tcp(buf: &'b mut [u8]) -> Result<Self> {
        Self::from_buf_tcp(WireWriter::new(buf))
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl MessageBuilder<alloc::vec::Vec<u8>> {
    /// Starts a length-prefixed message for DNS over TCP in a new `Vec`;
    /// see [`new_tcp`](MessageBuilder::new_tcp).
    ///
    /// ```
    /// use dnsbox::MessageBuilder;
    ///
    /// let frame = MessageBuilder::new_tcp_vec().finish();
    /// assert_eq!(frame.len(), 2 + 12);
    /// assert_eq!(frame[..2], [0, 12]);
    /// ```
    #[must_use]
    pub fn new_tcp_vec() -> Self {
        let mut b = Self::new_vec();
        b.buf = alloc::vec![0; 2 + crate::Header::LEN];
        b.base = 2;
        b.framed = true;
        b.sync_header();
        b
    }
}

impl<B: OutBuf> MessageBuilder<B> {
    /// Like [`from_buf`](Self::from_buf), but first appends a 2-byte TCP
    /// length prefix that the builder keeps up to date; see
    /// [`new_tcp`](MessageBuilder::new_tcp). The message is limited to
    /// 65535 bytes, the most the prefix can describe.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`](crate::Error::BufferTooSmall) if the
    /// buffer cannot hold the prefix and the 12-byte header.
    ///
    /// ```
    /// use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype, WireWriter};
    ///
    /// let name: NameBuf = "example.com".parse()?;
    /// let mut buf = [0u8; 128];
    /// let mut b = MessageBuilder::from_buf_tcp(WireWriter::new(&mut buf))?;
    /// b.start_query(1, &name, Rtype::MX, Class::IN)?;
    /// let frame = b.finish();
    /// // The prefix holds the length of the message that follows it.
    /// assert_eq!(usize::from(u16::from_be_bytes([frame[0], frame[1]])), frame.len() - 2);
    /// assert_eq!(Message::parse(&frame[2..])?.id(), 1);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn from_buf_tcp(mut buf: B) -> Result<Self> {
        buf.append(&[0, 0])?;
        let mut b = Self::from_buf(buf)?;
        b.framed = true;
        b.limit = b.limit.min(MAX_MESSAGE_LEN);
        b.sync_header();
        Ok(b)
    }

    /// Whether the message is preceded by a TCP length prefix
    /// ([`new_tcp`](MessageBuilder::new_tcp)).
    ///
    /// ```
    /// use dnsbox::MessageBuilder;
    ///
    /// let mut udp = [0u8; 512];
    /// assert!(!MessageBuilder::new(&mut udp)?.is_framed());
    /// let mut tcp = [0u8; 514];
    /// assert!(MessageBuilder::new_tcp(&mut tcp)?.is_framed());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[inline]
    pub const fn is_framed(&self) -> bool {
        self.framed
    }
}

#[cfg(test)]
mod tests {
    use crate::builder::{MAX_MESSAGE_LEN, MessageBuilder, Truncation};
    use crate::message::{Message, Section};
    use crate::name::NameBuf;
    use crate::rdata::{A, Null};
    use crate::wire::WireWriter;
    use crate::{Class, Error, Rtype, tcp};

    fn name(s: &str) -> NameBuf {
        s.parse().unwrap()
    }

    #[test]
    fn prefix_tracks_every_change() {
        let mut buf = [0u8; 600];
        let mut b = MessageBuilder::new_tcp(&mut buf).unwrap();
        assert!(b.is_framed());
        assert_eq!(b.limit(), 598);
        b.start_query(7, name("example.com"), Rtype::A, Class::IN)
            .unwrap();
        let cp = b.checkpoint();
        b.push_answer(
            name("example.com"),
            Class::IN,
            0,
            &A::new([1, 2, 3, 4].into()),
        )
        .unwrap();
        assert_eq!(b.len(), 29 + 16);
        b.rollback(cp);
        assert_eq!(b.len(), 29);
        b.set_truncation(Truncation::SetTc);
        b.set_limit(40);
        let out = b
            .push_rrset(
                Section::Answer,
                name("example.com"),
                Class::IN,
                0,
                [A::new([1, 2, 3, 4].into())],
            )
            .unwrap();
        assert!(out.is_truncated());
        let frame = b.finish();
        assert_eq!(frame.len(), 31);
        assert_eq!(&frame[..2], &[0, 29]);
        let (msg, rest) = tcp::split_frame(frame).unwrap();
        assert!(rest.is_empty());
        assert!(Message::parse_validated(msg).unwrap().flags().tc());
    }

    #[test]
    fn prefix_after_existing_data_and_small_buffers() {
        // Two frames written back to back into one buffer.
        let mut buf = [0u8; 200];
        let mut w = WireWriter::new(&mut buf);
        tcp::append_frame(&mut w, b"\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00").unwrap();
        let mut b = MessageBuilder::from_buf_tcp(w).unwrap();
        b.start_query(2, name("a.example"), Rtype::TXT, Class::IN)
            .unwrap();
        let out = b.finish();
        let frames: std::vec::Vec<_> = tcp::frames(out).collect();
        assert_eq!(frames.len(), 2);
        assert_eq!(Message::parse_validated(frames[1]).unwrap().id(), 2);

        for size in 0..14 {
            let mut buf = std::vec![0u8; size];
            assert_eq!(
                MessageBuilder::new_tcp(&mut buf).unwrap_err(),
                Error::BufferTooSmall
            );
        }
        let mut buf = [0u8; 14];
        assert_eq!(
            MessageBuilder::new_tcp(&mut buf).unwrap().finish(),
            &[0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn largest_tcp_message() {
        let mut buf = std::vec![0u8; 70000];
        let mut b = MessageBuilder::new_tcp(&mut buf).unwrap();
        assert_eq!(b.limit(), MAX_MESSAGE_LEN);
        let big = [0u8; 65535 - 12 - 11];
        b.push_answer(crate::Name::ROOT, Class::IN, 0, &Null { data: &big })
            .unwrap();
        assert_eq!(b.len(), MAX_MESSAGE_LEN);
        assert_eq!(
            b.push_answer(crate::Name::ROOT, Class::IN, 0, &Null { data: b"" }),
            Err(Error::BufferTooSmall)
        );
        let frame = b.finish();
        assert_eq!(&frame[..2], &[0xff, 0xff]);
        assert_eq!(frame.len(), 65537);
        Message::parse_validated(&frame[2..]).unwrap();
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn vec_tcp() {
        let mut b = MessageBuilder::new_tcp_vec();
        assert!(b.is_framed());
        b.start_query(3, name("example.net"), Rtype::NS, Class::IN)
            .unwrap();
        let v = b.finish();
        assert_eq!(v.len(), 2 + 29);
        assert_eq!(tcp::frame_len(&v), Some(31));
        let mut w = std::vec::Vec::new();
        tcp::append_frame(&mut w, &v[2..]).unwrap();
        assert_eq!(w, v);
        assert_eq!(crate::wire::OutBuf::as_bytes(&w).len(), 31);
    }
}
