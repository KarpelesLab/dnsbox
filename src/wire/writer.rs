use crate::name::{MAX_NAME_LEN, Name};
use crate::{Error, Result};

/// How a domain name embedded in record data may be encoded.
///
/// Record-data composers pass one of these with every name they write; the
/// sink decides what to do with it. Plain buffers always write names
/// uncompressed; the message builder compresses [`Compressible`] names when
/// compression is enabled; the [`Canonical`] adapter lowercases
/// [`Compressible`] and [`Lowercase`] names (RFC 4034 §6.2).
///
/// [`Compressible`]: NameEncoding::Compressible
/// [`Lowercase`]: NameEncoding::Lowercase
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NameEncoding {
    /// The name may be compressed. Only for owner/question names and the
    /// names inside the RDATA of the well-known RFC 1035 types (NS, MD, MF,
    /// CNAME, SOA, MB, MG, MR, PTR, MINFO, MX) — RFC 3597 §4 forbids
    /// compression in any type defined later. Lowercased in DNSSEC
    /// canonical form.
    Compressible,
    /// Never compressed, but lowercased in DNSSEC canonical form: the
    /// remaining types of the RFC 4034 §6.2 list (as amended by RFC 6840
    /// §5.1): RP, AFSDB, RT, SIG, PX, NXT, NAPTR, KX, SRV, DNAME, A6, RRSIG.
    Lowercase,
    /// Never compressed and never case-folded (e.g. NSEC next name per
    /// RFC 6840 §5.1, SVCB TargetName, HIP rendezvous servers).
    Plain,
}

/// A byte sink that a message or record can be written into.
///
/// Implemented by [`WireWriter`] (a cursor over a caller-supplied
/// `&mut [u8]`) and, with the `alloc` feature, by `Vec<u8>`. Every `OutBuf`
/// is also a [`Composer`] that writes names uncompressed.
pub trait OutBuf {
    /// What [`into_output`](Self::into_output) returns.
    type Output;

    /// The bytes written so far.
    fn as_bytes(&self) -> &[u8];

    /// The bytes written so far, mutably (for patching length fields).
    fn as_bytes_mut(&mut self) -> &mut [u8];

    /// The largest total length the buffer can reach.
    fn capacity_limit(&self) -> usize;

    /// Appends `data`, or fails with [`Error::BufferTooSmall`] without
    /// writing anything.
    fn append(&mut self, data: &[u8]) -> Result<()>;

    /// Shortens the written data to `len` bytes (no-op if already shorter).
    fn truncate(&mut self, len: usize);

    /// Consumes the buffer, returning the written data.
    fn into_output(self) -> Self::Output
    where
        Self: Sized;
}

/// A write cursor over a caller-supplied `&mut [u8]`.
#[derive(Debug)]
pub struct WireWriter<'b> {
    buf: &'b mut [u8],
    len: usize,
}

impl<'b> WireWriter<'b> {
    /// Creates a writer that fills `buf` from the start.
    #[inline]
    pub const fn new(buf: &'b mut [u8]) -> Self {
        WireWriter { buf, len: 0 }
    }

    /// Number of bytes written.
    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether nothing has been written yet.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Total size of the underlying buffer.
    #[inline]
    pub const fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// Bytes still available.
    #[inline]
    pub const fn remaining(&self) -> usize {
        self.buf.len() - self.len
    }

    /// The bytes written so far (also [`OutBuf::as_bytes`]).
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }

    /// Consumes the writer, returning the written prefix of the buffer
    /// (also [`OutBuf::into_output`]).
    #[inline]
    pub fn into_written(self) -> &'b mut [u8] {
        let len = self.len.min(self.buf.len());
        self.buf.split_at_mut(len).0
    }
}

impl<'b> OutBuf for WireWriter<'b> {
    type Output = &'b mut [u8];

    #[inline]
    fn as_bytes(&self) -> &[u8] {
        self.as_bytes()
    }

    #[inline]
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        let len = self.len;
        self.buf.get_mut(..len).unwrap_or(&mut [])
    }

    #[inline]
    fn capacity_limit(&self) -> usize {
        self.buf.len()
    }

    #[inline]
    fn append(&mut self, data: &[u8]) -> Result<()> {
        let end = self
            .len
            .checked_add(data.len())
            .ok_or(Error::BufferTooSmall)?;
        let dst = self
            .buf
            .get_mut(self.len..end)
            .ok_or(Error::BufferTooSmall)?;
        dst.copy_from_slice(data);
        self.len = end;
        Ok(())
    }

    #[inline]
    fn truncate(&mut self, len: usize) {
        self.len = self.len.min(len);
    }

    #[inline]
    fn into_output(self) -> &'b mut [u8] {
        self.into_written()
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl OutBuf for alloc::vec::Vec<u8> {
    type Output = alloc::vec::Vec<u8>;

    #[inline]
    fn as_bytes(&self) -> &[u8] {
        self
    }

    #[inline]
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        self
    }

    #[inline]
    fn capacity_limit(&self) -> usize {
        isize::MAX as usize
    }

    #[inline]
    fn append(&mut self, data: &[u8]) -> Result<()> {
        self.extend_from_slice(data);
        Ok(())
    }

    #[inline]
    fn truncate(&mut self, len: usize) {
        alloc::vec::Vec::truncate(self, len);
    }

    #[inline]
    fn into_output(self) -> Self {
        self
    }
}

/// A sink for wire-format data: what [`ComposeRdata`](crate::ComposeRdata)
/// implementations write to.
///
/// Positions ([`pos`](Self::pos), [`patch`](Self::patch)) are offsets from
/// the start of the sink — for the message builder, from the start of the
/// DNS message.
pub trait Composer {
    /// The current write position.
    fn pos(&self) -> usize;

    /// Appends raw bytes, or fails with [`Error::BufferTooSmall`] without
    /// writing anything.
    fn put_bytes(&mut self, data: &[u8]) -> Result<()>;

    /// Overwrites already-written bytes starting at `pos` (e.g. to fill in a
    /// length placeholder).
    fn patch(&mut self, pos: usize, data: &[u8]) -> Result<()>;

    /// Writes a domain name. `encoding` says whether the name may be
    /// compressed and how it behaves in canonical form; the sink decides.
    fn put_name(&mut self, name: Name<'_>, encoding: NameEncoding) -> Result<()>;

    /// Appends one byte.
    #[inline]
    fn put_u8(&mut self, v: u8) -> Result<()> {
        self.put_bytes(&[v])
    }

    /// Appends a big-endian `u16`.
    #[inline]
    fn put_u16(&mut self, v: u16) -> Result<()> {
        self.put_bytes(&v.to_be_bytes())
    }

    /// Appends a big-endian `u32`.
    #[inline]
    fn put_u32(&mut self, v: u32) -> Result<()> {
        self.put_bytes(&v.to_be_bytes())
    }

    /// Appends the low 48 bits of `v`, big-endian (RFC 8945 §4.2).
    #[inline]
    fn put_u48(&mut self, v: u64) -> Result<()> {
        let b = v.to_be_bytes();
        self.put_bytes(&b[2..])
    }

    /// Appends a big-endian `u64`.
    #[inline]
    fn put_u64(&mut self, v: u64) -> Result<()> {
        self.put_bytes(&v.to_be_bytes())
    }

    /// Appends a `<character-string>` (RFC 1035 §3.3): a length octet and
    /// the bytes. Fails with [`Error::CharStringTooLong`] beyond 255 bytes.
    #[inline]
    fn put_char_string(&mut self, data: &[u8]) -> Result<()> {
        let len = u8::try_from(data.len()).map_err(|_| Error::CharStringTooLong)?;
        self.put_u8(len)?;
        self.put_bytes(data)
    }

    /// Writes a 16-bit length placeholder, runs `f`, then patches the
    /// placeholder with the number of bytes `f` wrote. Use for
    /// length-prefixed sub-structures (EDNS options, SvcParams, ...).
    fn put_u16_prefixed(&mut self, f: impl FnOnce(&mut Self) -> Result<()>) -> Result<()> {
        let at = self.pos();
        self.put_u16(0)?;
        f(self)?;
        let len = self.pos() - at - 2;
        let len = u16::try_from(len).map_err(|_| Error::BufferTooSmall)?;
        self.patch(at, &len.to_be_bytes())
    }
}

/// Writes `name` uncompressed into `c`, optionally lowercasing it.
pub(crate) fn put_name_uncompressed<C: Composer + ?Sized>(
    c: &mut C,
    name: Name<'_>,
    lowercase: bool,
) -> Result<()> {
    if !lowercase && let Some(bytes) = name.as_contiguous() {
        return c.put_bytes(bytes);
    }
    let mut buf = [0u8; MAX_NAME_LEN];
    let len = name.flatten(&mut buf);
    let bytes = buf.get_mut(..len).ok_or(Error::NameTooLong)?;
    if lowercase {
        bytes.make_ascii_lowercase();
    }
    c.put_bytes(bytes)
}

impl<T: OutBuf + ?Sized> Composer for T {
    #[inline]
    fn pos(&self) -> usize {
        self.as_bytes().len()
    }

    #[inline]
    fn put_bytes(&mut self, data: &[u8]) -> Result<()> {
        self.append(data)
    }

    #[inline]
    fn patch(&mut self, pos: usize, data: &[u8]) -> Result<()> {
        let end = pos.checked_add(data.len()).ok_or(Error::BufferTooSmall)?;
        self.as_bytes_mut()
            .get_mut(pos..end)
            .ok_or(Error::BufferTooSmall)?
            .copy_from_slice(data);
        Ok(())
    }

    #[inline]
    fn put_name(&mut self, name: Name<'_>, _encoding: NameEncoding) -> Result<()> {
        put_name_uncompressed(self, name, false)
    }
}

/// A [`Composer`] adapter that produces DNSSEC canonical form (RFC 4034
/// §6.2): names are never compressed, and [`NameEncoding::Compressible`] /
/// [`NameEncoding::Lowercase`] names are converted to lowercase.
///
/// ```
/// use dnsbox::{ComposeRdata, NameBuf, WireWriter};
/// use dnsbox::rdata::Mx;
/// use dnsbox::wire::Canonical;
///
/// let exchange: NameBuf = "MAIL.Example.".parse()?;
/// let mx = Mx { preference: 10, exchange: exchange.as_name() };
/// let mut buf = [0u8; 64];
/// let mut w = WireWriter::new(&mut buf);
/// mx.compose_rdata(&mut Canonical::new(&mut w))?;
/// assert_eq!(w.as_bytes(), b"\x00\x0a\x04mail\x07example\x00");
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Debug)]
pub struct Canonical<'c, C: ?Sized> {
    inner: &'c mut C,
}

impl<'c, C: Composer + ?Sized> Canonical<'c, C> {
    /// Wraps a composer.
    #[inline]
    pub fn new(inner: &'c mut C) -> Self {
        Canonical { inner }
    }
}

impl<C: Composer + ?Sized> Composer for Canonical<'_, C> {
    #[inline]
    fn pos(&self) -> usize {
        self.inner.pos()
    }

    #[inline]
    fn put_bytes(&mut self, data: &[u8]) -> Result<()> {
        self.inner.put_bytes(data)
    }

    #[inline]
    fn patch(&mut self, pos: usize, data: &[u8]) -> Result<()> {
        self.inner.patch(pos, data)
    }

    #[inline]
    fn put_name(&mut self, name: Name<'_>, encoding: NameEncoding) -> Result<()> {
        put_name_uncompressed(&mut *self.inner, name, encoding != NameEncoding::Plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NameBuf;

    #[test]
    fn slice_writer() {
        let mut buf = [0u8; 8];
        let mut w = WireWriter::new(&mut buf);
        assert!(w.is_empty());
        w.put_u16(0x0102).unwrap();
        w.put_u8(3).unwrap();
        assert_eq!(w.put_u48(0), Err(Error::BufferTooSmall));
        assert_eq!(w.len(), 3, "failed write must not advance");
        w.put_u32(0x0405_0607).unwrap();
        assert_eq!(w.remaining(), 1);
        assert_eq!(w.put_u16(0), Err(Error::BufferTooSmall));
        w.patch(0, &[9]).unwrap();
        assert_eq!(w.patch(6, &[9, 9]), Err(Error::BufferTooSmall));
        assert_eq!(w.as_bytes(), &[9, 2, 3, 4, 5, 6, 7]);
        w.truncate(2);
        assert_eq!(w.into_written(), &[9, 2]);
    }

    #[test]
    fn prefixed() {
        let mut buf = [0u8; 300];
        let mut w = WireWriter::new(&mut buf);
        w.put_u16_prefixed(|w| w.put_char_string(b"hi")).unwrap();
        assert_eq!(w.as_bytes(), &[0, 3, 2, b'h', b'i']);
        assert_eq!(
            w.put_char_string(&[0u8; 256]),
            Err(Error::CharStringTooLong)
        );
        w.put_u64(1).unwrap();
        assert_eq!(w.len(), 13);
    }

    #[test]
    fn names() {
        let n: NameBuf = "WWW.Example.".parse().unwrap();
        let mut buf = [0u8; 64];
        let mut w = WireWriter::new(&mut buf);
        w.put_name(n.as_name(), NameEncoding::Compressible).unwrap();
        Canonical::new(&mut w)
            .put_name(n.as_name(), NameEncoding::Lowercase)
            .unwrap();
        Canonical::new(&mut w)
            .put_name(n.as_name(), NameEncoding::Plain)
            .unwrap();
        assert_eq!(
            w.as_bytes(),
            b"\x03WWW\x07Example\x00\x03www\x07example\x00\x03WWW\x07Example\x00"
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn vec_writer() {
        let mut v = alloc::vec::Vec::new();
        v.put_u16(7).unwrap();
        v.put_u16_prefixed(|v| v.put_u32(1)).unwrap();
        assert_eq!(v, [0, 7, 0, 4, 0, 0, 0, 1]);
        OutBuf::truncate(&mut v, 2);
        assert_eq!(v.into_output(), [0, 7]);
    }
}
