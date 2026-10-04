//! Building SVCB/HTTPS record data into a caller-supplied buffer, with
//! SvcParams kept sorted (RFC 9460 §2.2).

use core::net::{Ipv4Addr, Ipv6Addr};

use super::params::RawIter;
use super::{Https, SvcParamKey, SvcParamValue, SvcParams, Svcb};
use crate::name::{MAX_NAME_LEN, Name, ToName};
use crate::{Error, Result};

/// The largest RDATA a record can carry (RDLENGTH is 16 bits).
const MAX_RDATA: usize = u16::MAX as usize;

/// Builds SVCB/HTTPS RDATA in a caller-supplied buffer, without
/// allocating.
///
/// SvcParams may be added in any order: each one is validated (the same
/// checks as parsing, [`SvcParamValue::parse`]) and inserted at its sorted
/// position, so the wire form always has strictly increasing keys
/// (RFC 9460 §2.2). Adding a key twice fails with
/// [`Error::InvalidRdata`]; a failed call leaves the builder unchanged.
/// [`finish`](Self::finish) checks self-consistency (RFC 9460 §2.4.3:
/// every `mandatory` key present, `alpn` present with `no-default-alpn`)
/// and returns a view over the buffer, ready to be pushed into a message.
///
/// ```
/// use core::net::Ipv4Addr;
/// use dnsbox::rdata::{SvcParamKey, SvcbBuilder};
/// use dnsbox::NameBuf;
///
/// let target: NameBuf = "svc.example.net".parse()?;
/// let mut buf = [0u8; 128];
/// let mut b = SvcbBuilder::new(&mut buf, 1, &target)?;
/// b.ipv4hint([Ipv4Addr::new(192, 0, 2, 1)])?
///     .port(8443)?
///     .alpn(["h2", "h3"])?
///     .mandatory(&[SvcParamKey::PORT])?;
/// let https = b.finish_https()?;
/// assert_eq!(
///     https.to_string(),
///     "1 svc.example.net. mandatory=port alpn=\"h2,h3\" port=8443 ipv4hint=192.0.2.1"
/// );
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Debug)]
pub struct SvcbBuilder<'b> {
    buf: &'b mut [u8],
    /// Bytes written so far.
    len: usize,
    /// Offset of the first SvcParam (end of the TargetName).
    params_at: usize,
}

impl<'b> SvcbBuilder<'b> {
    /// Starts RDATA with SvcPriority `priority` (0 is AliasMode) and
    /// `target` (written uncompressed and verbatim, RFC 9460 §2.2).
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] if `buf` cannot hold them.
    pub fn new(buf: &'b mut [u8], priority: u16, target: impl ToName) -> Result<Self> {
        let mut flat = [0u8; MAX_NAME_LEN];
        let n = target.to_name().flatten(&mut flat);
        let name = flat.get(..n).ok_or(Error::NameTooLong)?;
        let params_at = 2 + n;
        let head = buf.get_mut(..params_at).ok_or(Error::BufferTooSmall)?;
        let (prio, rest) = head.split_at_mut(2);
        prio.copy_from_slice(&priority.to_be_bytes());
        rest.copy_from_slice(name);
        Ok(SvcbBuilder {
            buf,
            len: params_at,
            params_at,
        })
    }

    /// The RDATA written so far.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }

    /// The RDATA length so far.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether no SvcParams have been added yet (the RDATA is never empty).
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == self.params_at
    }

    /// Writes a SvcParam value with `write`, validates it, and moves it into
    /// sorted position. Leaves the builder unchanged on failure.
    pub(super) fn insert(
        &mut self,
        key: SvcParamKey,
        write: impl FnOnce(&mut Out<'_>) -> Result<()>,
    ) -> Result<&mut Self> {
        if key == SvcParamKey::INVALID {
            return Err(Error::InvalidRdata);
        }
        let start = self.len;
        let value_at = start + 4;
        let mut out = Out {
            buf: self.buf.get_mut(value_at..).ok_or(Error::BufferTooSmall)?,
            len: 0,
        };
        write(&mut out)?;
        let value_len = out.len;
        let end = value_at + value_len;
        if end > MAX_RDATA {
            return Err(Error::BufferTooSmall);
        }
        let value = self.buf.get(value_at..end).ok_or(Error::BufferTooSmall)?;
        SvcParamValue::parse(key, value)?;

        // Find the first existing param with a larger key.
        let existing = self.buf.get(self.params_at..start).unwrap_or(&[]);
        let mut iter = RawIter(existing);
        let mut at = self.params_at;
        while !iter.0.is_empty() {
            let (k, _) = iter.next_checked()?;
            if k == key {
                return Err(Error::InvalidRdata);
            }
            if k > key {
                break;
            }
            at = start - iter.0.len();
        }

        let header = self.buf.get_mut(start..value_at).ok_or(Error::BufferTooSmall)?;
        header[..2].copy_from_slice(&key.get().to_be_bytes());
        header[2..].copy_from_slice(&(value_len as u16).to_be_bytes());
        if let Some(moved) = self.buf.get_mut(at..end) {
            moved.rotate_right(end - start);
        }
        self.len = end;
        Ok(self)
    }

    /// Adds a SvcParam from its wire-format `value`, which must have the
    /// format the key requires (any value for unregistered keys).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRdata`] if the key is already present, is the
    /// reserved key 65535, or the value is malformed;
    /// [`Error::BufferTooSmall`] if the buffer is full. The builder is
    /// unchanged on error, as with every method adding a SvcParam.
    ///
    /// ```
    /// use dnsbox::rdata::{SvcParamKey, SvcbBuilder};
    /// use dnsbox::Name;
    ///
    /// let mut buf = [0u8; 64];
    /// let mut b = SvcbBuilder::new(&mut buf, 1, Name::ROOT)?;
    /// b.param(SvcParamKey::new(65300), b"private")?;
    /// assert!(b.port(443)?.port(853).is_err()); // a key appears once
    /// assert_eq!(b.finish()?.to_string(), "1 . port=443 key65300=\"private\"");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn param(&mut self, key: SvcParamKey, value: &[u8]) -> Result<&mut Self> {
        self.insert(key, |o| o.extend(value))
    }

    /// Adds `mandatory` (RFC 9460 §8). The keys may be given in any order;
    /// they are sorted.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRdata`] for an empty list, a key listed twice or
    /// `mandatory` itself; otherwise as [`param`](Self::param).
    pub fn mandatory(&mut self, keys: &[SvcParamKey]) -> Result<&mut Self> {
        self.insert(SvcParamKey::MANDATORY, |o| {
            for k in keys {
                o.put_u16(k.get())?;
            }
            o.sort_u16();
            Ok(())
        })
    }

    /// Adds `alpn` (RFC 9460 §7.1): one or more protocol IDs of 1–255
    /// octets.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRdata`] for no ID or an ID of the wrong length;
    /// otherwise as [`param`](Self::param).
    pub fn alpn<I>(&mut self, ids: I) -> Result<&mut Self>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        self.insert(SvcParamKey::ALPN, |o| o.put_items(ids))
    }

    /// Adds `no-default-alpn` (RFC 9460 §7.1).
    ///
    /// # Errors
    ///
    /// As [`param`](Self::param).
    pub fn no_default_alpn(&mut self) -> Result<&mut Self> {
        self.insert(SvcParamKey::NO_DEFAULT_ALPN, |_| Ok(()))
    }

    /// Adds `port` (RFC 9460 §7.2).
    ///
    /// # Errors
    ///
    /// As [`param`](Self::param).
    pub fn port(&mut self, port: u16) -> Result<&mut Self> {
        self.insert(SvcParamKey::PORT, |o| o.put_u16(port))
    }

    /// Adds `ipv4hint` (RFC 9460 §7.3): one or more addresses.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRdata`] for no address; otherwise as
    /// [`param`](Self::param).
    pub fn ipv4hint(&mut self, addrs: impl IntoIterator<Item = Ipv4Addr>) -> Result<&mut Self> {
        self.insert(SvcParamKey::IPV4HINT, |o| {
            addrs.into_iter().try_for_each(|a| o.extend(&a.octets()))
        })
    }

    /// Adds `ech` (RFC 9848): an ECHConfigList, length prefix included.
    ///
    /// # Errors
    ///
    /// As [`param`](Self::param).
    pub fn ech(&mut self, config_list: &[u8]) -> Result<&mut Self> {
        self.param(SvcParamKey::ECH, config_list)
    }

    /// Adds `ipv6hint` (RFC 9460 §7.3): one or more addresses.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRdata`] for no address; otherwise as
    /// [`param`](Self::param).
    pub fn ipv6hint(&mut self, addrs: impl IntoIterator<Item = Ipv6Addr>) -> Result<&mut Self> {
        self.insert(SvcParamKey::IPV6HINT, |o| {
            addrs.into_iter().try_for_each(|a| o.extend(&a.octets()))
        })
    }

    /// Adds `dohpath` (RFC 9461 §5): a relative URI template.
    ///
    /// # Errors
    ///
    /// As [`param`](Self::param).
    pub fn dohpath(&mut self, template: &str) -> Result<&mut Self> {
        self.param(SvcParamKey::DOHPATH, template.as_bytes())
    }

    /// Adds `ohttp` (RFC 9540 §4).
    ///
    /// # Errors
    ///
    /// As [`param`](Self::param).
    pub fn ohttp(&mut self) -> Result<&mut Self> {
        self.insert(SvcParamKey::OHTTP, |_| Ok(()))
    }

    /// Adds `tls-supported-groups` (draft-ietf-tls-key-share-prediction
    /// §3.1): one or more distinct TLS NamedGroup code points, most
    /// preferred first (the order is kept).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRdata`] for no group or a repeated one; otherwise
    /// as [`param`](Self::param).
    pub fn tls_supported_groups(
        &mut self,
        groups: impl IntoIterator<Item = u16>,
    ) -> Result<&mut Self> {
        self.insert(SvcParamKey::TLS_SUPPORTED_GROUPS, |o| {
            groups.into_iter().try_for_each(|g| o.put_u16(g))
        })
    }

    /// Adds `docpath` (RFC 9953 §3): zero or more path segments of 1–255
    /// octets (none is the root path).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRdata`] for a segment of the wrong length;
    /// otherwise as [`param`](Self::param).
    pub fn docpath<I>(&mut self, segments: I) -> Result<&mut Self>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        self.insert(SvcParamKey::DOCPATH, |o| o.put_items(segments))
    }

    /// Adds `pvd` (draft-ietf-intarea-proxy-config §2.1).
    ///
    /// # Errors
    ///
    /// As [`param`](Self::param).
    pub fn pvd(&mut self) -> Result<&mut Self> {
        self.insert(SvcParamKey::PVD, |_| Ok(()))
    }

    /// Adds `oots` (draft-johani-dnsop-svcb-oots §2.1): one or more
    /// `(protocol identifier, weight 0–100)` entries.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRdata`] for no entry, an identifier of the wrong
    /// length or a weight above 100; otherwise as [`param`](Self::param).
    pub fn oots<I, P>(&mut self, entries: I) -> Result<&mut Self>
    where
        I: IntoIterator<Item = (P, u8)>,
        P: AsRef<[u8]>,
    {
        self.insert(SvcParamKey::OOTS, |o| {
            for (proto, weight) in entries {
                o.put_item(proto.as_ref())?;
                o.push(weight)?;
            }
            Ok(())
        })
    }

    /// Checks self-consistency and returns the finished RDATA as an
    /// [`Svcb`] view over the buffer.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRdata`] if a `mandatory` key is missing or
    /// `no-default-alpn` lacks `alpn` (RFC 9460 §2.4.3, §7.1.1, §8).
    pub fn finish(self) -> Result<Svcb<'b>> {
        let buf: &'b [u8] = self.buf;
        let rdata = buf.get(..self.len).ok_or(Error::BufferTooSmall)?;
        let (head, params) = rdata.split_at(self.params_at);
        let (prio, target) = head.split_at(2);
        Ok(Svcb {
            priority: u16::from_be_bytes([prio[0], prio[1]]),
            target: Name::from_wire(target)?,
            params: SvcParams::new(params)?,
        })
    }

    /// Like [`finish`](Self::finish), for an `HTTPS` record.
    ///
    /// # Errors
    ///
    /// As [`finish`](Self::finish).
    pub fn finish_https(self) -> Result<Https<'b>> {
        self.finish().map(Https::from)
    }
}

/// Output cursor over the free part of the builder's buffer, used to write
/// one SvcParam value.
pub(super) struct Out<'o> {
    buf: &'o mut [u8],
    len: usize,
}

impl Out<'_> {
    /// Bytes written.
    #[inline]
    pub(super) fn len(&self) -> usize {
        self.len
    }

    /// The bytes written.
    #[inline]
    pub(super) fn as_bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }

    /// Appends one byte.
    pub(super) fn push(&mut self, b: u8) -> Result<()> {
        *self.buf.get_mut(self.len).ok_or(Error::BufferTooSmall)? = b;
        self.len += 1;
        Ok(())
    }

    /// Appends bytes.
    pub(super) fn extend(&mut self, data: &[u8]) -> Result<()> {
        let end = self.len + data.len();
        self.buf
            .get_mut(self.len..end)
            .ok_or(Error::BufferTooSmall)?
            .copy_from_slice(data);
        self.len = end;
        Ok(())
    }

    /// Appends a big-endian `u16`.
    pub(super) fn put_u16(&mut self, v: u16) -> Result<()> {
        self.extend(&v.to_be_bytes())
    }

    /// Overwrites one already-written byte.
    pub(super) fn set(&mut self, at: usize, b: u8) -> Result<()> {
        if at >= self.len {
            return Err(Error::BufferTooSmall);
        }
        *self.buf.get_mut(at).ok_or(Error::BufferTooSmall)? = b;
        Ok(())
    }

    /// Drops everything written from `len` on.
    pub(super) fn truncate(&mut self, len: usize) {
        self.len = self.len.min(len);
    }

    /// The unwritten space, to be filled by a decoder and committed with
    /// [`advance`](Self::advance).
    pub(super) fn spare(&mut self) -> &mut [u8] {
        self.buf.get_mut(self.len..).unwrap_or(&mut [])
    }

    /// Commits `n` bytes written into [`spare`](Self::spare).
    pub(super) fn advance(&mut self, n: usize) {
        self.len = (self.len + n).min(self.buf.len());
    }

    /// Appends a length-prefixed item of 1–255 octets.
    pub(super) fn put_item(&mut self, item: &[u8]) -> Result<()> {
        match u8::try_from(item.len()) {
            Ok(len) if len > 0 => {
                self.push(len)?;
                self.extend(item)
            }
            _ => Err(Error::InvalidRdata),
        }
    }

    /// Appends length-prefixed items.
    fn put_items<I>(&mut self, items: I) -> Result<()>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        items.into_iter().try_for_each(|i| self.put_item(i.as_ref()))
    }

    /// Sorts the written value as a list of big-endian `u16`s.
    pub(super) fn sort_u16(&mut self) {
        if let Some(v) = self.buf.get_mut(..self.len) {
            v.as_chunks_mut::<2>().0.sort_unstable();
        }
    }
}
