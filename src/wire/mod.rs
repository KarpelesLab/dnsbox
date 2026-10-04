//! Bounds-checked wire-format primitives.
//!
//! Every parser and builder in the crate sits on two primitives:
//!
//! - [`WireReader`]: a cursor over a received message. It remembers the
//!   *whole* message (so domain names can follow compression pointers,
//!   RFC 1035 §4.1.4) and a read window (so an RDATA parser cannot run past
//!   its RDLENGTH). Every read is bounds-checked and returns
//!   [`Error::UnexpectedEof`](crate::Error::UnexpectedEof) instead of
//!   panicking; a failed read does not move the cursor.
//! - [`Composer`]: the sink that record data and names are written to. It is
//!   implemented by every [`OutBuf`] (a plain [`WireWriter`] over `&mut [u8]`,
//!   or `Vec<u8>` with the `alloc` feature), which write names uncompressed,
//!   and by the message builder's internal writer, which may compress names
//!   according to their [`NameEncoding`].
//!
//! [`WireReader`], [`WireWriter`], [`Composer`], [`OutBuf`] and
//! [`NameEncoding`] are re-exported at the crate root.
//!
//! # Examples
//!
//! Reading and writing the fixed part of a resource record by hand:
//!
//! ```
//! use dnsbox::{Composer, NameBuf, NameEncoding, WireReader, WireWriter};
//!
//! let owner: NameBuf = "example".parse()?;
//! let mut buf = [0u8; 64];
//! let mut w = WireWriter::new(&mut buf);
//! w.put_name(owner.as_name(), NameEncoding::Compressible)?;
//! w.put_u16(1)?; // TYPE A
//! w.put_u16(1)?; // CLASS IN
//! w.put_u32(300)?; // TTL
//! w.put_u16_prefixed(|w| w.put_bytes(&[192, 0, 2, 1]))?; // RDLENGTH + RDATA
//! let wire = w.into_written();
//!
//! let mut r = WireReader::new(wire);
//! assert_eq!(r.read_name()?, owner.as_name());
//! assert_eq!((r.read_u16()?, r.read_u16()?, r.read_u32()?), (1, 1, 300));
//! let len = r.read_u16()?;
//! let mut rdata = r.sub_reader(usize::from(len))?;
//! assert_eq!(rdata.read_array::<4>()?, [192, 0, 2, 1]);
//! rdata.finish()?;
//! r.finish()?;
//! # Ok::<(), dnsbox::Error>(())
//! ```

mod reader;
mod writer;

pub use reader::WireReader;
pub(crate) use writer::put_name_uncompressed;
pub use writer::{Canonical, Composer, NameEncoding, OutBuf, WireWriter};
