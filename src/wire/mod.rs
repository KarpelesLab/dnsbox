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

mod reader;
mod writer;

pub use reader::WireReader;
pub(crate) use writer::put_name_uncompressed;
pub use writer::{Canonical, Composer, NameEncoding, OutBuf, WireWriter};
