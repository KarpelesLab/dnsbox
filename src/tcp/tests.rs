use super::*;
use crate::WireWriter;
use crate::message::Message;
use crate::testutil::hex;
use std::vec::Vec;

/// Two DNS-over-TCP frames as sent by `dig +tcp +keepopen` style clients
/// pipelining queries (RFC 7766 §6.2.1.1): `example.com A` (ID 0x1234)
/// and `example.com AAAA` (ID 0x1235), each length-prefixed.
fn pipelined() -> Vec<u8> {
    hex(
        "001d 1234 0100 0001 0000 0000 0000 076578616d706c6503636f6d00 0001 0001\
         001d 1235 0100 0001 0000 0000 0000 076578616d706c6503636f6d00 001c 0001",
    )
}

#[test]
fn prefix_bounds() {
    assert_eq!(length_prefix(0), Ok([0, 0]));
    assert_eq!(length_prefix(65535), Ok([0xff, 0xff]));
    assert_eq!(length_prefix(65536), Err(Error::MessageTooLong));
    assert_eq!(length_prefix(usize::MAX), Err(Error::MessageTooLong));
}

#[test]
fn write_and_append() {
    let mut out = [0u8; 8];
    assert_eq!(write_frame(&mut out, b"abc"), Ok(5));
    assert_eq!(&out[..5], &[0, 3, b'a', b'b', b'c']);
    assert_eq!(write_frame(&mut out, &[0; 7]), Err(Error::BufferTooSmall));
    assert_eq!(write_frame(&mut out, &[0; 6]), Ok(8));
    let big = std::vec![0u8; 65536];
    assert_eq!(
        write_frame(&mut std::vec![0u8; 70000], &big),
        Err(Error::MessageTooLong)
    );

    let mut buf = [0u8; 7];
    let mut w = WireWriter::new(&mut buf);
    append_frame(&mut w, b"xy").unwrap();
    assert_eq!(append_frame(&mut w, b"xy"), Err(Error::BufferTooSmall));
    assert_eq!(
        w.written(),
        &[0, 2, b'x', b'y'],
        "failed append left nothing"
    );
    append_frame(&mut w, b"z").unwrap();
    assert_eq!(w.written(), &[0, 2, b'x', b'y', 0, 1, b'z']);
    assert_eq!(append_frame(&mut w, b""), Err(Error::BufferTooSmall));
    assert_eq!(
        append_frame(&mut WireWriter::new(&mut []), &big),
        Err(Error::MessageTooLong)
    );
}

#[test]
fn split_and_iterate() {
    let stream = pipelined();
    let msgs: Vec<_> = frames(&stream).collect();
    assert_eq!(msgs.len(), 2);
    for (msg, id) in msgs.iter().zip([0x1234, 0x1235]) {
        assert_eq!(Message::parse_validated(msg).unwrap().id(), id);
    }
    // Every prefix of the stream: complete frames come out, the rest is
    // the remainder, nothing panics.
    for end in 0..=stream.len() {
        let mut it = frames(&stream[..end]);
        let n = it.by_ref().count();
        let expect = match end {
            0..=30 => 0,
            31..=61 => 1,
            _ => 2,
        };
        assert_eq!(n, expect, "end {end}");
        assert_eq!(it.consumed(), 31 * expect);
        assert_eq!(it.remainder(), &stream[31 * expect..end]);
        assert_eq!(split_frame(&stream[..end]).is_some(), end >= 31);
    }
    // Zero-length frames are returned as empty messages.
    assert_eq!(split_frame(&[0, 0, 9]), Some((&[][..], &[9][..])));
    assert_eq!(frame_len(&[]), None);
}

#[test]
fn reassembler_every_split() {
    let stream = pipelined();
    // Feed the stream in two reads split at every offset, through both
    // the copying and the in-place APIs.
    for cut in 0..=stream.len() {
        for in_place in [false, true] {
            let mut storage = [0u8; 40];
            let mut r = FrameReassembler::new(&mut storage);
            let mut ids = Vec::new();
            for part in [&stream[..cut], &stream[cut..]] {
                let mut part = part;
                while !part.is_empty() {
                    let n = if in_place {
                        let spare = r.spare();
                        let n = spare.len().min(part.len());
                        spare[..n].copy_from_slice(&part[..n]);
                        r.commit(n);
                        n
                    } else {
                        r.extend(part)
                    };
                    part = &part[n..];
                    while let Some(msg) = r.next_frame().unwrap() {
                        ids.push(Message::parse_validated(msg).unwrap().id());
                    }
                }
            }
            assert_eq!(ids, [0x1234, 0x1235], "cut {cut}");
            assert!(r.is_empty());
        }
    }
}

#[test]
fn reassembler_byte_by_byte_with_small_buffer() {
    // A buffer exactly one frame long: still works one byte at a time.
    let stream = pipelined();
    let mut storage = [0u8; 31];
    let mut r = FrameReassembler::new(&mut storage);
    assert_eq!(r.capacity(), 31);
    let mut count = 0;
    for &b in &stream {
        assert_eq!(r.extend(&[b]), 1);
        if let Some(msg) = r.next_frame().unwrap() {
            assert_eq!(msg.len(), 29);
            count += 1;
        }
    }
    assert_eq!(count, 2);
    assert_eq!(r.buffered(), 0);
    // When full, extend takes nothing.
    r.extend(&[0, 40]);
    r.extend(&[1; 29]);
    assert_eq!(r.extend(&[1]), 0);
    assert!(r.spare().is_empty());
}

#[test]
fn reassembler_oversized_frame() {
    let mut storage = [0u8; 16];
    let mut r = FrameReassembler::new(&mut storage);
    assert!(!r.skip_frame(), "no prefix yet");
    // A 20-byte message cannot fit in 16 bytes.
    let mut stream = std::vec![0, 20];
    stream.extend_from_slice(&[0xaa; 20]);
    stream.extend_from_slice(&[0, 2, b'o', b'k']);
    assert_eq!(r.extend(&stream[..10]), 10);
    assert_eq!(r.next_frame(), Err(Error::BufferTooSmall));
    assert!(r.skip_frame());
    assert!(!r.is_empty(), "12 bytes still to discard");
    assert_eq!(r.next_frame(), Ok(None));
    // The rest of the big frame arrives in two pieces, mixed with the next
    // frame, via both APIs.
    let spare = r.spare();
    spare[..5].copy_from_slice(&stream[10..15]);
    r.commit(5);
    assert_eq!(r.buffered(), 0);
    assert_eq!(r.extend(&stream[15..]), stream.len() - 15);
    assert_eq!(r.next_frame(), Ok(Some(&b"ok"[..])));
    assert!(r.is_empty());

    // Skipping a frame whose bytes are all buffered.
    let mut storage = [0u8; 16];
    let mut r = FrameReassembler::new(&mut storage);
    r.extend(&[0, 1, 7, 0, 1, 8]);
    assert!(r.skip_frame());
    assert_eq!(r.next_frame(), Ok(Some(&[8][..])));
    // commit beyond the spare space is clamped.
    r.commit(1000);
    assert_eq!(r.buffered(), 16);
    r.clear();
    assert!(r.is_empty());
}

#[test]
fn reassembler_max_frame() {
    let mut storage = std::vec![0u8; MAX_FRAME_LEN];
    let mut r = FrameReassembler::new(&mut storage);
    let mut frame = std::vec![0xff, 0xff];
    frame.resize(MAX_FRAME_LEN, 7);
    assert_eq!(r.extend(&frame), MAX_FRAME_LEN);
    assert_eq!(r.next_frame().unwrap().unwrap().len(), 65535);
}

#[cfg(feature = "std")]
#[test]
fn io_helpers() {
    use std::io::{self, Cursor, ErrorKind, IoSlice, Write};

    let stream = pipelined();
    let mut cur = Cursor::new(&stream[..]);
    let mut buf = [0u8; 512];
    assert_eq!(read_message(&mut cur, &mut buf).unwrap().unwrap().len(), 29);
    assert_eq!(read_message(&mut cur, &mut buf).unwrap().unwrap()[1], 0x35);
    assert_eq!(read_message(&mut cur, &mut buf).unwrap(), None);
    // Cut inside a frame.
    let mut cur = Cursor::new(&stream[..20]);
    assert_eq!(
        read_message(&mut cur, &mut buf).unwrap_err().kind(),
        ErrorKind::UnexpectedEof
    );
    let mut cur = Cursor::new(&stream[..1]);
    assert_eq!(
        read_message(&mut cur, &mut buf).unwrap_err().kind(),
        ErrorKind::UnexpectedEof
    );
    // Too big for the buffer.
    let mut cur = Cursor::new(&stream[..]);
    assert_eq!(
        read_message(&mut cur, &mut [0u8; 28]).unwrap_err().kind(),
        ErrorKind::InvalidData
    );

    let mut out = Vec::new();
    write_message(&mut out, &stream[2..31]).unwrap();
    write_message(&mut out, &stream[33..]).unwrap();
    assert_eq!(out, stream);
    assert_eq!(
        write_message(&mut out, &std::vec![0u8; 65536])
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidInput
    );

    /// A writer that accepts one byte per call and is sometimes
    /// interrupted.
    struct Dribble(Vec<u8>, u32);
    impl Write for Dribble {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.1 += 1;
            if self.1.is_multiple_of(3) {
                return Err(ErrorKind::Interrupted.into());
            }
            self.0.extend_from_slice(&buf[..buf.len().min(1)]);
            Ok(buf.len().min(1))
        }
        fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
            let first = bufs.iter().find(|b| !b.is_empty()).map_or(&[][..], |b| b);
            self.write(first)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut d = Dribble(Vec::new(), 0);
    write_message(&mut d, b"hello").unwrap();
    assert_eq!(d.0, b"\x00\x05hello");

    struct Full;
    impl Write for Full {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Ok(0)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    assert_eq!(
        write_message(&mut Full, b"x").unwrap_err().kind(),
        ErrorKind::WriteZero
    );
}
