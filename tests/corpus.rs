//! Interop corpus: real responses from BIND, NSD, Knot DNS, PowerDNS
//! (authoritative and recursor), Unbound, Knot Resolver, Cloudflare and the
//! large public resolvers, a local BIND serving DNSSEC-signed zones, and
//! dnspython-built messages, stored as hex under `tests/corpus/` (see
//! `tests/corpus/README.md` for where each comes from).
//!
//! Every message must validate, survive parse → build → parse unchanged
//! (and rebuild to a fixed point), and reject every truncation. Record
//! types without a typed implementation yet are carried as opaque data; as
//! types are added to the registry they are exercised here automatically.

#[path = "../fuzz/src/lib.rs"]
#[allow(dead_code)]
mod checks;

use std::fs;
use std::path::{Path, PathBuf};

use dnsbox::{Message, MessageBuilder, Rcode};

/// Loads every `tests/corpus/*.hex` file: `#` lines are comments.
fn corpus() -> Vec<(PathBuf, Vec<u8>)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .expect("tests/corpus exists")
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "hex"))
        .collect();
    files.sort();
    files
        .into_iter()
        .map(|path| {
            let text = fs::read_to_string(&path).expect("readable");
            let digits: Vec<u8> = text
                .lines()
                .filter(|l| !l.starts_with('#'))
                .flat_map(|l| l.bytes())
                .filter(|b| !b.is_ascii_whitespace())
                .map(|b| (b as char).to_digit(16).expect("hex digit") as u8)
                .collect();
            assert!(
                digits.len().is_multiple_of(2),
                "{}: odd hex length",
                path.display()
            );
            let wire = digits.chunks(2).map(|p| (p[0] << 4) | p[1]).collect();
            (path, wire)
        })
        .collect()
}

#[test]
fn corpus_is_populated() {
    let c = corpus();
    assert!(c.len() >= 170, "only {} corpus files", c.len());
}

#[test]
fn every_message_validates() {
    for (path, wire) in corpus() {
        let msg =
            Message::parse_validated(&wire).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert!(msg.flags().qr(), "{}: not a response", path.display());
        // Every record has a presentation form.
        for rr in msg.records() {
            let (_, rr) = rr.unwrap();
            assert!(!rr.to_string().is_empty());
        }
    }
}

#[test]
fn shared_fuzz_properties_hold() {
    // Full iteration, typed RDATA re-composition, canonical form, and
    // parse → build → parse identity with and without compression.
    for (path, wire) in corpus() {
        let res = std::panic::catch_unwind(|| checks::message(&wire));
        assert!(res.is_ok(), "{}", path.display());
    }
}

#[test]
fn truncations_are_rejected() {
    for (path, wire) in corpus() {
        for end in 0..wire.len() {
            let prefix = &wire[..end];
            assert!(
                Message::parse(prefix).and_then(|m| m.validate()).is_err(),
                "{}: prefix of {end} bytes validated",
                path.display()
            );
        }
    }
}

/// Rebuilding keeps every byte that is not a compression decision: the
/// output is never longer than what the server sent plus what its own
/// compression saved over ours, and most servers compress exactly like
/// dnsbox does, so a good share must come back byte for byte.
#[test]
fn rebuild_size_and_identity() {
    let mut identical = 0;
    let corpus = corpus();
    for (path, wire) in &corpus {
        let msg = Message::parse_validated(wire).unwrap();
        let mut buf = vec![0u8; 65535];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.set_id(msg.id());
        b.set_flags(msg.flags());
        for q in msg.questions() {
            b.copy_question(&q.unwrap()).unwrap();
        }
        for rr in msg.records() {
            let (s, rr) = rr.unwrap();
            b.copy_record(s, &rr).unwrap();
        }
        let out = b.finish();
        if out == &wire[..] {
            identical += 1;
        } else {
            println!("{}: rebuilt differently", path.display());
        }
        let rebuilt = Message::parse_validated(out).unwrap();
        checks::assert_same_message(&msg, &rebuilt);
        if msg.flags().rcode() == Rcode::NOERROR && msg.header().ancount > 0 {
            assert!(
                out.len() <= wire.len() + wire.len() / 4,
                "{}: rebuilt {} bytes from {}",
                path.display(),
                out.len(),
                wire.len()
            );
        }
    }
    println!("{identical} of {} rebuilt byte for byte", corpus.len());
    assert!(
        identical * 2 >= corpus.len(),
        "only {identical} of {} messages rebuilt byte for byte",
        corpus.len()
    );
}
