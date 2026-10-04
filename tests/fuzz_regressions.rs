//! Replays the fuzzing seed corpora (`fuzz/seeds/<target>/`) and every
//! reproducer of a fixed fuzzer finding (`fuzz/regressions/<target>/`)
//! through the same property checks the fuzz targets run, on stable Rust
//! and in every feature configuration.
//!
//! When a fuzz target finds a crash, fix it, then copy the reproducer from
//! `fuzz/artifacts/<target>/` to `fuzz/regressions/<target>/` with a
//! descriptive name so it is checked here forever.

#[path = "../fuzz/src/lib.rs"]
mod checks;

use std::fs;
use std::path::Path;

/// A property check over raw fuzzer bytes.
type Check = fn(&[u8]);

/// Runs `check` on every file of `fuzz/{seeds,regressions}/<target>/`.
fn replay(target: &str, check: Check) -> usize {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz");
    let mut n = 0;
    for kind in ["seeds", "regressions"] {
        let Ok(dir) = fs::read_dir(root.join(kind).join(target)) else {
            continue;
        };
        let mut paths: Vec<_> = dir.map(|e| e.expect("dir entry").path()).collect();
        paths.sort();
        for path in paths {
            let data = fs::read(&path).expect("readable corpus file");
            // Name the input on failure.
            let res = std::panic::catch_unwind(|| check(&data));
            assert!(res.is_ok(), "{target}: {} failed", path.display());
            n += 1;
        }
    }
    n
}

#[test]
fn message() {
    assert!(replay("message", checks::message) > 0);
}

#[test]
fn name() {
    assert!(replay("name", checks::name) > 0);
}

#[test]
fn rdata() {
    assert!(replay("rdata", checks::rdata) > 0);
}

#[test]
fn roundtrip() {
    assert!(replay("roundtrip", checks::roundtrip) > 0);
}

#[test]
fn text() {
    assert!(replay("text", checks::text) > 0);
}

/// The checks also hold for every prefix of every seed (cheap extra
/// coverage of the truncation paths without a fuzzer).
#[test]
fn seed_prefixes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds");
    let targets: [(&str, Check); 5] = [
        ("message", checks::message),
        ("name", checks::name),
        ("rdata", checks::rdata),
        ("roundtrip", checks::roundtrip),
        ("text", checks::text),
    ];
    for (target, check) in targets {
        for entry in fs::read_dir(root.join(target)).expect("seed dir") {
            let data = fs::read(entry.expect("entry").path()).expect("seed");
            for end in 0..data.len() {
                check(&data[..end]);
            }
        }
    }
}
