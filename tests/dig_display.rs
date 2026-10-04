//! `dig`-style `Display` of whole messages, checked against BIND's `dig`.
//!
//! Every `tests/data/dig/<name>.dig` file is the output of `dig` 9.18.49
//! (from the `;; ->>HEADER<<-` line to the end of the last section) for the
//! message `tests/corpus/<name>.hex` or `tests/data/named/<name>.bin`,
//! served to `dig` by a local UDP responder (with the transaction ID set
//! back to the capture's; `tests/corpus/dig_reference.py`). `Message`'s
//! `Display` must reproduce it line by line. The main known difference is
//! cosmetic: BIND splits long base64 and hex RDATA fields into
//! space-separated chunks of 56 characters (and leaves a trailing space
//! after the TSIG other-data), while dnsbox writes each field in one piece;
//! such lines must still agree byte for byte up to the RDATA column, and in
//! the RDATA once spaces are ignored. The others come from dig 9.18
//! predating some registrations: it shows the NXNAME type and the dohpath
//! SvcParamKey in generic form, and EDNS options it does not decode (DAU,
//! DHU, N3U, CHAIN, Report-Channel) as `OPT=<code>` with hex, where dnsbox
//! shows their mnemonic and value.

use std::fs;
use std::path::Path;

use dnsbox::Message;

/// Loads the wire message a reference output was produced from.
fn wire(name: &str) -> Vec<u8> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let bin = root.join("data/named").join(format!("{name}.bin"));
    if bin.exists() {
        return fs::read(bin).expect("readable capture");
    }
    let text = fs::read_to_string(root.join("corpus").join(format!("{name}.hex")))
        .expect("a corpus file for every reference output");
    let digits: Vec<u8> = text
        .lines()
        .filter(|l| !l.starts_with('#'))
        .flat_map(str::bytes)
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| (b as char).to_digit(16).expect("hex digit") as u8)
        .collect();
    digits.chunks(2).map(|p| (p[0] << 4) | p[1]).collect()
}

/// Every reference output, as (name, text).
fn references() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/dig");
    let mut out: Vec<(String, String)> = fs::read_dir(dir)
        .expect("tests/data/dig exists")
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "dig"))
        .map(|p| {
            let name = p.file_stem().unwrap().to_str().unwrap().to_owned();
            (name, fs::read_to_string(&p).expect("readable"))
        })
        .collect();
    out.sort();
    out
}

/// Whether two output lines agree, allowing for BIND's chunking of long
/// RDATA fields.
fn same_line(dig: &str, ours: &str) -> bool {
    if dig == ours {
        return true;
    }
    // EDNS options dig 9.18 does not decode (`; OPT=5: 08 0d 0f ("...")`)
    // and dnsbox does (`; DAU: 8,13,15`): the same option code.
    if let Some(code) = dig
        .strip_prefix("; OPT=")
        .and_then(|rest| rest.split(':').next())
        .and_then(|n| n.parse::<u16>().ok())
    {
        let code = dnsbox::edns::OptionCode::new(code);
        if code.mnemonic().is_some() && ours.starts_with(&format!("; {code}: ")) {
            return true;
        }
    }
    // Types registered after BIND 9.18: dig shows their generic form.
    if let Some(older) = NEWER_THAN_DIG
        .iter()
        .find(|(m, _)| ours.contains(m))
        .map(|(m, generic)| ours.replace(m, generic))
    {
        return same_line(dig, &older);
    }
    // Owner, TTL, class and type with their separators must be identical.
    let Some(head) = rdata_start(ours) else {
        return false;
    };
    let squeeze = |s: &str| s.replace(' ', "");
    dig.get(..head) == ours.get(..head)
        && dig.get(head..).map(squeeze) == ours.get(head..).map(squeeze)
}

/// Mnemonics dnsbox knows and dig 9.18 does not (it writes the generic
/// form): the NXNAME type (RFC 9824) of Cloudflare's compact-denial NSEC
/// bitmaps and the dohpath SvcParamKey (RFC 9461) of DDR SVCB records.
const NEWER_THAN_DIG: &[(&str, &str)] = &[(" NXNAME", " TYPE128"), (" dohpath=", " key7=")];

/// The offset of the RDATA in a record line: after four fields and the
/// whitespace that follows each.
fn rdata_start(line: &str) -> Option<usize> {
    let mut at = 0;
    for _ in 0..4 {
        let rest = line.get(at..)?;
        let field = rest.find(char::is_whitespace)?;
        let gap = rest[field..]
            .find(|c: char| !c.is_whitespace())
            .unwrap_or(rest.len() - field);
        at += field + gap;
    }
    Some(at)
}

#[test]
fn matches_dig() {
    let refs = references();
    assert!(refs.len() >= 80, "{} reference outputs", refs.len());
    let mut chunked = 0;
    let mut lines = 0;
    for (name, expected) in &refs {
        let wire = wire(name);
        let msg = Message::parse(&wire).unwrap();
        let ours = msg.to_string();
        let ours_lines: Vec<&str> = ours.trim_end().lines().collect();
        let dig_lines: Vec<&str> = expected.trim_end().lines().collect();
        assert_eq!(
            ours_lines.len(),
            dig_lines.len(),
            "{name}: line count\n--- dig\n{expected}\n--- ours\n{ours}"
        );
        lines += dig_lines.len();
        for (d, o) in dig_lines.iter().zip(&ours_lines) {
            assert!(same_line(d, o), "{name}:\n  dig:  {d:?}\n  ours: {o:?}");
            if d != o {
                chunked += 1;
            }
        }
        // The output ends with the blank line after the last section.
        assert!(
            ours.ends_with("\n\n") || !ours.contains("SECTION"),
            "{name}"
        );

        #[cfg(feature = "alloc")]
        {
            // The owned copy displays identically.
            let owned = dnsbox::OwnedMessage::from_wire(&wire).unwrap();
            assert_eq!(owned.to_string(), ours, "{name}");
        }
    }
    // Make sure the chunking allowance (mostly DNSSEC signatures and keys)
    // is not hiding everything.
    assert!(
        chunked * 4 < lines,
        "{chunked} of {lines} lines differ only in spacing"
    );
}

#[test]
fn tsig_and_sig0_pseudosections() {
    // A BIND TSIG-signed response: the TSIG record leaves the additional
    // section for its pseudosection (`dig` output, see above).
    let wire = wire("query-sha256.response");
    let s = Message::parse(&wire).unwrap().to_string();
    assert!(!s.contains("ADDITIONAL SECTION"), "{s}");
    assert!(
        s.ends_with(
            ";; TSIG PSEUDOSECTION:\n\
             tsig-key.\t\t0\tANY\tTSIG\thmac-sha256. 1791104299 300 32 \
             gAYbRXyO+nQ1zZ8F9hbwtcnYYp3lGJ93zucdUmt6LRU= 51660 NOERROR 0\n\n"
        ),
        "{s}"
    );

    // An UPDATE signed with SIG(0) by `nsupdate` (Ed25519): the zone,
    // update section names and the SIG0 pseudosection.
    let wire = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/named/sig0-ed25519.query.bin"),
    )
    .unwrap();
    let s = Message::parse(&wire).unwrap().to_string();
    assert!(
        s.contains(";; flags:; ZONE: 1, PREREQ: 0, UPDATE: 1, ADDITIONAL: 1\n"),
        "{s}"
    );
    assert!(
        s.contains("\n;; ZONE SECTION:\n;example.com.\t\t\tIN\tSOA\n\n"),
        "{s}"
    );
    assert!(s.contains("\n;; UPDATE SECTION:\n"), "{s}");
    assert!(!s.contains("ADDITIONAL SECTION"), "{s}");
    let sig0 = s.split(";; SIG0 PSEUDOSECTION:\n").nth(1).expect(&s);
    assert!(sig0.starts_with(".\t\t\t0\tANY\tSIG\tTYPE0 15 0 0 "), "{s}");
    assert!(sig0.ends_with("\n\n"), "{s}");
}

#[test]
fn malformed_input_never_panics() {
    // Every truncation and many single-octet mutations of every reference
    // message: formatting must terminate without panicking, and a message
    // that does not parse fully says so.
    for (name, _) in references() {
        let wire = wire(&name);
        for len in 12..wire.len() {
            let m = Message::parse(&wire[..len]).unwrap();
            let s = m.to_string();
            assert!(
                s.contains(";; ERROR: ") || s.contains("extra byte"),
                "{name} {len}"
            );
        }
        for i in (0..wire.len()).step_by(3) {
            for v in [0x00, 0x3f, 0xc0, 0xff] {
                let mut w = wire.clone();
                w[i] = v;
                if let Ok(m) = Message::parse(&w) {
                    let _ = m.to_string();
                }
            }
        }
    }
}
