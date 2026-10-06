//! Interoperability with dnspython 2.8 (`tests/corpus/dnspython/`; see
//! `tests/corpus/README.md`).
//!
//! RDATA: `rdata.txt` holds, for every record type dnspython implements,
//! examples in dnspython's presentation format next to dnspython's wire
//! encoding (see `gen_rdata.py`). In both directions dnsbox must agree with
//! it:
//!
//! - dnspython's text, read by dnsbox, gives dnspython's wire bytes;
//! - dnspython's wire bytes, decoded and displayed by dnsbox, read back
//!   (by dnsbox) to the same bytes, and the display matches dnspython's up
//!   to the documented differences of style (spacing, quoting and letter
//!   case of hex/base32 fields, plus the list in [`STYLE`]);
//! - dnspython reads dnsbox's display back to the same bytes:
//!   `rdata.dnsbox.txt` is that display (this test checks it is current,
//!   and rewrites it when `DNSBOX_WRITE_DNSPYTHON` is set), and
//!   `gen_rdata.py` checks it with dnspython.
//!
//! Messages and zones: TSIG with every algorithm, dynamic updates, EDNS
//! options and ZONEMD digests made by dnspython (`gen_messages.py`,
//! `gen_zonemd.py`).

#![cfg(feature = "alloc")]

use std::fmt::Write as _;

use dnsbox::rdata::RData;
use dnsbox::{Class, OwnedRData, Rtype, WireReader};

/// One example: type, class, dnspython's text, dnspython's wire bytes.
struct Example {
    rtype: Rtype,
    class: Class,
    text: String,
    wire: Vec<u8>,
}

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn examples() -> Vec<Example> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/corpus/dnspython/rdata.txt"
    );
    std::fs::read_to_string(path)
        .expect("rdata.txt")
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            assert_eq!(f.len(), 4, "{l}");
            Example {
                rtype: f[0].parse().unwrap_or_else(|_| panic!("type {}", f[0])),
                class: f[1].parse().unwrap_or_else(|_| panic!("class {}", f[1])),
                text: f[2].to_owned(),
                wire: hex(f[3]),
            }
        })
        .collect()
}

/// Types whose text form differs between dnspython and BIND, where dnsbox
/// writes BIND's: dnspython writes TKEY (which has no zone-file form)
/// without the key and other data sizes, and reads only that form. dnsbox
/// reads both, so dnspython's text is checked like any other
/// ([`dnspython_text_to_dnsbox_wire`]); dnspython reads dnsbox's display
/// only once `gen_rdata.py --check` has rewritten it to dnspython's layout.
const TEXT_DIFFERS: &[Rtype] = &[Rtype::TKEY];

/// dnsbox's display of the [`TEXT_DIFFERS`] examples: (dnspython text,
/// dnsbox text). dnspython does not read these as they are: `gen_rdata.py
/// --check` checks the sizes and rewrites them to dnspython's layout first.
const BIND_STYLE: &[(&str, &str)] = &[
    (
        "gss-tsig. 1791104299 1791107899 3 0 AAEC",
        "gss-tsig. 1791104299 1791107899 3 NOERROR 3 AAEC 0",
    ),
    (
        "hmac-sha256. 1791104299 1791107899 2 17 AAEC AQID",
        "hmac-sha256. 1791104299 1791107899 2 BADKEY 3 AAEC 3 AQID",
    ),
    (
        "hmac-md5.sig-alg.reg.int. 1791104299 1791190699 2 0 ESIzRFVmd4iZqrvM3e7/AA==",
        "hmac-md5.sig-alg.reg.int. 1791104299 1791190699 2 NOERROR 16 ESIzRFVmd4iZqrvM3e7/AA== 0",
    ),
    (
        "server.example. 1791104299 1791107899 1 0 12345678",
        "server.example. 1791104299 1791107899 1 NOERROR 6 12345678 0",
    ),
    (
        "gss-tsig. 0 0 3 0 YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGhw== AQIDBAUGBwg=",
        "gss-tsig. 0 0 3 NOERROR 40 YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGhw== 8 AQIDBAUGBwg=",
    ),
];

/// Where dnsbox's display legitimately differs from dnspython's beyond
/// spacing, quoting and letter case: (dnspython text, dnsbox text). Each
/// dnsbox text is read back by dnspython to the same bytes
/// (`gen_rdata.py --check`).
const STYLE: &[(&str, &str)] = &[
    // LOC (RFC 1876 Appendix A): dnsbox writes sizes and precisions in
    // whole metres without decimals, and all four fields, like BIND;
    // dnspython always writes two decimals and drops default values.
    (
        "52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000.00m 10.00m",
        "52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m",
    ),
    (
        "42 21 54.000 N 71 6 18.000 W -24.00m 30.00m 10000.00m 10.00m",
        "42 21 54.000 N 71 6 18.000 W -24.00m 30m 10000m 10m",
    ),
    (
        "0 0 0.000 S 0 0 0.000 W 0.00m",
        "0 0 0.000 N 0 0 0.000 E 0.00m 1m 10000m 10m",
    ),
    (
        "90 0 0.000 N 180 0 0.000 E 42849672.95m 90000000.00m 90000000.00m 90000000.00m",
        "90 0 0.000 N 180 0 0.000 E 42849672.95m 90000000m 90000000m 90000000m",
    ),
    // CERT algorithms whose mnemonics differ between IANA, BIND and
    // dnspython are written as numbers (RFC 4398 §2.2 allows both).
    ("SPKI 1 ECC AQID", "SPKI 1 4 AQID"),
    ("IPGP 1 DSANSEC3SHA1 AQID", "IPGP 1 6 AQID"),
    ("ACPKIX 1 RSASHA1NSEC3SHA1 AQID", "ACPKIX 1 7 AQID"),
    ("OID 1 ECCGOST AQID", "OID 1 12 AQID"),
];

/// Spacing, quoting and the case of hex/base32 digits are style.
fn normalize(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace() && *c != '"')
        .flat_map(char::to_lowercase)
        .collect()
}

#[test]
fn covers_every_type() {
    let ex = examples();
    assert!(ex.len() >= 130, "{} examples", ex.len());
    // Every type dnsbox types and dnspython implements is exercised.
    let mut seen: Vec<Rtype> = ex.iter().map(|e| e.rtype).collect();
    seen.sort();
    seen.dedup();
    assert!(seen.len() >= 60, "{} types", seen.len());
    for t in &seen {
        assert!(RData::is_known(*t), "{t}: not typed");
    }
}

#[test]
fn dnspython_text_to_dnsbox_wire() {
    let mut failures = String::new();
    for e in examples() {
        if !RData::is_known(e.rtype) || e.class != Class::IN {
            // dnsbox has no presentation format for these, or another
            // one: dnspython's typed text is rejected, the generic form is
            // not.
            assert!(
                OwnedRData::from_text(e.rtype, e.class, &e.text).is_err(),
                "{} {}",
                e.rtype,
                e.text
            );
            continue;
        }
        match OwnedRData::from_text(e.rtype, e.class, &e.text) {
            Ok(r) if r.as_wire() == e.wire => {}
            Ok(r) => writeln!(
                failures,
                "{} {:?}\n  dnsbox:    {:02x?}\n  dnspython: {:02x?}",
                e.rtype,
                e.text,
                r.as_wire(),
                e.wire
            )
            .unwrap(),
            Err(err) => writeln!(failures, "{} {:?}: {err}", e.rtype, e.text).unwrap(),
        }
    }
    assert!(failures.is_empty(), "\n{failures}");
}

#[test]
fn dnspython_wire_to_dnsbox_text() {
    let mut failures = String::new();
    let mut dump = String::from(
        "# dnsbox's display of every wire example of rdata.txt (tests/interop_dnspython.rs)\n",
    );
    for e in examples() {
        let data = match RData::parse(e.rtype, e.class, WireReader::new(&e.wire)) {
            Ok(d) => d,
            Err(err) => {
                writeln!(failures, "{} {:?}: wire: {err}", e.rtype, e.text).unwrap();
                continue;
            }
        };
        let shown = data.to_string();
        writeln!(
            dump,
            "{}\t{}\t{shown}\t{}",
            e.rtype,
            e.class,
            e.wire
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )
        .unwrap();
        // dnsbox reads its own display back to the same bytes.
        match OwnedRData::from_text(e.rtype, e.class, &shown) {
            Ok(r) if r.as_wire() == e.wire => {}
            other => writeln!(failures, "{} {shown:?}: reads back as {other:?}", e.rtype).unwrap(),
        }
        if matches!(data, RData::Unknown(_)) {
            assert!(shown.starts_with("\\# "), "{shown}");
            continue;
        }
        // Every example of a type whose text differs has its BIND-style
        // display pinned.
        assert_eq!(
            TEXT_DIFFERS.contains(&e.rtype),
            BIND_STYLE.iter().any(|(theirs, _)| *theirs == e.text),
            "{} {}",
            e.rtype,
            e.text
        );
        let expected = STYLE
            .iter()
            .chain(BIND_STYLE)
            .find(|(theirs, _)| *theirs == e.text)
            .map_or(e.text.as_str(), |(_, ours)| ours);
        if normalize(&shown) != normalize(expected) {
            writeln!(
                failures,
                "{}\n  dnsbox:    {shown}\n  dnspython: {}",
                e.rtype, e.text
            )
            .unwrap();
        }
    }
    assert!(failures.is_empty(), "\n{failures}");
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/corpus/dnspython/rdata.dnsbox.txt"
    );
    if std::env::var_os("DNSBOX_WRITE_DNSPYTHON").is_some() {
        std::fs::write(path, &dump).unwrap();
    }
    assert_eq!(
        std::fs::read_to_string(path).unwrap(),
        dump,
        "rerun with DNSBOX_WRITE_DNSPYTHON=1, then gen_rdata.py"
    );
}

/// A tab-separated fixture of `tests/corpus/dnspython/`, without comments.
fn fixture(file: &str) -> Vec<Vec<String>> {
    let path = format!(
        "{}/tests/corpus/dnspython/{file}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{path}: {e}"))
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| l.split('\t').map(str::to_owned).collect())
        .collect()
}

/// A `tests/corpus/*.hex` message.
fn corpus(label: &str) -> Vec<u8> {
    let path = format!("{}/tests/corpus/{label}.hex", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    hex(&text
        .lines()
        .filter(|l| !l.starts_with('#'))
        .collect::<String>())
}

/// TSIG (RFC 8945) with every algorithm dnspython implements, including
/// the truncated HMAC-SHA-2 variants (RFC 4635 §3.1, RFC 8945 §6): dnsbox
/// verifies dnspython's requests, responses, error response and
/// zone-transfer stream, and re-signs them to dnspython's exact bytes.
#[cfg(feature = "tsig")]
mod tsig {
    use super::*;
    use dnsbox::tsig::{
        self, HmacKey, TsigAlgorithm, TsigKey, TsigRcode, TsigSigner, TsigVerifier,
    };
    use dnsbox::{Error, Message, MessageBuilder, NameBuf};

    /// The time dnspython signed at.
    const NOW: u64 = 1_791_104_299;
    const SECRET: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];

    fn key(name: &str, alg: &str) -> HmacKey<'static> {
        let alg: NameBuf = alg.parse().unwrap();
        let alg = TsigAlgorithm::from_name(alg.as_name()).unwrap_or_else(|| panic!("{alg}"));
        let name: NameBuf = name.parse().unwrap();
        HmacKey::new(&name, alg, &SECRET)
    }

    /// Copies everything but the TSIG record of `msg` into a builder.
    fn copy_unsigned(msg: &Message<'_>) -> MessageBuilder<Vec<u8>> {
        let mut b = MessageBuilder::new_vec();
        b.set_id(msg.id());
        b.set_flags(msg.flags());
        for q in msg.questions() {
            b.copy_question(&q.unwrap()).unwrap();
        }
        for rr in msg.records() {
            let (s, rr) = rr.unwrap();
            if rr.rtype() != Rtype::TSIG {
                b.copy_record(s, &rr).unwrap();
            }
        }
        b
    }

    #[test]
    fn every_algorithm() {
        let rows: Vec<_> = fixture("tsig.txt")
            .into_iter()
            .filter(|r| r[0] == "query")
            .collect();
        assert_eq!(rows.len(), 9);
        let mut truncated = 0;
        for row in rows {
            let alg = &row[1];
            let key = key(&row[2], alg);
            let query = hex(&row[4]);
            let response = hex(&row[5]);
            let q = Message::parse_validated(&query).unwrap();
            let rec = tsig::find(&q).unwrap().unwrap();
            assert_eq!(rec.data.mac.len(), key.mac_len(), "{alg}");
            if key.mac_len() < key.algorithm_id().digest_len() {
                truncated += 1;
            }
            let verified = tsig::verify_request(&q, &key, NOW)
                .verified()
                .unwrap_or_else(|| panic!("{alg}"));
            let r = Message::parse_validated(&response).unwrap();
            let mut v = TsigVerifier::new(&key, verified.request_mac()).unwrap();
            assert!(v.verify(&r, NOW).unwrap().is_some(), "{alg}");
            v.finish().unwrap();

            // dnsbox's signatures are dnspython's, byte for byte, except
            // that dnspython writes `HMAC-MD5.SIG-ALG.REG.INT` in capitals
            // (the MAC covers the name in canonical, lowercase form,
            // RFC 8945 §4.3.3, so both MACs agree).
            let mut b = copy_unsigned(&q);
            let mac = TsigSigner::request(&key).sign(&mut b, NOW).unwrap();
            assert_eq!(mac.as_slice(), rec.data.mac, "{alg} request MAC");
            let ours = b.finish();
            assert_eq!(
                ours.to_ascii_lowercase(),
                query.to_ascii_lowercase(),
                "{alg} request"
            );
            let mut b = copy_unsigned(&r);
            let mac = verified.signer().sign(&mut b, NOW).unwrap();
            let theirs = tsig::find(&r).unwrap().unwrap();
            assert_eq!(mac.as_slice(), theirs.data.mac, "{alg} response MAC");
            let ours = b.finish();
            assert_eq!(
                ours.to_ascii_lowercase(),
                response.to_ascii_lowercase(),
                "{alg} response"
            );
            assert_eq!(ours == response, !alg.starts_with("HMAC-MD5"), "{alg}");

            // Tampering with the answer is caught.
            let mut bad = response.clone();
            let at = bad.len() - rec.data.mac.len() - 40;
            bad[at] ^= 1;
            let mut v = TsigVerifier::new(&key, verified.request_mac()).unwrap();
            if let Ok(bad) = Message::parse(&bad) {
                assert!(v.verify(&bad, NOW).is_err(), "{alg}");
            }
        }
        assert_eq!(truncated, 3);
    }

    #[test]
    fn badtime_response() {
        let row = fixture("tsig.txt")
            .into_iter()
            .find(|r| r[0] == "badtime")
            .unwrap();
        let key = key(&row[2], &row[1]);
        let query = hex(&row[4]);
        let response = hex(&row[5]);
        let q = Message::parse_validated(&query).unwrap();
        let r = Message::parse_validated(&response).unwrap();
        let t = tsig::find(&r).unwrap().unwrap();
        assert_eq!(t.data.error, TsigRcode::BADTIME);
        let server_now = t
            .data
            .other
            .iter()
            .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
        assert_eq!(server_now, NOW + 1000);
        // The client sees an authenticated BADTIME.
        let mac = tsig::find(&q).unwrap().unwrap().data.mac;
        let mut v = TsigVerifier::new(&key, mac).unwrap();
        assert_eq!(v.verify(&r, NOW), Err(Error::BadTime));
        // A dnsbox server 1000 s ahead rejects the request with the same
        // response, byte for byte.
        let rej = tsig::verify_request(&q, &key, server_now)
            .rejected()
            .unwrap();
        assert_eq!(rej.error, Error::BadTime);
        let mut b = copy_unsigned(&r);
        rej.sign_response(&mut b, server_now).unwrap();
        assert_eq!(b.finish(), &response[..]);
    }

    #[test]
    fn zone_transfer_stream() {
        let row = fixture("tsig.txt")
            .into_iter()
            .find(|r| r[0] == "axfr")
            .unwrap();
        let key = key(&row[2], &row[1]);
        let q = hex(&row[4]);
        let q = Message::parse_validated(&q).unwrap();
        let verified = tsig::verify_request(&q, &key, NOW).verified().unwrap();
        let stream: Vec<Vec<u8>> = row[5..].iter().map(|h| hex(h)).collect();
        assert_eq!(stream.len(), 3);
        let mut v = TsigVerifier::new(&key, verified.request_mac()).unwrap();
        let mut signer = verified.signer();
        for wire in &stream {
            let msg = Message::parse_validated(wire).unwrap();
            assert!(v.verify(&msg, NOW).unwrap().is_some());
            // dnsbox signs the stream to the same bytes.
            let mut b = copy_unsigned(&msg);
            signer.sign(&mut b, NOW).unwrap();
            assert_eq!(b.finish(), &wire[..]);
        }
        v.finish().unwrap();
        // Out of order, the chain breaks.
        let mut v = TsigVerifier::new(&key, verified.request_mac()).unwrap();
        let second = Message::parse_validated(&stream[1]).unwrap();
        assert_eq!(v.verify(&second, NOW), Err(Error::BadSignature));
    }
}

/// Dynamic updates built by dnspython's `dns.update` (RFC 2136): every
/// prerequisite and update form is classified as dnspython meant it.
#[test]
fn dnspython_updates() {
    use dnsbox::Message;
    use dnsbox::update::{Prerequisite, UpdateMessage, UpdateOp};
    let rows = fixture("update.txt");
    assert_eq!(rows.len(), 2);
    let wire = hex(&rows[0][1]);
    let up = UpdateMessage::new(Message::parse_validated(&wire).unwrap()).unwrap();
    up.validate().unwrap();
    assert_eq!(up.zone_name().to_string(), "example.com.");
    let pre: Vec<String> = up
        .prerequisites()
        .map(|p| match p.unwrap() {
            Prerequisite::NameInUse(n) => format!("in use {n}"),
            Prerequisite::NameAbsent(n) => format!("absent {n}"),
            Prerequisite::RrsetExists { name, rtype } => format!("exists {name} {rtype}"),
            Prerequisite::RrsetAbsent { name, rtype } => format!("absent {name} {rtype}"),
            Prerequisite::RrExists(rr) => format!("exists {rr}"),
        })
        .collect();
    assert_eq!(
        pre,
        [
            "in use www.example.com.",
            "exists www.example.com. A",
            "exists mail.example.com. 0 IN MX 10 mx.example.com.",
            "absent new.example.com.",
            "absent www.example.com. AAAA",
        ]
    );
    let ops: Vec<String> = up
        .updates()
        .map(|o| match o.unwrap() {
            UpdateOp::Add(rr) => format!("add {rr}"),
            UpdateOp::DeleteRrset { name, rtype } => format!("delete {name} {rtype}"),
            UpdateOp::DeleteName(n) => format!("delete {n}"),
            UpdateOp::DeleteRr(rr) => format!("delete {rr}"),
        })
        .collect();
    assert_eq!(
        ops,
        [
            "add new.example.com. 300 IN A 192.0.2.10",
            "add new.example.com. 300 IN TXT \"created by dnspython\"",
            // dnspython's replace(): delete the RRset, then add.
            "delete www.example.com. A",
            "add www.example.com. 600 IN A 192.0.2.80",
            "delete old.example.com.",
            "delete www.example.com. AAAA",
            "delete mail.example.com. 0 NONE MX 10 mx.example.com.",
        ]
    );

    let wire = hex(&rows[1][1]);
    let up = UpdateMessage::new(Message::parse_validated(&wire).unwrap()).unwrap();
    up.validate().unwrap();
    let ops: Vec<String> = up.updates().map(|o| format!("{:?}", o.unwrap())).collect();
    assert_eq!(ops.len(), 2);
}

/// EDNS options built by dnspython (`tests/corpus/dnspython-edns-*.hex`,
/// which tests/dig_display.rs also checks against dig): dnsbox decodes
/// every one to the values dnspython was given.
#[test]
fn dnspython_edns_options() {
    use dnsbox::Message;
    use dnsbox::edns::EdnsOption;
    let options = |label: &str| -> Vec<String> {
        let wire = corpus(label);
        let msg = Message::parse_validated(&wire).unwrap();
        msg.edns()
            .unwrap()
            .unwrap()
            .options()
            .map(|o| format!("{:?}", o.unwrap()))
            .collect()
    };
    let text = |b: &[u8]| format!("{:?}", b.to_vec());
    assert_eq!(
        options("dnspython-edns-options"),
        [
            format!("Nsid(Nsid {{ id: {} }})", text(b"dnspython-ns1")),
            "ClientSubnet(ClientSubnet { addr: 192.0.2.0, source_prefix: 24, scope_prefix: 16 })"
                .to_owned(),
            format!(
                "Cookie(Cookie {{ client: {}, server: {} }})",
                text(&(0..8).collect::<Vec<u8>>()),
                text(&(16..32).collect::<Vec<u8>>())
            ),
            format!(
                "ExtendedError(ExtendedError {{ info_code: Stale Answer, extra_text: {} }})",
                text(b"served stale")
            ),
            "ExtendedError(ExtendedError { info_code: Other Error, extra_text: [] })".to_owned(),
            "Expire(Expire { expire: Some(604800) })".to_owned(),
            "TcpKeepalive(TcpKeepalive { timeout: Some(1200) })".to_owned(),
            "ReportChannel(ReportChannel { agent_domain: Name(agent.example.net.) })".to_owned(),
            format!("Padding(Padding {{ data: {} }})", text(&[0; 11])),
        ]
    );
    assert_eq!(
        options("dnspython-edns-ecs6-ede"),
        [
            "ClientSubnet(ClientSubnet { addr: 2001:db8:1234::, source_prefix: 48, scope_prefix: 0 })"
                .to_owned(),
            format!(
                "ExtendedError(ExtendedError {{ info_code: DNSSEC Bogus, extra_text: {} }})",
                text(b"RRSIG A expired")
            ),
            "Dau(Dau { algorithms: [8, 13, 15] })".to_owned(),
            "Dhu(Dhu { algorithms: [1, 2, 4] })".to_owned(),
            "N3u(N3u { algorithms: [1] })".to_owned(),
            "Chain(Chain { closest_trust_point: Name(example.com.) })".to_owned(),
        ]
    );
    // Every option is a typed one.
    let wire = corpus("dnspython-edns-options");
    let msg = Message::parse_validated(&wire).unwrap();
    let edns = msg.edns().unwrap().unwrap();
    assert!(
        edns.options()
            .all(|o| !matches!(o.unwrap(), EdnsOption::Unknown(_)))
    );
    assert!(edns.dnssec_ok());
    assert_eq!(edns.udp_payload_size(), 1232);
}

/// ZONEMD (RFC 8976) digests computed by dnspython over BIND's zones
/// (every type BIND reads; signed zones with NSEC3, delegations and glue),
/// in zone files written by dnspython: dnsbox reads them, verifies both
/// digests and computes the same bytes.
#[cfg(feature = "dnssec-digest")]
#[test]
fn dnspython_zonemd() {
    use dnsbox::dnssec::{ZonemdFailure, ZonemdRecord, verify_zonemd, zonemd_digest};
    use dnsbox::rdata::{Zonemd, ZonemdHashAlg};
    use dnsbox::zone::ZoneReader;

    for (name, apex, count) in [
        ("alltypes", "alltypes.example.", 148),
        ("ed25519", "ed25519.example.", 87),
        ("nsec3rsasha1", "nsec3rsasha1.example.", 91),
    ] {
        let path = format!(
            "{}/tests/corpus/dnspython/{name}.zonemd",
            env!("CARGO_MANIFEST_DIR")
        );
        let text = std::fs::read_to_string(path).unwrap();
        let zone: Vec<_> = ZoneReader::new(&text)
            .records()
            .collect::<Result<_, _>>()
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(zone.len(), count, "{name}");
        let apex: dnsbox::NameBuf = apex.parse().unwrap();
        let records = |ttl_of_last: Option<u32>| {
            let n = zone.len();
            zone.iter().enumerate().map(move |(i, r)| {
                let ttl = if i + 1 == n {
                    ttl_of_last.unwrap_or(r.ttl)
                } else {
                    r.ttl
                };
                ZonemdRecord::new(r.name.as_name(), r.class, ttl, r.data().unwrap())
            })
        };
        let verified =
            verify_zonemd(apex.as_name(), records(None)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(verified.hash_alg, ZonemdHashAlg::SHA384, "{name}");
        // Both of dnspython's digests are dnsbox's.
        let theirs: Vec<Zonemd<'_>> = zone
            .iter()
            .filter(|r| r.rtype == Rtype::ZONEMD && r.name == apex)
            .map(|r| match r.data().unwrap() {
                RData::Zonemd(z) => z,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(theirs.len(), 2, "{name}");
        for z in theirs {
            let ours = zonemd_digest(apex.as_name(), records(None), z.hash_alg).unwrap();
            assert_eq!(ours.as_bytes(), z.digest, "{name} {}", z.hash_alg);
        }
        // Any change to the zone breaks it.
        assert_eq!(
            verify_zonemd(apex.as_name(), records(Some(1))),
            Err(ZonemdFailure::DigestMismatch),
            "{name}"
        );
    }
}
