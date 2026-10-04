//! A DNSSEC-validating `dig`-like printer for captured responses.
//!
//! It authenticates a zone's DNSKEY RRset against a trust anchor (DS
//! records, as in a root-anchors file or the parent zone), then verifies
//! every RRset of a response with those keys, and prints the response the
//! way `dig` does, followed by the verdict for each RRset.
//!
//! ```text
//! cargo run --example dnssec_dig --features dnssec
//! cargo run --example dnssec_dig --features dnssec -- \
//!     --anchor ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D" \
//!     --now 1791105383 root-dnskey.hex root-dnskey.hex
//! ```
//!
//! Arguments: `[--now UNIX-TIME] [--anchor DS-RECORD]... [RESPONSE
//! DNSKEY-RESPONSE]`. The responses are files holding a DNS message in
//! hex (whitespace and `#` comments allowed, as `tests/corpus/*.hex`) or
//! as raw bytes; DNSKEY-RESPONSE is the zone's answer to `DNSKEY`, with
//! its RRSIGs (query with the DO bit, e.g. `dig +dnssec`). Without files,
//! two responses captured from 1.1.1.1 on 2026-10-04 are checked as of the
//! capture time: the root DNSKEY RRset against the IANA root trust anchor,
//! and the SOA of `ed25519.nl` (Ed25519 signatures).
//!
//! What it shows: [`TrustedKeys::from_ds_with_budget`] (DS → DNSKEY,
//! RFC 4035 §5.2), [`TrustedKeys::verify_rrset_with_budget`] (RFC 4035
//! §5.3) over RRsets taken from a message without copying
//! ([`RecordRdata`]), one [`ValidationBudget`] per response (the KeyTrap
//! bounds), DS records read with the zone-file parser, and the
//! [`PurecryptoVerifier`] backend.

use std::error::Error as StdError;

use dnsbox::dnssec::{
    PurecryptoVerifier, RecordRdata, Rrset, Timestamp, TrustedKeys, ValidationBudget, Verified,
};
use dnsbox::rdata::{Dnskey, Ds, RData, Rrsig};
use dnsbox::zone::{ZoneReader, ZoneRecordBuf};
use dnsbox::{Class, Message, Name, Record, Rtype, Section};

/// `dig . DNSKEY +dnssec @1.1.1.1` (RSASHA256; KSK-2017 is key 20326).
const ROOT_DNSKEY: &str = "\
d00081a000010005000000010000300001000030000100000cca01080100030803010001ca2b37135cf6dd2e7b565e9c
f8d5311ba3950d982c1274a51ff85cc8c76f2f6faf4ddc4711522a75a9c5e8393cbdfce03f557aa752d5b8eb1b24ec1e
da1a8332373625c577cb231cc3a7671bb9a69ffe501220eed6ac62054c31d52233562efdcfaddf4775430fefe8d60b36
73a7cb04eee87b9487b635b1946afc665caf12c43571d0a322a93ab3abf11dfea9deb02baf48281f3464166d917f6b74
4a8a264fb26178c4673674ce4005b6198d802ade02853d3d5954eba7723ac68b8dfdf02949549bd48d38ab3eb4ae8bb9
29916caebed53fed3da45a301484bafd86eaf5df9c9d6ec8c6c6beda519ff60372f4e3ae9e83cc4e97c85e3841dc09de
82b1e1e9000030000100000cca01080100030803010001e0980fa67b5962952deb96828c0a3fede0f86b357272caabb6
b709a431429bfc6dfb85548d169c6df7a9a487fccc3d2018227eb7737f85d8fc340b9f2049f4c7da3b2016b846849982
7e1903e2c1555fb2d1b0480d4c71f14952db5382ad87baeef8280461b40f303e8fcddd7732610b4d873faa08ce4d05bd
de731fe76b0eac61a6fd2f14ba7f6714d2ad37fbe04fe4ab3451e7fc58909aff58b309813ebcc930a25b55fad10d6b78
695e267b8e57bfc5d81a66b3e2e591a6c8b548df88355d562b365b0209398dbc54087f35b949315016c4298b3733c859
fdaf72f34b1c4f08dc1d9421bce1b111d0199dc2a6c5e936a7bfe17130e6afada8648f8c08cb99000030000100000cca
01080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177
fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1
550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff
11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb
8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e79
2ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b5000030000100000cca01080101030803010001af7a8d
eba49d995a792aefc80263e991efdbc86138a931deb2c65d5682eab5d3b03738e3dfdc89d96da64c86c0224d9ce02514
d285da3068b19054e5e787b2969058e98e12566c8c808c40c0b769e1db1a24a1bd9b31e303184a31fc7bb56b85bbba8a
bc02cd5040a444a36d47695969849e16ad856bb58e8fac8855224400319bdab224d83fc0e66aab32ff74bfeaf0f91c45
4e6850a1295207bbd4cdde8f6ffb08faa9755c2e3284efa01f99393e18786cb132f1e66ebc6517318e1ce8a3b7337ebb
54d035ab57d9706ecd9350d4afacd825e43c8668eece89819caf6817af62dc4fbd82f0e33f6647b2b6bda175f14607f5
9f4635451e6b27df282ef73d8700002e000100000cca0113003008000002a3006ad952006abda2804f660001118e9810
f22e4af9a10751e4e6887a8781b62d4a5845ff2d8fe36654515f01747f479165a963169c95285b99333a5a7d2615b3b7
8b3988d5c96277884367e00121bd7f6268a996bb75e94925740fa6e1bf90fa6e4e0654f27b3464e703696be1f0bd96af
540f590ad50de3609b31652a108231310c17f3c10530d5e60b2cf3e2ed341ffb3035c1a907cb69a45a75f5f9b283cab4
3fa79adae1f828fcfbbb178ec55ea459109f8af68fd3c00fa7267dd1312e9d3da4b8e844414961c878903342f35010b2
38a406dd569ddddcddf74760b93315fa914ccd92ef02b725c662e9128bd2caf464f79eb1fd3bdeed0c00ead35cfbf1a3
e78e5fba84b4e03248aea700002904d0000080000000";

/// `dig ed25519.nl DNSKEY +dnssec @1.1.1.1` (ED25519; KSK 45515).
const ED25519_DNSKEY: &str = "\
d00281a000010003000000010765643235353139026e6c0000300001c00c0030000100000e1000240100030fdadb2d64
08e09a50d378f9f43555eb0070499a0f382e8685571ccb9756a78c62c00c0030000100000e1000240101030f9b53442c
b55540a9787c7567fca29d78d3b43eb60a193dc819b62c793f1770aac00c002e000100000e10005e00300f0200000e10
6ad017806ab46800b1cb0765643235353139026e6c00b1eddae71a1737ea54080602ec8af279343cb2bed51afa918702
e892658fff42f39aa9400f6d439b91aa08b18fc60674ccb7b7661615c784e9c278325ad2610600002904d00000800000
00";

/// `dig ed25519.nl SOA +dnssec @1.1.1.1`.
const ED25519_SOA: &str = "\
d00481a000010002000000010765643235353139026e6c0000060001c00c0006000100000e100032056d616e676f0670
6c65786973026575000a686f73746d6173746572c02e78c3d58500002a3000000e1000093a8000000e10c00c002e0001
00000e10005e00060f0200000e106ad017806ab468006c0e0765643235353139026e6c0044f48acd5a31652d498506f5
72743ecd3bd44d7f9bb1c751fb94a156ee0a72820013dee0d04d8ad65bc10cdce8b740aea056b33bb8e9ff100a2900a7
a8eae10100002904d0000080000000";

/// The IANA root zone trust anchor, KSK-2017
/// (<https://data.iana.org/root-anchors/root-anchors.xml>).
const ROOT_ANCHOR: &str =
    ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D";

/// The DS record of ed25519.nl's key-signing key, as published in `nl.`.
const ED25519_ANCHOR: &str =
    "ed25519.nl. IN DS 45515 15 2 1579CE721A8ADF5EF5222D48D6065FDD06E7BCE5C0154EC3EF1F30CC0D06EAAA";

/// When the captures were made (2026-10-04, seconds since 1970).
const CAPTURE_TIME: u32 = 1_791_105_383;

fn main() {
    if let Err(e) = run() {
        eprintln!("dnssec_dig: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn StdError>> {
    let mut anchors = Vec::new();
    let mut now = None;
    let mut files = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--anchor" => anchors.push(args.next().ok_or("--anchor needs a DS record")?),
            "--now" => now = Some(args.next().ok_or("--now needs a time")?.parse()?),
            "-h" | "--help" => {
                println!(
                    "usage: dnssec_dig [--now UNIX-TIME] [--anchor DS-RECORD]... [RESPONSE DNSKEY-RESPONSE]"
                );
                return Ok(());
            }
            _ => files.push(arg),
        }
    }

    match files.as_slice() {
        [] => {
            let now = now.unwrap_or(CAPTURE_TIME);
            let root = hex(ROOT_DNSKEY)?;
            let (soa, keys) = (hex(ED25519_SOA)?, hex(ED25519_DNSKEY)?);
            let anchors = parse_anchors(&[ROOT_ANCHOR, ED25519_ANCHOR])?;
            validate_and_print(&root, &root, &anchors, now)?;
            println!();
            validate_and_print(&soa, &keys, &anchors, now)?;
        }
        [response, dnskeys] => {
            let now = match now {
                Some(now) => now,
                None => std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs() as u32, // RRSIG times are modulo 2^32 (RFC 4034 §3.1.5)
            };
            let anchors: Vec<&str> = anchors.iter().map(String::as_str).collect();
            let anchors = parse_anchors(if anchors.is_empty() {
                &[ROOT_ANCHOR]
            } else {
                &anchors
            })?;
            validate_and_print(
                &read_message(response)?,
                &read_message(dnskeys)?,
                &anchors,
                now,
            )?;
        }
        _ => return Err("give both a response and the zone's DNSKEY response (or neither)".into()),
    }
    Ok(())
}

/// Authenticates the DNSKEY RRset in `dnskey_wire` with the trust anchors,
/// then checks every RRset of `response_wire`, and prints the result.
fn validate_and_print(
    response_wire: &[u8],
    dnskey_wire: &[u8],
    anchors: &[ZoneRecordBuf],
    now: u32,
) -> Result<(), Box<dyn StdError>> {
    let response = Message::parse_validated(response_wire)?;
    let dnskey_msg = Message::parse_validated(dnskey_wire)?;
    print!("{response}");
    println!(";; DNSSEC VALIDATION (at {}):", Timestamp::new(now));

    // The zone's DNSKEY RRset and the signatures over it.
    let mut zone = None;
    let mut dnskeys: Vec<Dnskey<'_>> = Vec::new();
    let mut key_sigs: Vec<Rrsig<'_>> = Vec::new();
    for rr in dnskey_msg.answers() {
        let rr = rr?;
        match rr.data()? {
            RData::Dnskey(key) => {
                zone.get_or_insert(rr.name());
                dnskeys.push(key);
            }
            RData::Rrsig(sig) if sig.type_covered == Rtype::DNSKEY => key_sigs.push(sig),
            _ => {}
        }
    }
    let zone = zone.ok_or("no DNSKEY RRset in the DNSKEY response")?;

    // DS -> DNSKEY (RFC 4035 §5.2).
    let ds: Vec<Ds<'_>> = anchors
        .iter()
        .filter(|a| a.name == zone)
        .filter_map(|a| match a.data() {
            Ok(RData::Ds(ds)) => Some(ds),
            _ => None,
        })
        .collect();
    if ds.is_empty() {
        println!(";; {zone} DNSKEY: insecure (no trust anchor for this zone)");
        return Ok(());
    }
    let mut scratch = Vec::new();
    // One budget for everything validated for this response: however many
    // keys, signatures and RRsets it carries, the work stays bounded.
    let budget = ValidationBudget::new();
    let keys = match TrustedKeys::from_ds_with_budget(
        &PurecryptoVerifier,
        Rrset::new(zone, Class::IN, dnskeys.clone()),
        ds,
        key_sigs,
        now,
        &mut scratch,
        &budget,
    ) {
        Ok(keys) => keys,
        Err(e) => {
            println!(";; {zone} DNSKEY: bogus ({e})");
            return Ok(());
        }
    };
    println!(
        ";; {zone} DNSKEY: authenticated by the trust anchor ({} keys)",
        dnskeys.len()
    );

    // Every RRset of the answer and authority sections (RFC 4035 §5.3).
    for section in [Section::Answer, Section::Authority] {
        for (owner, rtype, class) in rrsets(&response, section)? {
            let records: Vec<RecordRdata<'_>> = response
                .section(section)
                .filter_map(Result::ok)
                .filter(|rr| rr.name() == owner && rr.rtype() == rtype && rr.class() == class)
                .map(RecordRdata)
                .collect();
            let sigs = response
                .section(section)
                .filter_map(Result::ok)
                .filter(|rr| rr.name() == owner && rr.class() == class)
                .filter_map(|rr| rr.data_as::<Rrsig<'_>>().ok())
                .filter(|sig| sig.type_covered == rtype);
            let verdict = match keys.verify_rrset_with_budget(
                &PurecryptoVerifier,
                Rrset::new(owner, class, &records),
                sigs,
                now,
                &mut scratch,
                &budget,
            ) {
                Ok(v) => secure(&v),
                Err(e) if !owner.is_subdomain_of(&zone) => format!("not in zone {zone} ({e})"),
                Err(e) => format!("bogus ({e})"),
            };
            println!(
                ";; {owner} {class} {rtype} ({} records): {verdict}",
                records.len()
            );
        }
    }
    Ok(())
}

fn secure(v: &Verified) -> String {
    let mut s = format!(
        "secure (key {}, algorithm {}, signature valid until {})",
        v.key_tag,
        v.algorithm,
        Timestamp::new(v.expiration)
    );
    if v.is_wildcard_expansion() {
        s.push_str(", wildcard expansion: needs a denial proof");
    }
    s
}

/// The distinct RRsets (owner, type, class) of a section, RRSIGs and OPT
/// excluded, in order of appearance.
fn rrsets<'a>(
    msg: &Message<'a>,
    section: Section,
) -> Result<Vec<(Name<'a>, Rtype, Class)>, dnsbox::Error> {
    let mut out: Vec<(Name<'a>, Rtype, Class)> = Vec::new();
    for rr in msg.section(section) {
        let rr: Record<'a> = rr?;
        let key = (rr.name(), rr.rtype(), rr.class());
        if rr.rtype() != Rtype::RRSIG && rr.rtype() != Rtype::OPT && !out.contains(&key) {
            out.push(key);
        }
    }
    Ok(out)
}

/// DS records in zone-file form, one per string (a TTL is optional).
fn parse_anchors(texts: &[&str]) -> Result<Vec<ZoneRecordBuf>, Box<dyn StdError>> {
    let mut out = Vec::new();
    for text in texts {
        let records = ZoneReader::new(text)
            .with_default_ttl(0)
            .records()
            .collect::<Result<Vec<_>, _>>()?;
        for rr in records {
            if rr.rtype != Rtype::DS {
                return Err(format!("not a DS record: {rr}").into());
            }
            out.push(rr);
        }
    }
    Ok(out)
}

/// Reads a message from a file in hex (as `tests/corpus`) or raw bytes.
fn read_message(path: &str) -> Result<Vec<u8>, Box<dyn StdError>> {
    let bytes = std::fs::read(path)?;
    match std::str::from_utf8(&bytes) {
        Ok(text) => {
            let hex_text: String = text
                .lines()
                .map(|line| line.split('#').next().unwrap_or(""))
                .collect();
            if !hex_text.trim().is_empty()
                && hex_text
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() || c.is_whitespace())
            {
                return hex(&hex_text);
            }
            Ok(bytes)
        }
        Err(_) => Ok(bytes),
    }
}

fn hex(text: &str) -> Result<Vec<u8>, Box<dyn StdError>> {
    let digits: Vec<u8> = text
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_digit(16).map(|d| d as u8).ok_or("not hexadecimal"))
        .collect::<Result<_, _>>()?;
    if !digits.len().is_multiple_of(2) {
        return Err("odd number of hex digits".into());
    }
    Ok(digits.chunks(2).map(|p| p[0] << 4 | p[1]).collect())
}
