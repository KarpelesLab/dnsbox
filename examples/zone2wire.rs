//! Converts a master (zone) file to wire format: the AXFR response a
//! primary server would send for it (RFC 5936 §2.2) — the SOA, every
//! record, the SOA again — as a stream of TCP-framed messages.
//!
//! ```text
//! cargo run --example zone2wire                        # built-in sample, hex dump
//! cargo run --example zone2wire -- db.example          # origin from the SOA owner
//! cargo run --example zone2wire -- db.example example. -o example.axfr --max-size 4096
//! ```
//!
//! Arguments: `[ZONEFILE [ORIGIN]] [-o OUTPUT] [--max-size BYTES]`. With
//! `-o`, the frames are written to OUTPUT as raw bytes (what a client reads
//! from the TCP connection); otherwise a hex dump goes to stdout. The
//! stream is then read back with [`XfrProcessor`] as a check.
//!
//! What it shows: [`ZoneReader`] with `$INCLUDE` through [`FsIncludes`]
//! and errors reported with their position, [`MessageBuilder::new_tcp_vec`]
//! with a size limit (every push is atomic, so a full message is simply
//! closed and the record pushed again into the next one), and the
//! [`tcp::frames`] / [`XfrProcessor`] side that consumes the stream.

use std::error::Error as StdError;
use std::path::Path;

use dnsbox::tcp;
use dnsbox::xfr::{XfrEvent, XfrProcessor};
use dnsbox::zone::{FsIncludes, ZoneReader, ZoneRecordBuf};
use dnsbox::{Class, Error, Flags, Message, MessageBuilder, NameBuf, Rtype};

/// Used when no zone file is given.
const SAMPLE_ZONE: &str = r#"; A small zone, in the usual BIND layout.
$ORIGIN example.com.
$TTL 1h
@           IN  SOA   ns1 hostmaster (
                      2024010101 ; serial
                      2h         ; refresh
                      15m        ; retry
                      2w         ; expire
                      1h )       ; negative caching TTL
            IN  NS    ns1
            IN  NS    ns2.example.net.
            IN  MX    10 mail
            IN  TXT   "v=spf1 mx -all"
            IN  CAA   0 issue "letsencrypt.org"
ns1         IN  A     192.0.2.53
            IN  AAAA  2001:db8::53
mail        IN  A     192.0.2.25
www    300  IN  CNAME @
@           IN  A     192.0.2.80
_xmpp-server._tcp IN SRV 5 0 5269 mail
$GENERATE 1-20 host-$ IN A 198.51.100.$
"#;

/// The default largest message: well below the 65535-byte limit, as
/// servers do so that one lost segment does not stall too much data.
const DEFAULT_MAX_SIZE: usize = 16 * 1024;

fn main() {
    if let Err(e) = run() {
        eprintln!("zone2wire: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn StdError>> {
    let mut positional = Vec::new();
    let mut output = None;
    let mut max_size = DEFAULT_MAX_SIZE;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-o" => output = Some(args.next().ok_or("-o needs a file name")?),
            "--max-size" => max_size = args.next().ok_or("--max-size needs a number")?.parse()?,
            "-h" | "--help" => {
                println!("usage: zone2wire [ZONEFILE [ORIGIN]] [-o OUTPUT] [--max-size BYTES]");
                return Ok(());
            }
            _ => positional.push(arg),
        }
    }

    // Read the zone.
    let (text, file) = match positional.first() {
        Some(path) => (std::fs::read_to_string(path)?, Some(Path::new(path))),
        None => (SAMPLE_ZONE.to_string(), None),
    };
    let mut reader = ZoneReader::new(&text);
    if let Some(origin) = positional.get(1) {
        reader = reader.with_origin(&origin.parse::<NameBuf>()?);
    }
    let base = file.and_then(Path::parent).unwrap_or(Path::new("."));
    let mut records = Vec::new();
    let mut errors = 0;
    // `Records` reports each bad entry and carries on with the next one,
    // so every error of the file is shown in one run. Includes are served
    // from the zone file's directory only (`FsIncludes::unconfined` also
    // follows absolute paths and `..`, as BIND does).
    for item in reader.records().with_includes(FsIncludes::new(base)) {
        match item {
            Ok(rr) => records.push(rr),
            Err(e) => {
                // Errors in an included file name that file themselves.
                match (e.file(), file) {
                    (None, Some(path)) => eprintln!("{}: {e}", path.display()),
                    _ => eprintln!("{e}"),
                }
                errors += 1;
            }
        }
    }
    if errors > 0 {
        return Err(format!("{errors} error(s) in the zone file").into());
    }

    // The zone apex is the owner of the SOA, which must come first.
    let soa = match records.first() {
        Some(rr) if rr.rtype == Rtype::SOA => rr.clone(),
        _ => return Err("the zone file must start with the SOA record".into()),
    };
    let apex = soa.name.clone();
    if let Some(rr) = records
        .iter()
        .find(|rr| !rr.name.as_name().is_subdomain_of(&apex.as_name()))
    {
        return Err(format!("line {}: {} is outside the zone {apex}", rr.line, rr.name).into());
    }

    // Encode: SOA, the other records, SOA.
    let body = records.iter().skip(1).filter(|rr| rr.rtype != Rtype::SOA);
    let order = std::iter::once(&soa)
        .chain(body)
        .chain(std::iter::once(&soa));
    let stream = encode_axfr(&apex, soa.class, order, max_size)?;

    // Output.
    match output {
        Some(path) => {
            std::fs::write(&path, &stream)?;
            eprintln!("wrote {} bytes to {path}", stream.len());
        }
        None => hex_dump(&stream),
    }

    // Check: read the stream back as a client would.
    let (messages, count) = check_axfr(&apex, &stream)?;
    eprintln!(
        "{apex}: {} records in {messages} message(s), {} bytes",
        records.len(),
        stream.len()
    );
    assert_eq!(
        count,
        records.iter().filter(|rr| rr.rtype != Rtype::SOA).count() + 2
    );
    Ok(())
}

/// Writes `records` as AXFR response messages of at most `max_size`
/// bytes, each preceded by its TCP length prefix.
fn encode_axfr<'a>(
    apex: &NameBuf,
    class: Class,
    records: impl Iterator<Item = &'a ZoneRecordBuf>,
    max_size: usize,
) -> Result<Vec<u8>, Box<dyn StdError>> {
    let mut stream = Vec::new();
    let mut b = start_message(apex, class, true, max_size)?;
    for rr in records {
        let data = rr.data()?;
        match b.push_answer(&rr.name, rr.class, rr.ttl, &data) {
            Ok(()) => {}
            Err(Error::BufferTooSmall) if b.header().ancount > 0 => {
                // The message is full: send it, and push the record again
                // into a fresh one (the failed push left `b` untouched).
                stream.extend_from_slice(&b.finish());
                b = start_message(apex, class, false, max_size)?;
                b.push_answer(&rr.name, rr.class, rr.ttl, &data)
                    .map_err(|e| {
                        format!("line {}: record too large for one message: {e}", rr.line)
                    })?;
            }
            Err(e) => return Err(format!("line {}: {e}", rr.line).into()),
        }
    }
    stream.extend_from_slice(&b.finish());
    Ok(stream)
}

/// A response message of the transfer; the first one carries the question
/// (RFC 5936 §2.2.1).
fn start_message(
    apex: &NameBuf,
    class: Class,
    first: bool,
    max_size: usize,
) -> Result<MessageBuilder<Vec<u8>>, Error> {
    let mut b = MessageBuilder::new_tcp_vec();
    b.set_limit(max_size);
    b.set_flags(Flags::default().with_qr(true).with_aa(true));
    if first {
        b.push_question(apex, Rtype::AXFR, class)?;
    }
    Ok(b)
}

/// Splits the TCP stream into messages and runs them through an AXFR
/// client; returns the number of messages and of records.
fn check_axfr(apex: &NameBuf, stream: &[u8]) -> Result<(usize, usize), Box<dyn StdError>> {
    let mut xfr = XfrProcessor::axfr(apex);
    let mut frames = tcp::frames(stream);
    let mut records = 0;
    for wire in frames.by_ref() {
        for event in xfr.process(&Message::parse_validated(wire)?)? {
            match event? {
                XfrEvent::Start { .. } | XfrEvent::Record(_) | XfrEvent::End { .. } => records += 1,
                other => return Err(format!("unexpected event {other:?}").into()),
            }
        }
    }
    if !frames.remainder().is_empty() || !xfr.is_done() {
        return Err("incomplete transfer".into());
    }
    Ok((xfr.message_count() as usize, records))
}

/// Prints the stream as hex, 32 bytes per line, one block per message.
fn hex_dump(stream: &[u8]) {
    for (i, msg) in tcp::frames(stream).enumerate() {
        println!(
            "; message {} ({} bytes, plus the 2-byte length prefix)",
            i + 1,
            msg.len()
        );
        let len = u16::try_from(msg.len()).unwrap_or(u16::MAX).to_be_bytes();
        for chunk in len
            .iter()
            .chain(msg)
            .copied()
            .collect::<Vec<u8>>()
            .chunks(32)
        {
            let line: String = chunk.iter().map(|b| format!("{b:02x}")).collect();
            println!("{line}");
        }
    }
}
