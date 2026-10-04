//! A zone transfer (AXFR, RFC 5936) authenticated with TSIG (RFC 8945).
//!
//! ```text
//! cargo run --example tsig_axfr --features tsig
//! cargo run --example tsig_axfr --features tsig -- \
//!     --server 192.0.2.53 --key xfr-key:hmac-sha256:c2VjcmV0IGtleSBieXRlcw== example.com
//! ```
//!
//! Without arguments, a primary server runs on a loopback TCP port in a
//! second thread and the client transfers a built-in zone from it. With
//! `--server`, the client transfers ZONE from a real server (BIND:
//! `allow-transfer { key xfr-key; };`), the key given as
//! `NAME:ALGORITHM:BASE64-SECRET` like BIND's `key` statement.
//!
//! Both sides follow RFC 8945 §5.3.1: the server signs the first and last
//! message of the stream and may leave up to 99 in between unsigned (here,
//! every other one), each MAC covering the previous MAC and every message
//! since; the client checks each message with [`TsigVerifier`] while
//! [`XfrProcessor`] turns the records into events.

use std::error::Error as StdError;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dnsbox::tcp::{self, MAX_FRAME_LEN};
use dnsbox::tsig::{self, HmacKey, TsigAlgorithm, TsigSigner, TsigVerifier};
use dnsbox::xfr::{self, XfrEvent, XfrProcessor};
use dnsbox::zone::Scanner;
use dnsbox::{Class, Flags, Message, MessageBuilder, NameBuf, Rcode};

/// The zone the built-in server transfers.
const ZONE: &str = r#"$ORIGIN example.com.
$TTL 1h
@       SOA   ns1 hostmaster 2024060101 2h 15m 2w 1h
        NS    ns1
        NS    ns2
        MX    10 mail
ns1     A     192.0.2.53
ns2     A     198.51.100.53
mail    A     192.0.2.25
www     CNAME @
@       A     192.0.2.80
@       TXT   "transferred with TSIG"
"#;

/// Records per message in the built-in server's response (tiny, to show a
/// multi-message stream).
const RECORDS_PER_MESSAGE: usize = 3;

fn main() {
    if let Err(e) = run() {
        eprintln!("tsig_axfr: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn StdError>> {
    let mut server = None;
    let mut key_spec = None;
    let mut zone = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--server" => server = Some(args.next().ok_or("--server needs an address")?),
            "--key" => key_spec = Some(args.next().ok_or("--key needs NAME:ALG:SECRET")?),
            "-h" | "--help" => {
                println!("usage: tsig_axfr [--server ADDR --key NAME:ALG:BASE64 ZONE]");
                return Ok(());
            }
            _ => zone = Some(arg.parse::<NameBuf>()?),
        }
    }

    match server {
        Some(addr) => {
            let (name, alg, secret) =
                parse_key(&key_spec.ok_or("--key is required with --server")?)?;
            let key = HmacKey::new(&name, alg, &secret);
            let zone = zone.ok_or("no zone given")?;
            transfer(resolve(&addr)?, &zone, &key)
        }
        None => {
            // The built-in demo: a shared secret both sides know.
            let name: NameBuf = "xfr-key".parse()?;
            let secret = b"0123456789abcdef0123456789abcdef";
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let addr = listener.local_addr()?;
            let server = std::thread::spawn(move || -> Result<(), String> {
                let key = HmacKey::new(&name, TsigAlgorithm::HmacSha256, secret);
                serve_one(&listener, &key).map_err(|e| e.to_string())
            });
            let name: NameBuf = "xfr-key".parse()?;
            let key = HmacKey::new(&name, TsigAlgorithm::HmacSha256, secret);
            transfer(addr, &"example.com".parse()?, &key)?;
            server.join().map_err(|_| "server thread panicked")??;
            Ok(())
        }
    }
}

/// Seconds since 1970: TSIG's clock (RFC 8945 §5.2.3).
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The client: sends a signed AXFR query and verifies the signed stream.
fn transfer(addr: SocketAddr, zone: &NameBuf, key: &HmacKey<'_>) -> Result<(), Box<dyn StdError>> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;

    // The query, signed; keep its MAC to verify the response.
    let id = (now() as u16) ^ 0x5a5a;
    let mut qbuf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut qbuf)?;
    b.set_id(id);
    xfr::build_axfr_query(&mut b, zone, Class::IN)?;
    let request_mac = TsigSigner::request(key).sign(&mut b, now())?;
    tcp::write_message(&mut stream, b.finish())?;

    let mut verifier = TsigVerifier::new(key, request_mac.as_slice())?;
    let mut xfr = XfrProcessor::axfr(zone).with_id(id);
    let mut buf = vec![0u8; MAX_FRAME_LEN];
    let (mut signed, mut unsigned) = (0, 0);
    while !xfr.is_done() {
        let wire =
            tcp::read_message(&mut stream, &mut buf)?.ok_or("connection closed mid-transfer")?;
        let msg = Message::parse(wire)?;
        // Authenticate first, then interpret.
        match verifier.verify(&msg, now())? {
            Some(_) => signed += 1,
            None => unsigned += 1,
        }
        for event in xfr.process(&msg)? {
            match event? {
                XfrEvent::Start { record, .. } => println!("{record}"),
                XfrEvent::Record(record) => println!("{record}"),
                XfrEvent::End { soa, .. } => println!(";; end of transfer, serial {}", soa.serial),
                _ => {}
            }
        }
    }
    // The stream must end with a signed message (RFC 8945 §5.3.1).
    verifier.finish()?;
    println!(
        ";; {} records in {} messages ({signed} signed, {unsigned} covered by the next MAC)",
        xfr.record_count(),
        xfr.message_count()
    );
    Ok(())
}

/// The built-in primary: answers one TSIG-signed AXFR request.
fn serve_one(listener: &TcpListener, key: &HmacKey<'_>) -> Result<(), Box<dyn StdError>> {
    let (mut conn, _) = listener.accept()?;
    let mut buf = vec![0u8; MAX_FRAME_LEN];
    let wire = tcp::read_message(&mut conn, &mut buf)?.ok_or("client went away")?;
    let query = Message::parse(wire)?;

    // RFC 8945 §5.2: verify before doing anything else.
    let status = tsig::verify_request(&query, key, now());
    if let Some(rejected) = status.rejected() {
        // Answer as the RFC prescribes for this failure, then give up.
        let mut out = [0u8; 512];
        let mut r = MessageBuilder::response(&mut out, &query)?;
        r.set_rcode(rejected.rcode());
        rejected.sign_response(&mut r, now())?;
        tcp::write_message(&mut conn, r.finish())?;
        return Err(format!("request rejected: {}", rejected.error).into());
    }
    let Some(verified) = status.verified() else {
        // Unsigned: a real server would answer REFUSED.
        let mut out = [0u8; 512];
        let mut r = MessageBuilder::response(&mut out, &query)?;
        r.set_rcode(Rcode::REFUSED);
        tcp::write_message(&mut conn, r.finish())?;
        return Err("unsigned transfer request".into());
    };

    let records = dnsbox::zone::parse(ZONE)?;
    let soa = &records[0];
    let body: Vec<_> = records.iter().skip(1).collect();
    let mut order = vec![soa];
    order.extend(body);
    order.push(soa);

    let mut signer = verified.signer();
    let chunks: Vec<_> = order.chunks(RECORDS_PER_MESSAGE).collect();
    for (i, chunk) in chunks.iter().enumerate() {
        let mut b = MessageBuilder::new_vec();
        b.set_id(query.id());
        b.set_flags(Flags::default().with_qr(true).with_aa(true));
        if i == 0 {
            b.copy_question(&query.questions().next().ok_or("no question")??)?;
        }
        for rr in *chunk {
            b.push_answer(&rr.name, rr.class, rr.ttl, &rr.data()?)?;
        }
        // Sign the first, the last, and every other message in between.
        let last = i + 1 == chunks.len();
        if i == 0 || last || i % 2 == 0 {
            signer.sign(&mut b, now())?;
            tcp::write_message(&mut conn, &b.finish())?;
        } else {
            let msg = b.finish();
            signer.skip(&msg)?;
            tcp::write_message(&mut conn, &msg)?;
        }
    }
    Ok(())
}

/// `host`, `host:port`, `v6addr` or `[v6addr]:port`; port 53 by default.
fn resolve(s: &str) -> Result<SocketAddr, Box<dyn StdError>> {
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let with_port = if s.contains(':') {
        s.to_string()
    } else {
        format!("{s}:53")
    };
    Ok(with_port
        .to_socket_addrs()?
        .next()
        .ok_or("cannot resolve the server name")?)
}

/// `NAME:ALGORITHM:BASE64-SECRET`, as in BIND's `key` statement.
fn parse_key(spec: &str) -> Result<(NameBuf, TsigAlgorithm, Vec<u8>), Box<dyn StdError>> {
    let mut parts = spec.splitn(3, ':');
    let (Some(name), Some(alg), Some(secret)) = (parts.next(), parts.next(), parts.next()) else {
        return Err("--key must be NAME:ALGORITHM:BASE64-SECRET".into());
    };
    // The zone-file scanner decodes base64 (RFC 4648 §4) without a crate.
    let mut bytes = Vec::new();
    Scanner::new(secret).base64_into(&mut bytes)?;
    Ok((name.parse()?, alg.parse()?, bytes))
}
