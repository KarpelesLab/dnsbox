//! A minimal stub resolver: sends one query to a recursive resolver over
//! UDP, retries over TCP if the answer is truncated, and prints the
//! response the way `dig` does.
//!
//! ```text
//! cargo run --example stub_resolver -- example.com AAAA
//! cargo run --example stub_resolver -- @9.9.9.9 +dnssec ietf.org DNSKEY
//! ```
//!
//! Arguments, in any order: the name to look up, a record type (default
//! `A`), an optional class (default `IN`), `@server[:port]` (default: the
//! first `nameserver` of `/etc/resolv.conf`, else 9.9.9.9), `+dnssec` to
//! set the DO bit, `+tcp` to skip UDP.
//!
//! What it shows: [`MessageBuilder::query`] with EDNS(0) (RFC 6891), the
//! checks a stub must make on a UDP answer before trusting it (source
//! address, ID, question, RFC 5452 §9.1), the TC-bit fallback to TCP
//! (RFC 7766 §5) with [`tcp::write_message`] / [`tcp::read_message`], and
//! the `dig`-style `Display` of [`Message`].

use std::collections::hash_map::RandomState;
use std::error::Error as StdError;
use std::hash::{BuildHasher, Hasher};
use std::io::Read;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use dnsbox::edns::OptHeader;
use dnsbox::tcp::{self, MAX_FRAME_LEN};
use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};

/// Our advertised UDP payload size: the DNS Flag Day 2020 value, which
/// avoids IP fragmentation on almost every path.
const UDP_PAYLOAD_SIZE: u16 = 1232;

/// How long to wait for an answer.
const TIMEOUT: Duration = Duration::from_secs(3);

struct Args {
    name: NameBuf,
    qtype: Rtype,
    qclass: Class,
    server: SocketAddr,
    dnssec: bool,
    tcp_only: bool,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("stub_resolver: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn StdError>> {
    let args = parse_args()?;

    // A random transaction ID: with the random source port the OS picks,
    // the only protection a stub has against off-path spoofing (RFC 5452).
    let id = RandomState::new().build_hasher().finish() as u16;

    let mut qbuf = [0u8; 512];
    let mut b = MessageBuilder::query(&mut qbuf, id, &args.name, args.qtype, args.qclass)?;
    b.push_edns(
        OptHeader::new(UDP_PAYLOAD_SIZE).with_dnssec_ok(args.dnssec),
        &(),
    )?;
    let query = b.finish();

    let started = Instant::now();
    let mut answer_buf = vec![0u8; MAX_FRAME_LEN];
    let (len, transport) = if args.tcp_only {
        (query_tcp(args.server, query, &mut answer_buf)?, "TCP")
    } else {
        let len = query_udp(args.server, query, &mut answer_buf)?;
        if Message::parse(&answer_buf[..len])?.flags().tc() {
            // Truncated: the full answer only fits over TCP.
            println!(";; Truncated, retrying in TCP mode.");
            (query_tcp(args.server, query, &mut answer_buf)?, "TCP")
        } else {
            (len, "UDP")
        }
    };
    let elapsed = started.elapsed();

    let response = Message::parse(&answer_buf[..len])?;
    check_response(&Message::parse(query)?, &response)?;
    // `validate` walks the whole message once: fail on a malformed answer
    // here rather than half way through printing it.
    response.validate()?;

    print!("{response}");
    println!(";; Query time: {} msec", elapsed.as_millis());
    println!(
        ";; SERVER: {}#{} ({transport})",
        args.server.ip(),
        args.server.port()
    );
    println!(";; MSG SIZE  rcvd: {len}");
    Ok(())
}

/// Sends `query` over UDP and waits for a response from `server` with the
/// same ID, ignoring anything else that arrives on the socket.
fn query_udp(server: SocketAddr, query: &[u8], buf: &mut [u8]) -> Result<usize, Box<dyn StdError>> {
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let socket = UdpSocket::bind(bind)?;
    socket.set_read_timeout(Some(TIMEOUT))?;
    socket.send_to(query, server)?;
    let id = Message::parse(query)?.id();
    loop {
        let (len, from) = socket.recv_from(buf)?;
        if from != server {
            continue; // not from the server we asked
        }
        match Message::parse(&buf[..len]) {
            Ok(msg) if msg.id() == id && msg.flags().qr() => return Ok(len),
            _ => continue, // garbage or another transaction
        }
    }
}

/// Sends `query` over TCP (RFC 7766) and reads one length-prefixed
/// response into `buf`.
fn query_tcp(server: SocketAddr, query: &[u8], buf: &mut [u8]) -> Result<usize, Box<dyn StdError>> {
    let mut stream = TcpStream::connect_timeout(&server, TIMEOUT)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_nodelay(true)?;
    tcp::write_message(&mut stream, query)?;
    let msg = tcp::read_message(&mut stream, buf)?.ok_or("connection closed without an answer")?;
    Ok(msg.len())
}

/// The checks a stub resolver makes before accepting a response
/// (RFC 5452 §9.1): the same ID, a response, the same question.
fn check_response(query: &Message<'_>, response: &Message<'_>) -> Result<(), Box<dyn StdError>> {
    if response.id() != query.id() || !response.flags().qr() {
        return Err("response does not match the query".into());
    }
    let q = query
        .questions()
        .next()
        .ok_or("query without a question")??;
    match response.questions().next() {
        // RFC 1035 §7.3: compare names case-insensitively (dnsbox's `Name`
        // equality is), type and class exactly.
        Some(r) => {
            let r = r?;
            if r.name() != q.name() || r.qtype() != q.qtype() || r.qclass() != q.qclass() {
                return Err("response is for another question".into());
            }
        }
        // Some error responses (FORMERR, NOTIMP) carry no question.
        None if response.flags().rcode().get() != 0 => {}
        None => return Err("response without a question".into()),
    }
    Ok(())
}

fn parse_args() -> Result<Args, Box<dyn StdError>> {
    let mut name = None;
    let mut qtype = None;
    let mut qclass = None;
    let mut server = None;
    let mut dnssec = false;
    let mut tcp_only = false;
    for arg in std::env::args().skip(1) {
        if let Some(s) = arg.strip_prefix('@') {
            server = Some(resolve_server(s)?);
        } else if arg == "+dnssec" {
            dnssec = true;
        } else if arg == "+tcp" {
            tcp_only = true;
        } else if arg == "-h" || arg == "--help" {
            println!("usage: stub_resolver [@server[:port]] [+dnssec] [+tcp] name [type] [class]");
            std::process::exit(0);
        } else if name.is_some() && qtype.is_none() && arg.parse::<Rtype>().is_ok() {
            qtype = Some(arg.parse::<Rtype>()?);
        } else if name.is_some() && qclass.is_none() && arg.parse::<Class>().is_ok() {
            qclass = Some(arg.parse::<Class>()?);
        } else if name.is_none() {
            name = Some(arg.parse::<NameBuf>()?);
        } else {
            return Err(format!("unexpected argument {arg:?}").into());
        }
    }
    Ok(Args {
        name: name.ok_or("no name given (try --help)")?,
        qtype: qtype.unwrap_or(Rtype::A),
        qclass: qclass.unwrap_or(Class::IN),
        server: match server {
            Some(s) => s,
            None => system_resolver(),
        },
        dnssec,
        tcp_only,
    })
}

/// `host`, `host:port`, `v6addr` or `[v6addr]:port`.
fn resolve_server(s: &str) -> Result<SocketAddr, Box<dyn StdError>> {
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

/// The first `nameserver` of `/etc/resolv.conf`, or Quad9.
fn system_resolver() -> SocketAddr {
    let mut conf = String::new();
    if let Ok(mut f) = std::fs::File::open("/etc/resolv.conf") {
        let _ = f.read_to_string(&mut conf);
    }
    conf.lines()
        .filter_map(|line| line.trim().strip_prefix("nameserver"))
        .filter_map(|rest| {
            rest.trim()
                .split('%')
                .next()?
                .parse::<std::net::IpAddr>()
                .ok()
        })
        .map(|ip| SocketAddr::new(ip, 53))
        .next()
        .unwrap_or_else(|| SocketAddr::from(([9, 9, 9, 9], 53)))
}
