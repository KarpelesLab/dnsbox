//! Live interop checks of dnsbox-built messages against BIND 9's `named`,
//! run by `.github/workflows/interop.yml` once `tests/corpus/bind/run.sh
//! serve` has started an authoritative `named` and a validating one on
//! the runner.
//!
//! ```text
//! cargo run --example bind_probe --all-features -- \
//!     --named 127.0.0.1:5350 --resolver 127.0.0.1:5450 \
//!     --anchor OUT/anchor.ds --sig0 OUT/sig0 \
//!     [--named-label FILE --resolver-label FILE]
//! ```
//!
//! Every query is built by dnsbox and every response parsed and checked
//! by dnsbox: EDNS options (NSID, cookies, Client Subnet, Padding, an
//! unknown option) and named's RFC 9018 server cookies recomputed from
//! its configured secret, a DNSKEY RRset over TCP authenticated from the
//! parent's DS (itself verified from the trust anchor), TSIG-signed
//! queries with every HMAC (which named must accept), a wrong secret and
//! an unknown key (which it must reject), a TSIG-signed TKEY query (RFC
//! 2930), TSIG-signed AXFR streams of several messages, dynamic UPDATEs
//! (RFC 2136) named must apply, refuse or fail on a prerequisite, the IXFR
//! they produce, UPDATEs signed with SIG(0) (RFC 2931) by a key of the
//! zone, and the resolver's validated (AD), insecure and bogus (SERVFAIL)
//! answers. With `--named-label`/`--resolver-label` (the label files of
//! `tests/corpus/knot/proxy.py`), the exchanges are recorded under
//! `probe/<check>` for `tests/interop_bind.rs`.
//!
//! Exits with status 1 if any check fails.

use std::error::Error as StdError;
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dnsbox::dnssec::{Algorithm, PurecryptoVerifier, Rrset, SigningKey, TrustedKeys};
use dnsbox::edns::{
    ClientSubnet, Cookie, ExtendedError, Nsid, OptHeader, Padding, PaddingPolicy, UnknownOption,
};
use dnsbox::rdata::{
    A, Aaaa, Dnskey, Ds, Key, ParseRdataText, RData, Rrsig, Soa, Tkey, TkeyMode, Txt,
};
use dnsbox::sig0::{self, DnssecSig0Signer, Validity};
use dnsbox::tcp::{self, MAX_FRAME_LEN};
use dnsbox::tsig::{self, HmacKey, TsigAlgorithm, TsigRcode, TsigSigner, TsigVerifier};
use dnsbox::update::UpdateBuilder;
use dnsbox::xfr::{self, XfrEvent, XfrProcessor, XfrStyle};
use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rcode, Rtype, Section};

type Result<T> = std::result::Result<T, Box<dyn StdError>>;

/// The TSIG secret of every key `run.sh` gives named: 00 01 .. 1f.
const SECRET: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

/// named's `cookie-secret` in `run.sh`: 00 01 .. 0f.
#[cfg(feature = "cookie-siphash")]
const COOKIE_SECRET: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

/// How long to wait for a response.
const TIMEOUT: Duration = Duration::from_secs(5);

const HMACS: [(&str, TsigAlgorithm); 6] = [
    ("md5", TsigAlgorithm::HmacMd5),
    ("sha1", TsigAlgorithm::HmacSha1),
    ("sha224", TsigAlgorithm::HmacSha224),
    ("sha256", TsigAlgorithm::HmacSha256),
    ("sha384", TsigAlgorithm::HmacSha384),
    ("sha512", TsigAlgorithm::HmacSha512),
];

struct Probe {
    named: SocketAddr,
    resolver: SocketAddr,
    named_label: Option<String>,
    resolver_label: Option<String>,
    anchor: Option<String>,
    sig0: Option<PathBuf>,
    id: u16,
    failures: Vec<String>,
}

fn main() {
    match run() {
        Ok(0) => println!("bind_probe: every check passed"),
        Ok(n) => {
            eprintln!("bind_probe: {n} checks failed");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("bind_probe: {e}");
            std::process::exit(2);
        }
    }
}

fn run() -> Result<usize> {
    let mut p = Probe {
        named: "127.0.0.1:5350".parse()?,
        resolver: "127.0.0.1:5450".parse()?,
        named_label: None,
        resolver_label: None,
        anchor: None,
        sig0: None,
        id: (now() as u16) ^ 0x5353,
        failures: Vec::new(),
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or(format!("{arg} needs a value"));
        match arg.as_str() {
            "--named" => p.named = value()?.parse()?,
            "--resolver" => p.resolver = value()?.parse()?,
            "--named-label" => p.named_label = Some(value()?),
            "--resolver-label" => p.resolver_label = Some(value()?),
            "--anchor" => p.anchor = Some(std::fs::read_to_string(value()?)?),
            "--sig0" => p.sig0 = Some(value()?.into()),
            _ => return Err(format!("unknown argument {arg}").into()),
        }
    }

    p.check("edns", Probe::edns);
    p.check("tcp-dnskey", Probe::tcp_dnskey);
    for (h, alg) in HMACS {
        p.check(&format!("tsig-{h}"), |p| p.tsig_query(h, alg));
    }
    p.check("tsig-badsig", Probe::tsig_badsig);
    p.check("tsig-badkey", Probe::tsig_badkey);
    p.check("tkey", Probe::tkey);
    for (h, alg) in HMACS {
        p.check(&format!("axfr-{h}"), |p| p.axfr(h, alg));
    }
    p.check("update", Probe::update);
    p.check("sig0", Probe::sig0_update);
    p.check("resolver-secure", |p| {
        p.resolver_query("www.ed25519-nsec.interop.", false, Expect::Secure)
    });
    p.check("resolver-secure-tcp", |p| {
        p.resolver_query("www.ecdsap384-nsec3.interop.", true, Expect::Secure)
    });
    p.check("resolver-insecure", |p| {
        p.resolver_query("www.insecure.interop.", false, Expect::Insecure)
    });
    p.check("resolver-bogus", |p| {
        p.resolver_query("www.bogus.interop.", false, Expect::Bogus)
    });
    for f in &p.failures {
        eprintln!("FAILED: {f}");
    }
    Ok(p.failures.len())
}

/// Seconds since 1970.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn name(s: &str) -> Result<NameBuf> {
    Ok(s.parse()?)
}

fn ensure(cond: bool, what: impl Into<String>) -> Result<()> {
    if cond {
        Ok(())
    } else {
        Err(what.into().into())
    }
}

/// The RDATA and RRSIGs of an RRset in a section.
fn rrset<'m>(
    msg: &Message<'m>,
    section: Section,
    owner: &NameBuf,
    rtype: Rtype,
) -> Result<(Vec<RData<'m>>, Vec<Rrsig<'m>>)> {
    let mut rdata = Vec::new();
    let mut sigs = Vec::new();
    for rr in msg.records() {
        let (s, rr) = rr?;
        if s != section || rr.name() != owner.as_name() {
            continue;
        }
        if rr.rtype() == rtype {
            rdata.push(rr.data()?);
        } else if let Ok(sig) = rr.data_as::<Rrsig<'_>>()
            && sig.type_covered == rtype
        {
            sigs.push(sig);
        }
    }
    Ok((rdata, sigs))
}

/// The DNSKEY records among `rdata`.
fn dnskeys<'m>(rdata: Vec<RData<'m>>) -> Vec<Dnskey<'m>> {
    rdata
        .into_iter()
        .filter_map(|k| match k {
            RData::Dnskey(k) => Some(k),
            _ => None,
        })
        .collect()
}

/// Decodes standard base64.
fn base64(s: &str) -> Result<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.bytes().filter(|c| !c.is_ascii_whitespace() && *c != b'=') {
        let v = ALPHABET.iter().position(|&a| a == c).ok_or("not base64")?;
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

/// The expected outcome of a resolver query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    Secure,
    Insecure,
    Bogus,
}

impl Probe {
    /// Names the exchanges that follow `probe/<label>` in the proxies'
    /// recordings.
    fn label(&self, label: &str) {
        for file in [&self.named_label, &self.resolver_label]
            .into_iter()
            .flatten()
        {
            let _ = std::fs::write(file, format!("probe/{label}\n"));
        }
    }

    fn check(&mut self, label: &str, f: impl FnOnce(&mut Probe) -> Result<()>) {
        self.label(label);
        match f(self) {
            Ok(()) => println!("ok: {label}"),
            Err(e) => {
                println!("FAILED: {label}: {e}");
                self.failures.push(format!("{label}: {e}"));
            }
        }
    }

    fn next_id(&mut self) -> u16 {
        self.id = self.id.wrapping_add(1);
        self.id
    }

    /// Sends `query` over UDP and returns the response with its ID.
    fn udp(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.set_read_timeout(Some(TIMEOUT))?;
        socket.send_to(query, server)?;
        let id = Message::parse(query)?.id();
        let mut buf = vec![0u8; 65535];
        loop {
            let (len, from) = socket.recv_from(&mut buf)?;
            if from != server {
                continue;
            }
            if let Ok(msg) = Message::parse(&buf[..len])
                && msg.id() == id
                && msg.flags().qr()
            {
                return Ok(buf[..len].to_vec());
            }
        }
    }

    /// Sends `query` over TCP and reads responses until `done` says so.
    fn tcp(
        &self,
        server: SocketAddr,
        query: &[u8],
        mut done: impl FnMut(&Message<'_>) -> Result<bool>,
    ) -> Result<Vec<Vec<u8>>> {
        let mut stream = TcpStream::connect_timeout(&server, TIMEOUT)?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        tcp::write_message(&mut stream, query)?;
        let mut buf = vec![0u8; MAX_FRAME_LEN];
        let mut out = Vec::new();
        loop {
            let wire = tcp::read_message(&mut stream, &mut buf)?.ok_or("connection closed")?;
            out.push(wire.to_vec());
            if done(&Message::parse_validated(wire)?)? {
                return Ok(out);
            }
        }
    }

    /// A query for `qname`/`qtype` with DO and the given EDNS options.
    fn query<O: dnsbox::edns::ComposeOptions + ?Sized>(
        &mut self,
        qname: &str,
        qtype: Rtype,
        options: &O,
        padded: bool,
    ) -> Result<Vec<u8>> {
        let id = self.next_id();
        let mut b = MessageBuilder::query_vec(id, &name(qname)?, qtype, Class::IN)?;
        let header = OptHeader::new(1232).with_dnssec_ok(true);
        if padded {
            b.push_edns_padded(header, options, PaddingPolicy::QUERY)?;
        } else {
            b.push_edns(header, options)?;
        }
        Ok(b.finish())
    }

    /// EDNS options in queries to named: NSID, a client cookie, Client
    /// Subnet, an unknown option and Padding. named answers the client
    /// cookie alone with a server cookie (RFC 7873 §5.2.3), which dnsbox
    /// recomputes from its secret (RFC 9018), and the retry carrying it
    /// with a fresh one.
    fn edns(&mut self) -> Result<()> {
        let client = [0xd5, 0x0b, 0x0c, 0x5e, 0x11, 0x22, 0x33, 0x44];
        let ecs = ClientSubnet::new([192, 0, 2, 0].into(), 24, 0)?;
        let unknown = UnknownOption::new(65001.into(), b"dnsbox");
        let apex = name("ed25519-nsec.interop.")?;
        let mut server = Vec::new();
        for round in 0..2 {
            let q = if round == 0 {
                let options = (Nsid::REQUEST, Cookie::client_only(client), ecs, unknown);
                self.query("ed25519-nsec.interop.", Rtype::SOA, &options, true)?
            } else {
                let options = (Nsid::REQUEST, Cookie::new(client, &server)?, ecs, unknown);
                self.query("ed25519-nsec.interop.", Rtype::SOA, &options, true)?
            };
            ensure(q.len() % 128 == 0, "query not padded to 128 bytes")?;
            let r = self.udp(self.named, &q)?;
            let msg = Message::parse_validated(&r)?;
            ensure(
                msg.effective_rcode()? == Rcode::NOERROR,
                format!("rcode {}", msg.effective_rcode()?),
            )?;
            ensure(msg.flags().aa(), "not authoritative")?;
            let (soa, sigs) = rrset(&msg, Section::Answer, &apex, Rtype::SOA)?;
            ensure(soa.len() == 1 && sigs.len() == 1, "no signed SOA")?;
            let edns = msg.edns()?.ok_or("no OPT record")?;
            ensure(edns.dnssec_ok(), "DO not echoed")?;
            let nsid = edns.get::<Nsid<'_>>().ok_or("no NSID")??;
            ensure(
                nsid.as_str() == Some("named.dnsbox-interop"),
                format!("NSID {nsid}"),
            )?;
            let cookie = edns.get::<Cookie<'_>>().ok_or("no cookie")??;
            ensure(cookie.client() == client, "client cookie not echoed")?;
            server = cookie.server().ok_or("no server cookie")?.to_vec();
            let v1 = cookie.server_cookie_v1().ok_or("not an RFC 9018 cookie")?;
            ensure(v1.is_fresh(now() as u32), "stale server cookie")?;
            #[cfg(feature = "cookie-siphash")]
            ensure(
                v1.verify(&COOKIE_SECRET, &client, [127, 0, 0, 1].into()),
                "server cookie does not verify with named's secret",
            )?;
            // What named does with the other options is recorded for
            // tests/interop_bind.rs.
            println!(
                "   round {round}: {} bytes, ECS {:?}, padding {:?}",
                r.len(),
                edns.get::<ClientSubnet>().map(|e| e.map(|e| e.to_string())),
                edns.get::<Padding<'_>>().map(|p| p.map(|p| p.len())),
            );
            if edns.get::<Padding<'_>>().is_some() {
                ensure(r.len() % 128 == 0, "response padded, not to 128 bytes")?;
            }
        }
        Ok(())
    }

    /// The DNSKEY RRset of `rsasha512-nsec3.interop.` over TCP,
    /// authenticated from its DS in `interop.`, itself verified with
    /// `interop.`'s keys authenticated from the trust anchor.
    fn tcp_dnskey(&mut self) -> Result<()> {
        let anchor = self.anchor.clone().ok_or("--anchor is required")?;
        // dnssec-dsfromkey writes `owner IN DS ...` without a TTL.
        let anchor = dnsbox::zone::ZoneReader::new(&anchor)
            .with_default_ttl(3600)
            .records()
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let anchor: Vec<Ds<'_>> = anchor
            .iter()
            .filter_map(|r| match r.data() {
                Ok(RData::Ds(d)) => Some(d),
                _ => None,
            })
            .collect();
        let now = now() as u32;
        let mut scratch = Vec::new();

        let parent = name("interop.")?;
        self.label("tcp-dnskey/parent");
        let q = self.query("interop.", Rtype::DNSKEY, &(), false)?;
        let wires = self.tcp(self.named, &q, |_| Ok(true))?;
        let msg = Message::parse_validated(&wires[0])?;
        let (keys, sigs) = rrset(&msg, Section::Answer, &parent, Rtype::DNSKEY)?;
        let parent_keys = TrustedKeys::from_ds(
            &PurecryptoVerifier,
            Rrset::new(parent.as_name(), Class::IN, dnskeys(keys)),
            anchor.iter().copied(),
            sigs,
            now,
            &mut scratch,
        )?;

        let child = name("rsasha512-nsec3.interop.")?;
        self.label("tcp-dnskey/ds");
        let q = self.query("rsasha512-nsec3.interop.", Rtype::DS, &(), false)?;
        let r = self.udp(self.named, &q)?;
        let ds_msg = Message::parse_validated(&r)?;
        let (ds, sigs) = rrset(&ds_msg, Section::Answer, &child, Rtype::DS)?;
        parent_keys.verify_rrset(
            &PurecryptoVerifier,
            Rrset::new(child.as_name(), Class::IN, &ds),
            sigs,
            now,
            &mut scratch,
        )?;
        let ds: Vec<Ds<'_>> = ds
            .into_iter()
            .filter_map(|d| match d {
                RData::Ds(d) => Some(d),
                _ => None,
            })
            .collect();

        self.label("tcp-dnskey/child");
        let q = self.query("rsasha512-nsec3.interop.", Rtype::DNSKEY, &(), false)?;
        let wires = self.tcp(self.named, &q, |_| Ok(true))?;
        let msg = Message::parse_validated(&wires[0])?;
        let (keys, sigs) = rrset(&msg, Section::Answer, &child, Rtype::DNSKEY)?;
        TrustedKeys::from_ds(
            &PurecryptoVerifier,
            Rrset::new(child.as_name(), Class::IN, dnskeys(keys)),
            ds.iter().copied(),
            sigs,
            now,
            &mut scratch,
        )?;
        Ok(())
    }

    fn key(h: &str, alg: TsigAlgorithm) -> Result<HmacKey<'static>> {
        Ok(HmacKey::new(
            &name(&format!("hmac-{h}.key."))?,
            alg,
            &SECRET,
        ))
    }

    /// A TSIG-signed SOA query: named accepts it and signs its answer.
    fn tsig_query(&mut self, h: &str, alg: TsigAlgorithm) -> Result<()> {
        let key = Probe::key(h, alg)?;
        let id = self.next_id();
        let mut b = MessageBuilder::query_vec(id, &name("interop.")?, Rtype::SOA, Class::IN)?;
        let mac = TsigSigner::request(&key).sign(&mut b, now())?;
        let r = self.udp(self.named, &b.finish())?;
        let msg = Message::parse_validated(&r)?;
        ensure(
            msg.flags().rcode() == Rcode::NOERROR,
            format!("rcode {}", msg.flags().rcode()),
        )?;
        let mut v = TsigVerifier::new(&key, mac.as_slice())?;
        ensure(v.verify(&msg, now())?.is_some(), "response not signed")?;
        v.finish()?;
        Ok(())
    }

    /// A query signed with a known key name and a wrong secret: named
    /// answers NOTAUTH with TSIG error BADSIG and no MAC (RFC 8945
    /// §5.2.2).
    fn tsig_badsig(&mut self) -> Result<()> {
        let key = HmacKey::new(
            &name("hmac-sha256.key.")?,
            TsigAlgorithm::HmacSha256,
            b"not the secret",
        );
        self.tsig_rejected(&key, TsigRcode::BADSIG)
    }

    /// A query signed with a key named knows nothing of: NOTAUTH with TSIG
    /// error BADKEY (RFC 8945 §5.2.1).
    fn tsig_badkey(&mut self) -> Result<()> {
        let key = HmacKey::new(&name("no-such.key.")?, TsigAlgorithm::HmacSha256, &SECRET);
        self.tsig_rejected(&key, TsigRcode::BADKEY)
    }

    fn tsig_rejected(&mut self, key: &HmacKey<'_>, want: TsigRcode) -> Result<()> {
        let id = self.next_id();
        let mut b = MessageBuilder::query_vec(id, &name("interop.")?, Rtype::SOA, Class::IN)?;
        TsigSigner::request(key).sign(&mut b, now())?;
        let r = self.udp(self.named, &b.finish())?;
        let msg = Message::parse_validated(&r)?;
        ensure(
            msg.flags().rcode() == Rcode::NOTAUTH,
            format!("rcode {}", msg.flags().rcode()),
        )?;
        let rec = tsig::find(&msg)?.ok_or("no TSIG record")?;
        ensure(
            rec.data.error == want,
            format!("TSIG error {}", rec.data.error),
        )?;
        ensure(rec.data.mac.is_empty(), "error response with a MAC")
    }

    /// A TKEY query (RFC 2930 §4.2: delete the key that signs it), built by
    /// `dnsbox::tkey::build_query` and signed with TSIG. named only deletes
    /// keys TKEY made, not configured ones: whatever it answers must be a
    /// well-formed response to the query (an error, or a TKEY record dnsbox
    /// reads), and its TSIG must verify.
    fn tkey(&mut self) -> Result<()> {
        let key = Probe::key("sha256", TsigAlgorithm::HmacSha256)?;
        let key_name = name("hmac-sha256.key.")?;
        let alg = name("hmac-sha256.")?;
        let mut b = MessageBuilder::new_vec();
        b.set_id(self.next_id());
        let t = now() as u32;
        let tkey = Tkey::new(alg.as_name(), t, t + 3600, TkeyMode::KEY_DELETION, &[]);
        dnsbox::tkey::build_query(&mut b, &key_name, &tkey)?;
        let mac = TsigSigner::request(&key).sign(&mut b, now())?;
        let r = self.udp(self.named, &b.finish())?;
        let msg = Message::parse_validated(&r)?;
        let q = msg.questions().next().ok_or("no question")??;
        ensure(
            q.qtype() == Rtype::TKEY && q.name() == key_name.as_name(),
            "not our question",
        )?;
        let rcode = msg.flags().rcode();
        let answer = dnsbox::tkey::find(&msg)?;
        match &answer {
            Some(rec) => println!("   named answered TKEY with {rcode}: {}", rec.data),
            None => println!("   named answered TKEY with {rcode}, no TKEY record"),
        }
        ensure(
            rcode != Rcode::NOERROR || answer.is_some(),
            "NOERROR without a TKEY record",
        )?;
        if tsig::find(&msg)?.is_some_and(|t| !t.data.mac.is_empty()) {
            let mut v = TsigVerifier::new(&key, mac.as_slice())?;
            ensure(v.verify(&msg, now())?.is_some(), "response not signed")?;
            v.finish()?;
        }
        Ok(())
    }

    /// A TSIG-signed AXFR of `bulk.interop.`: a stream of several
    /// messages, every one verified, holding the zone.
    fn axfr(&mut self, h: &str, alg: TsigAlgorithm) -> Result<()> {
        let key = Probe::key(h, alg)?;
        let zone = name("bulk.interop.")?;
        let id = self.next_id();
        let mut b = MessageBuilder::new_vec();
        b.set_id(id);
        xfr::build_axfr_query(&mut b, &zone, Class::IN)?;
        let mac = TsigSigner::request(&key).sign(&mut b, now())?;
        let mut verifier = TsigVerifier::new(&key, mac.as_slice())?;
        let mut xfr = XfrProcessor::axfr(&zone).with_id(id);
        let mut records = 0;
        let wires = self.tcp(self.named, &b.finish(), |msg| {
            verifier.verify(msg, now())?;
            for e in xfr.process(msg)? {
                if let XfrEvent::Record(_) = e? {
                    records += 1;
                }
            }
            Ok(xfr.is_done())
        })?;
        verifier.finish()?;
        ensure(wires.len() >= 2, format!("{} messages", wires.len()))?;
        // SOA, NS, ns1 A, 250 × (A, TXT).
        ensure(records == 2 + 500, format!("{records} records"))
    }

    /// Dynamic updates of `dyn.interop.`: additions under a prerequisite,
    /// a deletion, a failed prerequisite (YXDOMAIN), an unsigned update
    /// (refused by the update policy), then an IXFR from the serial
    /// before them that holds exactly those changes.
    fn update(&mut self) -> Result<()> {
        let key = Probe::key("sha384", TsigAlgorithm::HmacSha384)?;
        let zone = name("dyn.interop.")?;
        let probe = name("probe.dyn.interop.")?;
        let www = name("www.dyn.interop.")?;
        self.label("update/serial");
        let serial = self.serial(&zone)?;

        let txt = Txt::from_wire(b"\x0fadded by dnsbox")?;
        let mut up = self.update_builder(&zone)?;
        up.require_name_absent(&probe)?;
        up.require_rrset_exists(&www, Rtype::A)?;
        up.add(&probe, 300, &A::new([192, 0, 2, 53].into()))?;
        up.add(&probe, 300, &Aaaa::new("2001:db8::53".parse()?))?;
        up.add(&probe, 300, &txt)?;
        self.label("update/add");
        self.send_update(up.into_builder(), Some(&key), Rcode::NOERROR)?;

        let mut up = self.update_builder(&zone)?;
        up.require_rr(&probe, &A::new([192, 0, 2, 53].into()))?;
        up.delete_rr(&probe, &Aaaa::new("2001:db8::53".parse()?))?;
        self.label("update/delete");
        self.send_update(up.into_builder(), Some(&key), Rcode::NOERROR)?;

        let mut up = self.update_builder(&zone)?;
        up.require_name_absent(&www)?;
        up.delete_name(&www)?;
        self.label("update/yxdomain");
        self.send_update(up.into_builder(), Some(&key), Rcode::YXDOMAIN)?;

        let mut up = self.update_builder(&zone)?;
        up.delete_name(&www)?;
        self.label("update/unsigned");
        self.send_update(up.into_builder(), None, Rcode::REFUSED)?;

        // The IXFR from before: the probe's records, added (A, AAAA, TXT)
        // and the AAAA deleted again.
        let id = self.next_id();
        let mut b = MessageBuilder::new_vec();
        b.set_id(id);
        let mut soa_buf = [0u8; 256];
        let soa = Soa::from_text(
            &format!("ns1.dyn.interop. hostmaster.dyn.interop. {serial} 7200 3600 1209600 300"),
            &mut soa_buf,
        )?;
        xfr::build_ixfr_query(&mut b, &zone, Class::IN, &soa)?;
        let mac = TsigSigner::request(&key).sign(&mut b, now())?;
        let mut verifier = TsigVerifier::new(&key, mac.as_slice())?;
        let mut xfr = XfrProcessor::ixfr(&zone, serial).with_id(id);
        self.label("update/ixfr");
        let (mut added, mut deleted) = (Vec::new(), Vec::new());
        self.tcp(self.named, &b.finish(), |msg| {
            verifier.verify(msg, now())?;
            for e in xfr.process(msg)? {
                match e? {
                    XfrEvent::Add(rr) if rr.name() == probe.as_name() => added.push(rr.rtype()),
                    XfrEvent::Delete(rr) if rr.name() == probe.as_name() => {
                        deleted.push(rr.rtype())
                    }
                    _ => {}
                }
            }
            Ok(xfr.is_done())
        })?;
        verifier.finish()?;
        ensure(
            xfr.style() == Some(XfrStyle::Incremental),
            "not incremental",
        )?;
        added.sort();
        ensure(
            added == [Rtype::A, Rtype::TXT, Rtype::AAAA],
            format!("added {added:?}"),
        )?;
        ensure(deleted == [Rtype::AAAA], format!("deleted {deleted:?}"))?;

        // And the data is served.
        self.label("update/query");
        let q = self.query("probe.dyn.interop.", Rtype::TXT, &(), false)?;
        let r = self.udp(self.named, &q)?;
        let msg = Message::parse_validated(&r)?;
        let (txt, _) = rrset(&msg, Section::Answer, &probe, Rtype::TXT)?;
        ensure(txt.len() == 1, "TXT not served")
    }

    fn update_builder(&mut self, zone: &NameBuf) -> Result<UpdateBuilder<Vec<u8>>> {
        let mut b = MessageBuilder::new_vec();
        b.set_id(self.next_id());
        Ok(UpdateBuilder::new(b, zone, Class::IN)?)
    }

    /// An UPDATE signed with SIG(0) (RFC 2931) by the Ed25519 KEY of
    /// `sig0-ed25519.dyn.interop.`, whose private key dnssec-keygen wrote:
    /// the KEY dnsbox derives from it is the one named serves, and named
    /// answers the update (BIND 9.18.28 and later no longer verify SIG(0):
    /// the answer is recorded for tests/interop_bind.rs).
    fn sig0_update(&mut self) -> Result<()> {
        let dir = self.sig0.clone().ok_or("--sig0 is required")?;
        let base = std::fs::read_to_string(dir.join("ed25519.name"))?;
        let private = std::fs::read_to_string(dir.join(format!("{}.private", base.trim())))?;
        let seed = private
            .lines()
            .find_map(|l| l.strip_prefix("PrivateKey: "))
            .ok_or("no PrivateKey in the .private file")?;
        let key = SigningKey::from_private_bytes(Algorithm::ED25519, &base64(seed)?)?;
        let owner = name("sig0-ed25519.dyn.interop.")?;
        let signer = DnssecSig0Signer::new(&key, owner.as_name(), 512);

        // The KEY named serves is dnsbox's.
        self.label("sig0/key");
        let q = self.query("sig0-ed25519.dyn.interop.", Rtype::KEY, &(), false)?;
        let r = self.udp(self.named, &q)?;
        let msg = Message::parse_validated(&r)?;
        let (keys, _) = rrset(&msg, Section::Answer, &owner, Rtype::KEY)?;
        let served: Vec<Key<'_>> = keys
            .into_iter()
            .filter_map(|k| match k {
                RData::Key(k) => Some(k),
                _ => None,
            })
            .collect();
        ensure(
            served == [signer.key()],
            format!("KEY {served:?}, dnsbox derives {}", signer.key()),
        )?;

        let zone = name("dyn.interop.")?;
        let added = name("sig0-probe.dyn.interop.")?;
        let mut up = self.update_builder(&zone)?;
        up.add(&added, 300, &A::new([192, 0, 2, 31].into()))?;
        let mut b = up.into_builder();
        sig0::sign(&mut b, &signer, Validity::around(now() as u32, 300), None)?;
        let wire = b.finish();
        // dnsbox verifies its own signature as named would.
        let msg = Message::parse_validated(&wire)?;
        let verifier = dnsbox::sig0::DnssecSig0Verifier::new(
            PurecryptoVerifier,
            owner.as_name(),
            signer.key(),
        );
        sig0::verify(&msg, &verifier, now() as u32, None)?;
        self.label("sig0/update");
        let r = self.udp(self.named, &wire)?;
        let msg = Message::parse_validated(&r)?;
        let rcode = msg.flags().rcode();
        println!(
            "   named answered the SIG(0)-signed UPDATE with {rcode}{}",
            if sig0::find(&msg)?.is_some() {
                ", signed"
            } else {
                ""
            }
        );
        ensure(
            msg.flags().opcode() == dnsbox::Opcode::UPDATE,
            "not an UPDATE response",
        )?;
        ensure(
            matches!(rcode, Rcode::NOERROR | Rcode::REFUSED),
            format!("rcode {rcode}"),
        )
    }

    /// The SOA serial of `zone`.
    fn serial(&mut self, zone: &NameBuf) -> Result<u32> {
        let id = self.next_id();
        let b = MessageBuilder::query_vec(id, zone, Rtype::SOA, Class::IN)?;
        let r = self.udp(self.named, &b.finish())?;
        let msg = Message::parse_validated(&r)?;
        let rr = msg.answers().next().ok_or("no SOA")??;
        Ok(rr.data_as::<Soa<'_>>()?.serial)
    }

    /// Sends an UPDATE (signed with `key`, if any) and checks the RCODE
    /// and, when signed, the response's MAC.
    fn send_update(
        &mut self,
        mut b: MessageBuilder<Vec<u8>>,
        key: Option<&HmacKey<'_>>,
        want: Rcode,
    ) -> Result<()> {
        let mac = match key {
            Some(k) => Some(TsigSigner::request(k).sign(&mut b, now())?),
            None => None,
        };
        let r = self.udp(self.named, &b.finish())?;
        let msg = Message::parse_validated(&r)?;
        ensure(
            msg.flags().rcode() == want,
            format!("rcode {} instead of {want}", msg.flags().rcode()),
        )?;
        if let (Some(k), Some(mac)) = (key, mac) {
            let mut v = TsigVerifier::new(k, mac.as_slice())?;
            ensure(v.verify(&msg, now())?.is_some(), "response not signed")?;
            v.finish()?;
        }
        Ok(())
    }

    /// A query to the resolver with NSID and a cookie: secure answers have
    /// AD and their RRSIGs, insecure ones neither AD nor SERVFAIL, bogus
    /// ones SERVFAIL (with an Extended DNS Error, if named gives one).
    fn resolver_query(&mut self, qname: &str, over_tcp: bool, expect: Expect) -> Result<()> {
        let client = [1, 2, 3, 4, 5, 6, 7, 8];
        let q = self.query(
            qname,
            Rtype::A,
            &(Nsid::REQUEST, Cookie::client_only(client)),
            false,
        )?;
        let r = if over_tcp {
            self.tcp(self.resolver, &q, |_| Ok(true))?.remove(0)
        } else {
            self.udp(self.resolver, &q)?
        };
        let msg = Message::parse_validated(&r)?;
        let edns = msg.edns()?.ok_or("no OPT record")?;
        let nsid = edns.get::<Nsid<'_>>().ok_or("no NSID")??;
        ensure(
            nsid.as_str() == Some("resolver.dnsbox-interop"),
            format!("NSID {nsid}"),
        )?;
        let cookie = edns.get::<Cookie<'_>>().ok_or("no cookie")??;
        ensure(cookie.client() == client, "client cookie not echoed")?;
        #[cfg(feature = "cookie-siphash")]
        if let Some(v1) = cookie.server_cookie_v1() {
            ensure(
                v1.verify(&COOKIE_SECRET, &client, [127, 0, 0, 1].into()),
                "server cookie does not verify with named's secret",
            )?;
        }
        let rcode = msg.flags().rcode();
        match expect {
            Expect::Secure | Expect::Insecure => {
                ensure(rcode == Rcode::NOERROR, format!("rcode {rcode}"))?;
                ensure(
                    msg.flags().ad() == (expect == Expect::Secure),
                    format!("AD {}", msg.flags().ad()),
                )?;
                let owner = name(qname)?;
                let (a, sigs) = rrset(&msg, Section::Answer, &owner, Rtype::A)?;
                ensure(!a.is_empty(), "no answer")?;
                ensure(
                    sigs.is_empty() == (expect == Expect::Insecure),
                    format!("{} RRSIGs", sigs.len()),
                )
            }
            Expect::Bogus => {
                ensure(rcode == Rcode::SERVFAIL, format!("rcode {rcode}"))?;
                match edns.get::<ExtendedError<'_>>() {
                    Some(ede) => println!("   resolver: {}", ede?),
                    None => println!("   resolver: no Extended DNS Error"),
                }
                Ok(())
            }
        }
    }
}
