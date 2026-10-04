//! Live interop checks of dnsbox-built queries against Knot DNS and
//! Unbound, run by `.github/workflows/interop.yml` once
//! `tests/corpus/knot/run.sh serve` has started them on the runner.
//!
//! ```text
//! cargo run --example interop_probe --all-features -- \
//!     --knot 127.0.0.1:5300 --unbound 127.0.0.1:5400 --anchor OUT/anchor.ds \
//!     [--knot-label FILE --unbound-label FILE]
//! ```
//!
//! Every query is built by dnsbox and every response parsed and checked
//! by dnsbox: EDNS options (NSID, cookies, Client Subnet, Padding, an
//! unknown option), knotd's RFC 9018 server cookies recomputed from its
//! configured secret, a DNSKEY RRset over TCP authenticated from the
//! parent's DS (verified with the parent's keys from the trust anchor),
//! TSIG-signed queries with every HMAC (which knotd must accept) and with
//! a wrong secret (which it must reject), a TSIG-signed TKEY query
//! (RFC 2930; knotd must answer it well-formed), TSIG-signed AXFR streams of
//! several messages, dynamic UPDATEs (RFC 2136) knotd must apply, refuse
//! or fail on a prerequisite, the IXFR they produce, and Unbound's
//! validated (AD), insecure and bogus (SERVFAIL with an Extended DNS
//! Error) answers. With `--knot-label`/`--unbound-label` (the label files
//! of `tests/corpus/knot/proxy.py`), the exchanges are recorded under
//! `probe/<check>` for `tests/interop_knot.rs`.
//!
//! Exits with status 1 if any check fails.

use std::error::Error as StdError;
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dnsbox::dnssec::{PurecryptoVerifier, Rrset, TrustedKeys};
use dnsbox::edns::{
    ClientSubnet, Cookie, ExtendedError, Nsid, OptHeader, PaddingPolicy, UnknownOption,
};
use dnsbox::rdata::{A, Aaaa, Dnskey, Ds, ParseRdataText, RData, Rrsig, Soa, Tkey, TkeyMode, Txt};
use dnsbox::tcp::{self, MAX_FRAME_LEN};
use dnsbox::tsig::{self, HmacKey, TsigAlgorithm, TsigRcode, TsigSigner, TsigVerifier};
use dnsbox::update::UpdateBuilder;
use dnsbox::xfr::{self, XfrEvent, XfrProcessor, XfrStyle};
use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rcode, Rtype, Section};

type Result<T> = std::result::Result<T, Box<dyn StdError>>;

/// The TSIG secret of every key `run.sh` gives knotd: 00 01 .. 1f.
const SECRET: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

/// knotd's mod-cookies secret in `run.sh`: 00 01 .. 0f.
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
    knot: SocketAddr,
    unbound: SocketAddr,
    knot_label: Option<String>,
    unbound_label: Option<String>,
    anchor: Option<String>,
    id: u16,
    failures: Vec<String>,
}

fn main() {
    match run() {
        Ok(0) => println!("interop_probe: every check passed"),
        Ok(n) => {
            eprintln!("interop_probe: {n} checks failed");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("interop_probe: {e}");
            std::process::exit(2);
        }
    }
}

fn run() -> Result<usize> {
    let mut p = Probe {
        knot: "127.0.0.1:5300".parse()?,
        unbound: "127.0.0.1:5400".parse()?,
        knot_label: None,
        unbound_label: None,
        anchor: None,
        id: (now() as u16) ^ 0x4242,
        failures: Vec::new(),
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or(format!("{arg} needs a value"));
        match arg.as_str() {
            "--knot" => p.knot = value()?.parse()?,
            "--unbound" => p.unbound = value()?.parse()?,
            "--knot-label" => p.knot_label = Some(value()?),
            "--unbound-label" => p.unbound_label = Some(value()?),
            "--anchor" => p.anchor = Some(std::fs::read_to_string(value()?)?),
            _ => return Err(format!("unknown argument {arg}").into()),
        }
    }

    p.check("edns", Probe::edns);
    p.check("tcp-dnskey", Probe::tcp_dnskey);
    for (h, alg) in HMACS {
        p.check(&format!("tsig-{h}"), |p| p.tsig_query(h, alg));
    }
    p.check("tsig-badsig", Probe::tsig_badsig);
    p.check("tkey", Probe::tkey);
    for (h, alg) in HMACS {
        p.check(&format!("axfr-{h}"), |p| p.axfr(h, alg));
    }
    p.check("update", Probe::update);
    p.check("unbound-secure", |p| {
        p.unbound_query("www.ed25519-nsec.interop.", false, Expect::Secure)
    });
    p.check("unbound-secure-tcp", |p| {
        p.unbound_query("www.ecdsap384-nsec3.interop.", true, Expect::Secure)
    });
    p.check("unbound-insecure", |p| {
        p.unbound_query("www.insecure.interop.", false, Expect::Insecure)
    });
    p.check("unbound-bogus", |p| {
        p.unbound_query("www.bogus.interop.", false, Expect::Bogus)
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

/// The expected outcome of an Unbound query.
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
        for file in [&self.knot_label, &self.unbound_label]
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

    /// EDNS options in a query to knotd: NSID, a client cookie, Client
    /// Subnet, an unknown option and Padding; knotd answers BADCOOKIE with
    /// a server cookie (RFC 7873 §5.2.3, knotd's default), the retry with
    /// it succeeds.
    fn edns(&mut self) -> Result<()> {
        let client = [0xd5, 0x0b, 0x0c, 0x5e, 0x11, 0x22, 0x33, 0x44];
        let ecs = ClientSubnet::new([192, 0, 2, 0].into(), 24, 0)?;
        let unknown = UnknownOption::new(65001.into(), b"dnsbox");
        let q = self.query(
            "ed25519-nsec.interop.",
            Rtype::SOA,
            &(Nsid::REQUEST, Cookie::client_only(client), ecs, unknown),
            true,
        )?;
        ensure(q.len() % 128 == 0, "query not padded to 128 bytes")?;
        let r = self.udp(self.knot, &q)?;
        let msg = Message::parse_validated(&r)?;
        ensure(
            msg.effective_rcode()? == Rcode::BADCOOKIE,
            format!("rcode {}", msg.effective_rcode()?),
        )?;
        let edns = msg.edns()?.ok_or("no OPT record")?;
        let cookie = edns.get::<Cookie<'_>>().ok_or("no cookie")??;
        ensure(cookie.client() == client, "client cookie not echoed")?;
        let server = cookie.server().ok_or("no server cookie")?.to_vec();
        let v1 = cookie.server_cookie_v1().ok_or("not an RFC 9018 cookie")?;
        ensure(v1.is_fresh(now() as u32), "stale server cookie")?;
        #[cfg(feature = "cookie-siphash")]
        ensure(
            v1.verify(&COOKIE_SECRET, &client, [127, 0, 0, 1].into()),
            "server cookie does not verify with knotd's secret",
        )?;

        let full = Cookie::new(client, &server)?;
        let q = self.query(
            "ed25519-nsec.interop.",
            Rtype::SOA,
            &(Nsid::REQUEST, full, ecs, unknown),
            true,
        )?;
        let r = self.udp(self.knot, &q)?;
        let msg = Message::parse_validated(&r)?;
        ensure(
            msg.effective_rcode()? == Rcode::NOERROR,
            format!("rcode {}", msg.effective_rcode()?),
        )?;
        ensure(msg.flags().aa(), "not authoritative")?;
        let apex = name("ed25519-nsec.interop.")?;
        let (soa, sigs) = rrset(&msg, Section::Answer, &apex, Rtype::SOA)?;
        ensure(soa.len() == 1 && sigs.len() == 1, "no signed SOA")?;
        let edns = msg.edns()?.ok_or("no OPT record")?;
        let nsid = edns.get::<Nsid<'_>>().ok_or("no NSID")??;
        ensure(
            nsid.as_str() == Some("dnsbox-interop"),
            format!("NSID {nsid}"),
        )?;
        let ecs_back = edns.get::<ClientSubnet>().ok_or("no Client Subnet")??;
        ensure(ecs_back == ecs, format!("Client Subnet {ecs_back}"))?;
        let cookie = edns.get::<Cookie<'_>>().ok_or("no cookie")??;
        ensure(cookie.client() == client, "client cookie not echoed")?;
        ensure(edns.dnssec_ok(), "DO not echoed")
    }

    /// The DNSKEY RRset of `rsasha512-nsec3.interop.` over TCP,
    /// authenticated from its DS in `interop.`, itself verified with
    /// `interop.`'s keys authenticated from the trust anchor.
    fn tcp_dnskey(&mut self) -> Result<()> {
        let anchor = self.anchor.clone().ok_or("--anchor is required")?;
        // keymgr writes `owner DS ...` without a TTL.
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
        let wires = self.tcp(self.knot, &q, |_| Ok(true))?;
        let msg = Message::parse_validated(&wires[0])?;
        let (keys, sigs) = rrset(&msg, Section::Answer, &parent, Rtype::DNSKEY)?;
        let keys = dnskeys(keys);
        let parent_keys = TrustedKeys::from_ds(
            &PurecryptoVerifier,
            Rrset::new(parent.as_name(), Class::IN, keys),
            anchor.iter().copied(),
            sigs,
            now,
            &mut scratch,
        )?;

        let child = name("rsasha512-nsec3.interop.")?;
        self.label("tcp-dnskey/ds");
        let q = self.query("rsasha512-nsec3.interop.", Rtype::DS, &(), false)?;
        let r = self.udp(self.knot, &q)?;
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
        let wires = self.tcp(self.knot, &q, |_| Ok(true))?;
        let msg = Message::parse_validated(&wires[0])?;
        let (keys, sigs) = rrset(&msg, Section::Answer, &child, Rtype::DNSKEY)?;
        let keys = dnskeys(keys);
        TrustedKeys::from_ds(
            &PurecryptoVerifier,
            Rrset::new(child.as_name(), Class::IN, keys),
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

    /// A TSIG-signed SOA query: knotd accepts it and signs its answer.
    fn tsig_query(&mut self, h: &str, alg: TsigAlgorithm) -> Result<()> {
        let key = Probe::key(h, alg)?;
        let id = self.next_id();
        let mut b = MessageBuilder::query_vec(id, &name("interop.")?, Rtype::SOA, Class::IN)?;
        let mac = TsigSigner::request(&key).sign(&mut b, now())?;
        let r = self.udp(self.knot, &b.finish())?;
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

    /// A query signed with the right key name and a wrong secret: knotd
    /// answers NOTAUTH with TSIG error BADSIG (RFC 8945 §5.2.2).
    fn tsig_badsig(&mut self) -> Result<()> {
        let key = HmacKey::new(
            &name("hmac-sha256.key.")?,
            TsigAlgorithm::HmacSha256,
            b"not the secret",
        );
        let id = self.next_id();
        let mut b = MessageBuilder::query_vec(id, &name("interop.")?, Rtype::SOA, Class::IN)?;
        TsigSigner::request(&key).sign(&mut b, now())?;
        let r = self.udp(self.knot, &b.finish())?;
        let msg = Message::parse_validated(&r)?;
        ensure(msg.flags().rcode() == Rcode::NOTAUTH, "not NOTAUTH")?;
        let rec = tsig::find(&msg)?.ok_or("no TSIG record")?;
        ensure(rec.data.error == TsigRcode::BADSIG, "not BADSIG")?;
        ensure(rec.data.mac.is_empty(), "error response with a MAC")
    }

    /// A TKEY query (RFC 2930 §4.2: delete the key that signs it), built by
    /// `dnsbox::tkey::build_query` and signed with TSIG. knotd does not
    /// implement TKEY: whatever it answers must be a well-formed response
    /// to the query, either an error or a TKEY record dnsbox reads, and a
    /// TSIG on it must verify.
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
        let r = self.udp(self.knot, &b.finish())?;
        let msg = Message::parse_validated(&r)?;
        let q = msg.questions().next().ok_or("no question")??;
        ensure(
            q.qtype() == Rtype::TKEY && q.name() == key_name.as_name(),
            "not our question",
        )?;
        let rcode = msg.flags().rcode();
        let answer = dnsbox::tkey::find(&msg)?;
        match &answer {
            Some(rec) => println!("knotd answered TKEY with {rcode}: {}", rec.data),
            None => println!("knotd answered TKEY with {rcode}, no TKEY record"),
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
        let wires = self.tcp(self.knot, &b.finish(), |msg| {
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

    /// Dynamic updates of `dyn.interop.` (knotd signs the zone itself):
    /// additions under a prerequisite, a deletion, a failed prerequisite
    /// (YXDOMAIN), an unsigned update (refused), then an IXFR from the
    /// serial before them that holds exactly those changes.
    fn update(&mut self) -> Result<()> {
        let key = Probe::key("sha384", TsigAlgorithm::HmacSha384)?;
        let zone = name("dyn.interop.")?;
        let probe = name("probe.dyn.interop.")?;
        let www = name("www.dyn.interop.")?;
        self.label("update/serial");
        let serial = self.serial(&zone)?;

        let txt = Txt::from_wire(b"\x0fadded by dnsbox")?;
        let id = self.next_id();
        let mut b = MessageBuilder::new_vec();
        b.set_id(id);
        let mut up = UpdateBuilder::new(b, &zone, Class::IN)?;
        up.require_name_absent(&probe)?;
        up.require_rrset_exists(&www, Rtype::A)?;
        up.add(&probe, 300, &A::new([192, 0, 2, 53].into()))?;
        up.add(&probe, 300, &Aaaa::new("2001:db8::53".parse()?))?;
        up.add(&probe, 300, &txt)?;
        self.label("update/add");
        self.send_update(up.into_builder(), Some(&key), Rcode::NOERROR)?;

        let id = self.next_id();
        let mut b = MessageBuilder::new_vec();
        b.set_id(id);
        let mut up = UpdateBuilder::new(b, &zone, Class::IN)?;
        up.require_rr(&probe, &A::new([192, 0, 2, 53].into()))?;
        up.delete_rr(&probe, &Aaaa::new("2001:db8::53".parse()?))?;
        self.label("update/delete");
        self.send_update(up.into_builder(), Some(&key), Rcode::NOERROR)?;

        let id = self.next_id();
        let mut b = MessageBuilder::new_vec();
        b.set_id(id);
        let mut up = UpdateBuilder::new(b, &zone, Class::IN)?;
        up.require_name_absent(&www)?;
        up.delete_name(&www)?;
        self.label("update/yxdomain");
        self.send_update(up.into_builder(), Some(&key), Rcode::YXDOMAIN)?;

        let id = self.next_id();
        let mut b = MessageBuilder::new_vec();
        b.set_id(id);
        let mut up = UpdateBuilder::new(b, &zone, Class::IN)?;
        up.delete_name(&www)?;
        self.label("update/unsigned");
        self.send_update(up.into_builder(), None, Rcode::NOTAUTH)?;

        // The IXFR from before: the probe's records, added (A, TXT) and
        // not deleted again, and the AAAA added and deleted.
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
        self.tcp(self.knot, &b.finish(), |msg| {
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
            added
                .iter()
                .filter(|t| **t != Rtype::RRSIG && **t != Rtype::NSEC3)
                .count()
                == 3,
            format!("added {added:?}"),
        )?;
        ensure(
            deleted.contains(&Rtype::AAAA),
            format!("deleted {deleted:?}"),
        )?;

        // And the data is served, signed by knotd.
        self.label("update/query");
        let q = self.query("probe.dyn.interop.", Rtype::TXT, &(), false)?;
        let r = self.udp(self.knot, &q)?;
        let msg = Message::parse_validated(&r)?;
        let (txt, sigs) = rrset(&msg, Section::Answer, &probe, Rtype::TXT)?;
        ensure(txt.len() == 1 && sigs.len() == 1, "TXT not served signed")
    }

    /// The SOA serial of `zone`.
    fn serial(&mut self, zone: &NameBuf) -> Result<u32> {
        let id = self.next_id();
        let b = MessageBuilder::query_vec(id, zone, Rtype::SOA, Class::IN)?;
        let r = self.udp(self.knot, &b.finish())?;
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
        let r = self.udp(self.knot, &b.finish())?;
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

    /// A query to Unbound with NSID and a cookie: secure answers have AD
    /// and their RRSIGs, insecure ones neither AD nor SERVFAIL, bogus ones
    /// SERVFAIL with a DNSSEC Extended DNS Error (RFC 8914 §4.7).
    fn unbound_query(&mut self, qname: &str, over_tcp: bool, expect: Expect) -> Result<()> {
        let client = [1, 2, 3, 4, 5, 6, 7, 8];
        let q = self.query(
            qname,
            Rtype::A,
            &(Nsid::REQUEST, Cookie::client_only(client)),
            false,
        )?;
        let r = if over_tcp {
            self.tcp(self.unbound, &q, |_| Ok(true))?.remove(0)
        } else {
            self.udp(self.unbound, &q)?
        };
        let msg = Message::parse_validated(&r)?;
        let edns = msg.edns()?.ok_or("no OPT record")?;
        let nsid = edns.get::<Nsid<'_>>().ok_or("no NSID")??;
        ensure(
            nsid.as_str() == Some("unbound.dnsbox-interop"),
            format!("NSID {nsid}"),
        )?;
        let cookie = edns.get::<Cookie<'_>>().ok_or("no cookie")??;
        ensure(cookie.client() == client, "client cookie not echoed")?;
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
                let ede = edns
                    .get::<ExtendedError<'_>>()
                    .ok_or("no Extended DNS Error")??;
                println!("   unbound: {ede}");
                // 1..=12 are the DNSSEC codes (6: DNSSEC Bogus).
                ensure(
                    (1..=12).contains(&ede.info_code.get()),
                    format!("EDE {ede}"),
                )
            }
        }
    }
}
