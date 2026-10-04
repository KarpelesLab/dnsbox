//! The hot path allocates nothing: parsing, iterating, typed RDATA,
//! validation, presentation formatting, name handling and building into a
//! caller buffer all run under an allocator that counts every allocation
//! (`assert_no_alloc`). CI runs this with `--no-default-features` (the bare
//! `no_std`, no-`alloc` configuration, where the library cannot allocate at
//! all) and with all features, where nothing on this path may allocate
//! either.

use core::fmt::{self, Write};

use assert_no_alloc::{AllocDisabler, assert_no_alloc, reset_violation_count, violation_count};
use dnsbox::rdata::{A, Mx, RData, TxtParts};
use dnsbox::wire::Canonical;
use dnsbox::{
    Class, ComposeRdata, Flags, Message, MessageBuilder, Name, NameBuf, Rtype, Section, WireReader,
    WireWriter,
};

#[global_allocator]
static ALLOC: AllocDisabler = AllocDisabler;

/// A `fmt::Write` sink over a fixed array.
struct StackText {
    buf: [u8; 1024],
    len: usize,
}

impl StackText {
    const fn new() -> Self {
        StackText {
            buf: [0; 1024],
            len: 0,
        }
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }

    fn clear(&mut self) {
        self.len = 0;
    }
}

impl Write for StackText {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len + s.len();
        self.buf
            .get_mut(self.len..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// `example.com SOA` response from 1.1.1.1 (compressed names in RDATA).
const SOA_RESPONSE: &[u8] = b"\xbe\xef\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\
    \x07example\x03com\x00\x00\x06\x00\x01\
    \xc0\x0c\x00\x06\x00\x01\x00\x00\x03\x6d\x00\x32\
    \x07elliott\x02ns\x0acloudflare\xc0\x14\x03dns\xc0\x34\
    \x90\x06\xf3\x98\x00\x00\x27\x10\x00\x00\x09\x60\x00\x09\x3a\x80\x00\x00\x07\x08";

/// Runs `f` and fails if it allocated.
fn no_alloc(what: &str, f: impl FnOnce()) {
    reset_violation_count();
    assert_no_alloc(f);
    assert_eq!(violation_count(), 0, "{what} allocated");
}

#[test]
fn allocator_detects_allocations() {
    // Guard against a vacuous pass: the counter must see a real allocation.
    reset_violation_count();
    assert_no_alloc(|| {
        let v = std::hint::black_box(vec![1u8; 16]);
        drop(v);
    });
    assert!(violation_count() > 0);
    reset_violation_count();
}

#[test]
fn parse_iterate_display() {
    no_alloc("parsing", || {
        let msg = Message::parse_validated(SOA_RESPONSE).unwrap();
        assert_eq!(msg.header().ancount, 1);
        let mut text = StackText::new();
        for q in msg.questions() {
            let q = q.unwrap();
            assert_eq!(q.qtype(), Rtype::SOA);
            write!(text, "{q}").unwrap();
        }
        assert_eq!(text.as_str(), "example.com. IN SOA");
        for rr in msg.records() {
            let (section, rr) = rr.unwrap();
            assert_eq!(section, Section::Answer);
            let RData::Soa(soa) = rr.data().unwrap() else {
                panic!("not SOA");
            };
            assert_eq!(soa.serial, 2_416_374_680);
            text.clear();
            write!(text, "{rr}").unwrap();
            assert_eq!(
                text.as_str(),
                "example.com. 877 IN SOA elliott.ns.cloudflare.com. dns.cloudflare.com. \
                 2416374680 10000 2400 604800 1800"
            );
            // Name handling on a compressed name.
            let mname = soa.mname;
            assert_eq!(mname.label_count(), 4);
            assert!(mname.is_subdomain_of(&rr.name().strip_labels(1).unwrap()));
            let owned: NameBuf = mname.to_buf();
            assert_eq!(owned, mname);
            let mut flat = [0u8; 255];
            assert_eq!(mname.flatten(&mut flat), mname.wire_len());
            // Canonical order compares from the right: cloudflare < example.
            assert!(mname < rr.name());
        }
        assert_eq!(msg.answers().count(), 1);
        assert_eq!(msg.additional().count(), 0);
    });
}

#[test]
fn malformed_input() {
    no_alloc("rejecting malformed input", || {
        for end in 0..SOA_RESPONSE.len() {
            let prefix = &SOA_RESPONSE[..end];
            assert!(Message::parse(prefix).and_then(|m| m.validate()).is_err());
            if let Ok(m) = Message::parse(prefix) {
                for r in m.records() {
                    let _ = r.and_then(|(_, rr)| rr.data());
                }
            }
        }
        let mut r = WireReader::new(b"\xc0\x00");
        assert!(r.read_name().is_err());
    });
}

#[test]
fn build_into_stack_buffer() {
    let name: NameBuf = "example.com".parse().unwrap();
    let mail: NameBuf = "mail.example.com".parse().unwrap();
    no_alloc("building", || {
        let mut buf = [0u8; 512];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.set_id(0x1234);
        b.set_flags(Flags::default().with_qr(true).with_rd(true));
        b.push_question(&name, Rtype::MX, Class::IN).unwrap();
        b.push_answer(
            &name,
            Class::IN,
            3600,
            &Mx {
                preference: 10,
                exchange: mail.as_name(),
            },
        )
        .unwrap();
        let cp = b.checkpoint();
        b.push_answer(&name, Class::IN, 60, &TxtParts(&[b"v=spf1 -all"]))
            .unwrap();
        b.rollback(cp);
        b.push_additional(&mail, Class::IN, 3600, &A::new([192, 0, 2, 1].into()))
            .unwrap();
        // Copy a parsed message's records (decompress + recompress).
        let src = Message::parse_validated(SOA_RESPONSE).unwrap();
        for (_, rr) in src.records().map(Result::unwrap) {
            b.copy_record(Section::Additional, &rr).unwrap();
        }
        let wire = b.finish();
        let msg = Message::parse_validated(wire).unwrap();
        assert_eq!(msg.header().ancount, 1);
        assert_eq!(msg.header().arcount, 2);

        // Canonical RDATA (RFC 4034 §6.2) into a stack buffer.
        let mut out = [0u8; 64];
        let mut w = WireWriter::new(&mut out);
        let mx = Mx {
            preference: 10,
            exchange: Name::from_wire(b"\x04MAIL\x07Example\x00").unwrap(),
        };
        mx.compose_rdata(&mut Canonical::new(&mut w)).unwrap();
        assert_eq!(w.written(), b"\x00\x0a\x04mail\x07example\x00");
    });
}

#[test]
fn text_parsing() {
    no_alloc("presentation parsing", || {
        let n: NameBuf = "a\\.b.Example.COM.".parse().unwrap();
        assert_eq!(n.label_count(), 3);
        assert_eq!("TYPE65534".parse::<Rtype>().unwrap(), Rtype::new(65534));
        assert_eq!("in".parse::<Class>().unwrap(), Class::IN);
        let mut text = StackText::new();
        write!(text, "{n}").unwrap();
        assert_eq!(text.as_str(), "a\\.b.Example.COM.");
    });
}

#[test]
fn zone_file_reading() {
    const ZONE: &str = "\
$ORIGIN example.
$TTL 1h
@ SOA ns1 hostmaster ( 1 2h 15m 2w 1h )
  NS ns1
  MX 10 mail
ns1 A 192.0.2.1
mail AAAA 2001:db8::25
txt TXT \"hello world\" more ; comment
$GENERATE 1-3 h$ CNAME ns1
svc HTTPS 1 . alpn=h2 port=443
bad A 300.1.1.1
";
    no_alloc("zone-file reading", || {
        let mut zone = dnsbox::zone::ZoneReader::new(ZONE);
        let mut buf = [0u8; 1024];
        let (mut records, mut errors) = (0, 0);
        loop {
            match zone.next_record(&mut buf) {
                Ok(Some(rr)) => {
                    let mut text = StackText::new();
                    write!(text, "{rr}").unwrap();
                    rr.data().unwrap();
                    records += 1;
                }
                Ok(None) => break,
                Err(_) => errors += 1,
            }
        }
        assert_eq!((records, errors), (10, 1));
        let mut buf = [0u8; 64];
        let mx = <Mx<'_> as dnsbox::ParseRdataText>::from_text("10 mx.example.", &mut buf).unwrap();
        assert_eq!(mx.preference, 10);
    });
}
