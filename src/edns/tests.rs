//! Shared EDNS test helpers (`parse`, `compose_tlv`, `round_trip`) — reuse
//! them from the tests of option modules via `crate::edns::tests::*` — and
//! tests of the OPT record, its header, the message accessors and the
//! builder.

use super::*;
use crate::message::Message;
use crate::rdata::{ComposeRdata, RData};
use crate::wire::WireWriter;
use crate::{Class, Error, Flags, MessageBuilder, NameBuf, Rcode, Rtype, Section};
use std::string::{String, ToString};
use std::vec::Vec;

/// Parses `data` as the value of an option with code `code`.
pub(crate) fn parse(code: OptionCode, data: &[u8]) -> Result<EdnsOption<'_>> {
    EdnsOption::parse(code, WireReader::new(data))
}

/// Composes the value of `o` (without code and length).
pub(crate) fn compose<O: ComposeOption + ?Sized>(o: &O) -> Vec<u8> {
    let mut buf = std::vec![0u8; 70000];
    let mut w = WireWriter::new(&mut buf);
    o.compose_option(&mut w).unwrap();
    w.as_bytes().to_vec()
}

/// Composes the whole option (code, length, value).
pub(crate) fn compose_tlv<O: ComposeOption + ?Sized>(o: &O) -> Vec<u8> {
    let mut buf = std::vec![0u8; 70000];
    let mut w = WireWriter::new(&mut buf);
    o.compose_tlv(&mut w).unwrap();
    w.as_bytes().to_vec()
}

/// Parses `data` as a typed option of `code`, checks its presentation
/// format, that composing gives the same bytes back (also as a whole OPT
/// RDATA), and that every truncation fails or parses without panicking.
/// Returns the display string.
pub(crate) fn round_trip(code: OptionCode, data: &[u8], display: &str) -> String {
    let o = parse(code, data).unwrap();
    assert!(
        !matches!(o, EdnsOption::Unknown(_)),
        "{code} parsed as unknown"
    );
    assert_eq!(o.code(), code);
    assert_eq!(o.to_string(), display, "{code}");
    assert_eq!(compose(&o), data, "{code}");
    // Through a whole OPT RDATA, between two other options.
    let mut rdata = compose_tlv(&UnknownOption::new(OptionCode::new(65001), b"x"));
    rdata.extend_from_slice(&compose_tlv(&o));
    rdata.extend_from_slice(&compose_tlv(&Nsid::REQUEST));
    let opt = Opt::new(&rdata).unwrap();
    let all: Vec<_> = opt.options().collect::<Result<_>>().unwrap();
    assert_eq!(all.len(), 3);
    assert_eq!(all[1], o);
    assert_eq!(opt.find(code).unwrap().data, data);
    assert_eq!(opt.raw_options().nth(1).unwrap().to_string(), display);
    // Truncations must not panic.
    for end in 0..data.len() {
        let _ = parse(code, &data[..end]);
    }
    o.to_string()
}

#[test]
fn option_code_registry() {
    let all: Vec<_> = OptionCode::all().collect();
    for w in all.windows(2) {
        assert!(w[0].0 < w[1].0, "{:?} / {:?}", w[0], w[1]);
    }
    for (c, m) in OptionCode::all() {
        assert_eq!(m.parse::<OptionCode>(), Ok(c));
        assert_eq!(c.to_string(), m);
    }
    assert_eq!(all.len(), 27);
    assert_eq!("edns-client-subnet".parse(), Ok(OptionCode::ECS));
    assert_eq!("keepalive".parse(), Ok(OptionCode::TCP_KEEPALIVE));
    assert_eq!("opt3".parse(), Ok(OptionCode::NSID));
    assert_eq!("OPT".parse::<OptionCode>(), Err(Error::InvalidText));
    assert_eq!("bogus".parse::<OptionCode>(), Err(Error::UnknownMnemonic));
    assert_eq!(OptionCode::new(0).to_string(), "OPT0");
    assert!(OptionCode::new(65001).is_local_use() && !OptionCode::new(65535).is_local_use());
    assert!(EdnsOption::is_known(OptionCode::COOKIE));
    assert!(!EdnsOption::is_known(OptionCode::LLQ));
}

#[test]
fn opt_framing() {
    let rdata =
        b"\x00\x03\x00\x00\x00\x0a\x00\x08\x01\x02\x03\x04\x05\x06\x07\x08\xfd\xe9\x00\x01\xaa";
    let opt = Opt::new(rdata).unwrap();
    assert_eq!(opt.as_wire(), rdata);
    assert!(!opt.is_empty() && Opt::EMPTY.is_empty());
    let raw: Vec<_> = opt.raw_options().collect();
    assert_eq!(raw.len(), 3);
    assert_eq!(
        raw[0],
        RawOption {
            code: OptionCode::NSID,
            data: b""
        }
    );
    assert_eq!(raw[2].code, OptionCode::new(65001));
    assert_eq!(opt.to_string(), "NSID COOKIE=0102030405060708 OPT65001=AA");
    let cookie: Cookie<'_> = opt.get().unwrap().unwrap();
    assert_eq!(cookie.client(), [1, 2, 3, 4, 5, 6, 7, 8]);
    assert!(opt.get::<Padding<'_>>().is_none());
    assert_eq!(raw[0].parse_as::<Cookie<'_>>(), Err(Error::WrongType));
    assert!(opt.validate().is_ok());
    assert_eq!(
        raw[2].parse(),
        Ok(EdnsOption::Unknown(UnknownOption::new(
            OptionCode::new(65001),
            b"\xaa"
        )))
    );
    let mut buf = [0u8; 64];
    let mut w = WireWriter::new(&mut buf);
    opt.compose_rdata(&mut w).unwrap();
    assert_eq!(w.as_bytes(), rdata);
    assert_eq!(opt.rtype(), Rtype::OPT);

    // Every truncation inside an option is a framing error.
    for end in 1..rdata.len() {
        if [4, 16, 21].contains(&end) {
            assert!(Opt::new(&rdata[..end]).is_ok());
        } else {
            assert_eq!(Opt::new(&rdata[..end]), Err(Error::UnexpectedEof), "{end}");
        }
    }
    assert_eq!(Opt::new(b""), Ok(Opt::EMPTY));
}

#[test]
fn malformed_option_value_is_isolated() {
    // A keepalive of length 1 between two good options.
    let rdata = b"\x00\x03\x00\x00\x00\x0b\x00\x01\x05\x00\x0c\x00\x00";
    let opt = Opt::new(rdata).unwrap();
    let items: Vec<_> = opt.options().collect();
    assert_eq!(items.len(), 3);
    assert!(items[0].is_ok() && items[2].is_ok());
    assert_eq!(items[1], Err(Error::InvalidOption));
    assert_eq!(opt.validate(), Err(Error::InvalidOption));
    assert_eq!(opt.get::<TcpKeepalive>(), Some(Err(Error::InvalidOption)));
    // Display falls back to hex for the bad option.
    assert_eq!(opt.to_string(), "NSID TCP-KEEPALIVE=05 PADDING=0");
    // Trailing data inside a typed option is reported.
    assert_eq!(
        parse(OptionCode::EXPIRE, b""),
        Ok(EdnsOption::Expire(Expire::REQUEST))
    );
    assert_eq!(
        parse(OptionCode::NSID, b"abc").unwrap().code(),
        OptionCode::NSID
    );
}

#[test]
fn rdata_registry_dispatch() {
    let d = RData::parse(
        Rtype::OPT,
        Class::new(1232),
        WireReader::new(b"\x00\x03\x00\x00"),
    )
    .unwrap();
    let RData::Opt(opt) = d else { panic!("{d:?}") };
    assert_eq!(opt.raw_options().count(), 1);
    assert_eq!(d.to_string(), "NSID");
    // OPT is a meta type: empty RDATA in "class" NONE/ANY is still typed.
    let d = RData::parse(Rtype::OPT, Class::ANY, WireReader::new(b"")).unwrap();
    assert_eq!(d, RData::Opt(Opt::EMPTY));
    assert_eq!(
        RData::parse(Rtype::OPT, Class::IN, WireReader::new(b"\x00\x03\x00\x01")),
        Err(Error::UnexpectedEof)
    );
}

#[test]
fn header_fields() {
    let h = OptHeader::from_fields(Class::new(4096), 0x01_02_80_01);
    assert_eq!(h.udp_payload_size, 4096);
    assert_eq!(h.extended_rcode, 1);
    assert_eq!(h.version, 2);
    assert!(h.dnssec_ok());
    assert_eq!(h.flags.bits(), 0x8001);
    assert_eq!(h.ttl(), 0x01_02_80_01);
    assert_eq!(h.class(), Class::new(4096));
    assert_eq!(h.to_string(), "version: 2, flags: do 0x0001; udp: 4096");
    // Z bits survive toggling DO.
    let h2 = h.with_dnssec_ok(false);
    assert_eq!(h2.flags.bits(), 0x0001);
    assert_eq!(h2.with_dnssec_ok(true).ttl(), h.ttl());
    assert_eq!(
        h.rcode(Flags::default().with_rcode(Rcode::new(7))),
        Rcode::BADCOOKIE
    );
    let h3 = OptHeader::new(100)
        .with_rcode(Rcode::BADVERS)
        .with_version(1);
    assert_eq!((h3.extended_rcode, h3.version), (1, 1));
    assert_eq!(h3.effective_udp_payload_size(), 512);
    assert_eq!(OptHeader::new(1232).effective_udp_payload_size(), 1232);
    let f = EdnsFlags::default().with_compact_ok(true);
    assert!(f.compact_ok() && !f.dnssec_ok());
    assert_eq!(std::format!("{f:?}"), "EdnsFlags(co)");
    assert_eq!(EdnsFlags::from_bits(0).to_string(), "");
    let h4 = OptHeader::new(1232).with_flags(EdnsFlags::from_bits(0xc000));
    assert_eq!(h4.flags.to_string(), "do co");
    assert!(!f.with_compact_ok(false).compact_ok());
}

/// Builds a response with the given additional records pushed by `f`.
fn message_with(f: impl FnOnce(&mut MessageBuilder<WireWriter<'_>>)) -> Vec<u8> {
    let name: NameBuf = "example.com".parse().unwrap();
    let mut buf = [0u8; 1500];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.set_id(0xbeef);
    b.set_flags(Flags::default().with_qr(true));
    b.push_question(&name, Rtype::A, Class::IN).unwrap();
    f(&mut b);
    b.finish().to_vec()
}

#[test]
fn message_edns() {
    let wire = message_with(|_| {});
    let msg = Message::parse_validated(&wire).unwrap();
    assert!(msg.edns().unwrap().is_none());
    assert_eq!(msg.effective_rcode(), Ok(Rcode::NOERROR));

    let wire = message_with(|b| {
        b.set_flags(Flags::default().with_qr(true).with_rcode(Rcode::BADVERS));
        let h = OptHeader::new(1232)
            .with_rcode(Rcode::BADVERS)
            .with_dnssec_ok(true);
        b.push_edns(h, &(Nsid::new(b"ns1"), Expire::new(10)))
            .unwrap();
    });
    let msg = Message::parse_validated(&wire).unwrap();
    let edns = msg.edns().unwrap().unwrap();
    assert_eq!(edns.udp_payload_size(), 1232);
    assert_eq!((edns.extended_rcode(), edns.version()), (1, 0));
    assert!(edns.dnssec_ok() && edns.flags().dnssec_ok());
    assert_eq!(msg.flags().rcode(), Rcode::new(0));
    assert_eq!(msg.effective_rcode(), Ok(Rcode::BADVERS));
    assert_eq!(edns.rcode(msg.flags()), Rcode::BADVERS);
    assert_eq!(edns.header().ttl(), 0x0100_8000);
    assert_eq!(edns.get::<Nsid<'_>>(), Some(Ok(Nsid::new(b"ns1"))));
    assert_eq!(edns.raw_options().count(), 2);
    assert_eq!(edns.options().count(), 2);
    assert_eq!(
        edns.opt().find(OptionCode::EXPIRE).unwrap().data,
        [0, 0, 0, 10]
    );
    assert_eq!(
        edns.to_string(),
        "version: 0, flags: do; udp: 1232; NSID=6E7331 EXPIRE=10"
    );
    assert_eq!(edns.record().end(), wire.len());
    assert_eq!(
        msg.additional().next().unwrap().unwrap().to_string(),
        ". 16809984 CLASS1232 OPT NSID=6E7331 EXPIRE=10"
    );

    // Two OPT records.
    let wire = message_with(|b| {
        b.push_edns(OptHeader::new(1232), &()).unwrap();
        b.push_edns(OptHeader::new(512), &()).unwrap();
    });
    let msg = Message::parse_validated(&wire).unwrap();
    assert_eq!(msg.edns().unwrap_err(), Error::DuplicateOpt);
    assert_eq!(msg.effective_rcode(), Err(Error::DuplicateOpt));

    // Non-root owner.
    let wire = message_with(|b| {
        let owner: NameBuf = "x".parse().unwrap();
        b.push_additional(&owner, Class::new(1232), 0, &Opt::EMPTY)
            .unwrap();
    });
    let msg = Message::parse_validated(&wire).unwrap();
    assert_eq!(msg.edns().unwrap_err(), Error::OptNotRoot);

    // An OPT record outside the additional section (RFC 6891 §6.1.1), alone
    // or besides a proper one, is malformed, not "no EDNS".
    for section in [Section::Answer, Section::Authority] {
        for with_proper in [false, true] {
            let wire = message_with(|b| {
                b.push_record(
                    section,
                    crate::Name::ROOT,
                    Class::new(1232),
                    0x8000,
                    &Opt::EMPTY,
                )
                .unwrap();
                if with_proper {
                    b.push_edns(OptHeader::new(4096), &()).unwrap();
                }
            });
            let msg = Message::parse_validated(&wire).unwrap();
            assert_eq!(msg.edns().unwrap_err(), Error::MisplacedOpt, "{section:?}");
            assert_eq!(msg.effective_rcode(), Err(Error::MisplacedOpt));
            let mut buf = [0u8; 512];
            let mut b = MessageBuilder::new(&mut buf).unwrap();
            assert_eq!(b.start_response_edns(&msg, 1232), Err(Error::MisplacedOpt));
            assert_eq!((b.len(), b.reserve()), (12, 0));
        }
    }

    // OPT among other additional records; an A record is not an OPT.
    let wire = message_with(|b| {
        let rr = crate::rdata::A::new([192, 0, 2, 1].into());
        b.push_additional(crate::Name::ROOT, Class::IN, 0, &rr)
            .unwrap();
        b.push_edns(OptHeader::new(4096), &()).unwrap();
    });
    let msg = Message::parse_validated(&wire).unwrap();
    let edns = msg.edns().unwrap().unwrap();
    assert_eq!(edns.udp_payload_size(), 4096);
    assert_eq!(edns.to_string(), "version: 0, flags:; udp: 4096");
    let a = msg.additional().next().unwrap().unwrap();
    assert_eq!(Edns::from_record(&a).unwrap_err(), Error::WrongType);

    // A broken additional section is reported.
    let mut wire = message_with(|b| b.push_edns(OptHeader::new(1232), &()).unwrap());
    let n = wire.len();
    wire.truncate(n - 1);
    let msg = Message::parse(&wire).unwrap();
    assert_eq!(msg.edns().unwrap_err(), Error::UnexpectedEof);
}

#[test]
fn compose_options_shapes() {
    let mut buf = [0u8; 256];
    let mut w = WireWriter::new(&mut buf);
    // Slice and array of one type.
    [Nsid::REQUEST, Nsid::new(b"a")]
        .compose_options(&mut w)
        .unwrap();
    assert_eq!(w.as_bytes(), b"\x00\x03\x00\x00\x00\x03\x00\x01a");
    let mut w = WireWriter::new(&mut buf);
    let opts = [
        EdnsOption::Nsid(Nsid::REQUEST),
        EdnsOption::Unknown(UnknownOption::new(OptionCode::new(65002), b"zz")),
    ];
    opts[..].compose_options(&mut w).unwrap();
    assert_eq!(w.as_bytes(), b"\x00\x03\x00\x00\xfd\xea\x00\x02zz");
    // Echoing a parsed Opt, nested tuples, unit.
    let opt = Opt::new(b"\x00\x0c\x00\x01\x00").unwrap();
    let mut w = WireWriter::new(&mut buf);
    (opt, (), (Expire::REQUEST,))
        .compose_options(&mut w)
        .unwrap();
    assert_eq!(w.as_bytes(), b"\x00\x0c\x00\x01\x00\x00\x09\x00\x00");
    let mut w = WireWriter::new(&mut buf);
    let o = (
        Nsid::REQUEST,
        Expire::REQUEST,
        TcpKeepalive::REQUEST,
        ZoneVersion::Request,
        PaddingLen(0),
        Dau::new(&[13]),
        Dhu::new(&[2]),
        N3u::new(&[1]),
    );
    o.compose_options(&mut w).unwrap();
    assert_eq!(w.len(), 8 * 4 + 3);
    let mut w = WireWriter::new(&mut buf);
    OptData(&o).compose_rdata(&mut w).unwrap();
    assert_eq!(OptData(&o).rtype(), Rtype::OPT);
    let parsed = Opt::new(w.as_bytes()).unwrap();
    assert!(parsed.validate().is_ok());
    assert_eq!(parsed.options().count(), 8);
    // Values over 65535 bytes cannot be framed.
    let big = std::vec![0u8; 70000];
    let mut out = std::vec![0u8; 80000];
    let mut w = WireWriter::new(&mut out);
    assert_eq!(
        Nsid::new(&big).compose_tlv(&mut w),
        Err(Error::BufferTooSmall)
    );
    // A parsed EdnsOption re-composes through ComposeOption.
    let e = parse(OptionCode::EXPIRE, b"\x00\x00\x00\x05").unwrap();
    assert_eq!(compose_tlv(&e), b"\x00\x09\x00\x04\x00\x00\x00\x05");
}

#[test]
fn padding_policies() {
    use PaddingPolicy::*;
    const QUERY: PaddingPolicy = PaddingPolicy::QUERY;
    const RESPONSE: PaddingPolicy = PaddingPolicy::RESPONSE;
    assert_eq!(QUERY.padding_len(100, 1232), 28);
    assert_eq!(QUERY.padding_len(128, 1232), 0);
    assert_eq!(QUERY.padding_len(129, 1232), 127);
    assert_eq!(RESPONSE.padding_len(500, 1232), 436);
    // Capped at the limit.
    assert_eq!(RESPONSE.padding_len(500, 600), 100);
    assert_eq!(RESPONSE.padding_len(700, 600), 0);
    assert_eq!(BlockLength(0).padding_len(77, 512), 0);
    assert_eq!(Maximal.padding_len(100, 512), 412);
    assert_eq!(Maximal.padding_len(100, 100_000), 65535);
    assert_eq!(Fixed(9).padding_len(100, 50), 9);
}

#[test]
fn builder_padding() {
    let name: NameBuf = "example.com".parse().unwrap();
    for (policy, limit, expect) in [
        (PaddingPolicy::QUERY, 1232, 128),
        (PaddingPolicy::RESPONSE, 1232, 468),
        (PaddingPolicy::Maximal, 700, 700),
        (PaddingPolicy::RESPONSE, 300, 300),
        (PaddingPolicy::Fixed(3), 1232, 29 + 11 + 4 + 3),
    ] {
        let mut buf = [0u8; 1232];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.set_limit(limit);
        b.push_question(&name, Rtype::A, Class::IN).unwrap();
        b.push_edns_padded(OptHeader::new(1232), &(), policy)
            .unwrap();
        assert_eq!(b.len(), expect, "{policy:?}");
        let msg = Message::parse_validated(b.as_bytes()).unwrap();
        let edns = msg.edns().unwrap().unwrap();
        let pad: Padding<'_> = edns.get().unwrap().unwrap();
        assert!(pad.data.iter().all(|&b| b == 0));
    }

    // With other options, padding comes last and the size still matches.
    let mut buf = [0u8; 1232];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.push_question(&name, Rtype::A, Class::IN).unwrap();
    let chain: NameBuf = "com".parse().unwrap();
    let opts = (Cookie::client_only([9; 8]), Chain::new(chain.as_name()));
    b.push_edns_padded(OptHeader::new(1232), &opts, PaddingPolicy::QUERY)
        .unwrap();
    assert_eq!(b.len(), 128);
    let msg = Message::parse_validated(b.as_bytes()).unwrap();
    let codes: Vec<_> = msg
        .edns()
        .unwrap()
        .unwrap()
        .raw_options()
        .map(|o| o.code)
        .collect();
    assert_eq!(
        codes,
        [OptionCode::COOKIE, OptionCode::CHAIN, OptionCode::PADDING]
    );

    // No room for even the empty padding option: the push fails atomically.
    let mut buf = [0u8; 1232];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.set_limit(29 + 11 + 3);
    b.push_question(&name, Rtype::A, Class::IN).unwrap();
    let before = b.as_bytes().to_vec();
    assert_eq!(
        b.push_edns_padded(OptHeader::new(1232), &(), PaddingPolicy::QUERY),
        Err(Error::BufferTooSmall)
    );
    assert_eq!(
        b.push_edns_padded(OptHeader::new(1232), &(), PaddingPolicy::Fixed(500)),
        Err(Error::BufferTooSmall)
    );
    assert_eq!(b.as_bytes(), before);
    assert_eq!(b.header().arcount, 0);
    // ... but an unpadded OPT fits.
    b.push_edns(OptHeader::new(1232), &()).unwrap();
    assert_eq!(b.section(), Section::Additional);
}

/// Padding stops at the limit minus the reserve, so the room kept for a
/// TSIG / SIG(0) record (or the OPT echo) is never taken, and the push
/// does not fail for lack of it.
#[test]
fn builder_padding_respects_reserve() {
    use crate::rdata::Null;
    let name: NameBuf = "example.com".parse().unwrap();
    for (policy, expect) in [
        (PaddingPolicy::Maximal, 412),
        (PaddingPolicy::BlockLength(468), 412),
        (PaddingPolicy::QUERY, 128),
    ] {
        let mut buf = [0u8; 4096];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        b.set_limit(512);
        b.push_question(&name, Rtype::AAAA, Class::IN).unwrap();
        b.set_reserve(100);
        b.push_edns_padded(OptHeader::new(1232), &(), policy)
            .unwrap();
        assert_eq!(b.len(), expect, "{policy:?}");
        b.set_reserve(0);
        assert!(b.remaining() >= 100);
    }

    // A response sized past the last 468-octet block below the limit.
    let mut buf = [0u8; 1232];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.push_question(&name, Rtype::A, Class::IN).unwrap();
    b.push_record(
        Section::Answer,
        &name,
        Class::IN,
        0,
        &Null { data: &[0; 960] },
    )
    .unwrap();
    b.set_reserve(100);
    b.push_edns_padded(OptHeader::new(1232), &(), PaddingPolicy::RESPONSE)
        .unwrap();
    assert_eq!(b.len(), 1132);

    // The server flow: start_response_edns reserves room for the OPT echo.
    let mut qbuf = [0u8; 512];
    let mut q = MessageBuilder::query(&mut qbuf, 1, &name, Rtype::A, Class::IN).unwrap();
    q.push_edns(OptHeader::new(1232), &()).unwrap();
    let query = Message::parse(q.finish()).unwrap();
    for policy in [PaddingPolicy::Maximal, PaddingPolicy::RESPONSE] {
        let mut buf = [0u8; 468];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        let opt = b.start_response_edns(&query, 1232).unwrap().unwrap();
        b.push_edns_padded(opt, &(), policy).unwrap();
        assert_eq!(b.len(), 468 - OPT_RR_OVERHEAD, "{policy:?}");
        assert!(
            Message::parse_validated(b.as_bytes())
                .unwrap()
                .edns()
                .unwrap()
                .is_some()
        );
        // Giving back the OPT reserve pads up to the limit.
        let mut buf = [0u8; 468];
        let mut b = MessageBuilder::new(&mut buf).unwrap();
        let opt = b.start_response_edns(&query, 1232).unwrap().unwrap();
        b.set_reserve(b.reserve() - OPT_RR_OVERHEAD);
        b.push_edns_padded(opt, &(), policy).unwrap();
        assert_eq!(b.len(), 468, "{policy:?}");
    }
}

#[cfg(feature = "alloc")]
#[test]
fn vec_builder() {
    let name: NameBuf = "example.com".parse().unwrap();
    let mut b = MessageBuilder::new_vec();
    b.push_question(&name, Rtype::A, Class::IN).unwrap();
    b.push_edns_padded(OptHeader::new(1232), &Nsid::REQUEST, PaddingPolicy::QUERY)
        .unwrap();
    let wire = b.finish();
    assert_eq!(wire.len(), 128);
    assert!(
        Message::parse_validated(&wire)
            .unwrap()
            .edns()
            .unwrap()
            .is_some()
    );
}

/// Random mutations of a message with a rich OPT record must never make
/// the EDNS accessors panic.
#[test]
fn mutations_never_panic() {
    let wire = message_with(|b| {
        let chain: NameBuf = "example".parse().unwrap();
        let ecs = ClientSubnet::new([192, 0, 2, 0].into(), 24, 0).unwrap();
        let opts = (
            Nsid::REQUEST,
            Cookie::new([1; 8], &[2; 16]).unwrap(),
            ecs,
            ExtendedError::new(InfoCode::BLOCKED, b"no"),
            Chain::new(chain.as_name()),
            KeyTags(&[1, 2]),
            ZoneVersion::soa_serial(1, &[0, 0, 0, 1]),
            TcpKeepalive::new(5),
        );
        b.push_edns(OptHeader::new(1232), &opts).unwrap();
    });
    let msg = Message::parse_validated(&wire).unwrap();
    assert_eq!(msg.edns().unwrap().unwrap().options().count(), 8);
    assert!(msg.edns().unwrap().unwrap().opt().validate().is_ok());

    let exercise = |w: &[u8]| {
        let Ok(msg) = Message::parse(w) else { return };
        let _ = msg.effective_rcode();
        if let Ok(Some(edns)) = msg.edns() {
            for o in edns.options().flatten() {
                let _ = o.to_string();
                let _ = compose_tlv(&o);
            }
            let _ = edns.to_string();
        }
    };
    let mut seed = 0x1234_5678_u32;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        seed
    };
    for _ in 0..20_000 {
        let mut m = wire.clone();
        for _ in 0..1 + next() % 4 {
            let i = next() as usize % m.len();
            m[i] = next() as u8;
        }
        exercise(&m);
    }
    for end in 0..wire.len() {
        exercise(&wire[..end]);
    }
}

/// A query for example.com/A with the given OPT headers (none, one, two).
fn query_with(opts: &[OptHeader]) -> Vec<u8> {
    let name: NameBuf = "example.com".parse().unwrap();
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::query(&mut buf, 0x4242, &name, Rtype::A, Class::IN).unwrap();
    for h in opts {
        b.push_edns(*h, &()).unwrap();
    }
    b.finish().to_vec()
}

#[test]
fn response_edns_echo() {
    use crate::builder::{Outcome, Truncation};
    use crate::rdata::A;

    let name: NameBuf = "example.com".parse().unwrap();
    let addrs: Vec<A> = (0..60u8).map(|i| A::new([192, 0, 2, i].into())).collect();

    // No EDNS in the query: no OPT, no reserve.
    let wire = query_with(&[]);
    let q = Message::parse(&wire).unwrap();
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    assert_eq!(b.start_response_edns(&q, 1232), Ok(None));
    assert_eq!(b.reserve(), 0);

    // EDNS with DO: echoed; the reserve keeps room for the OPT record even
    // when the answer is truncated at a 512-byte limit (RFC 6891 §7).
    let wire = query_with(&[OptHeader::new(4096).with_dnssec_ok(true)]);
    let q = Message::parse(&wire).unwrap();
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.set_truncation(Truncation::SetTc);
    let opt = b.start_response_edns(&q, 1232).unwrap().unwrap();
    assert_eq!(opt, OptHeader::new(1232).with_dnssec_ok(true));
    assert_eq!(b.reserve(), OPT_RR_OVERHEAD);
    assert_eq!(
        b.push_rrset(Section::Answer, &name, Class::IN, 300, &addrs),
        Ok(Outcome::Truncated)
    );
    b.push_reserved_edns(opt, &()).unwrap();
    assert_eq!(b.reserve(), 0);
    let r = Message::parse_validated(b.finish()).unwrap();
    assert!(r.flags().tc() && r.flags().qr());
    assert_eq!(r.id(), 0x4242);
    let e = r.edns().unwrap().unwrap();
    assert!(e.dnssec_ok());
    assert_eq!((e.udp_payload_size(), e.version()), (1232, 0));

    // Options that do not fit in the reserve: error, reserve restored.
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    b.set_truncation(Truncation::SetTc);
    let opt = b.start_response_edns(&q, 1232).unwrap().unwrap();
    // Fill the answer one record at a time until it no longer fits.
    for a in &addrs {
        if b.push_rrset(Section::Answer, &name, Class::IN, 300, [a]) == Ok(Outcome::Truncated) {
            break;
        }
    }
    assert!(b.header().flags.tc());
    let big = Nsid::new(&[0u8; 64]);
    assert_eq!(b.push_reserved_edns(opt, &big), Err(Error::BufferTooSmall));
    assert_eq!(b.reserve(), OPT_RR_OVERHEAD);
    b.push_reserved_edns(opt, &()).unwrap();

    // EDNS version 1: BADVERS split between header and OPT.
    let wire = query_with(&[OptHeader::new(1232).with_version(1)]);
    let q = Message::parse(&wire).unwrap();
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    let opt = b.start_response_edns(&q, 1232).unwrap().unwrap();
    b.push_reserved_edns(opt, &()).unwrap();
    let r = Message::parse_validated(b.finish()).unwrap();
    assert_eq!(r.effective_rcode(), Ok(Rcode::BADVERS));
    assert_eq!(r.edns().unwrap().unwrap().version(), 0);

    // Two OPT records: error, builder untouched.
    let wire = query_with(&[OptHeader::new(1232), OptHeader::new(1232)]);
    let q = Message::parse(&wire).unwrap();
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::new(&mut buf).unwrap();
    assert_eq!(b.start_response_edns(&q, 1232), Err(Error::DuplicateOpt));
    assert_eq!((b.len(), b.reserve()), (12, 0));
    assert_eq!(b.header().id, 0);
}
