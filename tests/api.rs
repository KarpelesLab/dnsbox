//! Public API conventions (Rust API Guidelines) that the type system can
//! check: thread safety (C-SEND-SYNC), iteration by reference (C-ITER),
//! `Display` / `FromStr` pairs and the common traits (C-COMMON-TRAITS).

use dnsbox::builder::{Checkpoint, Outcome, Truncation};
use dnsbox::charstr::{CharStr, CharStrs};
use dnsbox::dnssec::{
    Algorithm, BogusReason, ClosestEncloser, Denial, DenialStatus, DigestType, InsecureReason,
    Nsec3Hash, Nsec3HashAlgorithm, Nsec3Limits, Nsec3Record, NsecRecord, RsaPublicKey, Timestamp,
    Verified, ZoneKey,
};
use dnsbox::edns::{
    Cookie, Dau, Edns, EdnsFlags, EdnsOption, InfoCode, Opt, OptHeader, OptionCode, PaddingPolicy,
    ServerCookie,
};
use dnsbox::message::{AllRecords, Questions, Records};
use dnsbox::name::Labels;
use dnsbox::rdata::{
    Apl, HipServers, SvcParamKey, SvcParams, SvcbBuilder, TypeBitmap, UnknownRdata,
};
use dnsbox::sig0::{Sig0Record, Validity};
use dnsbox::tcp::{FrameReassembler, Frames};
use dnsbox::tkey::TkeyRecord;
use dnsbox::tsig::{MacBuf, TsigAlgorithm, TsigRecord};
use dnsbox::update::{UpdateBuilder, UpdateMessage};
use dnsbox::xfr::{XfrEvent, XfrProcessor, XfrStyle};
use dnsbox::zone::{Entry, Include, Scanner, Token, ZoneError, ZoneReader, ZoneRecord};
use dnsbox::{
    Class, Error, Flags, Header, Label, Message, MessageBuilder, Name, NameBuf, NameEncoding,
    Opcode, Question, RData, Rcode, Record, Rtype, Section, WireReader, WireWriter,
};

fn send_sync<T: Send + Sync>() {}

/// Every public type is `Send` and `Sync` (views hold only shared borrows;
/// builders own or exclusively borrow their buffers).
#[test]
fn send_and_sync() {
    send_sync::<Error>();
    send_sync::<ZoneError>();
    send_sync::<Message<'static>>();
    send_sync::<Question<'static>>();
    send_sync::<Record<'static>>();
    send_sync::<Questions<'static>>();
    send_sync::<Records<'static>>();
    send_sync::<AllRecords<'static>>();
    send_sync::<Header>();
    send_sync::<Flags>();
    send_sync::<Opcode>();
    send_sync::<Rcode>();
    send_sync::<Rtype>();
    send_sync::<Class>();
    send_sync::<Section>();
    send_sync::<Name<'static>>();
    send_sync::<NameBuf>();
    send_sync::<Label<'static>>();
    send_sync::<Labels<'static>>();
    send_sync::<CharStr<'static>>();
    send_sync::<CharStrs<'static>>();
    send_sync::<RData<'static>>();
    send_sync::<UnknownRdata<'static>>();
    send_sync::<SvcParams<'static>>();
    send_sync::<SvcbBuilder<'static>>();
    send_sync::<EdnsOption<'static>>();
    send_sync::<Opt<'static>>();
    send_sync::<Edns<'static>>();
    send_sync::<OptHeader>();
    send_sync::<WireReader<'static>>();
    send_sync::<WireWriter<'static>>();
    send_sync::<NameEncoding>();
    send_sync::<MessageBuilder<WireWriter<'static>>>();
    send_sync::<Checkpoint>();
    send_sync::<Outcome>();
    send_sync::<UpdateBuilder<WireWriter<'static>>>();
    send_sync::<UpdateMessage<'static>>();
    send_sync::<XfrProcessor>();
    send_sync::<XfrEvent<'static>>();
    send_sync::<FrameReassembler<'static>>();
    send_sync::<Frames<'static>>();
    send_sync::<TsigRecord<'static>>();
    send_sync::<TkeyRecord<'static>>();
    send_sync::<MacBuf>();
    send_sync::<Sig0Record<'static>>();
    send_sync::<ZoneKey<'static>>();
    send_sync::<Verified>();
    send_sync::<DenialStatus>();
    send_sync::<ClosestEncloser<'static>>();
    send_sync::<NsecRecord<'static>>();
    send_sync::<Nsec3Record<'static>>();
    send_sync::<ZoneReader<'static>>();
    send_sync::<ZoneRecord<'static>>();
    send_sync::<Entry<'static, 'static>>();
    send_sync::<Include<'static>>();
    send_sync::<Scanner<'static>>();
    send_sync::<Token<'static>>();
    #[cfg(feature = "alloc")]
    {
        send_sync::<MessageBuilder<Vec<u8>>>();
        send_sync::<dnsbox::OwnedMessage>();
        send_sync::<dnsbox::OwnedRecord>();
        send_sync::<dnsbox::OwnedRData>();
        send_sync::<dnsbox::zone::ZoneRecordBuf>();
        send_sync::<dnsbox::dnssec::ZoneCollation>();
    }
    #[cfg(feature = "dnssec")]
    {
        send_sync::<dnsbox::dnssec::SigningKey>();
        send_sync::<dnsbox::dnssec::PurecryptoVerifier>();
    }
    #[cfg(feature = "tsig")]
    send_sync::<dnsbox::tsig::HmacKey<'static>>();
}

fn common<T: Clone + core::fmt::Debug + PartialEq + Eq + core::hash::Hash>() {}
fn registry<T>()
where
    T: Copy
        + core::fmt::Debug
        + core::fmt::Display
        + core::str::FromStr<Err = Error>
        + Default
        + Eq
        + Ord
        + core::hash::Hash,
{
}

/// Value types implement the common traits; protocol registries also
/// order, default and parse back their `Display` form.
#[test]
fn common_traits() {
    registry::<Rtype>();
    registry::<Class>();
    registry::<Opcode>();
    registry::<Rcode>();
    registry::<OptionCode>();
    registry::<InfoCode>();
    registry::<SvcParamKey>();
    registry::<Algorithm>();
    registry::<DigestType>();
    registry::<Nsec3HashAlgorithm>();
    common::<Error>();
    common::<Header>();
    common::<Flags>();
    common::<EdnsFlags>();
    common::<OptHeader>();
    common::<Section>();
    common::<NameBuf>();
    common::<Name<'static>>();
    common::<Truncation>();
    common::<Outcome>();
    common::<PaddingPolicy>();
    common::<Cookie<'static>>();
    common::<ServerCookie>();
    common::<Nsec3Hash>();
    common::<Nsec3Limits>();
    common::<Timestamp>();
    common::<RsaPublicKey<'static>>();
    common::<Denial>();
    common::<BogusReason>();
    common::<InsecureReason>();
    common::<Validity>();
    common::<XfrStyle>();
    common::<TsigAlgorithm>();
    common::<ZoneError>();
}

#[test]
fn display_from_str_pairs() {
    for v in [0u16, 1, 6, 15] {
        let op = Opcode::new(v as u8);
        assert_eq!(op.to_string().parse::<Opcode>(), Ok(op));
    }
    for v in [0u16, 3, 16, 23, 4095] {
        let rc = Rcode::new(v);
        assert_eq!(rc.to_string().parse::<Rcode>(), Ok(rc));
    }
    let name: NameBuf = "www.example.com.".parse().unwrap();
    assert_eq!(name.to_string().parse::<NameBuf>(), Ok(name));
    let ts: Timestamp = "20240101000000".parse().unwrap();
    assert_eq!(ts.to_string().parse::<Timestamp>(), Ok(ts));
    let names: Vec<String> = Section::ALL.iter().map(|s| s.to_string()).collect();
    assert_eq!(names, ["QUESTION", "ANSWER", "AUTHORITY", "ADDITIONAL"]);
}

/// Collection-like views iterate by value and by reference.
#[test]
fn iterate_by_reference() {
    let strs = CharStrs::new(b"\x01a\x02bc").unwrap();
    let by_ref: Vec<&[u8]> = (&strs).into_iter().map(|s| s.as_bytes()).collect();
    let by_val: Vec<&[u8]> = strs.into_iter().map(|s| s.as_bytes()).collect();
    assert_eq!(by_ref, [&b"a"[..], b"bc"]);
    assert_eq!(by_ref, by_val);

    let bitmap = TypeBitmap::new(b"\x00\x01\x40").unwrap();
    for t in &bitmap {
        assert_eq!(t, Rtype::A);
    }

    let dau = Dau::new(&[8, 13]);
    assert_eq!((&dau).into_iter().collect::<Vec<_>>(), [8, 13]);

    let apl = Apl::from_wire(b"\x00\x01\x18\x03\xc0\x00\x02").unwrap();
    assert_eq!((&apl).into_iter().count(), 1);

    let servers = HipServers::new(b"\x03rvs\x07example\x00").unwrap();
    assert_eq!((&servers).into_iter().count(), 1);

    let params = SvcParams::new(b"\x00\x03\x00\x02\x01\xbb").unwrap();
    assert_eq!((&params).into_iter().count(), 1);
}
