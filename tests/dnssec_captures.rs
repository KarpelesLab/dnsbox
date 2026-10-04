//! Real DNSSEC responses, captured from 1.1.1.1 over TCP with the DO bit
//! set on 2026-10-04 (Unix time 1791105383): the root DNSKEY RRset
//! (RSASHA256, KSK 20326), cloudflare.com (ECDSAP256SHA256), ed25519.nl
//! (ED25519) and ed448.nl (ED448) DNSKEY RRsets, and the ed25519.nl SOA.
//! Every RRSIG is verified with the purecrypto backend, and tampering,
//! time and case variations are checked.

#![cfg(feature = "dnssec")]

use dnsbox::dnssec::{
    Algorithm, DigestType, PurecryptoVerifier, RecordRdata, Rrset, ZoneKey, verify_ds, verify_rrsig,
};
use dnsbox::rdata::{Dnskey, Ds, Rrsig};
use dnsbox::{Error, Message, NameBuf, Rtype};

/// The capture time.
const NOW: u32 = 1_791_105_383;

const ROOT_DNSKEY: usize = 0;
const CLOUDFLARE_DNSKEY: usize = 1;
const ED25519_DNSKEY: usize = 2;
const ED448_DNSKEY: usize = 3;
const ED25519_SOA: usize = 4;

const CAPTURES: [&str; 5] = [
    // . DNSKEY
    "d00081a000010005000000010000300001000030000100000cca01080100030803010001ca2b37135cf6dd2e7b565e9c\
         f8d5311ba3950d982c1274a51ff85cc8c76f2f6faf4ddc4711522a75a9c5e8393cbdfce03f557aa752d5b8eb1b24ec1e\
         da1a8332373625c577cb231cc3a7671bb9a69ffe501220eed6ac62054c31d52233562efdcfaddf4775430fefe8d60b36\
         73a7cb04eee87b9487b635b1946afc665caf12c43571d0a322a93ab3abf11dfea9deb02baf48281f3464166d917f6b74\
         4a8a264fb26178c4673674ce4005b6198d802ade02853d3d5954eba7723ac68b8dfdf02949549bd48d38ab3eb4ae8bb9\
         29916caebed53fed3da45a301484bafd86eaf5df9c9d6ec8c6c6beda519ff60372f4e3ae9e83cc4e97c85e3841dc09de\
         82b1e1e9000030000100000cca01080100030803010001e0980fa67b5962952deb96828c0a3fede0f86b357272caabb6\
         b709a431429bfc6dfb85548d169c6df7a9a487fccc3d2018227eb7737f85d8fc340b9f2049f4c7da3b2016b846849982\
         7e1903e2c1555fb2d1b0480d4c71f14952db5382ad87baeef8280461b40f303e8fcddd7732610b4d873faa08ce4d05bd\
         de731fe76b0eac61a6fd2f14ba7f6714d2ad37fbe04fe4ab3451e7fc58909aff58b309813ebcc930a25b55fad10d6b78\
         695e267b8e57bfc5d81a66b3e2e591a6c8b548df88355d562b365b0209398dbc54087f35b949315016c4298b3733c859\
         fdaf72f34b1c4f08dc1d9421bce1b111d0199dc2a6c5e936a7bfe17130e6afada8648f8c08cb99000030000100000cca\
         01080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177\
         fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1\
         550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff\
         11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb\
         8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e79\
         2ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b5000030000100000cca01080101030803010001af7a8d\
         eba49d995a792aefc80263e991efdbc86138a931deb2c65d5682eab5d3b03738e3dfdc89d96da64c86c0224d9ce02514\
         d285da3068b19054e5e787b2969058e98e12566c8c808c40c0b769e1db1a24a1bd9b31e303184a31fc7bb56b85bbba8a\
         bc02cd5040a444a36d47695969849e16ad856bb58e8fac8855224400319bdab224d83fc0e66aab32ff74bfeaf0f91c45\
         4e6850a1295207bbd4cdde8f6ffb08faa9755c2e3284efa01f99393e18786cb132f1e66ebc6517318e1ce8a3b7337ebb\
         54d035ab57d9706ecd9350d4afacd825e43c8668eece89819caf6817af62dc4fbd82f0e33f6647b2b6bda175f14607f5\
         9f4635451e6b27df282ef73d8700002e000100000cca0113003008000002a3006ad952006abda2804f660001118e9810\
         f22e4af9a10751e4e6887a8781b62d4a5845ff2d8fe36654515f01747f479165a963169c95285b99333a5a7d2615b3b7\
         8b3988d5c96277884367e00121bd7f6268a996bb75e94925740fa6e1bf90fa6e4e0654f27b3464e703696be1f0bd96af\
         540f590ad50de3609b31652a108231310c17f3c10530d5e60b2cf3e2ed341ffb3035c1a907cb69a45a75f5f9b283cab4\
         3fa79adae1f828fcfbbb178ec55ea459109f8af68fd3c00fa7267dd1312e9d3da4b8e844414961c878903342f35010b2\
         38a406dd569ddddcddf74760b93315fa914ccd92ef02b725c662e9128bd2caf464f79eb1fd3bdeed0c00ead35cfbf1a3\
         e78e5fba84b4e03248aea700002904d0000080000000",
    // cloudflare.com DNSKEY
    "d00181a000010003000000010a636c6f7564666c61726503636f6d0000300001c00c00300001000007d300440100030d\
         a09311112cf9138818cd2feae970ebbd4d6a30f6088c25b325a39abbc5cd1197aa098283e5aaf421177c2aa5d714992a\
         9957d1bcc18f98cd71f1f1806b65e148c00c00300001000007d300440101030d99db2cc14cabdc33d6d77da63a2f15f7\
         1112584f234e8d1dc428e39e8a4a97e1aa271a555dc90701e17e2a4c4b6f120b7c32d44f4ac02bd894cf2d4be7778a19\
         c00c002e0001000007d3006200300d0200000e106afe81496aae15c909430a636c6f7564666c61726503636f6d00793c\
         02f36147ba059893adcc435401ddda425451c96cf75e229ad109058dc28e4a5e5a1d2da52315a5e8a616a62a3bfa5769\
         e32133ef877d3f27e62c0cdbd6f900002904d0000080000000",
    // ed25519.nl DNSKEY
    "d00281a000010003000000010765643235353139026e6c0000300001c00c0030000100000e1000240100030fdadb2d64\
         08e09a50d378f9f43555eb0070499a0f382e8685571ccb9756a78c62c00c0030000100000e1000240101030f9b53442c\
         b55540a9787c7567fca29d78d3b43eb60a193dc819b62c793f1770aac00c002e000100000e10005e00300f0200000e10\
         6ad017806ab46800b1cb0765643235353139026e6c00b1eddae71a1737ea54080602ec8af279343cb2bed51afa918702\
         e892658fff42f39aa9400f6d439b91aa08b18fc60674ccb7b7661615c784e9c278325ad2610600002904d00000800000\
         00",
    // ed448.nl DNSKEY
    "d00381800001000200000001056564343438026e6c0000300001c00c0030000100000708003d01010310f296058d3ba6\
         eb52f493eabc1e222410f8a94d36ee62765c78c55326fa8c65b859770ce99226074411dc5719a73a9d5126c1b2b7a234\
         9b2380c00c002e000100000708008e00301002000007086ad017806ab468005fa0056564343438026e6c00fc0523b715\
         2db7363257fd88117bfddb07954a87bb5c3b4caa75f7ab0e43137fb0a04955de3cb81173fbead61149491c587ba00d0a\
         7b7aea0098ada082e2c71355cef67158eb87eb681d0ebc91b3da226a05ae5640180635ba501b45afeb58fa1dfa38ccc9\
         396380386924a303c5641a210000002904d0000080000031000f002d00016e6f20737570706f7274656420444e534b45\
         5920616c676f726974686d20666f722065643434382e6e6c2e",
    // ed25519.nl SOA
    "d00481a000010002000000010765643235353139026e6c0000060001c00c0006000100000e100032056d616e676f0670\
         6c65786973026575000a686f73746d6173746572c02e78c3d58500002a3000000e1000093a8000000e10c00c002e0001\
         00000e10005e00060f0200000e106ad017806ab468006c0e0765643235353139026e6c0044f48acd5a31652d498506f5\
         72743ecd3bd44d7f9bb1c751fb94a156ee0a72820013dee0d04d8ad65bc10cdce8b740aea056b33bb8e9ff100a2900a7\
         a8eae10100002904d0000080000000",
];

fn hex(s: &str) -> Vec<u8> {
    let d: Vec<u8> = s
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| (b as char).to_digit(16).unwrap() as u8)
        .collect();
    d.chunks(2).map(|p| p[0] << 4 | p[1]).collect()
}

fn capture(i: usize) -> Vec<u8> {
    hex(CAPTURES[i])
}

/// The DNSKEYs in the answer section of `msg`, with their owners.
fn keys(msg: &[u8]) -> Vec<(NameBuf, Dnskey<'_>)> {
    let Ok(msg) = Message::parse(msg) else {
        return Vec::new();
    };
    msg.answers()
        .filter_map(Result::ok)
        .filter_map(|rr| Some((rr.name().to_buf(), rr.data_as::<Dnskey<'_>>().ok()?)))
        .collect()
}

/// Verifies every RRSIG of the answer section of `msg` with the matching
/// key from `keys_msg`, returning the verified (type covered, key tag)
/// pairs.
fn verify_answers(msg: &[u8], keys_msg: &[u8], now: u32) -> Result<Vec<(Rtype, u16)>, Error> {
    let keys = keys(keys_msg);
    let msg = Message::parse(msg)?;
    let mut done = Vec::new();
    let mut scratch = Vec::new();
    for rr in msg.answers() {
        let rr = rr?;
        let Ok(rrsig) = rr.data_as::<Rrsig<'_>>() else {
            continue;
        };
        let (owner, dnskey) = keys
            .iter()
            .find(|(_, k)| k.key_tag() == rrsig.key_tag && k.algorithm == rrsig.algorithm)
            .ok_or(Error::KeyMismatch)?;
        let key = ZoneKey::new(owner.as_name(), *dnskey);
        let records = msg
            .answers()
            .filter_map(Result::ok)
            .filter(|r| r.rtype() == rrsig.type_covered && r.name() == rr.name())
            .map(RecordRdata);
        let rrset = Rrset::new(rr.name(), rr.class(), records);
        verify_rrsig(&PurecryptoVerifier, &key, &rrsig, rrset, now, &mut scratch)?;
        assert!(scratch.is_empty());
        done.push((rrsig.type_covered, rrsig.key_tag));
    }
    if done.is_empty() {
        return Err(Error::RrsetMismatch);
    }
    Ok(done)
}

#[test]
fn every_signature_verifies() {
    for (msg, keys_msg, alg) in [
        (ROOT_DNSKEY, ROOT_DNSKEY, Algorithm::RSASHA256),
        (
            CLOUDFLARE_DNSKEY,
            CLOUDFLARE_DNSKEY,
            Algorithm::ECDSAP256SHA256,
        ),
        (ED25519_DNSKEY, ED25519_DNSKEY, Algorithm::ED25519),
        (ED448_DNSKEY, ED448_DNSKEY, Algorithm::ED448),
        (ED25519_SOA, ED25519_DNSKEY, Algorithm::ED25519),
    ] {
        let (m, k) = (capture(msg), capture(keys_msg));
        Message::parse_validated(&m).unwrap();
        let done = verify_answers(&m, &k, NOW).unwrap_or_else(|e| panic!("capture {msg}: {e}"));
        assert!(!done.is_empty(), "capture {msg}");
        assert!(keys(&k).iter().all(|(_, key)| key.algorithm == alg));
    }
}

#[test]
fn root_trust_anchor() {
    let m = capture(ROOT_DNSKEY);
    let keys = keys(&m);
    let (owner, ksk) = keys.iter().find(|(_, k)| k.key_tag() == 20326).unwrap();
    assert!(owner.is_root() && ksk.is_sep() && ksk.is_zone_key());
    // The IANA root trust anchor (KSK-2017).
    let digest = hex("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D");
    let ds = Ds::new(20326, Algorithm::RSASHA256, DigestType::SHA256, &digest);
    assert_eq!(verify_ds(&ds, owner.as_name(), ksk), Ok(()));
    let signed = verify_answers(&m, &m, NOW).unwrap();
    assert!(signed.contains(&(Rtype::DNSKEY, 20326)));
}

#[test]
fn time_window() {
    let m = capture(ED25519_SOA);
    let k = capture(ED25519_DNSKEY);
    let msg = Message::parse(&m).unwrap();
    let rrsig: Rrsig<'_> = msg
        .answers()
        .map(Result::unwrap)
        .find_map(|rr| rr.data_as().ok())
        .unwrap();
    assert!(verify_answers(&m, &k, rrsig.inception).is_ok());
    assert!(verify_answers(&m, &k, rrsig.expiration).is_ok());
    assert_eq!(
        verify_answers(&m, &k, rrsig.inception.wrapping_sub(1)),
        Err(Error::SignatureNotYetValid)
    );
    assert_eq!(
        verify_answers(&m, &k, rrsig.expiration.wrapping_add(1)),
        Err(Error::SignatureExpired)
    );
}

#[test]
fn owner_case_does_not_matter() {
    // Uppercase the question name the answers point to: owner names and the
    // SOA's compressed RDATA names change case, the signature still holds
    // (RFC 4034 §6.2).
    let mut m = capture(ED25519_SOA);
    for b in &mut m[13..23] {
        b.make_ascii_uppercase();
    }
    let k = capture(ED25519_DNSKEY);
    let msg = Message::parse(&m).unwrap();
    let q = msg.questions().next().unwrap().unwrap();
    assert_eq!(q.name().to_string(), "ED25519.NL.");
    assert!(verify_answers(&m, &k, NOW).is_ok());
}

#[test]
fn tampering_is_detected() {
    for (msg, keys_msg) in [
        (ROOT_DNSKEY, ROOT_DNSKEY),
        (CLOUDFLARE_DNSKEY, CLOUDFLARE_DNSKEY),
        (ED448_DNSKEY, ED448_DNSKEY),
        (ED25519_SOA, ED25519_DNSKEY),
    ] {
        let m = capture(msg);
        let k = capture(keys_msg);
        let parsed = Message::parse(&m).unwrap();
        let answers: Vec<_> = parsed.answers().map(Result::unwrap).collect();
        // Flip one bit in every RDATA byte of every answer record:
        // verification must fail (never panic).
        for rr in &answers {
            for i in rr.rdata_range() {
                let mut bad = m.clone();
                bad[i] ^= 0x01;
                let keys_src = if msg == keys_msg {
                    bad.clone()
                } else {
                    k.clone()
                };
                let r = verify_answers(&bad, &keys_src, NOW);
                assert!(
                    r.is_err(),
                    "capture {msg}: byte {i} of {} not covered",
                    rr.rtype()
                );
            }
        }
    }
}
