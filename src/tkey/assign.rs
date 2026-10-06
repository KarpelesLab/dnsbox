//! Server and resolver assigned keying (RFC 2930 §4.4, §4.5): keying
//! material encrypted under an RSA KEY (§6), through purecrypto (feature
//! `tkey`).

use alloc::vec::Vec;

use purecrypto::bignum::BoxedUint;
use purecrypto::rng::{CryptoRng, RngCore};
use purecrypto::rsa::{BoxedRsaPrivateKey, BoxedRsaPublicKey};
use purecrypto::zeroize::Zeroize;

use super::exchange::check_answer;
use super::{
    KeyGrant, SharedKey, atomic, build_query_with_key, build_response, find_answer, find_request,
    keys,
};
use crate::builder::MessageBuilder;
use crate::dnssec::RsaPublicKey;
use crate::message::{Message, Section};
use crate::name::{Name, ToName};
use crate::rdata::{Key, Tkey, TkeyMode, TsigRcode};
use crate::wire::OutBuf;
use crate::{Class, Error, Result};

/// The most RSA blocks one TKEY key data field may hold (RFC 2930 §6:
/// keying material longer than a block is "included" in further blocks).
/// Decrypting a block is a private-key operation, so this bounds the
/// work a message can ask for: real keying material (at most a few dozen
/// octets, §6: "usually less than 256 bits") fits one block.
pub const MAX_ENCRYPTED_BLOCKS: usize = 4;

/// RSA modulus sizes accepted for encryption, in bits (1024 is the
/// smallest RSAES-PKCS1-v1_5 key purecrypto and current guidance accept;
/// 4096 bounds the work, as for DNSSEC signatures).
const MIN_RSA_BITS: usize = 1024;
const MAX_RSA_BITS: usize = 4096;
/// The largest public exponent accepted, in octets (256 bits, the FIPS
/// 186-5 bound; real keys use 3 or 65537).
const MAX_RSA_EXPONENT_LEN: usize = 32;
/// RFC 2535 §3.1.2: the key type bit that prohibits use for
/// confidentiality (also set in "no key" KEYs).
const NO_CONFIDENTIALITY: u16 = 0x4000;
/// RSAES-PKCS1-v1_5 overhead per block (RFC 8017 §7.2.1).
const PKCS1_OVERHEAD: usize = 11;

/// The RSA public key of `key`, if it may encrypt (RFC 2930 §6).
fn encryption_key(key: &Key<'_>) -> Result<BoxedRsaPublicKey> {
    if !key.algorithm.is_rsa() {
        return Err(Error::UnsupportedAlgorithm);
    }
    if key.flags & NO_CONFIDENTIALITY != 0 {
        return Err(Error::InvalidKey);
    }
    let rsa = RsaPublicKey::from_dnskey(key.public_key)?;
    if !(MIN_RSA_BITS..=MAX_RSA_BITS).contains(&rsa.modulus_bits())
        || rsa.exponent.len() > MAX_RSA_EXPONENT_LEN
    {
        return Err(Error::InvalidKey);
    }
    let n = BoxedUint::from_be_bytes(rsa.modulus);
    let e = BoxedUint::from_be_bytes(rsa.exponent);
    if !n.is_odd() || !e.is_odd() || e.bit_len() < 2 || !e.lt(&n) {
        return Err(Error::InvalidKey);
    }
    Ok(BoxedRsaPublicKey::new(n, e))
}

/// The public key field of an RSA KEY record for `private` (RFC 3110 §2:
/// exponent length, exponent, modulus), to publish or send with a TKEY
/// query; any RSA algorithm number (e.g. RSASHA256) describes it.
///
/// # Errors
///
/// [`Error::InvalidKey`] if the key's exponent is longer than 65535
/// octets.
///
/// ```
/// use dnsbox::dnssec::{Algorithm, RsaPublicKey};
/// use dnsbox::rdata::Key;
/// use dnsbox::tkey::purecrypto::{bignum::BoxedUint, rsa::BoxedRsaPrivateKey};
/// use dnsbox::tkey::rsa_public_key;
///
/// // A toy key (n = 3233 = 61 * 53, e = 17, d = 413); real ones come
/// // from `BoxedRsaPrivateKey::generate` or a key file.
/// let private = BoxedRsaPrivateKey::from_components(
///     BoxedUint::from_u64(3233), BoxedUint::from_u64(17), BoxedUint::from_u64(413));
/// let public = rsa_public_key(&private)?;
/// assert_eq!(public, [1, 17, 0x0c, 0xa1]);
/// let key = Key::new(0x0200, 3, Algorithm::RSASHA256, &public);
/// assert_eq!(RsaPublicKey::from_dnskey(key.public_key)?.modulus, [0x0c, 0xa1]);
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn rsa_public_key(private: &BoxedRsaPrivateKey) -> Result<Vec<u8>> {
    let public = private.public_key();
    let (n, e) = (public.modulus(), public.exponent());
    let modulus = n.to_be_bytes(n.bit_len().div_ceil(8));
    let exponent = e.to_be_bytes(e.bit_len().div_ceil(8));
    let key = RsaPublicKey {
        exponent: &exponent,
        modulus: &modulus,
    };
    let mut out = Vec::with_capacity(key.wire_len());
    key.compose(&mut out)?;
    Ok(out)
}

/// Encrypts keying material under an RSA KEY (RFC 2930 §6): with
/// RSAES-PKCS1-v1_5 (RFC 8017 §7.2), in as many blocks as it needs (each
/// one modulus long, carrying up to the modulus length minus 11 octets).
/// The result is the key data of a server assigned (§4.4) or resolver
/// assigned (§4.5) TKEY record. `rng` must be a cryptographically secure
/// generator.
///
/// # Errors
///
/// [`Error::UnsupportedAlgorithm`] if `key` is not an RSA KEY,
/// [`Error::InvalidKey`] if its flags prohibit encryption (RFC 2535
/// §3.1.2), it is malformed or its modulus is not 1024 to 4096 bits,
/// [`Error::InvalidTkey`] for empty keying material, and
/// [`Error::LimitExceeded`] if it needs more than
/// [`MAX_ENCRYPTED_BLOCKS`] blocks.
///
/// ```
/// use dnsbox::dnssec::Algorithm;
/// use dnsbox::rdata::Key;
/// use dnsbox::tkey::purecrypto::{bignum::BoxedUint, hash::Sha256, rng::HmacDrbg, rsa::BoxedRsaPrivateKey};
/// use dnsbox::tkey::{decrypt_keying_material, encrypt_keying_material, rsa_public_key};
///
/// let mut rng = HmacDrbg::<Sha256>::new(b"example seed", b"", b"");
/// let private = BoxedRsaPrivateKey::generate(1024, BoxedUint::from_u64(65537), &mut rng, 0);
/// let public = rsa_public_key(&private)?;
/// let key = Key::new(0x0200, 3, Algorithm::RSASHA256, &public);
/// let data = encrypt_keying_material(&key, b"0123456789abcdef", &mut rng)?;
/// assert_eq!(data.len(), 128);
/// assert_eq!(decrypt_keying_material(&private, &data)?, b"0123456789abcdef");
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn encrypt_keying_material<R: RngCore + CryptoRng>(
    key: &Key<'_>,
    material: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    let public = encryption_key(key)?;
    let k = public.modulus().bit_len().div_ceil(8);
    let chunk = k.saturating_sub(PKCS1_OVERHEAD).max(1);
    if material.is_empty() {
        return Err(Error::InvalidTkey);
    }
    if material.len().div_ceil(chunk) > MAX_ENCRYPTED_BLOCKS {
        return Err(Error::LimitExceeded);
    }
    let mut out = Vec::with_capacity(material.len().div_ceil(chunk) * k);
    for block in material.chunks(chunk) {
        let c = public
            .encrypt_pkcs1v15(block, rng)
            .map_err(|_| Error::InvalidKey)?;
        out.extend_from_slice(&c);
    }
    Ok(out)
}

/// Decrypts keying material encrypted under the RSA KEY of `private`
/// (RFC 2930 §6, the inverse of [`encrypt_keying_material`]): the key
/// data must be one or more blocks of exactly the modulus length, at most
/// [`MAX_ENCRYPTED_BLOCKS`] of them.
///
/// Blocks with invalid padding do not fail: they decrypt to pseudo-random
/// octets (purecrypto's implicit rejection), so that answers cannot serve
/// as a Bleichenbacher padding oracle. A wrong key is then noticed when
/// the first message signed with it fails to verify.
///
/// # Errors
///
/// [`Error::InvalidTkey`] if the data is empty or not a whole number of
/// blocks, or decrypts to nothing, and [`Error::LimitExceeded`] for more
/// than [`MAX_ENCRYPTED_BLOCKS`] blocks.
///
/// ```
/// use dnsbox::tkey::purecrypto::{bignum::BoxedUint, hash::Sha256, rng::HmacDrbg, rsa::BoxedRsaPrivateKey};
/// use dnsbox::tkey::{decrypt_keying_material, MAX_ENCRYPTED_BLOCKS};
/// use dnsbox::Error;
///
/// let mut rng = HmacDrbg::<Sha256>::new(b"example seed", b"", b"");
/// let private = BoxedRsaPrivateKey::generate(1024, BoxedUint::from_u64(65537), &mut rng, 0);
/// assert_eq!(decrypt_keying_material(&private, &[1; 100]), Err(Error::InvalidTkey));
/// let many = vec![1; 128 * (MAX_ENCRYPTED_BLOCKS + 1)];
/// assert_eq!(decrypt_keying_material(&private, &many), Err(Error::LimitExceeded));
/// // Garbage of the right length "decrypts" to something.
/// assert!(decrypt_keying_material(&private, &[1; 128]).is_ok());
/// ```
pub fn decrypt_keying_material(private: &BoxedRsaPrivateKey, data: &[u8]) -> Result<Vec<u8>> {
    let k = private.modulus().bit_len().div_ceil(8);
    if k == 0 || data.is_empty() || !data.len().is_multiple_of(k) {
        return Err(Error::InvalidTkey);
    }
    if data.len() / k > MAX_ENCRYPTED_BLOCKS {
        return Err(Error::LimitExceeded);
    }
    let mut out = Vec::new();
    for block in data.chunks(k) {
        let mut m = private
            .decrypt_pkcs1v15_implicit(block)
            .map_err(|_| Error::InvalidTkey)?;
        out.extend_from_slice(&m);
        m.zeroize();
    }
    if out.is_empty() {
        return Err(Error::InvalidTkey);
    }
    Ok(out)
}

/// The server side of server assigned keying (RFC 2930 §4.4): reads the
/// TKEY request of `query` ([`find_request`], mode SERVER-ASSIGNMENT),
/// encrypts `secret` under the first RSA KEY of its additional section
/// ([`encrypt_keying_material`]), and writes the response into an empty
/// builder: the TKEY record (owner `grant.key_name`, the requested
/// algorithm, `grant`'s validity, the encrypted secret as key data) in the
/// answer section and the resolver's KEY echoed in the additional section.
/// Returns the established key; sign the response afterwards (§3).
///
/// `secret` is the keying material, from a cryptographically secure
/// generator (16 to 32 octets for HMAC; §4.4 recommends mixing in the key
/// data of the request, which adds nothing to secure randomness). The
/// resolver's KEY MUST be authenticated (§4.4), through the query's TSIG
/// or SIG(0) signature, which the caller checks first.
///
/// # Errors
///
/// [`Error::InvalidTkey`] if the query is not a server assignment request
/// or has no RSA KEY (answer FORMERR), the errors of
/// [`encrypt_keying_material`] for an unusable KEY (answer BADKEY), and
/// the builder's errors; on any error the builder is left unchanged.
///
/// ```
/// use dnsbox::dnssec::Algorithm;
/// use dnsbox::rdata::{Key, Tkey, TkeyMode};
/// use dnsbox::tkey::purecrypto::{bignum::BoxedUint, hash::Sha256, rng::HmacDrbg, rsa::BoxedRsaPrivateKey};
/// use dnsbox::tkey::{self, KeyGrant};
/// use dnsbox::{Message, MessageBuilder, NameBuf};
///
/// let mut rng = HmacDrbg::<Sha256>::new(b"example seed", b"", b"");
/// let resolver = BoxedRsaPrivateKey::generate(1024, BoxedUint::from_u64(65537), &mut rng, 0);
/// let public = tkey::rsa_public_key(&resolver)?;
/// let (requested, owner, alg): (NameBuf, NameBuf, NameBuf) =
///     ("k1.resolver.example".parse()?, "resolver.example".parse()?, "hmac-sha256".parse()?);
///
/// // Resolver: ask for a key, sending the KEY to encrypt it to.
/// let request = Tkey::new(alg.as_name(), 1_700_000_000, 1_700_086_400, TkeyMode::SERVER_ASSIGNMENT, &[]);
/// let mut q = MessageBuilder::new_vec();
/// tkey::build_query_with_key(&mut q, &requested, &request, &owner, &Key::new(0x0200, 3, Algorithm::RSASHA256, &public))?;
/// let query = q.finish();
///
/// // Server: assign a key under a name of its own.
/// let assigned: NameBuf = "89n3mdgx072pp.server.example".parse()?;
/// let mut r = MessageBuilder::new_vec();
/// let grant = KeyGrant::new(assigned.as_name(), 1_700_000_000, 1_700_043_200);
/// let server_key = tkey::respond_server_assigned(&mut r, &Message::parse(&query)?, &grant, &[0x37; 32], &mut rng)?;
/// let response = r.finish();
///
/// // Resolver: decrypt it.
/// let key = tkey::server_assigned_key(&Message::parse(&query)?, &Message::parse(&response)?, &resolver)?;
/// assert_eq!((key.name(), key.secret()), (assigned.as_name(), server_key.secret()));
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn respond_server_assigned<B: OutBuf, R: RngCore + CryptoRng>(
    b: &mut MessageBuilder<B>,
    query: &Message<'_>,
    grant: &KeyGrant<'_>,
    secret: &[u8],
    rng: &mut R,
) -> Result<SharedKey> {
    let request = find_request(query)?;
    if request.data.mode != TkeyMode::SERVER_ASSIGNMENT {
        return Err(Error::InvalidTkey);
    }
    let (owner, key) = first_rsa_key(query)?.ok_or(Error::InvalidTkey)?;
    let mut data = encrypt_keying_material(&key, secret, rng)?;
    let reply = Tkey {
        algorithm: request.data.algorithm,
        inception: grant.inception,
        expiration: grant.expiration,
        mode: TkeyMode::SERVER_ASSIGNMENT,
        error: TsigRcode::NOERROR,
        key: &data,
        other: &[],
    };
    let res = atomic(b, |b| {
        build_response(b, query, grant.key_name, &reply)?;
        b.push_additional(owner, Class::ANY, 0, &key)
    });
    data.zeroize();
    res?;
    Ok(SharedKey::new(
        grant.key_name,
        request.data.algorithm,
        grant.inception,
        grant.expiration,
        secret,
    ))
}

/// The first KEY of the additional section of `query` with an RSA
/// algorithm.
fn first_rsa_key<'a>(query: &Message<'a>) -> Result<Option<(Name<'a>, Key<'a>)>> {
    for item in keys(query, Section::Additional) {
        let (owner, key) = item?;
        if key.algorithm.is_rsa() {
            return Ok(Some((owner, key)));
        }
    }
    Ok(None)
}

/// The resolver side of server assigned keying (RFC 2930 §4.4): given the
/// query the resolver sent (with the KEY of `private`) and the server's
/// response, checks the answer's TKEY record ([`find_answer`]: mode
/// SERVER-ASSIGNMENT, error NOERROR, the requested algorithm) and
/// decrypts its key data with `private`
/// ([`decrypt_keying_material`]). The key is named by the answer's owner
/// (the name the server assigned) and valid for the period it answered.
/// Verify the response's signature first (§3).
///
/// # Errors
///
/// [`Error::ErrorResponse`] if the server refused (an error RCODE or TKEY
/// error), [`Error::InvalidTkey`] if either message is not a server
/// assignment exchange or the key data does not decrypt, and the errors
/// of [`decrypt_keying_material`].
///
/// ```
/// use dnsbox::rdata::{Key, Tkey, TkeyMode, TsigRcode};
/// use dnsbox::tkey::purecrypto::{bignum::BoxedUint, hash::Sha256, rng::HmacDrbg, rsa::BoxedRsaPrivateKey};
/// use dnsbox::tkey;
/// use dnsbox::{Error, Message, MessageBuilder, Name, NameBuf};
///
/// let mut rng = HmacDrbg::<Sha256>::new(b"example seed", b"", b"");
/// let resolver = BoxedRsaPrivateKey::generate(1024, BoxedUint::from_u64(65537), &mut rng, 0);
/// let name: NameBuf = "k.example".parse()?;
/// let request = Tkey::new(Name::ROOT, 0, 0, TkeyMode::SERVER_ASSIGNMENT, &[]);
/// let mut q = MessageBuilder::new_vec();
/// tkey::build_query(&mut q, &name, &request)?;
/// let query = q.finish();
/// let query = Message::parse(&query)?;
/// // The server found no KEY and refused.
/// let mut r = MessageBuilder::new_vec();
/// tkey::build_response(&mut r, &query, &name, &request.with_error(TsigRcode::BADKEY))?;
/// let response = r.finish();
/// let refused = tkey::server_assigned_key(&query, &Message::parse(&response)?, &resolver);
/// assert_eq!(refused.unwrap_err(), Error::ErrorResponse);
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn server_assigned_key(
    query: &Message<'_>,
    response: &Message<'_>,
    private: &BoxedRsaPrivateKey,
) -> Result<SharedKey> {
    let request = find_request(query)?;
    let answer = find_answer(response)?;
    check_answer(&request.data, &answer.data, TkeyMode::SERVER_ASSIGNMENT)?;
    let secret = decrypt_keying_material(private, answer.data.key)?;
    Ok(SharedKey::from_secret(
        answer.key_name,
        answer.data.algorithm,
        answer.data.inception,
        answer.data.expiration,
        secret,
    ))
}

/// Writes a resolver assigned keying query into an empty builder (RFC
/// 2930 §4.5): `secret` (the keying material the resolver chose, from a
/// cryptographically secure generator) encrypted under the server's RSA
/// KEY `server_key` ([`encrypt_keying_material`]) as the key data of a
/// TKEY record built from `request` (algorithm, validity; mode
/// RESOLVER-ASSIGNMENT), and `server_key`, owned by `server_key_owner`,
/// in the additional section ([`build_query_with_key`]). The query MUST
/// then be signed with TSIG or SIG(0) (§4.5). Use a globally unique key
/// name (§4.5).
///
/// # Errors
///
/// [`Error::InvalidTkey`] if `request` has another mode, the errors of
/// [`encrypt_keying_material`] and of [`build_query_with_key`]; on any
/// error the builder is left unchanged.
///
/// ```
/// use dnsbox::dnssec::Algorithm;
/// use dnsbox::rdata::{Key, Tkey, TkeyMode};
/// use dnsbox::tkey::purecrypto::{bignum::BoxedUint, hash::Sha256, rng::HmacDrbg, rsa::BoxedRsaPrivateKey};
/// use dnsbox::tkey;
/// use dnsbox::{Message, MessageBuilder, NameBuf};
///
/// let mut rng = HmacDrbg::<Sha256>::new(b"example seed", b"", b"");
/// // The server's key, which the resolver knows from its KEY record.
/// let server = BoxedRsaPrivateKey::generate(1024, BoxedUint::from_u64(65537), &mut rng, 0);
/// let public = tkey::rsa_public_key(&server)?;
/// let server_key = Key::new(0x0200, 3, Algorithm::RSASHA256, &public);
/// let (key_name, server_owner, alg): (NameBuf, NameBuf, NameBuf) =
///     ("6d1f2a.resolver.example".parse()?, "server.example".parse()?, "hmac-sha256".parse()?);
///
/// // Resolver: choose the key and send it (then sign the query).
/// let secret = [0x29; 32];
/// let request = Tkey::new(alg.as_name(), 1_700_000_000, 1_700_086_400, TkeyMode::RESOLVER_ASSIGNMENT, &[]);
/// let mut q = MessageBuilder::new_vec();
/// tkey::build_resolver_assigned_query(&mut q, &key_name, &request, &server_owner, &server_key, &secret, &mut rng)?;
/// let query = q.finish();
///
/// // Server: after verifying the query's signature, accept the key.
/// let mut r = MessageBuilder::new_vec();
/// let accepted = tkey::accept_resolver_assigned(&mut r, &Message::parse(&query)?, &server, 1_700_000_000, 1_700_043_200)?;
/// assert_eq!(accepted.secret(), secret);
/// let response = r.finish();
///
/// // Resolver: the server agreed, for the period it answered.
/// let key = tkey::resolver_assigned_key(&Message::parse(&query)?, &Message::parse(&response)?, &secret)?;
/// assert_eq!((key.name(), key.expiration()), (key_name.as_name(), 1_700_043_200));
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn build_resolver_assigned_query<B: OutBuf, R: RngCore + CryptoRng>(
    b: &mut MessageBuilder<B>,
    key_name: impl ToName,
    request: &Tkey<'_>,
    server_key_owner: impl ToName,
    server_key: &Key<'_>,
    secret: &[u8],
    rng: &mut R,
) -> Result<()> {
    if request.mode != TkeyMode::RESOLVER_ASSIGNMENT {
        return Err(Error::InvalidTkey);
    }
    let mut data = encrypt_keying_material(server_key, secret, rng)?;
    let tkey = Tkey {
        key: &data,
        ..*request
    };
    let res = build_query_with_key(b, key_name, &tkey, server_key_owner, server_key);
    data.zeroize();
    res
}

/// The server side of resolver assigned keying (RFC 2930 §4.5): reads
/// the TKEY request of `query` ([`find_request`], mode
/// RESOLVER-ASSIGNMENT), checks that its additional section carries the
/// KEY of `private` (the server's own RSA key, compared by its public
/// key), decrypts the keying material ([`decrypt_keying_material`]) and
/// writes the response into an empty builder: the TKEY record (the
/// request's key name and algorithm, the validity from `inception` to
/// `expiration`, no key data) in the answer section and the KEY echoed in
/// the additional section. Returns the established key; sign the response
/// afterwards (§3).
///
/// The query MUST be authenticated with TSIG or SIG(0) (§4.5: otherwise
/// anyone could plant a key), which the caller checks first, and the
/// caller refuses key names it already holds (BADNAME). The validity
/// should not exceed the one requested (§4.5: the server "can return a
/// lesser time interval").
///
/// # Errors
///
/// [`Error::InvalidTkey`] if the query is not a resolver assignment
/// request, has no KEY, or its key data is not a whole number of blocks
/// (answer FORMERR), [`Error::BadKey`] if no KEY is the server's (answer
/// BADKEY), [`Error::LimitExceeded`] for more than
/// [`MAX_ENCRYPTED_BLOCKS`] blocks, the errors of [`rsa_public_key`] and
/// the builder's errors; on any error the builder is left unchanged.
///
/// ```
/// use dnsbox::dnssec::Algorithm;
/// use dnsbox::rdata::{Key, Tkey, TkeyMode};
/// use dnsbox::tkey::purecrypto::{bignum::BoxedUint, hash::Sha256, rng::HmacDrbg, rsa::BoxedRsaPrivateKey};
/// use dnsbox::tkey;
/// use dnsbox::{Error, Message, MessageBuilder, Name, NameBuf};
///
/// let mut rng = HmacDrbg::<Sha256>::new(b"example seed", b"", b"");
/// let server = BoxedRsaPrivateKey::generate(1024, BoxedUint::from_u64(65537), &mut rng, 0);
/// let other = BoxedRsaPrivateKey::generate(1024, BoxedUint::from_u64(65537), &mut rng, 0);
/// let public = tkey::rsa_public_key(&other)?;
/// let name: NameBuf = "k.example".parse()?;
/// let request = Tkey::new(Name::ROOT, 0, 0, TkeyMode::RESOLVER_ASSIGNMENT, &[]);
/// let mut q = MessageBuilder::new_vec();
/// let other_key = Key::new(0x0200, 3, Algorithm::RSASHA256, &public);
/// tkey::build_resolver_assigned_query(&mut q, &name, &request, &name, &other_key, &[1; 16], &mut rng)?;
/// let query = q.finish();
/// // Encrypted to a key that is not the server's.
/// let mut r = MessageBuilder::new_vec();
/// let res = tkey::accept_resolver_assigned(&mut r, &Message::parse(&query)?, &server, 0, 0);
/// assert_eq!(res.unwrap_err(), Error::BadKey);
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn accept_resolver_assigned<B: OutBuf>(
    b: &mut MessageBuilder<B>,
    query: &Message<'_>,
    private: &BoxedRsaPrivateKey,
    inception: u32,
    expiration: u32,
) -> Result<SharedKey> {
    let request = find_request(query)?;
    if request.data.mode != TkeyMode::RESOLVER_ASSIGNMENT {
        return Err(Error::InvalidTkey);
    }
    let ours = rsa_public_key(private)?;
    let ours = RsaPublicKey::from_dnskey(&ours)?;
    let mut any = false;
    let mut found = None;
    for item in keys(query, Section::Additional) {
        let (owner, key) = item?;
        any = true;
        // Compared as numbers: the exponent length may be written in
        // either of the RFC 3110 forms.
        let same = RsaPublicKey::from_dnskey(key.public_key)
            .is_ok_and(|k| k.exponent == ours.exponent && k.modulus == ours.modulus);
        if key.algorithm.is_rsa() && same {
            found = Some((owner, key));
            break;
        }
    }
    let (owner, key) = match found {
        Some(k) => k,
        None if any => return Err(Error::BadKey),
        None => return Err(Error::InvalidTkey),
    };
    let secret = decrypt_keying_material(private, request.data.key)?;
    let reply = Tkey {
        algorithm: request.data.algorithm,
        inception,
        expiration,
        mode: TkeyMode::RESOLVER_ASSIGNMENT,
        error: TsigRcode::NOERROR,
        key: &[],
        other: &[],
    };
    atomic(b, |b| {
        build_response(b, query, request.key_name, &reply)?;
        b.push_additional(owner, Class::ANY, 0, &key)
    })?;
    Ok(SharedKey::from_secret(
        request.key_name,
        request.data.algorithm,
        inception,
        expiration,
        secret,
    ))
}

/// The resolver side of resolver assigned keying (RFC 2930 §4.5): given
/// the query the resolver sent ([`build_resolver_assigned_query`]), the
/// server's response and the `secret` the resolver assigned, checks the
/// answer's TKEY record ([`find_answer`]: mode RESOLVER-ASSIGNMENT, error
/// NOERROR, the requested key name and algorithm) and returns the key,
/// valid for the period the server answered. Verify the response's
/// signature first (§3).
///
/// # Errors
///
/// [`Error::ErrorResponse`] if the server refused (an error RCODE or TKEY
/// error), [`Error::InvalidTkey`] if either message is not a resolver
/// assignment exchange for the same key, or the parse error of a
/// malformed message.
///
/// ```
/// use dnsbox::rdata::{Tkey, TkeyMode};
/// use dnsbox::tkey;
/// use dnsbox::{Error, Message, MessageBuilder, Name, NameBuf};
///
/// let (name, other): (NameBuf, NameBuf) = ("k.example".parse()?, "other.example".parse()?);
/// let request = Tkey::new(Name::ROOT, 0, 100, TkeyMode::RESOLVER_ASSIGNMENT, &[0; 128]);
/// let mut q = MessageBuilder::new_vec();
/// tkey::build_query(&mut q, &name, &request)?;
/// let query = q.finish();
/// let query = Message::parse(&query)?;
/// // A response about another key is not an answer.
/// let mut r = MessageBuilder::new_vec();
/// tkey::build_response(&mut r, &query, &other, &Tkey { key: &[], ..request })?;
/// let response = r.finish();
/// let res = tkey::resolver_assigned_key(&query, &Message::parse(&response)?, &[1; 16]);
/// assert_eq!(res.unwrap_err(), Error::InvalidTkey);
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub fn resolver_assigned_key(
    query: &Message<'_>,
    response: &Message<'_>,
    secret: &[u8],
) -> Result<SharedKey> {
    let request = find_request(query)?;
    let answer = find_answer(response)?;
    check_answer(&request.data, &answer.data, TkeyMode::RESOLVER_ASSIGNMENT)?;
    if answer.key_name != request.key_name {
        return Err(Error::InvalidTkey);
    }
    Ok(SharedKey::new(
        answer.key_name,
        answer.data.algorithm,
        answer.data.inception,
        answer.data.expiration,
        secret,
    ))
}
