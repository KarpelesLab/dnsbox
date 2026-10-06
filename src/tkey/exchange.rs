//! Diffie-Hellman exchanged keying (RFC 2930 §4.1) and the established
//! key, through purecrypto (feature `tkey`).

use alloc::vec::Vec;
use core::fmt;

use purecrypto::bignum::BoxedUint;
use purecrypto::dh;
use purecrypto::hash::{Digest, Md5};
use purecrypto::rng::{CryptoRng, RngCore};
use purecrypto::zeroize::Zeroize;

use super::dh::trim;
use super::{
    DhKey, DhPrime, atomic, build_query_with_key, build_response, find_answer, find_request, keys,
    well_known_prime,
};
use crate::builder::MessageBuilder;
use crate::dnssec::Algorithm;
use crate::message::{Message, Section};
use crate::name::{Name, NameBuf, ToName};
use crate::rdata::{Key, Tkey, TkeyMode, TsigRcode};
use crate::tsig::{HmacKey, TsigAlgorithm};
use crate::wire::OutBuf;
use crate::{Class, Error, Result};

/// The KEY flags dnsbox writes for its Diffie-Hellman keys: a key for a
/// host or other end entity (RFC 2535 §3.1.2, name type 10), usable for
/// authentication and confidentiality, as BIND's `dnssec-keygen -n HOST`
/// writes them.
const HOST_KEY_FLAGS: u16 = 0x0200;

/// The KEY protocol octet (RFC 2535 §3.1.3: 3, DNSSEC).
const PROTOCOL_DNSSEC: u8 = 3;

/// The private exponent size for a group of `bits` (RFC 7919 Appendix A,
/// as purecrypto sizes the RFC 3526 groups).
const fn private_bits(bits: usize) -> usize {
    if bits <= 2048 {
        256
    } else if bits <= 3072 {
        288
    } else if bits <= 4096 {
        384
    } else {
        512
    }
}

/// A Diffie-Hellman group (a prime `p` and a generator `g`) for TKEY
/// exchanged keying (RFC 2930 §4.1, RFC 2539).
///
/// Both parties must use the same group: a server answers BADKEY to a
/// KEY in another group. A group is either one of the well-known groups
/// of RFC 2539 Appendix A, written as an index in the KEY record
/// ([`well_known`](Self::well_known)), or written out in full
/// ([`rfc3526`](Self::rfc3526), [`explicit`](Self::explicit)).
///
/// The well-known groups have 768, 1024 and 1536-bit primes, which no
/// longer resist well-funded attackers (the 1024-bit discrete logarithm
/// is within reach of nation states, and precomputation for these widely
/// shared primes pays off); they are what BIND used. Prefer an RFC 3526
/// group of 2048 bits or more when the peer accepts explicit groups.
///
/// ```
/// use dnsbox::tkey::DhGroup;
///
/// let g2 = DhGroup::well_known(2)?;
/// assert_eq!((g2.bits(), g2.well_known_index()), (1024, Some(2)));
/// let g14 = DhGroup::rfc3526(14)?;
/// assert_eq!((g14.bits(), g14.well_known_index(), g14.generator()), (2048, None, &[2][..]));
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone)]
pub struct DhGroup {
    /// The prime, without leading zero octets.
    prime: Vec<u8>,
    /// The generator, without leading zero octets.
    generator: Vec<u8>,
    /// The well-known index the group is written as, if any.
    index: Option<u16>,
    inner: dh::DhGroup,
}

impl DhGroup {
    /// A well-known group (RFC 2539 Appendix A): 1 (768-bit prime), 2
    /// (1024-bit prime) or BIND's 3 (the 1536-bit prime of RFC 3526 §2),
    /// all with generator 2. Its KEY records carry the index, not the
    /// prime. See [`well_known_prime`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKey`] for another index.
    ///
    /// ```
    /// use dnsbox::tkey::DhGroup;
    /// use dnsbox::Error;
    ///
    /// assert_eq!(DhGroup::well_known(1)?.bits(), 768);
    /// assert_eq!(DhGroup::well_known(7).unwrap_err(), Error::InvalidKey);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn well_known(index: u16) -> Result<Self> {
        let prime = well_known_prime(index).ok_or(Error::InvalidKey)?;
        let bits = prime.len() * 8;
        // The tables hold the RFC's safe primes (checked in the tests),
        // so the expensive validation of `from_custom` is not needed.
        let inner = dh::DhGroup::from_custom_unchecked(
            BoxedUint::from_be_bytes(prime),
            BoxedUint::from_u64(2),
            private_bits(bits),
        )
        .map_err(|_| Error::InvalidKey)?;
        Ok(DhGroup {
            prime: prime.to_vec(),
            generator: alloc::vec![2],
            index: Some(index),
            inner,
        })
    }

    /// One of the MODP groups of RFC 3526 (14: 2048 bits, 15: 3072, 16:
    /// 4096, 17: 6144, 18: 8192; generator 2), written out in full in the
    /// KEY record.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKey`] for another group number.
    ///
    /// ```
    /// use dnsbox::tkey::DhGroup;
    ///
    /// assert_eq!(DhGroup::rfc3526(16)?.bits(), 4096);
    /// assert!(DhGroup::rfc3526(5).is_err()); // as well-known group 3 instead
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn rfc3526(group: u8) -> Result<Self> {
        let inner = match group {
            14 => dh::group14(),
            15 => dh::group15(),
            16 => dh::group16(),
            17 => dh::group17(),
            18 => dh::group18(),
            _ => return Err(Error::InvalidKey),
        };
        Ok(DhGroup {
            prime: inner.p().to_be_bytes(inner.byte_size()),
            generator: alloc::vec![2],
            index: None,
            inner,
        })
    }

    /// A group of the caller's choosing, written out in full in the KEY
    /// record (as BIND writes the groups `dnssec-keygen -a DH` generates).
    /// The group is validated by purecrypto: a safe prime of 2048 to 16384
    /// bits and a generator of large order. That costs a few hundred
    /// milliseconds for 2048 bits and seconds for 8192, so build it once
    /// from configuration; never from a peer's KEY (an exchange only
    /// compares the peer's group with the local one).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKey`] if the group fails validation.
    ///
    /// ```
    /// use dnsbox::tkey::{DhGroup, well_known_prime};
    /// use dnsbox::Error;
    ///
    /// // Below 2048 bits, explicit groups are refused.
    /// let p = well_known_prime(2).unwrap();
    /// assert_eq!(DhGroup::explicit(p, &[2]).unwrap_err(), Error::InvalidKey);
    /// ```
    pub fn explicit(prime: &[u8], generator: &[u8]) -> Result<Self> {
        let (prime, generator) = (trim(prime), trim(generator));
        let bits = prime.len() * 8;
        if bits > dh::DhGroup::MAX_CUSTOM_GROUP_BITS || generator.len() > prime.len() {
            return Err(Error::InvalidKey);
        }
        let inner = dh::DhGroup::from_custom(
            BoxedUint::from_be_bytes(prime),
            BoxedUint::from_be_bytes(generator),
            private_bits(bits),
        )
        .map_err(|_| Error::InvalidKey)?;
        Ok(DhGroup {
            prime: prime.to_vec(),
            generator: generator.to_vec(),
            index: None,
            inner,
        })
    }

    /// The size of the prime in bits.
    ///
    /// ```
    /// assert_eq!(dnsbox::tkey::DhGroup::well_known(3)?.bits(), 1536);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn bits(&self) -> usize {
        self.inner.bit_size()
    }

    /// The well-known index the group's KEY records carry, or `None` for
    /// a group written out in full.
    ///
    /// ```
    /// assert_eq!(dnsbox::tkey::DhGroup::well_known(2)?.well_known_index(), Some(2));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub const fn well_known_index(&self) -> Option<u16> {
        self.index
    }

    /// The prime, most significant octet first, without leading zeros.
    ///
    /// ```
    /// use dnsbox::tkey::{DhGroup, well_known_prime};
    ///
    /// assert_eq!(DhGroup::well_known(1)?.prime(), well_known_prime(1).unwrap());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn prime(&self) -> &[u8] {
        &self.prime
    }

    /// The generator, most significant octet first, without leading
    /// zeros.
    ///
    /// ```
    /// assert_eq!(dnsbox::tkey::DhGroup::well_known(1)?.generator(), [2]);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn generator(&self) -> &[u8] {
        &self.generator
    }

    /// Whether `key` is in this group (equal prime and generator, however
    /// the key writes them; see [`DhKey::same_group`]).
    ///
    /// ```
    /// use dnsbox::tkey::{DhGroup, DhKey, DhPrime, well_known_prime};
    ///
    /// let group = DhGroup::well_known(2)?;
    /// let explicit = DhKey { prime: DhPrime::Explicit(well_known_prime(2).unwrap()), generator: &[2], public_value: &[5] };
    /// let other = DhKey { prime: DhPrime::WellKnown(1), generator: &[], public_value: &[5] };
    /// assert!(group.contains(&explicit) && !group.contains(&other));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn contains(&self, key: &DhKey<'_>) -> bool {
        key.group()
            .is_some_and(|(p, g)| trim(p) == self.prime && trim(g) == self.generator)
    }

    /// How KEY records write this group.
    fn key_prime(&self) -> (DhPrime<'_>, &[u8]) {
        match self.index {
            Some(i) => (DhPrime::WellKnown(i), &[]),
            None => (DhPrime::Explicit(&self.prime), &self.generator),
        }
    }
}

impl fmt::Debug for DhGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DhGroup")
            .field("bits", &self.bits())
            .field("well_known_index", &self.index)
            .finish_non_exhaustive()
    }
}

/// Mixes a Diffie-Hellman result with the two TKEY nonces into the
/// keying material (RFC 2930 §4.1):
///
/// ```text
/// keying material = XOR ( DH value, MD5 ( query data | DH value ) |
///                                   MD5 ( server data | DH value ) )
/// ```
///
/// `dh_value` is the shared secret `g^(xy) mod p` as an unsigned integer
/// without leading zero octets (as BIND computed it), `query_data` and
/// `server_data` the key data of the query's and the response's TKEY
/// records. The shorter operand of the XOR is padded with zero octets on
/// the right, so the result is as long as the longer one (the DH value,
/// for every group of more than 256 bits). The result is the TSIG secret.
///
/// ```
/// use dnsbox::tkey::dh_keying_material;
///
/// // Short DH values are padded to the 32 octets of the two digests.
/// let k = dh_keying_material(&[0xff], b"q", b"s");
/// assert_eq!(k.len(), 32);
/// assert_eq!(dh_keying_material(&[7; 128], b"q", b"s").len(), 128);
/// ```
#[must_use]
pub fn dh_keying_material(dh_value: &[u8], query_data: &[u8], server_data: &[u8]) -> Vec<u8> {
    let digest = |nonce: &[u8]| {
        let mut h = Md5::new();
        h.update(nonce);
        h.update(dh_value);
        h.finalize()
    };
    let (q, s) = (digest(query_data), digest(server_data));
    let mut out = alloc::vec![0u8; dh_value.len().max(32)];
    for (o, d) in out.iter_mut().zip(dh_value) {
        *o = *d;
    }
    for (o, d) in out.iter_mut().zip(q.iter().chain(s.iter())) {
        *o ^= *d;
    }
    out
}

/// A Diffie-Hellman key pair for TKEY exchanged keying (RFC 2930 §4.1):
/// the private exponent and the public KEY record (RFC 2539).
///
/// A resolver generates one per exchange, sends its KEY with the query
/// ([`build_query`](Self::build_query)) and derives the TSIG key from the
/// response ([`complete`](Self::complete)). A server keeps one (its
/// published DH KEY) and answers queries in its group
/// ([`respond`](Self::respond)). Either side computes at most one
/// Diffie-Hellman result per call, whatever the message holds, and the
/// group is never taken from the peer.
///
/// Both messages must be authenticated with TSIG or SIG(0) under keys the
/// parties already share (RFC 2930 §3): sign after building and verify
/// before calling [`respond`](Self::respond) or
/// [`complete`](Self::complete).
///
/// ```
/// use dnsbox::tkey::purecrypto::{hash::Sha256, rng::HmacDrbg};
/// use dnsbox::rdata::{Tkey, TkeyMode};
/// use dnsbox::tkey::{DhGroup, DhKeyPair, KeyGrant};
/// use dnsbox::{Message, MessageBuilder, NameBuf};
///
/// // Use purecrypto::rng::OsRng (purecrypto's `std` feature) in real code.
/// let mut rng = HmacDrbg::<Sha256>::new(b"example seed", b"", b"");
/// let server = DhKeyPair::generate(DhGroup::well_known(2)?, &mut rng);
/// let client = DhKeyPair::generate(DhGroup::well_known(2)?, &mut rng);
/// let (key_name, alg): (NameBuf, NameBuf) = ("k1.client.example".parse()?, "hmac-sha256".parse()?);
/// let (client_owner, server_owner): (NameBuf, NameBuf) = ("client.example".parse()?, "server.example".parse()?);
///
/// // Resolver: the query, with a random nonce (then sign it).
/// let nonce = [0x5a; 16];
/// let request = Tkey::new(alg.as_name(), 1_700_000_000, 1_700_086_400, TkeyMode::DIFFIE_HELLMAN, &nonce);
/// let mut q = MessageBuilder::new_vec();
/// client.build_query(&mut q, &key_name, &request, &client_owner)?;
/// let query = q.finish();
///
/// // Server: after verifying the query's signature.
/// let mut r = MessageBuilder::new_vec();
/// let grant = KeyGrant::new(key_name.as_name(), 1_700_000_000, 1_700_043_200);
/// let theirs = server.respond(&mut r, &Message::parse(&query)?, &server_owner, &grant, &[0xa5; 16])?;
/// let response = r.finish(); // then sign it
///
/// // Resolver: after verifying the response's signature.
/// let ours = client.complete(&Message::parse(&query)?, &Message::parse(&response)?)?;
/// assert_eq!(ours.secret(), theirs.secret());
/// assert_eq!(ours.secret().len(), 128);
/// assert_eq!((ours.name(), ours.expiration()), (key_name.as_name(), 1_700_043_200));
/// let _tsig_key = ours.hmac_key()?; // sign later messages with it
/// # Ok::<(), dnsbox::Error>(())
/// ```
pub struct DhKeyPair {
    group: DhGroup,
    private: dh::DhPrivateKey,
    /// The RFC 2539 public key field.
    public_key: Vec<u8>,
}

impl DhKeyPair {
    /// Generates a key pair in `group`. `rng` must be a cryptographically
    /// secure generator, e.g. `purecrypto::rng::OsRng` with purecrypto's
    /// `std` feature.
    ///
    /// ```
    /// use dnsbox::tkey::purecrypto::{hash::Sha256, rng::HmacDrbg};
    /// use dnsbox::tkey::{DhGroup, DhKey, DhKeyPair, DhPrime};
    ///
    /// let mut rng = HmacDrbg::<Sha256>::new(b"example seed", b"", b"");
    /// let pair = DhKeyPair::generate(DhGroup::well_known(1)?, &mut rng);
    /// let public = DhKey::parse(pair.public_key())?;
    /// assert_eq!(public.prime, DhPrime::WellKnown(1));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn generate<R: RngCore + CryptoRng>(group: DhGroup, rng: &mut R) -> Self {
        let private = dh::DhPrivateKey::generate(group.inner.clone(), rng);
        Self::with_private(group, private)
    }

    /// A key pair from a private exponent (most significant octet first),
    /// for a key kept in configuration (a server's published DH KEY) or a
    /// test vector.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKey`] if the exponent is 0 or not below the prime.
    ///
    /// ```
    /// use dnsbox::tkey::{DhGroup, DhKey, DhKeyPair};
    ///
    /// let pair = DhKeyPair::from_private_bytes(DhGroup::well_known(2)?, &[3])?;
    /// // 2^3 = 8.
    /// assert_eq!(DhKey::parse(pair.public_key())?.public_value, [8]);
    /// assert!(DhKeyPair::from_private_bytes(DhGroup::well_known(2)?, &[0]).is_err());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn from_private_bytes(group: DhGroup, exponent: &[u8]) -> Result<Self> {
        let private = dh::DhPrivateKey::from_bytes(group.inner.clone(), exponent)
            .map_err(|_| Error::InvalidKey)?;
        Ok(Self::with_private(group, private))
    }

    fn with_private(group: DhGroup, private: dh::DhPrivateKey) -> Self {
        let value = private.public_key().to_bytes();
        let (prime, generator) = group.key_prime();
        let key = DhKey {
            prime,
            generator,
            public_value: trim(&value),
        };
        let mut public_key = Vec::with_capacity(key.wire_len());
        // Cannot fail: every field is at most 2048 octets.
        let _ = key.compose(&mut public_key);
        DhKeyPair {
            group,
            private,
            public_key,
        }
    }

    /// The group.
    ///
    /// ```
    /// use dnsbox::tkey::{DhGroup, DhKeyPair};
    ///
    /// let pair = DhKeyPair::from_private_bytes(DhGroup::well_known(2)?, &[0x42; 32])?;
    /// assert_eq!(pair.group().bits(), 1024);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub const fn group(&self) -> &DhGroup {
        &self.group
    }

    /// The private exponent, most significant octet first, padded to the
    /// prime's length; for storing the key. Keep it secret.
    ///
    /// ```
    /// use dnsbox::tkey::{DhGroup, DhKeyPair};
    ///
    /// let pair = DhKeyPair::from_private_bytes(DhGroup::well_known(1)?, &[1, 2, 3])?;
    /// let stored = pair.private_bytes();
    /// assert_eq!(stored.len(), 96);
    /// let again = DhKeyPair::from_private_bytes(pair.group().clone(), &stored)?;
    /// assert_eq!(again.public_key(), pair.public_key());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn private_bytes(&self) -> Vec<u8> {
        self.private.to_bytes()
    }

    /// The public key field of the KEY record (RFC 2539 §2): the group (a
    /// well-known index or the prime and generator) and the public value
    /// `g^x mod p`, without leading zero octets.
    ///
    /// ```
    /// use dnsbox::tkey::{DhGroup, DhKeyPair};
    ///
    /// let pair = DhKeyPair::from_private_bytes(DhGroup::well_known(2)?, &[1])?;
    /// assert_eq!(pair.public_key(), [0, 1, 2, 0, 0, 0, 1, 2]);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// The KEY record data to publish or send: flags 0x0200 (a host key
    /// usable for authentication and confidentiality, RFC 2535 §3.1.2, as
    /// BIND writes it), protocol 3, algorithm DH (2), and
    /// [`public_key`](Self::public_key). Change the flags with struct
    /// update syntax if needed.
    ///
    /// ```
    /// use dnsbox::tkey::{DhGroup, DhKeyPair};
    ///
    /// let pair = DhKeyPair::from_private_bytes(DhGroup::well_known(2)?, &[1])?;
    /// assert_eq!(pair.key().to_string(), "512 3 2 AAECAAAAAQI=");
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn key(&self) -> Key<'_> {
        Key::new(
            HOST_KEY_FLAGS,
            PROTOCOL_DNSSEC,
            Algorithm::DH,
            &self.public_key,
        )
    }

    /// The Diffie-Hellman value shared with the owner of `peer`:
    /// `peer^x mod p` as an unsigned integer without leading zero octets
    /// (RFC 2930 §4.1, as BIND computed it). [`dh_keying_material`] turns
    /// it into the TSIG secret; [`respond`](Self::respond) and
    /// [`complete`](Self::complete) do both. Keep it secret.
    ///
    /// # Errors
    ///
    /// [`Error::BadKey`] if `peer` is in another group (TKEY error BADKEY,
    /// §4.1), [`Error::InvalidKey`] if its public value is not in the
    /// range `[2, p - 2]` or the result is degenerate (purecrypto's
    /// checks; answer BADKEY too).
    ///
    /// ```
    /// use dnsbox::tkey::{DhGroup, DhKey, DhKeyPair};
    ///
    /// let a = DhKeyPair::from_private_bytes(DhGroup::well_known(2)?, &[0x1f; 20])?;
    /// let b = DhKeyPair::from_private_bytes(DhGroup::well_known(2)?, &[0x2e; 20])?;
    /// let ab = a.dh_value(&DhKey::parse(b.public_key())?)?;
    /// let ba = b.dh_value(&DhKey::parse(a.public_key())?)?;
    /// assert_eq!(ab, ba);
    /// let other_group = DhKeyPair::from_private_bytes(DhGroup::well_known(1)?, &[3])?;
    /// assert_eq!(a.dh_value(&DhKey::parse(other_group.public_key())?), Err(dnsbox::Error::BadKey));
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn dh_value(&self, peer: &DhKey<'_>) -> Result<Vec<u8>> {
        if !self.group.contains(peer) {
            return Err(Error::BadKey);
        }
        let value = trim(peer.public_value);
        if value.len() > self.group.prime.len() {
            return Err(Error::InvalidKey);
        }
        let peer = dh::DhPublicKey::from_bytes(self.group.inner.clone(), value)
            .map_err(|_| Error::InvalidKey)?;
        let shared = self
            .private
            .shared_secret(&peer)
            .map_err(|_| Error::InvalidKey)?;
        Ok(trim(shared.as_bytes()).to_vec())
    }

    /// Writes a Diffie-Hellman TKEY query into an empty builder (RFC 2930
    /// §4.1): [`build_query_with_key`] with this pair's
    /// [`key`](Self::key) owned by `key_owner`. `request` gives the TSIG
    /// algorithm the resolver wants, the validity it asks for and, as key
    /// data, a random nonce (16 octets is plenty); its mode must be
    /// DIFFIE-HELLMAN. Sign the query afterwards (§3).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidTkey`] if `request` has another mode, and the
    /// errors of [`build_query_with_key`]; on any error the builder is
    /// left unchanged.
    ///
    /// ```
    /// use dnsbox::rdata::{Tkey, TkeyMode};
    /// use dnsbox::tkey::{self, DhGroup, DhKeyPair};
    /// use dnsbox::{Message, MessageBuilder, Name, NameBuf, Section};
    ///
    /// let pair = DhKeyPair::from_private_bytes(DhGroup::well_known(2)?, &[0x33; 32])?;
    /// let key_name: NameBuf = "k.example".parse()?;
    /// let request = Tkey::new(Name::ROOT, 0, 0, TkeyMode::DIFFIE_HELLMAN, &[1; 16]);
    /// let mut buf = [0u8; 512];
    /// let mut b = MessageBuilder::new(&mut buf)?;
    /// pair.build_query(&mut b, &key_name, &request, &key_name)?;
    /// let query = Message::parse_validated(b.finish())?;
    /// let (_, key) = tkey::keys(&query, Section::Additional).next().unwrap()?;
    /// assert_eq!(key, pair.key());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn build_query<B: OutBuf>(
        &self,
        b: &mut MessageBuilder<B>,
        key_name: impl ToName,
        request: &Tkey<'_>,
        key_owner: impl ToName,
    ) -> Result<()> {
        if request.mode != TkeyMode::DIFFIE_HELLMAN {
            return Err(Error::InvalidTkey);
        }
        build_query_with_key(b, key_name, request, key_owner, &self.key())
    }

    /// The first Diffie-Hellman KEY of `section` that is not this pair's
    /// own (BIND echoes the resolver's KEY next to its own) and is in this
    /// pair's group, with its owner and record data.
    fn find_peer<'a>(
        &self,
        msg: &Message<'a>,
        section: Section,
    ) -> Result<(Name<'a>, Key<'a>, DhKey<'a>)> {
        let ours = DhKey::parse(&self.public_key)?;
        let mut incompatible = false;
        for item in keys(msg, section) {
            let (owner, key) = item?;
            if key.algorithm != Algorithm::DH {
                continue;
            }
            match DhKey::parse(key.public_key) {
                Ok(dh) if trim(dh.public_value) == trim(ours.public_value) => {}
                Ok(dh) if self.group.contains(&dh) => return Ok((owner, key, dh)),
                _ => incompatible = true,
            }
        }
        // §4.1: FORMERR without a DH KEY, BADKEY with an incompatible one.
        Err(if incompatible {
            Error::BadKey
        } else {
            Error::InvalidTkey
        })
    }

    /// The server side of Diffie-Hellman exchanged keying (RFC 2930 §4.1):
    /// reads the TKEY request of `query` ([`find_request`]), takes the
    /// first Diffie-Hellman KEY of its additional section that is in this
    /// pair's group, and writes the response into an empty builder: the
    /// TKEY record (owner `grant.key_name`, the requested algorithm,
    /// `grant`'s validity, `nonce` as key data) and this pair's
    /// [`key`](Self::key) owned by `key_owner` in the answer section, the
    /// resolver's KEY echoed in the additional section. Returns the
    /// established key; sign the response afterwards (§3).
    ///
    /// `nonce` should be fresh random data (BIND sends 16 octets). The
    /// caller checks first that the query is authenticated (§3), and
    /// chooses the key name (often the requested one under the server's
    /// own domain, as BIND does), refusing names of keys it already has.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidTkey`] if the query is not a Diffie-Hellman TKEY
    /// request or has no Diffie-Hellman KEY (answer FORMERR),
    /// [`Error::BadKey`] or [`Error::InvalidKey`] if its KEYs are in other
    /// groups or invalid (answer with the request's TKEY and error BADKEY,
    /// [`build_response`] and [`Tkey::with_error`]), and the builder's
    /// errors; on any error the builder is left unchanged.
    ///
    /// ```
    /// use dnsbox::rdata::{Tkey, TkeyMode, TsigRcode};
    /// use dnsbox::tkey::{self, DhGroup, DhKeyPair, KeyGrant};
    /// use dnsbox::{Error, Message, MessageBuilder, Name, NameBuf};
    ///
    /// let server = DhKeyPair::from_private_bytes(DhGroup::well_known(2)?, &[0x44; 32])?;
    /// let client = DhKeyPair::from_private_bytes(DhGroup::well_known(1)?, &[0x55; 32])?;
    /// let name: NameBuf = "k.example".parse()?;
    /// let mut q = MessageBuilder::new_vec();
    /// client.build_query(&mut q, &name, &Tkey::new(Name::ROOT, 0, 0, TkeyMode::DIFFIE_HELLMAN, &[1; 16]), &name)?;
    /// let query = q.finish();
    /// let query = Message::parse(&query)?;
    ///
    /// // Another group: refuse with BADKEY.
    /// let mut r = MessageBuilder::new_vec();
    /// let grant = KeyGrant::new(name.as_name(), 0, 3600);
    /// assert_eq!(server.respond(&mut r, &query, &name, &grant, &[2; 16]).unwrap_err(), Error::BadKey);
    /// let request = tkey::find_request(&query)?;
    /// tkey::build_response(&mut r, &query, request.key_name, &request.data.with_error(TsigRcode::BADKEY))?;
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn respond<B: OutBuf>(
        &self,
        b: &mut MessageBuilder<B>,
        query: &Message<'_>,
        key_owner: impl ToName,
        grant: &KeyGrant<'_>,
        nonce: &[u8],
    ) -> Result<SharedKey> {
        let request = find_request(query)?;
        if request.data.mode != TkeyMode::DIFFIE_HELLMAN {
            return Err(Error::InvalidTkey);
        }
        let (client_owner, client_key, peer) = self.find_peer(query, Section::Additional)?;
        let mut value = self.dh_value(&peer)?;
        let secret = dh_keying_material(&value, request.data.key, nonce);
        value.zeroize();
        let reply = Tkey {
            algorithm: request.data.algorithm,
            inception: grant.inception,
            expiration: grant.expiration,
            mode: TkeyMode::DIFFIE_HELLMAN,
            error: TsigRcode::NOERROR,
            key: nonce,
            other: &[],
        };
        let key_owner = key_owner.to_name();
        atomic(b, |b| {
            build_response(b, query, grant.key_name, &reply)?;
            b.push_answer(key_owner, Class::ANY, 0, &self.key())?;
            b.push_additional(client_owner, Class::ANY, 0, &client_key)
        })?;
        Ok(SharedKey::from_secret(
            grant.key_name,
            request.data.algorithm,
            grant.inception,
            grant.expiration,
            secret,
        ))
    }

    /// The resolver side of Diffie-Hellman exchanged keying (RFC 2930
    /// §4.1): given the query this pair built ([`build_query`](Self::build_query)) and the
    /// server's response, checks the answer's TKEY record
    /// ([`find_answer`]: mode DIFFIE-HELLMAN, error NOERROR, the requested
    /// algorithm), takes the first Diffie-Hellman KEY of the answer
    /// section that is in this pair's group and not its own, and derives
    /// the key: named by the answer's owner name, valid for the period the
    /// server answered. Verify the response's signature first (§3).
    ///
    /// # Errors
    ///
    /// [`Error::ErrorResponse`] if the server refused (an error RCODE or
    /// TKEY error), [`Error::InvalidTkey`] if either message is not a
    /// Diffie-Hellman exchange or the response carries no server KEY,
    /// [`Error::BadKey`] or [`Error::InvalidKey`] if the server's KEY is
    /// in another group or invalid, or the parse error of a malformed
    /// message.
    ///
    /// ```
    /// use dnsbox::rdata::{Tkey, TkeyMode, TsigRcode};
    /// use dnsbox::tkey::{self, DhGroup, DhKeyPair};
    /// use dnsbox::{Error, Message, MessageBuilder, Name, NameBuf};
    ///
    /// let client = DhKeyPair::from_private_bytes(DhGroup::well_known(2)?, &[0x66; 32])?;
    /// let name: NameBuf = "k.example".parse()?;
    /// let mut q = MessageBuilder::new_vec();
    /// let request = Tkey::new(Name::ROOT, 0, 0, TkeyMode::DIFFIE_HELLMAN, &[1; 16]);
    /// client.build_query(&mut q, &name, &request, &name)?;
    /// let query = q.finish();
    /// let query = Message::parse(&query)?;
    /// // The server refused.
    /// let mut r = MessageBuilder::new_vec();
    /// tkey::build_response(&mut r, &query, &name, &request.with_error(TsigRcode::BADALG))?;
    /// let response = r.finish();
    /// assert_eq!(client.complete(&query, &Message::parse(&response)?).unwrap_err(), Error::ErrorResponse);
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn complete(&self, query: &Message<'_>, response: &Message<'_>) -> Result<SharedKey> {
        let request = find_request(query)?;
        let answer = find_answer(response)?;
        check_answer(&request.data, &answer.data, TkeyMode::DIFFIE_HELLMAN)?;
        let (_, _, peer) = self.find_peer(response, Section::Answer)?;
        let mut value = self.dh_value(&peer)?;
        let secret = dh_keying_material(&value, request.data.key, answer.data.key);
        value.zeroize();
        Ok(SharedKey::from_secret(
            answer.key_name,
            answer.data.algorithm,
            answer.data.inception,
            answer.data.expiration,
            secret,
        ))
    }
}

impl fmt::Debug for DhKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DhKeyPair")
            .field("group", &self.group)
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

/// Checks a resolver's view of an exchange: both TKEY records have
/// `mode`, the answer no error, and the algorithm the resolver asked for.
pub(super) fn check_answer(request: &Tkey<'_>, answer: &Tkey<'_>, mode: TkeyMode) -> Result<()> {
    if request.mode != mode || answer.mode != mode {
        return Err(Error::InvalidTkey);
    }
    if answer.error != TsigRcode::NOERROR {
        return Err(Error::ErrorResponse);
    }
    if answer.algorithm != request.algorithm {
        return Err(Error::InvalidTkey);
    }
    Ok(())
}

/// What a server grants in answer to a TKEY request (RFC 2930 §4.1,
/// §4.4): the key's name and validity.
///
/// ```
/// use dnsbox::NameBuf;
/// use dnsbox::tkey::KeyGrant;
///
/// let name: NameBuf = "1234.server.example".parse()?;
/// let grant = KeyGrant::new(name.as_name(), 1_700_000_000, 1_700_086_400);
/// assert_eq!(grant.key_name, name.as_name());
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyGrant<'a> {
    /// The key name: the owner of the answer's TKEY record, the name later
    /// TSIG records use (§2.1). The requested name, or one the server
    /// chooses.
    pub key_name: Name<'a>,
    /// Start of the validity the server grants, seconds since the epoch
    /// modulo 2³² (§2.4).
    pub inception: u32,
    /// End of that validity; at most what was requested (§4.1: "the
    /// maximum period the server will consider the keying material
    /// valid").
    pub expiration: u32,
}

impl<'a> KeyGrant<'a> {
    /// A grant of `key_name`, valid from `inception` to `expiration`.
    ///
    /// ```
    /// use dnsbox::Name;
    /// use dnsbox::tkey::KeyGrant;
    ///
    /// assert_eq!(KeyGrant::new(Name::ROOT, 1, 2).expiration, 2);
    /// ```
    #[must_use]
    pub const fn new(key_name: Name<'a>, inception: u32, expiration: u32) -> Self {
        KeyGrant {
            key_name,
            inception,
            expiration,
        }
    }
}

/// A shared secret established with TKEY (RFC 2930 §1): the TSIG key's
/// name, algorithm, validity and secret. [`hmac_key`](Self::hmac_key)
/// makes it a TSIG key for the HMAC algorithms; the secret is wiped when
/// the value is dropped, and `Debug` does not show it.
///
/// ```
/// use dnsbox::NameBuf;
/// use dnsbox::tkey::SharedKey;
///
/// let name: NameBuf = "k.example".parse()?;
/// let alg: NameBuf = "hmac-sha256".parse()?;
/// let key = SharedKey::new(&name, &alg, 100, 200, b"0123456789abcdef");
/// assert!(key.is_valid_at(150) && !key.is_valid_at(201));
/// assert_eq!(key.algorithm(), alg.as_name());
/// assert!(!format!("{key:?}").contains("0123"));
/// assert_eq!(key.hmac_key()?.algorithm_id(), dnsbox::tsig::TsigAlgorithm::HmacSha256);
/// # Ok::<(), dnsbox::Error>(())
/// ```
#[derive(Clone)]
pub struct SharedKey {
    name: NameBuf,
    algorithm: NameBuf,
    inception: u32,
    expiration: u32,
    secret: Vec<u8>,
}

impl SharedKey {
    /// A key named `name` for `algorithm`, valid from `inception` to
    /// `expiration`, with `secret` (copied); for keys a resolver assigns
    /// itself (§4.5) or that are configured.
    ///
    /// ```
    /// use dnsbox::Name;
    /// use dnsbox::tkey::SharedKey;
    ///
    /// let key = SharedKey::new(Name::ROOT, Name::ROOT, 0, 0, &[1, 2]);
    /// assert_eq!((key.secret(), key.inception()), (&[1, 2][..], 0));
    /// ```
    #[must_use]
    pub fn new(
        name: impl ToName,
        algorithm: impl ToName,
        inception: u32,
        expiration: u32,
        secret: &[u8],
    ) -> Self {
        Self::from_secret(name, algorithm, inception, expiration, secret.to_vec())
    }

    pub(super) fn from_secret(
        name: impl ToName,
        algorithm: impl ToName,
        inception: u32,
        expiration: u32,
        secret: Vec<u8>,
    ) -> Self {
        SharedKey {
            name: name.to_name().to_buf(),
            algorithm: algorithm.to_name().to_buf(),
            inception,
            expiration,
            secret,
        }
    }

    /// The key name (the TKEY owner name, used by the TSIG records signed
    /// with the key, §2.1).
    ///
    /// ```
    /// use dnsbox::{Name, NameBuf};
    /// use dnsbox::tkey::SharedKey;
    ///
    /// let name: NameBuf = "k.example".parse()?;
    /// assert_eq!(SharedKey::new(&name, Name::ROOT, 0, 0, &[1]).name(), name.as_name());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn name(&self) -> Name<'_> {
        self.name.as_name()
    }

    /// The TSIG algorithm name (§2.3).
    ///
    /// ```
    /// use dnsbox::{Name, NameBuf};
    /// use dnsbox::tkey::SharedKey;
    ///
    /// let alg: NameBuf = "hmac-sha512".parse()?;
    /// assert_eq!(SharedKey::new(Name::ROOT, &alg, 0, 0, &[1]).algorithm(), alg.as_name());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    #[must_use]
    pub fn algorithm(&self) -> Name<'_> {
        self.algorithm.as_name()
    }

    /// Start of the key's validity, seconds since the epoch modulo 2³²
    /// (§2.4).
    ///
    /// ```
    /// use dnsbox::Name;
    /// use dnsbox::tkey::SharedKey;
    ///
    /// assert_eq!(SharedKey::new(Name::ROOT, Name::ROOT, 7, 9, &[1]).inception(), 7);
    /// ```
    #[must_use]
    pub const fn inception(&self) -> u32 {
        self.inception
    }

    /// End of the key's validity, as [`inception`](Self::inception).
    ///
    /// ```
    /// use dnsbox::Name;
    /// use dnsbox::tkey::SharedKey;
    ///
    /// assert_eq!(SharedKey::new(Name::ROOT, Name::ROOT, 7, 9, &[1]).expiration(), 9);
    /// ```
    #[must_use]
    pub const fn expiration(&self) -> u32 {
        self.expiration
    }

    /// Whether `now` (seconds since the epoch, modulo 2³²) lies within the
    /// validity, in RFC 1982 serial arithmetic (§2.4).
    ///
    /// ```
    /// use dnsbox::Name;
    /// use dnsbox::tkey::SharedKey;
    ///
    /// let key = SharedKey::new(Name::ROOT, Name::ROOT, u32::MAX - 5, 5, &[1]);
    /// assert!(key.is_valid_at(0) && !key.is_valid_at(6));
    /// ```
    #[must_use]
    pub const fn is_valid_at(&self, now: u32) -> bool {
        crate::dnssec::check_validity(self.inception, self.expiration, now).is_ok()
    }

    /// The shared secret (the keying material of §4.1, or the key
    /// assigned by one party, §4.4, §4.5). Keep it secret.
    ///
    /// ```
    /// use dnsbox::Name;
    /// use dnsbox::tkey::SharedKey;
    ///
    /// assert_eq!(SharedKey::new(Name::ROOT, Name::ROOT, 0, 0, b"s3cr3t").secret(), b"s3cr3t");
    /// ```
    #[must_use]
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    /// The key as a TSIG HMAC key ([`HmacKey`]), for signing and verifying
    /// later messages (RFC 8945).
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedAlgorithm`] if the algorithm is not one of the
    /// HMAC algorithms of [`TsigAlgorithm`] (e.g. `gss-tsig`).
    ///
    /// ```
    /// use dnsbox::{Name, NameBuf};
    /// use dnsbox::tkey::SharedKey;
    /// use dnsbox::tsig::{TsigAlgorithm, TsigKey};
    ///
    /// let name: NameBuf = "k.example".parse()?;
    /// let key = SharedKey::new(&name, TsigAlgorithm::HmacSha1.name(), 0, 0, &[9; 20]);
    /// assert_eq!(key.hmac_key()?.name(), name.as_name());
    /// let gss: NameBuf = "gss-tsig".parse()?;
    /// assert!(SharedKey::new(&name, &gss, 0, 0, &[9; 20]).hmac_key().is_err());
    /// # Ok::<(), dnsbox::Error>(())
    /// ```
    pub fn hmac_key(&self) -> Result<HmacKey<'_>> {
        let algorithm =
            TsigAlgorithm::from_name(self.algorithm()).ok_or(Error::UnsupportedAlgorithm)?;
        Ok(HmacKey::new(self.name(), algorithm, &self.secret))
    }
}

impl Drop for SharedKey {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl fmt::Debug for SharedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedKey")
            .field("name", &self.name)
            .field("algorithm", &self.algorithm)
            .field("inception", &self.inception)
            .field("expiration", &self.expiration)
            .field("secret_len", &self.secret.len())
            .finish_non_exhaustive()
    }
}
