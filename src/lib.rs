//! # dnsbox
//!
//! High-performance DNS message parsing and building, for both queries and
//! responses.
//!
//! The design goals, in order:
//!
//! 1. **Safe on hostile input.** Parsing never panics and never reads out of
//!    bounds; malformed messages are rejected with an [`Error`]. Work is
//!    bounded by default where input could amplify it (zone files:
//!    [`zone::ZoneLimits`]; DNSSEC validation: [`dnssec::ValidationBudget`]).
//!    The crate is `#![forbid(unsafe_code)]`.
//! 2. **Zero-copy, allocation-free parsing.** Messages are parsed as views
//!    over the caller's buffer; names and record data are decoded lazily.
//! 3. **Fast building.** Messages are written straight into a caller-supplied
//!    buffer, with name compression handled by the builder.
//! 4. **Broad RFC coverage.** EDNS(0), DNSSEC, SVCB/HTTPS, and the long tail
//!    of record types — see `ROADMAP.md` for the plan.
//!
//! The crate is `no_std`; the `alloc` and `std` features add owned types and
//! standard-library integration (see [Cargo features](#cargo-features)).
//!
//! ## Guided tour
//!
//! The sections below walk through the crate from a received message to
//! signed zone transfers. Every example runs as a doctest; the ones that
//! need a Cargo feature say so. The [`examples/`] directory of the
//! repository has complete programs (see [Examples](#examples)).
//!
//! [`examples/`]: https://github.com/KarpelesLab/dnsbox/tree/master/examples
//!
//! ### Parsing a message
//!
//! [`Message::parse`] wraps the caller's buffer after checking the 12-byte
//! header; nothing is copied or allocated, and the sections are decoded
//! lazily. [`Message::parse_validated`] walks the whole message once
//! first, to fail fast on malformed input. Here is a real response from
//! Google Public DNS for `gmail.com. MX`:
//!
//! ```
//! use dnsbox::{Class, Message, Rcode, Rtype};
//!
//! # fn hex(s: &str) -> Vec<u8> {
//! #     (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
//! # }
//! // 161 bytes received from 8.8.8.8 over UDP.
//! let wire = hex("037b8180000100050000000105676d61696c03636f6d00000f0001c00c000f00\
//!                 0100000df6001b00050d676d61696c2d736d74702d696e016c06676f6f676c65\
//!                 c012c00c000f000100000df60009000a04616c7431c029c00c000f000100000d\
//!                 f60009002804616c7434c029c00c000f000100000df60009001404616c7432c0\
//!                 29c00c000f000100000df60009001e04616c7433c02900002902000000000000\
//!                 00");
//! let msg = Message::parse_validated(&wire)?;
//! assert_eq!(msg.id(), 891);
//! assert!(msg.flags().qr() && msg.flags().ra());
//! assert_eq!(msg.flags().rcode(), Rcode::NOERROR);
//! let q = msg.questions().next().expect("one question")?;
//! assert_eq!((q.name().to_string(), q.qtype(), q.qclass()), ("gmail.com.".into(), Rtype::MX, Class::IN));
//! assert_eq!(msg.header().ancount, 5);
//! # Ok::<(), dnsbox::Error>(())
//! ```
//!
//! Hostile input never panics: every malformed message is an [`Error`].
//!
//! ### Iterating over records
//!
//! [`Message::answers`], [`authority`](Message::authority),
//! [`additional`](Message::additional) and [`section`](Message::section)
//! iterate over one section, [`Message::records`] over all three in one
//! pass. Items are `Result<Record>`: an iterator yields an error once and
//! stops. Each [`Record`] exposes its owner name, type, class and TTL
//! without touching the RDATA, and `Display`s in zone-file form; a whole
//! [`Message`] displays the way `dig` prints it.
//!
//! ```
//! use dnsbox::{Message, Rtype, Section};
//! # fn hex(s: &str) -> Vec<u8> {
//! #     (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
//! # }
//! # let wire = hex("037b8180000100050000000105676d61696c03636f6d00000f0001c00c000f00\
//! #     0100000df6001b00050d676d61696c2d736d74702d696e016c06676f6f676c65\
//! #     c012c00c000f000100000df60009000a04616c7431c029c00c000f000100000d\
//! #     f60009002804616c7434c029c00c000f000100000df60009001404616c7432c0\
//! #     29c00c000f000100000df60009001e04616c7433c02900002902000000000000\
//! #     00");
//! let msg = Message::parse(&wire)?;
//! for rr in msg.answers() {
//!     let rr = rr?;
//!     assert_eq!((rr.rtype(), rr.ttl()), (Rtype::MX, 3574));
//! }
//! let first = msg.answers().next().unwrap()?;
//! assert_eq!(first.to_string(), "gmail.com. 3574 IN MX 5 gmail-smtp-in.l.google.com.");
//!
//! // All record sections at once: the additional section holds the OPT record.
//! let sections: Vec<Section> = msg.records().map(|r| r.map(|(s, _)| s)).collect::<Result<_, _>>()?;
//! assert_eq!(sections.last(), Some(&Section::Additional));
//!
//! // `dig`-style text of the whole message.
//! assert!(msg.to_string().contains(";; ANSWER SECTION:\ngmail.com.\t\t3574\tIN\tMX\t5 gmail-smtp-in.l.google.com.\n"));
//! # Ok::<(), dnsbox::Error>(())
//! ```
//!
//! ### Typed record data
//!
//! [`Record::data`] decodes the RDATA into [`RData`], an enum with a typed
//! view for about 90 record types ([`rdata`]); unknown types stay opaque
//! and round-trip (RFC 3597). [`Record::data_as`] asks for one type.
//! Names inside RDATA follow compression pointers into the message.
//!
//! ```
//! use dnsbox::rdata::{Mx, RData};
//! use dnsbox::Message;
//! # fn hex(s: &str) -> Vec<u8> {
//! #     (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
//! # }
//! # let wire = hex("037b8180000100050000000105676d61696c03636f6d00000f0001c00c000f00\
//! #     0100000df6001b00050d676d61696c2d736d74702d696e016c06676f6f676c65\
//! #     c012c00c000f000100000df60009000a04616c7431c029c00c000f000100000d\
//! #     f60009002804616c7434c029c00c000f000100000df60009001404616c7432c0\
//! #     29c00c000f000100000df60009001e04616c7433c02900002902000000000000\
//! #     00");
//! let msg = Message::parse(&wire)?;
//! // Mail exchanges in preference order.
//! let mut exchanges: Vec<(u16, String)> = Vec::new();
//! for rr in msg.answers() {
//!     if let RData::Mx(mx) = rr?.data()? {
//!         exchanges.push((mx.preference, mx.exchange.to_string()));
//!     }
//! }
//! exchanges.sort();
//! assert_eq!(exchanges[0], (5, "gmail-smtp-in.l.google.com.".to_string()));
//! assert_eq!(exchanges[4].0, 40);
//!
//! // One type directly; the presentation format parses back too.
//! let mx: Mx<'_> = msg.answers().nth(1).unwrap()?.data_as()?;
//! assert_eq!(mx.to_string(), "10 alt1.gmail-smtp-in.l.google.com.");
//! # Ok::<(), dnsbox::Error>(())
//! ```
//!
//! Every type also parses from its zone-file text into a caller buffer
//! ([`ParseRdataText::from_text`], [`RData::from_text`]) and composes back
//! into a message ([`ComposeRdata`]).
//!
//! ### Building a message
//!
//! [`MessageBuilder`] writes straight into a buffer — a `&mut [u8]` on the
//! stack, or a `Vec<u8>` with `alloc` ([`MessageBuilder::new_vec`]) —
//! compressing names as it goes and keeping the header counts up to date.
//! Every push is atomic: a record that does not fit leaves the message as
//! it was. [`MessageBuilder::query`] and [`MessageBuilder::response`]
//! start the common shapes.
//!
//! ```
//! use dnsbox::rdata::Aaaa;
//! use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
//!
//! // A stub resolver's query: QUERY, RD set.
//! let name: NameBuf = "www.example.com".parse()?;
//! let mut qbuf = [0u8; 512];
//! let query = MessageBuilder::query(&mut qbuf, 0x1234, &name, Rtype::AAAA, Class::IN)?.finish();
//! assert_eq!(query.len(), 33);
//!
//! // A server's answer: ID, opcode, RD and the question copied; QR set.
//! let query = Message::parse(query)?;
//! let mut rbuf = [0u8; 512];
//! let mut b = MessageBuilder::response(&mut rbuf, &query)?;
//! b.set_flags(b.header().flags.with_aa(true));
//! b.push_answer(&name, Class::IN, 300, &Aaaa::new("2001:db8::80".parse().unwrap()))?;
//! let response = Message::parse_validated(b.finish())?;
//! assert_eq!(response.id(), 0x1234);
//! assert_eq!(response.answers().next().unwrap()?.to_string(), "www.example.com. 300 IN AAAA 2001:db8::80");
//! # Ok::<(), dnsbox::Error>(())
//! ```
//!
//! ### EDNS(0)
//!
//! The OPT pseudo-record (RFC 6891) carries the UDP payload size, the
//! DNSSEC OK bit, the extended RCODE and options. Push one with
//! [`MessageBuilder::push_edns`] from an [`edns::OptHeader`] and any
//! options; read it back with [`Message::edns`]. A server echoes EDNS
//! with [`MessageBuilder::start_response_edns`].
//!
//! ```
//! use dnsbox::edns::{Cookie, EdnsOption, Nsid, OptHeader, PaddingPolicy};
//! use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
//!
//! let name: NameBuf = "example.com".parse()?;
//! let mut buf = [0u8; 512];
//! let mut q = MessageBuilder::query(&mut buf, 7, &name, Rtype::A, Class::IN)?;
//! let header = OptHeader::new(1232).with_dnssec_ok(true);
//! let cookie = Cookie::client_only([0x24, 0x64, 0xc4, 0xab, 0xcf, 0x10, 0xc9, 0x57]);
//! // NSID request and a client cookie, padded to 128 bytes (RFC 8467).
//! q.push_edns_padded(header, &(Nsid::REQUEST, cookie), PaddingPolicy::QUERY)?;
//! let query = Message::parse_validated(q.finish())?;
//! assert_eq!(query.as_bytes().len(), 128);
//!
//! let edns = query.edns()?.expect("OPT record");
//! assert_eq!(edns.udp_payload_size(), 1232);
//! assert!(edns.dnssec_ok());
//! let mut names = Vec::new();
//! for option in edns.options() {
//!     match option? {
//!         EdnsOption::Cookie(c) => assert_eq!(c.server(), None),
//!         other => names.push(other.to_string()),
//!     }
//! }
//! assert_eq!(names, ["NSID", "PADDING=68"]);
//! # Ok::<(), dnsbox::Error>(())
//! ```
//!
//! ### Truncation
//!
//! Over UDP a response must fit the client's payload size. The RRset-level
//! pushes ([`MessageBuilder::push_rrset`],
//! [`copy_message`](MessageBuilder::copy_message), ...) drop a whole RRset
//! that does not fit and, with [`builder::Truncation::SetTc`], set the TC
//! bit (RFC 2181 §9); the client then retries over TCP.
//!
//! ```
//! use dnsbox::builder::{Outcome, Truncation};
//! use dnsbox::rdata::A;
//! use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype, Section};
//!
//! let name: NameBuf = "pool.example.com".parse()?;
//! let pool: Vec<A> = (1..=64).map(|i| A::new([192, 0, 2, i].into())).collect();
//!
//! let mut qbuf = [0u8; 512];
//! let query = MessageBuilder::query(&mut qbuf, 1, &name, Rtype::A, Class::IN)?.finish();
//! let query = Message::parse(query)?;
//!
//! let mut buf = [0u8; 4096];
//! let mut b = MessageBuilder::response(&mut buf, &query)?;
//! b.set_limit(512); // plain UDP without EDNS
//! b.set_truncation(Truncation::SetTc);
//! let outcome = b.push_rrset(Section::Answer, &name, Class::IN, 60, &pool)?;
//! assert_eq!(outcome, Outcome::Truncated);
//! let response = Message::parse_validated(b.finish())?;
//! assert!(response.flags().tc());
//! assert_eq!(response.header().ancount, 0); // never half an RRset
//! # Ok::<(), dnsbox::Error>(())
//! ```
//!
//! ### TCP framing
//!
//! Over TCP (and TLS) each message is preceded by its 16-bit length.
//! [`MessageBuilder::new_tcp`] builds a message with its prefix in place;
//! [`tcp::FrameReassembler`] splits a byte stream back into messages, in a
//! caller buffer; with `std`, [`tcp::read_message`] and
//! [`tcp::write_message`] work on any `Read`/`Write` such as a
//! `TcpStream`.
//!
//! ```
//! use dnsbox::tcp::FrameReassembler;
//! use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
//!
//! let name: NameBuf = "example.com".parse()?;
//! let mut buf = [0u8; 514];
//! let mut b = MessageBuilder::new_tcp(&mut buf)?;
//! b.start_query(42, &name, Rtype::SOA, Class::IN)?;
//! let frame = b.finish();
//! assert_eq!(&frame[..2], [0, 29]);
//!
//! // The receiving side gets the bytes in arbitrary pieces.
//! let mut storage = [0u8; 1024];
//! let mut stream = FrameReassembler::new(&mut storage);
//! let (head, tail) = frame.split_at(5);
//! stream.extend(head);
//! assert_eq!(stream.next_frame()?, None); // not complete yet
//! stream.extend(tail);
//! let msg = stream.next_frame()?.expect("a whole message");
//! assert_eq!(Message::parse(msg)?.id(), 42);
//! # Ok::<(), dnsbox::Error>(())
//! ```
//!
//! ### Zone files
//!
//! [`zone::ZoneReader`] streams the records of an RFC 1035 master file
//! without allocating (`$ORIGIN`, `$TTL`, `$INCLUDE`, `$GENERATE`, TTL
//! units, generic RDATA); errors carry their line and column. Each record
//! comes with its RDATA in wire form, ready for a message.
//!
//! ```
//! use dnsbox::zone::ZoneReader;
//! use dnsbox::{Message, MessageBuilder, Section};
//!
//! let zone = "\
//! $ORIGIN example.com.
//! $TTL 1h
//! @     IN SOA ns1 hostmaster ( 2024010101 2h 15m 2w 1h )
//!       IN NS  ns1
//! ns1   IN A   192.0.2.53
//! www   300 IN CNAME @
//! ";
//! let mut reader = ZoneReader::new(zone);
//! let mut rdata = [0u8; 512];
//! let mut buf = [0u8; 512];
//! let mut b = MessageBuilder::new(&mut buf)?;
//! while let Some(rr) = reader.next_record(&mut rdata)? {
//!     b.push_record(Section::Answer, &rr.name, rr.class, rr.ttl, &rr.data()?)?;
//! }
//! let msg = Message::parse_validated(b.finish())?;
//! let last = msg.answers().last().unwrap()?;
//! assert_eq!(last.to_string(), "www.example.com. 300 IN CNAME example.com.");
//! # Ok::<(), dnsbox::Error>(())
//! ```
//!
//! With `alloc`, [`zone::parse`] collects a whole file and
//! [`zone::ZoneReader::records`] follows `$INCLUDE` through a resolver.
//!
//! ### DNSSEC
//!
//! [`dnssec`] covers the wire side of DNSSEC without any feature —
//! canonical forms, key tags, signed data, the RFC 4035 checks, NSEC and
//! NSEC3 denial proofs — and, through the `purecrypto` crate,
//! signature verification and signing (`dnssec`) and digests
//! (`dnssec-digest`). [`dnssec::TrustedKeys`] walks the chain of trust:
//! DS (or a trust anchor) → DNSKEY RRset → the zone's RRsets, with bounded
//! work per call and per response ([`dnssec::ValidationBudget`]).
//!
//! ```
//! # #[cfg(feature = "dnssec")] {
//! use dnsbox::dnssec::{Algorithm, PurecryptoVerifier, Rrset, Signer, SigningKey, ZoneKey};
//! use dnsbox::dnssec::{sign_rrset, verify_rrsig};
//! use dnsbox::rdata::{A, Dnskey};
//! use dnsbox::{Class, NameBuf, Rtype};
//!
//! // A zone key (the RFC 8080 §6.1 Ed25519 example seed).
//! let key = SigningKey::from_private_bytes(Algorithm::ED25519, b"82260384628080122645190204142262")?;
//! let zone: NameBuf = "example.com".parse()?;
//! let zone_key = ZoneKey::new(zone.as_name(), key.dnskey(Dnskey::ZONE | Dnskey::SEP));
//! assert_eq!(zone_key.key_tag(), 3613);
//!
//! // Sign the RRset www.example.com. A ...
//! let www: NameBuf = "www.example.com".parse()?;
//! let addrs = [A::new([192, 0, 2, 1].into()), A::new([192, 0, 2, 2].into())];
//! let rrset = Rrset::new(www.as_name(), Class::IN, &addrs);
//! let (inception, expiration) = (1_790_000_000, 1_792_000_000);
//! let template = zone_key.rrsig_template(www.as_name(), Rtype::A, 3600, inception, expiration);
//! let mut scratch = Vec::new();
//! let mut sig = [0u8; 64];
//! let len = sign_rrset(&key, &template, rrset, &mut scratch, &mut sig)?;
//! let rrsig = template.with_signature(&sig[..len]);
//!
//! // ... and validate it, as a resolver does with an authenticated key.
//! let now = 1_791_105_383;
//! verify_rrsig(&PurecryptoVerifier, &zone_key, &rrsig, rrset, now, &mut scratch)?;
//! let tampered = [A::new([192, 0, 2, 66].into())];
//! let bad = Rrset::new(www.as_name(), Class::IN, &tampered);
//! assert!(verify_rrsig(&PurecryptoVerifier, &zone_key, &rrsig, bad, now, &mut scratch).is_err());
//! # }
//! # Ok::<(), dnsbox::Error>(())
//! ```
//!
//! The `dnssec_dig` example validates a real captured response against a
//! trust anchor.
//!
//! ### TSIG
//!
//! [`tsig`] signs and verifies transactions with a shared secret
//! (RFC 8945): requests, responses and multi-message zone transfers. The
//! MAC comes from `purecrypto` with the `tsig` feature ([`tsig::HmacKey`]),
//! or from any [`tsig::TsigKey`] implementation.
//!
//! ```
//! # #[cfg(feature = "tsig")] {
//! use dnsbox::tsig::{self, HmacKey, TsigAlgorithm, TsigSigner, TsigVerifier};
//! use dnsbox::{Class, Message, MessageBuilder, NameBuf, Rtype};
//!
//! let key_name: NameBuf = "transfer-key".parse()?;
//! let key = HmacKey::new(&key_name, TsigAlgorithm::HmacSha256, b"a shared secret");
//! let zone: NameBuf = "example.com".parse()?;
//! let now = 1_700_000_000;
//!
//! // Client: sign the query, keep the MAC.
//! let mut qbuf = [0u8; 512];
//! let mut q = MessageBuilder::query(&mut qbuf, 7, &zone, Rtype::SOA, Class::IN)?;
//! let request_mac = TsigSigner::request(&key).sign(&mut q, now)?;
//! let query = Message::parse(q.finish())?;
//!
//! // Server: verify, then sign the response with the request MAC.
//! let verified = tsig::verify_request(&query, &key, now).verified().expect("valid TSIG");
//! let mut rbuf = [0u8; 512];
//! let mut r = MessageBuilder::response(&mut rbuf, &query)?;
//! verified.signer().sign(&mut r, now)?;
//! let response = Message::parse(r.finish())?;
//!
//! // Client: verify the response.
//! let mut v = TsigVerifier::new(&key, request_mac.as_slice())?;
//! assert!(v.verify(&response, now)?.is_some());
//! v.finish()?;
//! # }
//! # Ok::<(), dnsbox::Error>(())
//! ```
//!
//! SIG(0) ([`sig0`]), TKEY key establishment ([`tkey`]), dynamic UPDATE
//! ([`update`]), NOTIFY ([`notify`]), AXFR/IXFR ([`xfr`]) and DNS
//! Stateful Operations ([`dso`]) follow the same patterns.
//!
//! ## Examples
//!
//! The repository's `examples/` directory holds small complete programs:
//!
//! | Example | Features | What it does |
//! |---------|----------|--------------|
//! | `stub_resolver` | `std` | queries a recursive resolver over UDP with EDNS, retries over TCP when truncated, prints the answer `dig`-style |
//! | `zone2wire` | `std` | reads a master file and writes its records as wire-format messages (or a hex dump) |
//! | `dnssec_dig` | `dnssec` | validates a captured response against a trust anchor (DS → DNSKEY → RRset) and prints it with the verdict per RRset |
//! | `tsig_axfr` | `tsig` | signs an AXFR request and verifies a multi-message response stream |
//! | `interop_probe` | `std`, `tsig`, `dnssec` | the live checks against Knot DNS and Unbound of the interop CI workflow: EDNS, cookies, TSIG, AXFR/IXFR, UPDATE, validation verdicts |
//! | `bind_probe` | `std`, `tsig`, `dnssec` | the live checks against BIND 9's `named` (authoritative and validating) of the interop CI workflow: EDNS, cookies, TSIG, TKEY, AXFR/IXFR, UPDATE with TSIG and SIG(0), validation verdicts |
//!
//! Run one with `cargo run --example <name> --features <features> -- <args>`.
//!
//! ## Text, owned data and serde
//!
//! A [`Message`] displays in `dig` style (BIND 9's layout, no allocation).
//! With `alloc`, [`OwnedMessage`] and friends ([`owned`]) copy a message
//! out of its buffer and write it back through the builder. Text parses
//! back too: [`ParseRdataText`] and [`RData::parse_text`] read a record's
//! presentation format, and [`zone::ZoneReader`] reads RFC 1035 master
//! files, both without allocating. The `serde`
//! feature (`no_std`) serializes protocol numbers ([`Rtype`], [`Class`],
//! [`Opcode`], [`Rcode`], every registry newtype) as mnemonics such as
//! `"MX"` or `"TYPE65534"` in human-readable formats and as integers
//! otherwise, names as presentation strings, [`Flags`] as a struct of
//! bits, and, with `alloc`, the owned types.
//!
//! ## Cargo features
//!
//! Every feature is additive, and the crate builds with none of them
//! (`no_std`, no allocation, no dependencies). Items that need a feature
//! are labelled with it in the documentation.
//!
//! | Feature | Default | Adds |
//! |---------|---------|------|
//! | `std` | yes | `std::io` TCP helpers ([`tcp::read_message`], [`tcp::write_message`]), `$INCLUDE` from the file system ([`zone::FsIncludes`]); implies `alloc` |
//! | `alloc` | | `Vec`-backed builders ([`MessageBuilder::new_vec`]), the owned types ([`owned`]), [`zone::ZoneReader::records`] and [`zone::parse`], DNSSEC RRset sorting and ZONEMD collation, the SIG(0) adapters over the DNSSEC traits |
//! | `dnssec-digest` | | DS digests and NSEC3 hashing ([`dnssec::verify_ds`], [`dnssec::nsec3_hash`]) without `alloc`; with `alloc`, ZONEMD digests |
//! | `dnssec` | | DNSSEC and SIG(0) signature verification and signing: RSA, ECDSA P-256/P-384, Ed25519, Ed448; implies `alloc` and `dnssec-digest` |
//! | `tsig` | | the TSIG HMAC backend ([`tsig::HmacKey`]: HMAC-MD5, SHA-1, SHA-2) |
//! | `tkey` | | TKEY key agreement ([`tkey::DhKeyPair`]: Diffie-Hellman exchanged keying; RSA-encrypted server and resolver assigned keying), producing TSIG keys ([`tkey::SharedKey`]); implies `alloc` and `tsig` |
//! | `cookie-siphash` | | RFC 9018 server cookies ([`edns::ServerCookie::generate`] / [`verify`][edns::ServerCookie::verify]) |
//! | `serde` | | `Serialize` / `Deserialize` (`no_std`) for the registries, names, header flags and, with `alloc`, the owned types |
//!
//! dnsbox never implements cryptography: the crypto features enable the
//! optional, `no_std` [`purecrypto`](https://crates.io/crates/purecrypto)
//! dependency. Every crypto-using API sits behind a trait
//! ([`dnssec::Verifier`], [`dnssec::Signer`], [`tsig::TsigKey`],
//! [`sig0::Sig0Signer`], ...) so other backends can be plugged in, and the
//! wire-format side (signed data, MAC input, canonical forms) works without
//! any feature.
//!
//! ## Errors
//!
//! Fallible functions return [`Result<T>`](Result) with the crate-wide
//! [`Error`]: one byte, `Copy`, `#[non_exhaustive]`. Zone-file errors carry
//! their position ([`zone::ZoneError`]) and convert into [`Error`] with `?`.
//! Parsing never panics on hostile input; see `SECURITY.md`.
//!
//! ## Conventions
//!
//! - Protocol numbers ([`Rtype`], [`Class`], [`Opcode`], [`Rcode`],
//!   [`edns::OptionCode`], [`dnssec::Algorithm`], ...) are open newtypes:
//!   unknown values round-trip, `Display` prints the mnemonic or the
//!   generic form (`TYPE65534`) and `FromStr` parses both back.
//! - Views borrow the caller's buffer (`Message<'a>`, `Name<'a>`, every
//!   type in [`rdata`]); `parse` / `from_wire` read wire data, `from_text`
//!   presentation format; `as_wire` returns a view's wire form, `as_bytes`
//!   the contents of a buffer or an opaque field.
//! - Builders write into an [`OutBuf`]: a [`WireWriter`] over a caller's
//!   `&mut [u8]` (`new`), or, with `alloc`, a `Vec<u8>` (`new_vec`); any
//!   `OutBuf` (`from_buf`). `set_*` methods configure a builder in place;
//!   `with_*` methods take a value and return it modified (builder style).
//! - Every public type is `Send` and `Sync` (when its type parameters
//!   are).
//!
//! See `ARCHITECTURE.md` in the repository for the module layout and the
//! extension recipes (adding record types, EDNS options, ...).
//!
// Links to feature-gated items resolve only when their feature is on;
// otherwise they point at the feature table, so `cargo doc` is clean in
// every feature configuration.
#![cfg_attr(
    feature = "alloc",
    doc = "
[`MessageBuilder::new_vec`]: MessageBuilder::new_vec
[`OwnedMessage`]: OwnedMessage
[`owned`]: owned
[`zone::parse`]: zone::parse
[`zone::ZoneReader::records`]: zone::ZoneReader::records"
)]
#![cfg_attr(
    not(feature = "alloc"),
    doc = "
[`MessageBuilder::new_vec`]: crate#cargo-features
[`OwnedMessage`]: crate#cargo-features
[`owned`]: crate#cargo-features
[`zone::parse`]: crate#cargo-features
[`zone::ZoneReader::records`]: crate#cargo-features"
)]
#![cfg_attr(
    feature = "std",
    doc = "
[`tcp::read_message`]: tcp::read_message
[`tcp::write_message`]: tcp::write_message
[`zone::FsIncludes`]: zone::FsIncludes"
)]
#![cfg_attr(
    not(feature = "std"),
    doc = "
[`tcp::read_message`]: crate#cargo-features
[`tcp::write_message`]: crate#cargo-features
[`zone::FsIncludes`]: crate#cargo-features"
)]
#![cfg_attr(
    feature = "dnssec-digest",
    doc = "
[`dnssec::verify_ds`]: dnssec::verify_ds
[`dnssec::nsec3_hash`]: dnssec::nsec3_hash"
)]
#![cfg_attr(
    not(feature = "dnssec-digest"),
    doc = "
[`dnssec::verify_ds`]: crate#cargo-features
[`dnssec::nsec3_hash`]: crate#cargo-features"
)]
#![cfg_attr(feature = "tsig", doc = "[`tsig::HmacKey`]: tsig::HmacKey")]
#![cfg_attr(not(feature = "tsig"), doc = "[`tsig::HmacKey`]: crate#cargo-features")]
#![cfg_attr(
    feature = "tkey",
    doc = "
[`tkey::DhKeyPair`]: tkey::DhKeyPair
[`tkey::SharedKey`]: tkey::SharedKey"
)]
#![cfg_attr(
    not(feature = "tkey"),
    doc = "
[`tkey::DhKeyPair`]: crate#cargo-features
[`tkey::SharedKey`]: crate#cargo-features"
)]
#![cfg_attr(
    feature = "cookie-siphash",
    doc = "
[`edns::ServerCookie::generate`]: edns::ServerCookie::generate
[edns::ServerCookie::verify]: edns::ServerCookie::verify"
)]
#![cfg_attr(
    not(feature = "cookie-siphash"),
    doc = "
[`edns::ServerCookie::generate`]: crate#cargo-features
[edns::ServerCookie::verify]: crate#cargo-features"
)]
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(any(test, feature = "alloc"))]
extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate std;

#[macro_use]
mod macros;

pub mod builder;
pub mod charstr;
pub mod class;
pub mod dnssec;
pub mod dso;
pub mod edns;
mod error;
pub mod header;
pub mod message;
pub mod name;
pub mod notify;
#[cfg(feature = "alloc")]
pub mod owned;
pub mod rdata;
pub mod rtype;
#[cfg(feature = "serde")]
mod serde_impls;
pub mod sig0;
pub mod tcp;
pub mod text;
pub mod tkey;
pub mod tsig;
pub mod update;
mod util;
pub mod wire;
pub mod xfr;
pub mod zone;

pub use builder::{Checkpoint, MessageBuilder};
pub use charstr::CharStr;
pub use class::Class;
pub use error::{Error, Result};
pub use header::{Flags, Header, Opcode, Rcode};
pub use message::{Message, Question, Record, Section};
pub use name::{Label, Name, NameBuf, ToName};
#[cfg(feature = "alloc")]
pub use owned::{OwnedMessage, OwnedQuestion, OwnedRData, OwnedRecord};
pub use rdata::{ComposeRdata, ParseRdata, ParseRdataText, RData};
pub use rtype::Rtype;
pub use wire::{Composer, NameEncoding, OutBuf, WireReader, WireWriter};

#[cfg(test)]
pub(crate) mod testutil {
    use std::vec::Vec;

    /// Decodes a hex string (whitespace ignored).
    pub(crate) fn hex(s: &str) -> Vec<u8> {
        let digits: Vec<u8> = s
            .bytes()
            .filter(|b| !b.is_ascii_whitespace())
            .map(|b| (b as char).to_digit(16).expect("hex digit") as u8)
            .collect();
        digits.chunks(2).map(|p| p[0] << 4 | p[1]).collect()
    }
}

// Compile and run the README example as a doctest.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
