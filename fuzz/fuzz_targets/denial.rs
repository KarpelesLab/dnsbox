//! Fuzz target: NSEC/NSEC3 denial-of-existence proofs (see `dnsbox_fuzz::security::denial`).
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dnsbox_fuzz::security::denial(data));
