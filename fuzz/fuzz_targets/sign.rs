//! Fuzz target: TSIG and SIG(0) signing and tamper detection (see `dnsbox_fuzz::security::sign`).
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dnsbox_fuzz::security::sign(data));
