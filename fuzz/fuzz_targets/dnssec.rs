//! Fuzz target: the DNSSEC signature backend and the chain of trust (see `dnsbox_fuzz::security::dnssec`).
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dnsbox_fuzz::security::dnssec(data));
