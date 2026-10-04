//! Fuzz target: build → parse identity of builder-generated messages (see
//! `dnsbox_fuzz::roundtrip`).
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dnsbox_fuzz::roundtrip(data));
