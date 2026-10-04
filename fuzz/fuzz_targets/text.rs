//! Fuzz target: presentation-format parsing (see `dnsbox_fuzz::text`).
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dnsbox_fuzz::text(data));
