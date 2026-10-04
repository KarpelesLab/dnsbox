//! Fuzz target: name decompression and name invariants (see
//! `dnsbox_fuzz::name`).
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dnsbox_fuzz::name(data));
