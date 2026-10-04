//! Fuzz target: every record type through the generic `RData` dispatch
//! (see `dnsbox_fuzz::rdata`).
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dnsbox_fuzz::rdata(data));
