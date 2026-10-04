//! Fuzz target: OPT RDATA framing and every typed EDNS(0) option
//! (see `dnsbox_fuzz::edns`).
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dnsbox_fuzz::edns(data));
