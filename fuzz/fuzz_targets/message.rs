//! Fuzz target: whole-message parsing, iteration, validation and
//! parse → build → parse identity (see `dnsbox_fuzz::message`).
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dnsbox_fuzz::message(data));
