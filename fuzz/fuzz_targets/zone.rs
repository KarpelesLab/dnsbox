//! Fuzz target: master files with $INCLUDE and $GENERATE, and ZONEMD collation (see `dnsbox_fuzz::security::zone`).
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dnsbox_fuzz::security::zone(data));
