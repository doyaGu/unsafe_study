#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz httparse request parsing with arbitrary byte input.
// httparse::Request::parse is the main input-facing API and contains direct
// unsafe code for SIMD-accelerated header scanning.
fuzz_target!(|data: &[u8]| {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    let _ = req.parse(data);
});
