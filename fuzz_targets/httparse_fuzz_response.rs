#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz httparse response parsing.
fuzz_target!(|data: &[u8]| {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers);
    let _ = resp.parse(data);
});
