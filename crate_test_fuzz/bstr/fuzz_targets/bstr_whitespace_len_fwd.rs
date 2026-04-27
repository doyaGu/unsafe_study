#![no_main]

use bstr::ByteSlice;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = data.trim();
    let _ = data.trim_start();
    let _ = data.trim_end();
    for _ in data.fields() {}
});