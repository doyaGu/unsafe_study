#![no_main]

use bstr::ByteSlice;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let needle = data[0];
    let _ = data.find_byte(needle);
    let _ = data.find(&[needle, needle]);
    let _ = data.find_not_byteset(&[needle]);
});