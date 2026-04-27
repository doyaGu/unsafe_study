#![no_main]

use bstr::ByteSlice;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let needle = *data.last().unwrap();
    let _ = data.rfind_byte(needle);
    let _ = data.rfind(&[needle, needle]);
    let _ = data.rfind_not_byteset(&[needle]);
});