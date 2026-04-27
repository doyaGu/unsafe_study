#![no_main]

use bstr::{decode_utf8, ByteSlice};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = data.to_str();
    let _ = data.to_str_lossy();
    let mut index = 0;
    while index < data.len() {
        let (_, size) = decode_utf8(&data[index..]);
        index += size.max(1);
    }
});