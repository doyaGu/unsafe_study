#![no_main]

use bstr::ByteSlice;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for _ in data.graphemes() {}
    for _ in data.grapheme_indices() {}
});