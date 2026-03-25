#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz bstr's BStr operations with arbitrary bytes.
// bstr has unsafe code for working with byte strings that may or may not be UTF-8.
fuzz_target!(|data: &[u8]| {
    use bstr::ByteSlice;

    // Exercise key bstr APIs that touch unsafe code
    let _ = data.to_str();
    let _ = data.to_str_lossy();

    // Find/split operations that use SIMD-accelerated unsafe code
    let _ = data.find_byte(b'\n');
    let _ = data.rfind_byte(b'\n');
    let _ = data.find(b"needle");

    // Lines iterator
    for _line in data.lines() {}

    // Word/grapheme iteration touches unsafe boundary logic
    for _word in data.words() {}
});
