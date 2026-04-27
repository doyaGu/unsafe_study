#![no_main]

use libfuzzer_sys::fuzz_target;
use memchr::memmem;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    for offset in [0usize, 1, 2] {
        if offset >= data.len() {
            continue;
        }
        let haystack = &data[offset..];
        let byte = haystack[0];
        let _ = memchr::memchr(byte, haystack);
        let _ = memchr::memrchr(byte, haystack);

        let needle_len = haystack.len().min(8);
        let needle = &haystack[..needle_len];
        let finder = memmem::Finder::new(needle);
        let _ = finder.find(haystack);
        let _ = memmem::rfind(haystack, needle);
    }
});