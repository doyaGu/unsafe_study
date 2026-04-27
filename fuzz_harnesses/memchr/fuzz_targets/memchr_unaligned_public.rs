#![no_main]

use libfuzzer_sys::fuzz_target;
use memchr::memmem;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    let mut owned = Vec::with_capacity(data.len() + 2);
    owned.push(0);
    owned.extend_from_slice(data);
    owned.push(0xff);

    let haystack = &owned[1..owned.len() - 1];
    let _ = memchr::memchr(b':', haystack);
    let _ = memchr::memrchr(b'\n', haystack);
    let _ = memchr::memchr2(b'\r', b'\n', haystack);
    let _ = memchr::memchr3(b'f', b'b', b'z', haystack);

    let needle = &haystack[..haystack.len().min(3)];
    let finder = memmem::Finder::new(needle);
    let _ = finder.find(haystack);
    let _ = memmem::rfind(haystack, needle);
});