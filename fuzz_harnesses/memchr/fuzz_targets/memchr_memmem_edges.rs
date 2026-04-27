#![no_main]

use libfuzzer_sys::fuzz_target;
use memchr::memmem;

fuzz_target!(|data: &[u8]| {
    let split = data.first().copied().unwrap_or(0) as usize;
    let split = if data.is_empty() { 0 } else { split % data.len() };
    let (needle, haystack) = data.split_at(split);

    let _ = memmem::find(haystack, b"");
    let _ = memmem::find(haystack, needle);
    let _ = memmem::rfind(haystack, needle);

    let prefix_len = needle.len().min(4);
    let prefix = &needle[..prefix_len];
    let finder = memmem::Finder::new(prefix);
    let _ = finder.find(haystack);
    let _ = finder.find_iter(haystack).count();
});