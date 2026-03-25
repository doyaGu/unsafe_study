#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz serde_json deserialization from arbitrary bytes.
// Inner unsafe in serde_json's number parsing and string indexing.
fuzz_target!(|data: &[u8]| {
    // Try parsing as serde_json::Value (accepts any valid JSON structure)
    let _ = serde_json::from_slice::<serde_json::Value>(data);
});
