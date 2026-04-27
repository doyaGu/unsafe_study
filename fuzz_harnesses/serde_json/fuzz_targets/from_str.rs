#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::{from_str, Value};

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        _ = from_str::<Value>(text);
    }
});