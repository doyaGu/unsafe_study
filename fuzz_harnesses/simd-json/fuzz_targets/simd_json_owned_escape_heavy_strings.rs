#![no_main]

use libfuzzer_sys::fuzz_target;
use simd_json::{prelude::{ValueAsScalar, ValueObjectAccess}, OwnedValue};

fuzz_target!(|data: &[u8]| {
    let mut input = data.to_vec();
    if let Ok(value) = simd_json::to_owned_value(&mut input) {
        let value: OwnedValue = value;
        if let Some(entry) = value.get("text") {
            let _ = entry.as_str();
        }
        if let Some(entry) = value.get("emoji") {
            let _ = entry.as_str();
        }
        if let Some(entry) = value.get("path") {
            let _ = entry.as_str();
        }
    }
});