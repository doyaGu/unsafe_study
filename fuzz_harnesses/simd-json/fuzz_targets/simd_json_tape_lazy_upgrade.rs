#![no_main]

use libfuzzer_sys::fuzz_target;
use simd_json::prelude::{ValueAsScalar, ValueObjectAccess};

fuzz_target!(|data: &[u8]| {
    let mut input = data.to_vec();
    if let Ok(tape) = simd_json::to_tape(&mut input) {
        let root = tape.as_value();
        let _ = root.get("outer");
        let _ = root.get("items");
        if let Some(entry) = root.get("text") {
            let _ = entry.as_str();
        }

        let lazy = simd_json::value::lazy::Value::from_tape(root);
        let value = lazy.into_value();
        let _ = value.get("outer");
        let _ = value.get("items");
        if let Some(entry) = value.get("text") {
            let _ = entry.as_str();
        }
    }
});