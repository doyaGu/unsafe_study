#![no_main]

use libfuzzer_sys::fuzz_target;
use simd_json::{prelude::{ValueAsScalar, ValueObjectAccess}, BorrowedValue};

fuzz_target!(|data: &[u8]| {
    let mut input = data.to_vec();
    match simd_json::to_borrowed_value(&mut input) {
        Ok(value) => {
            let value: BorrowedValue = value;
            let _ = value.get("outer");
            let _ = value.get("items");
            if let Some(entry) = value.get("text") {
                let _ = entry.as_str();
            }
        }
        Err(_) => {}
    };
});