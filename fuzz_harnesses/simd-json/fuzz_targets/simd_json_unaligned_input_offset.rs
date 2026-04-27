#![no_main]

use libfuzzer_sys::fuzz_target;
use simd_json::{prelude::{ValueAsScalar, ValueObjectAccess}, BorrowedValue};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mut owned = Vec::with_capacity(data.len() + 2);
    owned.push(b'X');
    owned.extend_from_slice(data);
    owned.push(b'Y');

    let end = owned.len() - 1;
    match simd_json::to_borrowed_value(&mut owned[1..end]) {
        Ok(value) => {
            let value: BorrowedValue = value;
            let _ = value.get("outer");
            if let Some(entry) = value.get("text") {
                let _ = entry.as_str();
            }
        }
        Err(_) => {}
    };
});