#![no_main]

use libfuzzer_sys::fuzz_target;
use toml_edit::DocumentMut;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(doc) = text.parse::<DocumentMut>() {
        let rendered = doc.to_string();
        let _ = rendered.len();
    }
});