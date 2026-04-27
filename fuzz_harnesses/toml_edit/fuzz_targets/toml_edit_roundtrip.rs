#![no_main]

use libfuzzer_sys::fuzz_target;
use toml_edit::{value, Array, DocumentMut};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(mut doc) = text.parse::<DocumentMut>() {
        doc["package"]["version"] = value("0.1.0");
        doc["features"]["default"] = value(Array::from_iter(["base"]));
        doc["features"]["extra"] = value(Array::from_iter(["b", "c"]));

        let rendered = doc.to_string();
        if let Ok(reparsed) = rendered.parse::<DocumentMut>() {
            let _ = reparsed.to_string().len();
            let _ = reparsed["package"]["version"].as_str();
            let _ = reparsed["features"]["extra"].as_array().map(|array| array.len());
        }
    }
});