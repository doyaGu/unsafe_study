#![no_main]

use libfuzzer_sys::fuzz_target;
use toml_edit::{value, Array, DocumentMut};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(mut doc) = text.parse::<DocumentMut>() {
        doc["study"]["mode"] = value("fuzz");
        doc["study"]["enabled"] = value(true);
        doc["study"]["cases"] = value(Array::from_iter(["a", "b", "c"]));
        doc["study"].as_inline_table_mut().map(|table| table.fmt());

        let rendered = doc.to_string();
        let _ = rendered.len();
    }
});