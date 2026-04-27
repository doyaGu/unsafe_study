#![no_main]

use libfuzzer_sys::fuzz_target;
use roxmltree::Document;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(doc) = Document::parse(text) {
        let input = doc.input_text();
        let _ = input.len();

        for node in doc.descendants() {
            let range = node.range();
            let _ = doc.text_pos_at(range.start);
            let _ = doc.text_pos_at(range.end);
            let _ = input.get(range.clone());
            let _ = node.text();
            let _ = node.tail();
        }
    }
});