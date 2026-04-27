#![no_main]

use libfuzzer_sys::fuzz_target;
use roxmltree::Document;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(doc) = Document::parse(text) {
        let root = doc.root_element();
        let _ = root.tag_name().name();
        let _ = root.default_namespace();

        let mut last_element = None;
        for child in root.children() {
            let _ = child.is_element();
            let _ = child.is_text();
            let _ = child.text();
            let _ = child.tail();

            if child.is_element() {
                let _ = child.tag_name().name();
                let _ = child.attribute("id");
                let _ = child.has_siblings();
                last_element = Some(child);
            }
        }

        if let Some(first) = root.first_element_child() {
            let _ = first.next_sibling_element();
            let _ = first.parent_element();
        }
        if let Some(last) = last_element {
            let _ = last.prev_sibling_element();
            let _ = last.parent();
        }
    }
});