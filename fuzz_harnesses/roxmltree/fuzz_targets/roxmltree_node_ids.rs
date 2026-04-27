#![no_main]

use libfuzzer_sys::fuzz_target;
use roxmltree::Document;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(doc) = Document::parse(text) {
        for node in doc.descendants() {
            let id = node.id();
            if let Some(again) = doc.get_node(id) {
                let _ = again.node_type();
                let _ = again.parent();
                let _ = again.parent_element();
                let _ = again.ancestors().count();
                let _ = again.prev_siblings().count();
                let _ = again.next_siblings().count();
                if again.is_element() {
                    let _ = again.attribute("id");
                    let _ = again.lookup_namespace_uri(None);
                }
            }
        }
    }
});