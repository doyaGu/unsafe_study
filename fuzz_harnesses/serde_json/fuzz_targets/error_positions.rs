#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::{from_str, Value};

fn touch_error_path(candidate: &str) {
    if let Err(error) = from_str::<Value>(candidate) {
        let _ = error.classify();
        let _ = error.line();
        let _ = error.column();
        let _ = error.to_string();
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    touch_error_path(text);

    if !text.is_empty() {
        let mut split = text.len() / 2;
        while split > 0 && !text.is_char_boundary(split) {
            split -= 1;
        }
        touch_error_path(&text[..split]);
    }

    let mut malformed = String::with_capacity(text.len() + 3);
    malformed.push_str(text);
    malformed.push('\n');
    malformed.push('{');
    touch_error_path(&malformed);
});