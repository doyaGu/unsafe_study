#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::{Deserializer, Value};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let mut stream = Deserializer::from_str(text).into_iter::<Value>();
    for _ in 0..8 {
        match stream.next() {
            Some(Ok(value)) => {
                let _ = value.is_array();
                let _ = value.is_object();
                let _ = value.as_str();
            }
            Some(Err(error)) => {
                let _ = error.classify();
                let _ = error.line();
                let _ = error.column();
                break;
            }
            None => break,
        }
    }
});