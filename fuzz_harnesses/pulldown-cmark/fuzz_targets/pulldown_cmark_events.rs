#![no_main]

use libfuzzer_sys::fuzz_target;
use pulldown_cmark::{Options, Parser, TextMergeStream};

fuzz_target!(|data: &[u8]| {
    let Ok(markdown) = std::str::from_utf8(data) else {
        return;
    };

    for event in TextMergeStream::new(Parser::new_ext(markdown, Options::all())) {
        let _ = format!("{event:?}").len();
    }
});