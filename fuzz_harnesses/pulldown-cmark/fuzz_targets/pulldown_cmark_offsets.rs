#![no_main]

use libfuzzer_sys::fuzz_target;
use pulldown_cmark::{Options, Parser};

fuzz_target!(|data: &[u8]| {
    let Ok(markdown) = std::str::from_utf8(data) else {
        return;
    };

    let mut total_span = 0usize;
    for (event, range) in Parser::new_ext(markdown, Options::all()).into_offset_iter() {
        total_span = total_span.wrapping_add(range.end.saturating_sub(range.start));
        let _ = format!("{event:?}").len();
    }
    let _ = total_span;
});