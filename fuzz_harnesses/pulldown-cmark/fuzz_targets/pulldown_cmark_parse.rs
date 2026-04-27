#![no_main]

use libfuzzer_sys::fuzz_target;
use pulldown_cmark::{html, Options, Parser};

fuzz_target!(|data: &[u8]| {
    let Ok(markdown) = std::str::from_utf8(data) else {
        return;
    };

    let parser = Parser::new_ext(markdown, Options::all());
    let mut html_output = String::new();
    html::push_html(&mut html_output, parser);
    let _ = html_output.len();
});