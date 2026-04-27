#![no_main]

use libfuzzer_sys::fuzz_target;
use toml_parser::parser::parse_document;
use toml_parser::parser::Event;
use toml_parser::Source;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let source = Source::new(text);
    let tokens = source.lex().into_vec();
    let mut events = Vec::<Event>::new();
    let mut errors = Vec::new();

    parse_document(&tokens, &mut events, &mut errors);

    let _ = events.len();
    let _ = errors.len();
});