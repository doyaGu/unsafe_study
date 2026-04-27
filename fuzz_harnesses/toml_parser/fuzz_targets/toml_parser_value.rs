#![no_main]

use libfuzzer_sys::fuzz_target;
use toml_parser::parser::parse_key;
use toml_parser::parser::parse_value;
use toml_parser::parser::Event;
use toml_parser::Source;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let source = Source::new(text);
    let tokens = source.lex().into_vec();

    let mut value_events = Vec::<Event>::new();
    let mut value_errors = Vec::new();
    parse_value(&tokens, &mut value_events, &mut value_errors);

    let mut key_events = Vec::<Event>::new();
    let mut key_errors = Vec::new();
    parse_key(&tokens, &mut key_events, &mut key_errors);

    let _ = value_events.len() + key_events.len();
    let _ = value_errors.len() + key_errors.len();
});