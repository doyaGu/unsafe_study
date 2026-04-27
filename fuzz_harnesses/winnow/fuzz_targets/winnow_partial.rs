#![no_main]

use libfuzzer_sys::fuzz_target;
use winnow::ascii::{dec_uint, multispace0};
use winnow::error::ContextError;
use winnow::prelude::*;
use winnow::Partial;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let mut numeric = Partial::new(text);
    let _ = dec_uint::<_, u64, ContextError>.parse_next(&mut numeric);

    let mut spaced = Partial::new(text);
    let _ = multispace0::<_, ContextError>.parse_next(&mut spaced);
});