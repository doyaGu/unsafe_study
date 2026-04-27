#![no_main]

use libfuzzer_sys::fuzz_target;
use winnow::ascii::{dec_uint, multispace0};
use winnow::error::ContextError;
use winnow::prelude::*;
use winnow::token::{take_till, take_while};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let mut numeric = text;
    let _ = dec_uint::<_, u64, ContextError>.parse_next(&mut numeric);

    let mut spaced = text;
    let _ = multispace0::<_, ContextError>.parse_next(&mut spaced);

    let mut unicode = text;
    let _ = take_till::<_, _, ContextError>(0.., |c| c == '點').parse_next(&mut unicode);

    let mut hexish = text;
    let _ = take_while::<_, _, ContextError>(1.., ('0'..='9', 'A'..='F')).parse_next(&mut hexish);
});