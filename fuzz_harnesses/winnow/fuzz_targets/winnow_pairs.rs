#![no_main]

use libfuzzer_sys::fuzz_target;
use winnow::error::ContextError;
use winnow::prelude::*;
use winnow::token::{take_till, take_while};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let mut nested = text;
    let _ = ('[', take_till::<_, _, ContextError>(0.., |c| c == ']'), ']')
        .parse_next(&mut nested);

    let mut pairish = text;
    let _ = (
        take_while::<_, _, ContextError>(0.., ('a'..='z', 'A'..='Z')),
        ':',
        take_till::<_, _, ContextError>(0.., |c| c == '\n'),
    )
        .parse_next(&mut pairish);
});