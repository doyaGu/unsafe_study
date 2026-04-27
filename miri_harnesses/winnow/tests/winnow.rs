use winnow::ascii::{dec_uint, multispace0};
use winnow::error::ContextError;
use winnow::prelude::*;
use winnow::token::{take_till, take_while};
use winnow::Partial;

#[test]
fn winnow_parses_ascii_and_unicode_boundaries() {
    let mut numeric = "12345 rest";
    let parsed: u64 = dec_uint::<_, _, ContextError>
        .parse_next(&mut numeric)
        .unwrap();
    assert_eq!(parsed, 12345);
    assert_eq!(numeric, " rest");

    let mut spaced = " \t\nalpha";
    let ws = multispace0::<_, ContextError>
        .parse_next(&mut spaced)
        .unwrap();
    assert_eq!(ws, " \t\n");
    assert_eq!(spaced, "alpha");

    let mut unicode = "abc點rest";
    let prefix = take_till::<_, _, ContextError>(0.., |c| c == '點')
        .parse_next(&mut unicode)
        .unwrap();
    assert_eq!(prefix, "abc");
    assert_eq!(unicode, "點rest");

    let mut hexish = "AB12-zzz";
    let matched = take_while::<_, _, ContextError>(1.., ('0'..='9', 'A'..='F'))
        .parse_next(&mut hexish)
        .unwrap();
    assert_eq!(matched, "AB12");
    assert_eq!(hexish, "-zzz");
}

#[test]
fn winnow_handles_partial_numeric_and_whitespace_input() {
    let mut numeric = Partial::new("98765 ");
    let parsed: u64 = dec_uint::<_, _, ContextError>
        .parse_next(&mut numeric)
        .unwrap();
    assert_eq!(parsed, 98765);
    assert_eq!(numeric.into_inner(), " ");

    let mut spaced = Partial::new(" \t\r\nvalue");
    let ws = multispace0::<_, ContextError>
        .parse_next(&mut spaced)
        .unwrap();
    assert_eq!(ws, " \t\r\n");
    assert_eq!(spaced.into_inner(), "value");
}

#[test]
fn winnow_parses_nested_delimited_segments() {
    let mut nested = "[alpha|beta|gamma] trailing";
    let content = ('[', take_till::<_, _, ContextError>(0.., |c| c == ']'), ']')
        .parse_next(&mut nested)
        .unwrap();

    assert_eq!(content.1, "alpha|beta|gamma");
    assert_eq!(nested, " trailing");
}
