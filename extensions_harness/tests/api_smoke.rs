use bstr::ByteSlice;
use memchr::memmem;
use serde_json::{Deserializer, Value};
use toml_parser::lexer::TokenKind;
use toml_parser::parser::{parse_document, RecursionGuard, ValidateWhitespace};
use toml_parser::Source;
use winnow::ascii::{dec_uint, multispace0};
use winnow::error::ContextError;
use winnow::prelude::*;
use winnow::token::{take_till, take_while};
use winnow::Partial;

fn naive_find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[test]
fn memchr_handles_unaligned_public_inputs() {
    let owned = b"Xheader:value\r\nfoo bar foo baz foo\0tail".to_vec();
    let haystack = &owned[1..owned.len() - 1];

    assert_eq!(
        memchr::memchr(b':', haystack),
        haystack.iter().position(|&b| b == b':')
    );
    assert_eq!(
        memchr::memrchr(b'o', haystack),
        haystack.iter().rposition(|&b| b == b'o')
    );
    assert_eq!(
        memchr::memchr2(b'\r', b'\n', haystack),
        haystack.iter().position(|&b| b == b'\r' || b == b'\n')
    );
    assert_eq!(
        memchr::memchr3(b'f', b'b', b'z', haystack),
        haystack
            .iter()
            .position(|&b| b == b'f' || b == b'b' || b == b'z')
    );

    let finder = memmem::Finder::new(b"foo");
    assert_eq!(finder.find(haystack), naive_find(haystack, b"foo"));
    assert_eq!(
        memmem::rfind(haystack, b"foo"),
        haystack.windows(3).rposition(|w| w == b"foo")
    );
}

#[test]
fn memchr_memmem_handles_edge_needles() {
    let haystack = b"\0foofoo\0barbazfoo";

    assert_eq!(memmem::find(haystack, b""), Some(0));
    assert_eq!(memmem::find(haystack, b"foo"), Some(1));
    assert_eq!(memmem::rfind(haystack, b"foo"), Some(14));

    let finder = memmem::Finder::new(b"bar");
    assert_eq!(finder.find(haystack), Some(8));
}

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

#[test]
fn serde_json_streams_multiple_values() {
    let mut stream = Deserializer::from_str(r#"{"x":1} {"x":2} [3,4]"#).into_iter::<Value>();

    assert_eq!(stream.next().unwrap().unwrap()["x"], 1);
    assert_eq!(stream.next().unwrap().unwrap()["x"], 2);
    assert_eq!(stream.next().unwrap().unwrap()[0], 3);
    assert!(stream.next().is_none());
}

#[test]
fn serde_json_handles_escape_and_number_edges() {
    let cases = [
        br#"{"text":"line\nbreak","value":-0.0,"exp":1e-9}"#.as_slice(),
        br#"["\uD83D\uDE00",18446744073709551615,-9223372036854775808]"#.as_slice(),
        br#"{"nested":{"arr":[0,1,2,3],"unicode":"\u2603"}}"#.as_slice(),
    ];

    for input in cases {
        let parsed = serde_json::from_slice::<Value>(input);
        assert!(parsed.is_ok(), "failed to parse {:?}", input);
    }
}

#[test]
fn bstr_ascii_boundary_offsets() {
    let owned = b"Xascii only line\nsecond line\xfftail".to_vec();
    let slice = &owned[1..owned.len() - 1];

    assert_eq!(slice.find_byte(b'\n'), Some(15));
    assert!(slice.lines().count() >= 2);
    assert!(slice.fields().count() >= 4);
    assert!(slice.to_str().is_err());
}

#[test]
fn bstr_invalid_utf8_search_and_trim() {
    let owned = b" \talpha\xffbeta  ".to_vec();
    let slice = &owned[1..owned.len() - 1];

    assert_eq!(slice.trim_start().as_bytes(), b"alpha\xffbeta ");
    assert_eq!(slice.trim_end().as_bytes(), b"\talpha\xffbeta");
    assert_eq!(slice.find("beta"), Some(7));
    assert_eq!(slice.rfind_byte(b'a'), Some(10));
}

#[test]
fn bstr_grapheme_iteration_and_reverse_search() {
    let text = "a\u{0300}\u{0316} 🇺🇸 z";
    let bytes = text.as_bytes();
    let graphemes: Vec<_> = bytes.graphemes().collect();
    let grapheme_indices: Vec<_> = bytes.grapheme_indices().collect();

    assert!(graphemes.len() >= 3);
    assert_eq!(graphemes.len(), grapheme_indices.len());
    assert_eq!(bytes.rfind("z"), Some(text.len() - 1));
}

#[test]
fn toml_parser_lexes_and_parses_nested_inputs() {
    let cases = [
        "\u{feff}title = \"hello\"\narr = [1, 2, 3]\n",
        "[table]\nkey = '''multi\nline'''\nflag = true\n",
        "path = \"C:\\\\tmp\"\ninvalid = \"\\u00ZZ\"\n",
        "deep = [[[{ value = [1, { nested = \"ok\" }] }]]]\n",
    ];

    for input in cases {
        let source = Source::new(input);
        let tokens = source.lex().into_vec();
        assert!(!tokens.is_empty());
        assert_eq!(tokens.last().map(|t| t.kind()), Some(TokenKind::Eof));

        let mut events = Vec::new();
        let mut errors = Vec::new();
        let mut receiver = |event| events.push(event);
        let mut whitespace = ValidateWhitespace::new(&mut receiver, Source::new(input));
        let mut guard = RecursionGuard::new(&mut whitespace, 32);
        parse_document(&tokens, &mut guard, &mut errors);

        assert!(!events.is_empty());
        assert!(errors.len() <= tokens.len());
    }
}

#[test]
fn toml_parser_handles_multiline_strings() {
    let input = "[table]\nkey = '''multi\nline'''\nflag = true\n";
    let source = Source::new(input);
    let tokens = source.lex().into_vec();

    assert_eq!(tokens.last().map(|t| t.kind()), Some(TokenKind::Eof));

    let mut events = Vec::new();
    let mut errors = Vec::new();
    let mut receiver = |event| events.push(event);
    let mut whitespace = ValidateWhitespace::new(&mut receiver, Source::new(input));
    let mut guard = RecursionGuard::new(&mut whitespace, 32);
    parse_document(&tokens, &mut guard, &mut errors);

    assert!(!events.is_empty());
    assert!(errors.is_empty());
}

#[test]
fn toml_parser_tracks_invalid_escape_errors() {
    let input = "path = \"C:\\\\tmp\"\ninvalid = \"\\u00ZZ\"\n";
    let source = Source::new(input);
    let tokens = source.lex().into_vec();
    let invalid = tokens
        .iter()
        .find(|token| {
            token.kind() == TokenKind::BasicString
                && source.get(*token).unwrap().as_str() == "\"\\u00ZZ\""
        })
        .copied()
        .expect("invalid basic string token");
    let raw = source.get(invalid).expect("raw invalid string");
    let mut decoded = String::new();
    let mut errors = Vec::new();
    let kind = raw.decode_scalar(&mut decoded, &mut errors);

    assert_eq!(kind, toml_parser::decoder::ScalarKind::String);
    assert!(!errors.is_empty());
}
