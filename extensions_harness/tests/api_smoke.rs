use memchr::memmem;
use toml_parser::lexer::TokenKind;
use toml_parser::parser::{parse_document, RecursionGuard, ValidateWhitespace};
use toml_parser::Source;
use winnow::error::ContextError;
use winnow::ascii::{dec_uint, multispace0};
use winnow::prelude::*;
use winnow::token::{take_till, take_while};

fn naive_find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

#[test]
fn memchr_handles_unaligned_public_inputs() {
    let owned = b"Xheader:value\r\nfoo bar foo baz foo\0tail".to_vec();
    let haystack = &owned[1..owned.len() - 1];

    assert_eq!(memchr::memchr(b':', haystack), haystack.iter().position(|&b| b == b':'));
    assert_eq!(memchr::memrchr(b'o', haystack), haystack.iter().rposition(|&b| b == b'o'));
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
    assert_eq!(memmem::rfind(haystack, b"foo"), haystack.windows(3).rposition(|w| w == b"foo"));
}

#[test]
fn winnow_parses_ascii_and_unicode_boundaries() {
    let mut numeric = "12345 rest";
    let parsed: u64 = dec_uint::<_, _, ContextError>.parse_next(&mut numeric).unwrap();
    assert_eq!(parsed, 12345);
    assert_eq!(numeric, " rest");

    let mut spaced = " \t\nalpha";
    let ws = multispace0::<_, ContextError>.parse_next(&mut spaced).unwrap();
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
