use toml_parser::lexer::TokenKind;
use toml_parser::parser::{parse_document, RecursionGuard, ValidateWhitespace};
use toml_parser::Source;

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
