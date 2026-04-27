#![no_main]

use libfuzzer_sys::fuzz_target;
use toml_parser::lexer::TokenKind;
use toml_parser::Source;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let source = Source::new(text);
    let tokens = source.lex().into_vec();
    let mut errors = Vec::new();
    let mut output = String::new();

    for token in tokens {
        let Some(raw) = source.get(token.span()) else {
            continue;
        };
        output.clear();

        match token.kind() {
            TokenKind::LiteralString
            | TokenKind::BasicString
            | TokenKind::MlLiteralString
            | TokenKind::MlBasicString
            | TokenKind::Atom => {
                let _ = raw.decode_scalar(&mut output, &mut errors);
                raw.decode_key(&mut output, &mut errors);
            }
            TokenKind::Comment => raw.decode_comment(&mut errors),
            TokenKind::Newline => raw.decode_newline(&mut errors),
            TokenKind::Whitespace => raw.decode_whitespace(&mut errors),
            TokenKind::Dot
            | TokenKind::Equals
            | TokenKind::Comma
            | TokenKind::LeftSquareBracket
            | TokenKind::RightSquareBracket
            | TokenKind::LeftCurlyBracket
            | TokenKind::RightCurlyBracket
            | TokenKind::Eof => {
                let _ = raw.as_bytes();
            }
        }
    }

    let _ = errors.len();
});