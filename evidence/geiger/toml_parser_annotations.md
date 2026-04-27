# toml_parser — Unsafe Hotspot Annotations

This extension pass used a manual offline hotspot survey (`rg "unsafe"`) rather
than a fresh `cargo-geiger` run because `cargo-geiger` is not installed in this
environment.

## Module 1: `src/lexer/mod.rs` — Token Scanning Fast Paths

**Unsafe items**: ~70 occurrences

toml_parser gates unsafe behind its `unsafe` feature. The lexer is the dominant
hotspot: it advances through `LocatingSlice<&str>` with
`next_slice_unchecked(offset)` after matching ASCII delimiters, whitespace, and
comment boundaries that guarantee the offset is valid and on a UTF-8 boundary.
This is the core performance tradeoff in the crate.

## Module 2: `src/decoder/string.rs` — String Escape Decoding

**Unsafe items**: ~27 occurrences

String decoding uses unchecked slicing when the parser has already identified a
valid escape span or boundary class. The unsafe code is mostly about avoiding
repeated UTF-8 boundary checks while walking TOML escape sequences and multiline
string continuations.

## Module 3: `src/source.rs` — Span-to-Source Projection

**Unsafe items**: ~26 occurrences

This module translates validated `Span` values back into `Raw<'_>` views over
the original source text. The unsafe surface is `get_unchecked`-style access:
once the parser or lexer has established a span, this layer turns it into a raw
string slice without re-checking bounds.

## Summary

toml_parser is unusual in this study because unsafe is opt-in rather than
default. The extension harness enabled the `unsafe` feature, then lexed and
parsed nested, multiline, BOM-prefixed, and malformed TOML inputs using
`Source::lex` and `parse_document`. Miri reported no violations under
`-Zmiri-symbolic-alignment-check -Zmiri-strict-provenance`.
