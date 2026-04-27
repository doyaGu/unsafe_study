# winnow — Unsafe Hotspot Annotations

This extension pass used a manual offline hotspot survey (`rg "unsafe"`) rather
than a fresh `cargo-geiger` run because `cargo-geiger` is not installed in this
environment.

## Module 1: `src/stream/mod.rs` — Core Stream Slicing

**Unsafe items**: ~14 occurrences

This is the central abstraction behind winnow's zero-copy parsing model. The
unsafe operations are unchecked slice splits (`get_unchecked(..offset)`,
`get_unchecked(offset..)`) used after parser combinators have established that
the offset is in range and, for string streams, on a UTF-8 boundary. These
helpers are then reused by the higher-level stream wrappers.

## Module 2: `src/stream/bytes.rs` / `src/stream/bstr.rs` — Raw Byte Views

**Unsafe items**: ~12 occurrences combined

These wrappers expose byte-oriented stream views and convert between slice
representations with `transmute` and unchecked slicing. The pattern is typical
for parser libraries: preserve zero-copy behavior while pushing the boundary
checks to the combinator layer that computed the slice length.

## Module 3: `src/ascii/mod.rs` — ASCII Numeric/Text Parsers

**Unsafe items**: ~2 occurrences

The main noteworthy unsafe here is `from_utf8_unchecked` when decoding ASCII
digits after the parser has already constrained the accepted token set to
7-bit ASCII. This is a small count but a high-value hotspot because it is
reached through very common public APIs such as `dec_uint`.

## Summary

winnow's unsafe is modest and concentrated in stream slicing primitives. The
extension harness exercised `multispace0`, `dec_uint`, `take_till`, and
`take_while` over ASCII and Unicode inputs, and Miri reported no issues under
strict alignment and provenance checking.
