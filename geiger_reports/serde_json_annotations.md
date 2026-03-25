# serde_json — Unsafe Hotspot Annotations

## Module 1: `src/read.rs` — Fast JSON Scanning & String Decoding

**Unsafe items**: ~35 expressions

The `SliceRead` and `StrRead` implementations use raw pointer arithmetic to
scan JSON input efficiently. Key patterns:
- `offset_from()` computes byte offsets between chunk addresses and slice starts
  for fast position tracking during error reporting.
- `str::from_utf8_unchecked()` converts byte slices to `&str` after the decoder
  has already validated UTF-8 correctness byte-by-byte during string parsing.
- Manual scratch-buffer pointer manipulation (`as_mut_ptr().add(len)`) to append
  encoded Unicode codepoints without bounds re-checking, relying on prior length
  guarantees (encoded UTF-8 is always ≤ 4 bytes).

This is where the Miri-detected UB manifests: `position_of_index` calls
`memchr::memrchr` to locate newlines for error line/column reporting, which
triggers the SSE2 aligned-load violation in memchr.

## Module 2: `src/ser.rs` — Fast Serialization

**Unsafe items**: ~25 expressions

The serializer converts known-valid internal byte buffers to strings via
`str::from_utf8_unchecked()` and `String::from_utf8_unchecked()`. These
calls skip UTF-8 validation on output that serde_json itself generated
character-by-character. Additionally, `hint::unreachable_unchecked()` is used
in the escape-character dispatch to eliminate a branch the compiler can't prove
dead (the escape table only contains specific character types, so the default
arm is unreachable by construction).

## Module 3: `src/raw.rs` — RawValue Transmutation

**Unsafe items**: ~15 expressions

`RawValue` is a `#[repr(transparent)]` wrapper around `str`, which makes
`mem::transmute::<&str, &RawValue>()` and the `Box` equivalents sound. These
transmutes allow zero-cost conversion between validated JSON strings and the
`RawValue` type without allocation or copying. The safety invariant is that the
inner `str` is always valid JSON — this is enforced by the constructor, not by
the transmute itself.

## Summary

serde_json's direct unsafe is moderate (75 expressions) and follows well-
established patterns: skip-redundant-validation via `from_utf8_unchecked`,
transparent newtype transmutes, and pointer arithmetic in hot paths. The real
unsafe volume comes from dependencies — memchr alone contributes 2111 unsafe
items. The Miri UB finding is in memchr's SSE2 `load_aligned` path, triggered
via serde_json's error-position calculation, not in serde_json's own unsafe code.
