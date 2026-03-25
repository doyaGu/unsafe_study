# bstr — Unsafe Hotspot Annotations

## Module 1: `src/ascii.rs` — ASCII Detection (UB found here)

**Unsafe items**: ~90 expressions

Two parallel implementations for finding the first non-ASCII byte in a slice:

**Fallback path** (`first_non_ascii_byte_fallback`): Uses a "word-at-a-time"
strategy — casts a `*const u8` to `*const usize` and dereferences it to check
8 bytes simultaneously with `& ASCII_MASK`. The function attempts alignment:
after the first unaligned read via `read_unaligned_usize`, it bumps the pointer
to a `usize`-aligned boundary before entering the tight loop. *However*, the
Miri finding at line 80 (`*(ptr as *const usize)`) shows the pointer may not
actually be aligned when the loop body executes — this is the UB that Miri
flagged during `positive_fallback_forward`. The inner `findpos` function
performs the same cast pattern to re-read the failing chunk.

**SSE2 path** (`first_non_ascii_byte_sse2`): Uses `_mm_loadu_si128` (unaligned)
for the first chunk, then aligns the pointer and uses `_mm_load_si128` (aligned)
in the hot loop — following the same align-then-read-aligned pattern, but with
explicit SSE2 alignment requirements (16 bytes). This path is selected at
runtime on x86_64 when SSE2 is available.

## Module 2: `src/ext_slice.rs` / `src/ext_vec.rs` — Byte String Operations

**Unsafe items**: ~160 expressions

These modules implement the `ByteSlice` and `ByteVec` extension traits that
provide string-like operations on `&[u8]` and `Vec<u8>`. Key unsafe patterns:
- `str::from_utf8_unchecked()` after bstr's own validation confirms UTF-8.
- Unchecked slice indexing (`get_unchecked`) in hot paths where bounds have
  been pre-validated by iterators or length checks.
- Raw pointer manipulation for efficient in-place operations (e.g., replacing
  bytes, splitting at boundaries).
- `Vec::set_len()` after writing bytes into spare capacity.

## Module 3: `src/unicode/grapheme.rs` + `src/utf8.rs` — Unicode Handling

**Unsafe items**: ~60 expressions

UTF-8 decoding and grapheme cluster detection use unchecked byte access for
performance after validating byte-sequence structure. The `decode_utf8` function
reads leading/continuation bytes via `get_unchecked` after confirming the
expected byte counts from the leading byte pattern. Grapheme segmentation
iterates through decoded characters using these optimized decoder paths.

## Summary

bstr has the highest direct unsafe count (364 expressions) of the three crates.
The UB Miri found is in the fallback ASCII detection path — a fundamental
word-at-a-time optimization that casts byte pointers to usize pointers. Unlike
httparse's clean SWAR code that uses `read_unaligned`, bstr's fallback uses
`*(ptr as *const usize)` which requires alignment that may not hold. The SSE2
path in the same module correctly uses `_mm_loadu_si128` for the first read,
suggesting the fallback path may have been written before the aligned-read
pattern was fully adopted. The shared `memchr` dependency adds another 2111
unsafe items but was not reached in Miri testing (Miri aborted on the first UB).
