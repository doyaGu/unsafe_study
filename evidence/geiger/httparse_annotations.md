# httparse — Unsafe Hotspot Annotations

## Module 1: `src/simd/sse42.rs` — SSE4.2 Byte Scanning

**Unsafe items**: ~120 expressions (SIMD intrinsics)

This module implements vectorized URI and header-value character classification
using SSE4.2 intrinsics (`_mm_lddqu_si128`, `_mm_set1_epi8`, `_mm_cmpeq_epi8`,
`_mm_movemask_epi8`). Each function loads 16 bytes at a time from the input
buffer, builds bitmasks to classify which bytes are legal HTTP characters, and
returns how many consecutive valid bytes were found. The `unsafe` is inherent to
`core::arch::x86_64` intrinsics — there's no safe wrapper for these CPU
instructions. Alignment is not a concern here because `_mm_lddqu_si128`
(unaligned load) is used for the initial chunk, and the code never assumes
alignment beyond what `&[u8]` guarantees.

## Module 2: `src/simd/swar.rs` — SWAR Fallback

**Unsafe items**: ~80 expressions (pointer arithmetic + bitwise tricks)

SWAR ("SIMD Within A Register") uses `usize`-width integer reads to process
4 or 8 bytes at a time without actual SIMD instructions. The unsafe code
performs `read_unaligned` or raw pointer casts to load `usize`-sized chunks
from a `&[u8]` slice, then applies bitmask operations (e.g., checking if any
byte has bit 7 set, which would indicate non-ASCII) to classify characters in
bulk. This is the fallback when SSE4.2 is not available at runtime.

## Module 3: `src/lib.rs` — Core Parser

**Unsafe items**: ~48 expressions (pointer arithmetic, `Bytes` wrapper)

The core parsing loop in `lib.rs` uses a `Bytes` wrapper that tracks a raw
pointer position through the input slice. Functions like `parse_headers_iter`
advance this pointer while checking bounds, converting sub-slices to `&str`
via `from_utf8_unchecked` after byte-level validation has already confirmed
ASCII content. The unsafe is concentrated in the tight inner loops that scan
for delimiters (`:`, `\r\n`) and in converting validated byte spans to string
references without redundant UTF-8 checks.

## Summary

All `unsafe` in httparse is direct (no transitive dependencies contribute).
The code follows a common pattern in parsing libraries: SIMD fast path →
SWAR medium path → scalar slow path, all gated by runtime feature detection.
Miri found no UB, which is consistent with the code's careful use of unaligned
loads (`_mm_lddqu_si128`, `read_unaligned`) rather than aligned load intrinsics.
