# memchr — Unsafe Hotspot Annotations

This extension pass used a manual offline hotspot survey (`rg "unsafe"`) rather
than a fresh `cargo-geiger` run because `cargo-geiger` is not installed in this
environment.

## Module 1: `src/arch/x86_64/avx2/memchr.rs` — AVX2 Search Kernels

**Unsafe items**: ~44 occurrences

This is the hottest x86_64 path for single-byte and multi-byte search. The code
constructs vector searchers, dispatches to AVX2 or SSE2 implementations, and
walks raw start/end pointers across the haystack. The unsafe is dominated by
SIMD intrinsics, raw-pointer range traversal, and assumptions about the
caller-provided pointer pair in `find_raw`/`rfind_raw`/`count_raw`.

## Module 2: `src/arch/x86_64/sse2/memchr.rs` — SSE2 Fallback Kernels

**Unsafe items**: ~37 occurrences

This mirrors the AVX2 logic for CPUs that only expose SSE2. The pattern is the
same: construct a vectorized searcher, align the scan window numerically, and
perform raw-pointer scanning with explicit intrinsic loads. This is the code
path most relevant to the earlier serde_json false-positive report because it
contains the aligned-load helpers used by memchr's vector layer.

## Module 3: `src/vector.rs` — Cross-Architecture Vector Abstraction

**Unsafe items**: ~37 occurrences

This module centralizes vector operations across x86_64, aarch64, and wasm32:
aligned and unaligned loads, comparisons, masks, and boolean vector ops. The
unsafe here is structural rather than algorithmic; it exists because the trait
surface is a thin layer over architecture intrinsics that have no safe API.

## Summary

memchr's unsafe is broad but disciplined: most of it is concentrated in
vectorized search backends and their raw-pointer front ends. A focused Miri run
through `miri_harnesses` executed memchr's public API on deliberately
unaligned slices and remained clean under
`-Zmiri-symbolic-alignment-check -Zmiri-strict-provenance`.
