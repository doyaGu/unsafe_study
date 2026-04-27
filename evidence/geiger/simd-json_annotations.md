# simd-json 0.17.0 - Hotspot Notes

## Intake Summary

- Version studied: `0.17.0`
- Local target: `targets/simd-json`
- Direct `unsafe` survey: ~504 `unsafe` source matches
- Harnesses:
  - `miri_harnesses/simd_json/tests/simd_json_triage.rs`
  - `targets/simd-json/tests/miri_triage.rs`

## Main Unsafe Concentration

- `src/lib.rs`
  - Core `Deserializer` construction and tape walking.
  - The key Miri failure site is `Deserializer::next_` at line 875:
    copying `Node<'de>` out of `Vec<Node<'de>>` with unchecked indexing.
- `src/stage2.rs`
  - Tape construction over de-escaped input.
  - Dense use of unchecked writes and parser-state mutation.
- `src/value/borrowed.rs`
  - Borrowed DOM construction from the tape.
  - `BorrowDeserializer::parse*` and `BorrowSliceDeserializer::next_` copy
    `Node<'de>` values that may contain borrowed `&str`.
- `src/value/owned.rs`
  - Same tape-walk pattern as borrowed mode, but converts strings into owned
    allocations after reading each node.

## Miri Triage Result

- `cargo test --offline --test simd_json_triage`: all 6 focused tests pass natively.
- Under `MIRIFLAGS='-Zmiri-strict-provenance'`, repeated borrowed-string paths
  fail with a Stacked Borrows / retag error.
- Numeric-only controls pass under the same flag.
- The crate-local repro gives the stronger provenance chain: Miri traces the
  string tag back to `src/stage2.rs` tape insertion before it is invalidated by
  a later Unique retag on the mutable input buffer.
- Root strings and single-string compounds are clean.
- In compounds with repeated string parses, the ordering effect appears:
  - first key in `{"a":1,"b":2}` fails, second key passes
  - first element in `["a","b"]` fails, second element passes
- This points to repeated `insert_str!()` calls invalidating earlier string
  nodes, not to object values specifically.
- The same pattern now reproduces without tape storage in `src/tests.rs`:
  the historical failing case retained two borrowed `&str` results from
  back-to-back `parse_str_` calls while rebuilding the raw input pointer each
  time.
- The concrete `parse_str` implementations return `&str` slices into the
  mutable input itself; the temporary buffer is only scratch space.
- An experimental mitigation in `src/stage2.rs` that caches one raw input
  pointer for all `insert_str!()` calls makes the tape-level and public-API Miri
  repros pass, which strongly implicates repeated `input.as_mut_ptr()`
  reborrows in the original failure.
- The internal `parse_str_` API was then refactored to take `SillyWrapper<'de>`
  directly, which makes single-wrapper reuse the natural internal call pattern.
- The active low-level tests now also follow that single-wrapper pattern and
  pass under Miri; the older repeated-reborrow failure is retained as a
  historical diagnostic log rather than an active code path.

## Current Classification

The failure is not limited to `to_borrowed_value`. The same retag pattern shows
up in:

- borrowed DOM parsing via `Deserializer::next_`
- owned DOM parsing via `Deserializer::next_`
- tape-backed string access via `Node::as_str`
- lazy upgrade from tape via `BorrowSliceDeserializer::next_`

The current evidence points to a string-reference issue in copied
`Node::String(&str)` tape entries rather than an alignment problem or a
borrowed-only API misuse.
