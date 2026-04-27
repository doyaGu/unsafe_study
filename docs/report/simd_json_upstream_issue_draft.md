# simd-json 0.17.0 - Upstream Issue Draft

## Proposed title

`parse_str_` / tape string paths trip Miri Stacked Borrows on repeated string parsing from one mutable input buffer

## Scope

Studied target:

- `targets/simd-json` copied from crates.io, version `0.17.0`

Local study status:

- `cargo test --offline` for the local target is fully green
- upstream `jsonchecker` fixtures were restored under `targets/simd-json/data/`
- crate-local focused Miri triage is green after a local pointer-reuse mitigation

This draft does **not** claim a confirmed real-world crash. The current claim is
more limited:

- older `simd-json` string-bearing paths reproducibly triggered Miri
  Stacked Borrows / retag failures
- the failure pattern narrowed to repeated parsing of borrowed strings from the
  same mutable input buffer
- a local mitigation that reuses one input handle per parse flow makes the
  active Miri repros clean

## Summary

While studying `simd-json` under Miri with
`MIRIFLAGS='-Zmiri-strict-provenance'`, string-bearing parse paths originally
failed with retag errors in:

- `src/lib.rs` (`Deserializer::next_`)
- `src/value/tape.rs` (`Node::as_str`)
- `src/value/borrowed.rs` (`BorrowSliceDeserializer::next_`)

The failure was narrowed to a repeated-borrowed-string pattern:

- numeric-only controls pass
- root-string and single-string control cases pass
- earlier strings in a compound container fail after a later string parse on
  the same mutable input buffer

Examples from the crate-local triage:

- `{"a":1,"b":2}`: first key failed, second key passed
- `["a","b"]`: first string failed, second string passed

This suggests that later string parses on the same mutable input may invalidate
earlier borrowed `&str` results under Miri's model.

## Why this looked suspicious

The concrete `parse_str` implementations return `&str` slices into the mutable
input buffer itself. Even escaped strings are normalized back into that same
input region before the `&str` is returned.

That means repeated string parsing is not returning independently stored string
data. It is returning multiple borrowed slices into one mutable input buffer
that continues to be reused.

## Smallest observed pattern

The strongest historical low-level reduction was below the tape layer:

- call `parse_str_` twice on the same mutable input
- reconstruct a fresh raw input handle from that `&mut [u8]` each time
- keep both returned borrowed `&str` values alive

Under Miri, the first borrowed string was then reported as invalidated by the
later retag/reborrow.

The study retains the old failing log here:

- `evidence/miri/simd_json_parse_str_tuple_fail.log`

## Local mitigation that made the repros clean

Two local changes were enough to make the active `simd-json` Miri repros pass:

1. In `src/stage2.rs`, cache one input handle for the `build_tape` flow instead
   of rebuilding it inside every `insert_str!()` call.
2. Make the internal `parse_str_` API take `SillyWrapper<'de>` directly, so the
   internal call pattern naturally becomes "obtain once, reuse many times".

After that:

- `targets/simd-json/tests/miri_triage.rs` passed fully under Miri
- `miri_harnesses/simd_json/tests/simd_json_triage.rs` passed fully under Miri
- the low-level `src/tests.rs` `parse_str_store_in_tuple*` tests also passed
  once they reused one input wrapper per buffer

## Reproduction commands

### Historical failing shape

The historical failing log is already captured in:

- `evidence/miri/simd_json_parse_str_tuple_fail.log`

### Current crate-local focused triage

```bash
cd targets/simd-json
env MIRIFLAGS='-Zmiri-strict-provenance' cargo miri test --offline --test miri_triage
```

Expected current study result:

- all 19 focused tests pass with the local pointer-reuse mitigation in place

Reference log:

- `evidence/miri/simd_json_miri_triage_after_api_refactor.log`

### Current low-level direct tests

```bash
cd targets/simd-json
env MIRIFLAGS='-Zmiri-strict-provenance' cargo miri test --offline parse_str_store_in_tuple --lib
```

Expected current study result:

- all 4 focused low-level tests pass when they reuse one input wrapper

Reference log:

- `evidence/miri/simd_json_parse_str_tuple_after_wrapper_reuse.log`

## Current interpretation

This currently looks like one of two things:

1. a real aliasing / reference-model issue around returning multiple live
   `&str` slices from one mutable input buffer while continuing to parse more
   strings from that buffer
2. a Miri-model incompatibility that `simd-json` intentionally relies on

The study does **not** yet prove which of these is correct.

## Concrete questions for upstream

1. Is it intentional that parsed borrowed strings are returned as slices into
   the mutable input buffer even across repeated string parses in the same
   container?
2. Is repeated reconstruction of the input raw pointer from the same
   `&mut [u8]` considered a supported internal usage pattern?
3. Would a "single input handle per parse flow" rule be acceptable as an
   internal invariant?
4. Is there prior upstream discussion about Miri / Stacked Borrows on the tape
   representation or string parser?

## Suggested issue body

While studying `simd-json 0.17.0` under Miri
(`MIRIFLAGS='-Zmiri-strict-provenance'`), I hit repeatable Stacked Borrows /
retag failures on string-bearing parse paths. The original failures appeared in
`Deserializer::next_`, `Node::as_str`, and borrowed tape upgrade paths, but the
issue narrowed to repeated parsing of borrowed strings from one mutable input
buffer.

The strongest historical reduction was: call `parse_str_` twice on the same
`&mut [u8]`, rebuild the raw input handle each time, and keep both returned
borrowed `&str` values alive. Under Miri, the first string becomes invalidated
after the later parse. At the container level, that showed up as patterns like
`{"a":1,"b":2}` where the first key failed and the second passed, and
`["a","b"]` where the first element failed and the second passed.

A local mitigation made the active repros clean: cache one input handle for the
whole `stage2` / string-parse flow, and pass that handle through `parse_str_`
instead of recreating it from `input.as_mut_ptr()` at each call site. With that
change, the crate-local Miri triage and low-level direct tests both pass.

I am not claiming a confirmed real-world crash here. This may be either a real
aliasing issue or a Miri-model incompatibility. I am opening the issue mainly
because the reduction is consistent and the mitigation direction is concrete.

## Local study references

- stacked borrows technical explainer: `docs/report/simd_json_stacked_borrows_explainer.md`
- focused triage note: `evidence/miri/simd_json_triage.md`
- hotspot notes: `evidence/geiger/simd-json_annotations.md`
- final report: `docs/report/final_report.md`
