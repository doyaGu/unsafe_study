# simd-json 0.17.0 - Focused Miri Triage

Date: 2026-03-11

Harness: `miri_harnesses/simd_json/tests/simd_json_triage.rs`

Miri configuration used for classification:

```text
MIRIFLAGS='-Zmiri-strict-provenance'
```

## Native Baseline

`cargo test --offline --test simd_json_triage` passes all 6 focused tests.

## Focused Matrix

| Test | Native | Miri | Result |
|------|--------|------|--------|
| `simd_json_borrowed_value_parses_object_with_strings` | pass | fail | retag error in `src/lib.rs:875` |
| `simd_json_owned_value_parses_object_with_strings` | pass | fail | retag error in `src/lib.rs:875` |
| `simd_json_tape_builds_and_exposes_root_value` | pass | fail | retag error in `src/value/tape.rs:106` |
| `simd_json_lazy_upgrade_from_tape_preserves_fields` | pass | fail | retag error in `src/value/borrowed.rs:450` |
| `simd_json_borrowed_value_parses_numeric_array` | pass | pass | clean control |
| `simd_json_tape_exposes_numeric_array` | pass | pass | clean control |
| `tape_directly_exposes_root_string_node` | pass | pass | clean control |
| `tape_directly_exposes_string_array_nodes` | pass | pass | clean control |
| `tape_directly_exposes_object_key_with_numeric_value` | pass | pass | clean control |
| `tape_directly_exposes_string_node` (`{"text":"hi"}`) | pass | fail | direct-tape repro |
| `tape_first_object_key_with_later_key_present` | pass | fail | earlier object string fails |
| `tape_second_object_key_with_later_key_present` | pass | pass | latest object string passes |
| `tape_first_string_array_element_with_later_string_present` | pass | fail | earlier array string fails |
| `tape_second_string_array_element_with_later_string_present` | pass | pass | latest array string passes |

## Interpretation

The failure is broader than the first smoke test suggested:

- it is not limited to `to_borrowed_value`
- it is not specific to symbolic alignment checking
- it is not limited to tape storage or tape readers

The strongest reduction now lives below the tape layer in `src/tests.rs`:

- the historical failing pattern was: call `parse_str_` twice while rebuilding
  a fresh input raw pointer from the same `&mut [u8]` on each call, then retain
  both borrowed `&str` values
- the current low-level tests now use one `SillyWrapper<'de>` per input and are
  clean under Miri, which matches the public-path mitigation

So the core issue is no longer "reading `Node::String(&str)` from the tape".
The tape failures are downstream symptoms of a simpler pattern: multiple live
borrowed strings derived from repeated `parse_str_` calls over the same mutable
input buffer.

The crate-local repros in `targets/simd-json/tests/miri_triage.rs` and
`src/tests.rs` show a more specific provenance story:

- Miri says the problematic tag is created in `src/stage2.rs` when
  `insert_res!(Node::String(...))` writes the parsed string node into the tape.
- The same tag is later invalidated by a Unique retag tied to
  `input.as_mut_ptr()` in the same stage-2 object-building flow.
- The eventual failure happens when a later reader copies that node back out of
  the tape and retags the embedded `&str`.
- In the historical direct `parse_str_` tests, the same pattern appeared
  without any tape: the first borrowed `&str` was created by the first call,
  then invalidated by the second call's `input.as_mut_ptr()` retag before both
  were returned together.
  together.

The latest minimization sharpens the trigger further:

- A root string literal is clean under Miri.
- A single-string array is clean under Miri.
- An object with a single string key and numeric value is clean under Miri.
- Earlier strings in compound containers fail after a later string parse:
  - first key in `{"a":1,"b":2}` fails, second key passes
  - first element in `["a","b"]` fails, second element passes

That means the problem is broader than the object path. The current local
pattern is:

- the first string node inserted into a container is initially valid
- a later `insert_str!()` in the same container path calls `parse_str_` again on
  the same mutable input buffer
- that later parse invalidates the earlier string node's tag
- the most recently inserted string remains readable

One important implementation detail supports this classification: the concrete
`parse_str` implementations do not return buffer-backed strings. Even when they
use the temporary `buffer` for escape handling, they copy the normalized bytes
back into the mutable input and return `&str` slices into that same input
region. So all parsed strings ultimately alias the mutable input.

For a detailed, fact-checked walkthrough of the Stacked Borrows mechanism
behind this finding, see `docs/report/simd_json_stacked_borrows_explainer.md`.

## Experimental Fix Direction

An experimental one-line change in `src/stage2.rs` hoists
`input.as_mut_ptr()` out of `insert_str!()` and reuses one cached raw pointer
for all string parses in `build_tape`.

Observed effect:

- `tests/miri_triage.rs` becomes fully clean under
  `MIRIFLAGS='-Zmiri-strict-provenance'`
- the dedicated `miri_harnesses/simd_json/tests/simd_json_triage.rs` harness
  becomes fully clean under the same flag
- the historical lower-level direct test that called `parse_str_` twice with
  fresh `input.as_mut_ptr()` arguments failed and was kept as a diagnostic log
- the current direct tests reuse one wrapper for both calls and are clean under
  Miri

This strongly suggests that the stage-2 issue is driven by repeated reborrowing
of the mutable input when obtaining fresh raw pointers, and that caching one
input handle is a viable local mitigation for the public and low-level parsing
paths.

We then pushed that direction one step lower by changing the internal
`parse_str_` API to accept `SillyWrapper<'de>` directly instead of a raw
`*mut u8`. That makes the intended call pattern explicit:

- historical callers that constructed a fresh wrapper from `input.as_mut_ptr()`
  on every call reproduced the failure
- current callers construct one wrapper/input handle and reuse it, and the
  focused low-level tests are clean

So the API refactor preserves the causal explanation while aligning the internal
implementation with the now-validated mitigation strategy.

## Working Classification

This currently looks like a real aliasing / reference-model issue or a Miri
model incompatibility around returning multiple live `&str` slices from repeated
`parse_str_` calls while continuing to reuse the same mutable input buffer. The
tape-level failures are consistent with that lower-level mechanism. It does not
look like an alignment false positive and does not appear to be caused by
harness misuse of the public API.
