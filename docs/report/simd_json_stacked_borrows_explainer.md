# simd-json Stacked Borrows Violation -- Technical Explainer

**Date:** 2026-04-06
**Status:** Fact-checked against source code and Miri logs

This document explains the Stacked Borrows violation found in simd-json 0.17.0
during the unsafe study project. It is written for readers who are not familiar
with Miri's aliasing model.

---

## 1. Background: What Is Stacked Borrows?

Rust's borrow checker enforces aliasing rules at compile time: you can have
many `&T` (shared references) or one `&mut T` (exclusive mutable reference),
but not both simultaneously. These rules only apply to references that the
compiler can see. Code that uses `unsafe` and raw pointers bypasses the
compiler's checks entirely.

**Stacked Borrows** is a runtime model, implemented in Miri, that extends
these aliasing rules to raw pointers. It assigns a **tag** (a unique numeric
identifier) to every reference and pointer, and maintains a **borrow stack**
for each memory location. The stack tracks which tags are currently permitted
to access that location.

Key rules:

1. Creating a new `&mut T` (or calling `.as_mut_ptr()` on one) pushes a new
   `Unique` tag onto the borrow stack.
2. Creating a new `&T` (including the `&str` inside a string slice) pushes a
   `SharedReadOnly` tag.
3. When a new `Unique` tag is created from an existing tag (the "granting
   item"), Miri finds the granting item in the stack, **pops everything above
   it**, and pushes the new tag on top. The granting item itself remains.
4. Accessing memory through a tag that is no longer on the stack is
   **Undefined Behavior**.

Rule 3 is the critical one for this finding: a new mutable retag invalidates
every permission that was stacked above the granting item, including any
`SharedReadOnly` tags that derived from them.

---

## 2. simd-json's Zero-Copy String Design

simd-json accepts a `&mut [u8]` as input and returns parsed values that
**borrow directly from that input buffer**. This is the "zero-copy" design
that gives simd-json its performance advantage.

The `parse_str_` function signature makes this explicit:

```rust
// src/lib.rs:465-470
pub(crate) unsafe fn parse_str_<'invoke>(
    input: SillyWrapper<'de>,
    data: &'invoke [u8],
    buffer: &'invoke mut [u8],
    idx: usize,
) -> Result<&'de str>   // lifetime 'de = input buffer's lifetime
```

The returned `&'de str` points into the mutable input buffer. Even when
escape sequences are present (e.g., `\"` -> `"`), the normalized bytes are
written back into the same input region before the `&str` is returned. All
parsed strings ultimately alias the mutable input.

These strings are stored in a tape as `Node::String(&'input str)`
(`src/value/tape.rs:79`), which the consumer later reads back.

---

## 3. The Problem: Repeated Raw Pointer Acquisition

### Pre-fix code pattern

In the original simd-json 0.17.0 code, the `insert_str!()` macro in
`src/stage2.rs` called `input.as_mut_ptr()` (or the equivalent) **on every
invocation**, creating a fresh raw pointer each time. The historical test code
preserved in the Miri failure log shows this pattern:

```rust
// Historical code (pre-fix) -- from evidence/miri/simd_json_parse_str_tuple_fail.log
let first = unsafe {
    Deserializer::parse_str_(input.as_mut_ptr(), input2, buffer, first_idx)?
    //                       ^^^^^^^^^^^^^^^^^^ fresh raw pointer each time
};
let second = unsafe {
    Deserializer::parse_str_(input.as_mut_ptr(), input2, buffer, second_idx)?
    //                       ^^^^^^^^^^^^^^^^^^ another fresh raw pointer
};
```

Each `input.as_mut_ptr()` call constitutes a mutable reborrow of
`input: &mut [u8]`, which triggers a Stacked Borrows **retag** -- a new
`Unique` tag is pushed onto the borrow stack.

### Post-fix code pattern

The study's local mitigation caches one pointer at the top of the function:

```rust
// Current code (post-fix) -- src/stage2.rs:115
let input_ptr = crate::SillyWrapper::new(input);  // one retag, once

// src/stage2.rs:185-194
macro_rules! insert_str {
    () => {
        insert_res!(Node::String(s2try!(Self::parse_str_(
            input_ptr,  // reuse, no retag
            &input2, buffer, idx
        ))));
    };
}
```

`SillyWrapper` is `#[derive(Clone, Copy)]` and contains only a `*mut u8`
and a `PhantomData`. Copying it is a plain numeric copy of the pointer value
-- no new borrow tag is created.

---

## 4. Stacked Borrows Step-by-Step (Pre-Fix)

Input: `["a","b"]` (bytes at offsets 0..8).

### Step 1: Initial state

```
input: &mut [u8] has tag0 (Unique)

Borrow stack for input's memory region:
+----------------+
| tag0: Unique   |  <-- input's permission
+----------------+
```

### Step 2: First `input.as_mut_ptr()` (parsing "a")

`as_mut_ptr()` takes `&mut self`, triggering a mutable reborrow from `tag0`.
Miri creates `tag1` and pushes it above `tag0`:

```
+----------------+
| tag1: Unique   |  <-- first as_mut_ptr()'s permission
+----------------+
| tag0: Unique   |  <-- input's permission (granting item, retained)
+----------------+
```

`parse_str_` uses `tag1` to locate and return `&str` pointing to "a" in the
buffer. This creates a `SharedReadOnly` tag:

```
+---------------------+
| shared1: SharedRO   |  <-- first_str ("a") permission
+---------------------+
| tag1: Unique         |
+---------------------+
| tag0: Unique         |
+---------------------+
```

`Node::String(first_str)` is written into the tape.

### Step 3: Second `input.as_mut_ptr()` (parsing "b") -- invalidation

Another `input.as_mut_ptr()` call. This reborrows from `input`, whose tag is
`tag0`. Miri finds `tag0` in the stack and **pops everything above it**:

```
Pop shared1  (first_str's permission -- GONE)
Pop tag1     (first raw pointer's permission -- GONE)
Push tag2    (second as_mut_ptr()'s permission)

+----------------+
| tag2: Unique   |  <-- second as_mut_ptr()'s permission
+----------------+
| tag0: Unique   |  <-- input's permission (granting item, still valid)
+----------------+
```

`shared1` has been popped. **`first_str` is now invalidated.**

`parse_str_` returns `second_str` pointing to "b", creating `shared2`:

```
+---------------------+
| shared2: SharedRO   |  <-- second_str ("b") permission (valid)
+---------------------+
| tag2: Unique         |
+---------------------+
| tag0: Unique         |
+---------------------+
```

### Step 4: Reading the first string back -- Miri error

When the tape consumer (or the return statement `Ok((first, second))`) tries
to use `first_str`, Miri checks for `shared1` in the borrow stack. It is not
there -- it was popped in Step 3.

Miri's actual error message (from `simd_json_parse_str_tuple_fail.log`):

```
error: Undefined Behavior: trying to retag from <417896> for SharedReadOnly
       permission at alloc110473[0x2], but that tag does not exist in the
       borrow stack for this location

help: <417896> was created by a SharedReadOnly retag at offsets [0x2..0x3]
   --> src/tests.rs:166: ... parse_str_(input.as_mut_ptr(), ... first_idx) ...

help: <417896> was later invalidated at offsets [0x0..0x9] by a Unique
       function-entry retag inside this call
   --> src/tests.rs:168: ... input.as_mut_ptr() ...
```

Miri detects the violation **lazily**, at the point where the invalidated
reference is used (retag on return or read), not at the point where the tag
was popped.

### Why the second string survives

`second_str` was derived from `tag2`, and `shared2` is still on the stack.
No subsequent retag has popped it. This explains the observed pattern from
the triage matrix:

| Test | Result | Reason |
|------|--------|--------|
| First key in `{"a":1,"b":2}` | **fail** | `shared1` popped by second parse |
| Second key in `{"a":1,"b":2}` | pass | `shared2` still on stack |
| First element in `["a","b"]` | **fail** | Same mechanism |
| Second element in `["a","b"]` | pass | Same mechanism |
| Single string / numeric-only | pass | No second retag to invalidate |

---

## 5. Why the Fix Works

After the fix, there is only **one** `SillyWrapper::new(input)` call (one
retag). All subsequent `parse_str_` calls receive a `Copy` of the same
`SillyWrapper`, which carries the same `tag1` without creating new tags:

```
After fix -- stable borrow stack throughout parsing:
+---------------------+
| shared2: SharedRO   |  <-- second_str, valid
+---------------------+
| shared1: SharedRO   |  <-- first_str, STILL VALID (nothing popped it)
+---------------------+
| tag1: Unique         |  <-- the one cached input_ptr
+---------------------+
| tag0: Unique         |
+---------------------+
```

No tag is ever popped, so all `SharedReadOnly` tags accumulate and remain
valid for the lifetime of the parse.

---

## 6. Why This Does Not Crash on Real Hardware

All tests pass natively (`cargo test`), and fuzzing found no issues. Three
reasons:

1. **Memory contents are intact.** The bytes `a` and `b` are never
   overwritten. `first_str` points to the correct address with the correct
   length.
2. **Pointer values are valid.** The numeric address in `first_str` is a
   legitimate heap address within the `Vec<u8>` allocation.
3. **CPUs do not enforce Stacked Borrows.** The borrow stack is a
   compile-time/Miri-time semantic model, not a hardware feature. The CPU
   only checks page-level permissions, not per-reference aliasing tags.

This is why fuzzing (which runs on real hardware) can never detect this class
of issue on x86_64.

---

## 7. Why It Still Matters

Even though the code works today on all tested hardware:

1. **Rust's aliasing model is normative.** The language specification
   (currently formalized through Stacked Borrows and the newer Tree Borrows)
   says this pattern is UB. Code that violates the model is technically
   unsound, even if no current compiler exploits the violation.

2. **Compiler optimizations may assume aliasing rules hold.** LLVM can
   attach `noalias` metadata to `&mut T` references, enabling reordering
   and elimination of loads/stores. If the compiler ever propagates these
   assumptions through the raw pointer boundary, code relying on
   invalidated references could be miscompiled.

   **Caveat for this specific case:** simd-json's hot path operates
   through raw pointers (`*mut u8`), which do not carry `noalias` metadata
   in current LLVM. The practical risk of miscompilation is low today, but
   the Rust memory model is still evolving.

3. **Model evolution.** The Rust project is actively developing Tree
   Borrows as a potential successor to Stacked Borrows. Tree Borrows is
   generally more permissive for some patterns but may still flag this one,
   since the core issue (creating a new exclusive permission that
   invalidates earlier shared permissions) is fundamental to both models.

---

## 8. Classification Status

The project's triage classifies this as one of two possibilities:

| Possibility | Implication |
|-------------|-------------|
| **Real aliasing issue** | simd-json's design of returning multiple `&str` from repeated mutable-input parses has inherent tension with Rust's reference model. Future compiler versions could exploit this for optimization. |
| **Miri model incompatibility** | Stacked Borrows (or its successor) may be overly strict for this legitimate raw-pointer usage pattern. The model may need to accommodate "freeze the input, then hand out shared slices" as a valid idiom. |

The study does not resolve which interpretation is correct. An upstream issue
draft exists at `docs/report/simd_json_upstream_issue_draft.md` but has not been
submitted.

---

## 9. Evidence Chain

| Claim | Evidence |
|-------|---------|
| Pre-fix code called `input.as_mut_ptr()` per parse | `evidence/miri/simd_json_parse_str_tuple_fail.log` lines 16, 21 |
| Post-fix code caches one `SillyWrapper` | `src/stage2.rs:115` + `src/stage2.rs:188` |
| `parse_str_` returns `&str` into mutable input | Function signature `src/lib.rs:465-470`; triage doc section "Interpretation" |
| First string fails, last passes | Triage matrix (14 test cases) in `evidence/miri/simd_json_triage.md` |
| `SillyWrapper` is `Copy` (no retag on pass) | `src/lib.rs:301`: `#[derive(Debug, Clone, Copy)]` |
| Miri error is a lazy retag check | Error at `Ok((first, second))` not at `input.as_mut_ptr()` in the log |
| Fix makes all Miri tests pass | `evidence/miri/simd_json_miri_triage_after_api_refactor.log` |
| Native execution always succeeds | Triage matrix: all 14 tests pass natively |
| `SillyWrapper` API is a study modification, not upstream | Triage doc: "changing the internal `parse_str_` API to accept `SillyWrapper<'de>` directly instead of a raw `*mut u8`" |

---

## References

- Ralf Jung et al. *Stacked Borrows: An Aliasing Model for Rust.*
  <https://plv.mpi-sws.org/rustbelt/stacked-borrows/>
- Ralf Jung et al. *Miri: Practical Undefined Behavior Detection for Rust.* POPL, 2026.
- Tree Borrows (experimental successor): <https://perso.crans.org/vanille/treebor/>
- simd-json project: <https://github.com/simd-lite/simd-json>
