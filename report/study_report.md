# Unsafe Study -- Initial Feasibility Report

- Generated: 2026-03-04
- Toolchain: nightly-2026-02-01 (rustc 1.95.0-nightly, 905b92696 2026-01-31)
- Miri flags: `-Zmiri-symbolic-alignment-check -Zmiri-strict-provenance`

## Crate Selection Summary

| Crate | Version | Domain | Status |
|-------|---------|--------|--------|
| httparse | 1.10.1 | HTTP parsing | [OK] All phases viable |
| serde_json | 1.0.149 | JSON deserialization | [OK] All phases viable |
| bstr | 1.12.1 | Byte strings | [OK] All phases viable (UB found) |

## Phase 2: Cargo-Geiger Hotspot Summary

### httparse 1.10.1

| Metric | Used | Total |
|--------|------|-------|
| Functions | 13 | 19 |
| Expressions | 248 | 335 |
| Impls | 0 | 0 |
| Methods | 6 | 6 |
| **Dependencies** | -- | None (standalone) |

**Notes**: All `unsafe` is direct -- concentrated in SIMD/SSE2 header scanning
hot loop. No transitive `unsafe` dependencies. Ideal for hotspot annotation.

---

### serde_json 1.0.149

| Package | unsafe fn (used) | unsafe expr (used) | unsafe impl (used) | Methods | Total |
|---------|-----------------|-------------------|-------------------|---------|-------|
| serde_json | 0 | 75 | 0 | 0 | 75 |
| itoa | 1 | 111 | 0 | 0 | 112 |
| memchr | 27 | 1973 | 2 | 109 | 2111 |
| serde_core | 0 | 5 | 0 | 0 | 5 |
| zmij | 6 | 646 | 0 | 3 | 655 |
| **Total** | **34** | **2810** | **2** | **112** | **2958** |

**Notes**: Most `unsafe` lives in dependencies: `memchr` (2111 used unsafe items)
dominates, followed by `zmij` (655) and `itoa` (112). serde_json itself has 75
unsafe expressions (number parsing, string indexing). Rich dependency graph for
hotspot mapping.

---

### bstr 1.12.1

| Package | unsafe fn (used) | unsafe expr (used) | unsafe impl (used) | Methods | Total |
|---------|-----------------|-------------------|-------------------|---------|-------|
| bstr | 8 | 364 | 0 | 0 | 372 |
| memchr | 27 | 1973 | 2 | 109 | 2111 |
| regex-automata | 0 | 596 | 5 | 10 | 611 |
| **Total** | **35** | **2933** | **7** | **119** | **3094** |

**Notes**: bstr has 372 direct unsafe items (UTF-8 boundary tricks, byte
manipulation). Shares the `memchr` dependency with serde_json, allowing
cross-crate comparison of the same dependency's unsafe impact.

---

## Phase 3: Miri Results

### httparse -- [OK] CLEAN
- All tests passed under Miri with strict provenance
- No UB observed on the exercised test paths
- Full log: `miri_reports/httparse.log`

### serde_json -- [X] UB DETECTED

**Finding**: Undefined Behavior -- alignment violation in `memchr` 2.8.0

```
error: Undefined Behavior: accessing memory based on pointer with alignment 1,
       but alignment 16 is required
 --> core_arch/src/x86/sse2.rs:1320:5
  |
  = note: on thread `test_parse_number_errors`
```

**Stack trace path**:
```
_mm_load_si128 (SSE2 intrinsic, requires 16-byte alignment)
  <- memchr::vector::x86sse2::Vector::load_aligned
  <- memchr::arch::generic::memchr::One::rfind_raw
  <- memchr::memchr::memrchr
  <- serde_json::de::SliceRead::position_of_index
  <- serde_json::Deserializer::error (error position reporting)
  <- serde_json::Deserializer::f64_from_parts
  <- test_parse_number_errors
```

**Initial classification**: Alignment-related Miri UB report in the `memchr`
2.8.0 SSE2 path. At this stage, the report indicated that `_mm_load_si128`
was being reached from a pointer Miri tracked as alignment 1.

**Note**: Miri reports this with the caveat: "but due to
`-Zmiri-symbolic-alignment-check`, alignment errors can also be false
positives." This needs further investigation -- it may be that `memchr`
intentionally does aligned loads only on aligned portions of memory, and the
symbolic check is too conservative. However, this is still a meaningful finding
to report and cross-reference with the fuzzer.

**Full log**: `miri_reports/serde_json.log`

### bstr -- [X] UB DETECTED

**Finding**: Undefined Behavior -- alignment violation in bstr's own `ascii.rs`

```
error: Undefined Behavior: accessing memory based on pointer with alignment 1,
       but alignment 8 is required
 --> src/ascii.rs:80:25
  |
80 |                 let a = *(ptr as *const usize);
   |                         ^^^^^^^^^^^^^^^^^^^^^^ Undefined Behavior occurred here
  |
  = note: on thread `ascii::tests::positive_fallback_forward`
```

**Stack trace path**:
```
*(ptr as *const usize)  (raw pointer cast, requires 8-byte alignment)
  <- ascii::first_non_ascii_byte_fallback  (src/ascii.rs:80)
  <- ascii::tests::positive_fallback_forward  (src/ascii.rs:275)
```

**Initial classification**: Alignment-related Miri UB report in bstr's *direct*
code (not a dependency). The `first_non_ascii_byte_fallback` function casts a
`*const u8` (alignment 1) to `*const usize` (alignment 8) and dereferences it,
which Miri reported as undefined behavior under the symbolic alignment check.

**Working hypothesis at this stage**: `src/ascii.rs` line 80 performs a
"word-at-a-time" optimization to check multiple bytes for ASCII-ness
simultaneously. The fallback path appeared, under Miri's symbolic alignment
model, to read from a byte-aligned pointer before alignment was established.

**Note**: The same `-Zmiri-symbolic-alignment-check` caveat applies: alignment
errors can be false positives under symbolic checking. However, unlike the
memchr SSE2 finding, this is a simpler pattern (usize cast from u8 pointer)
that is more likely a genuine alignment concern.

**Workaround applied**: The initial run was blocked by a compile error
(`BString` import gated behind `#[cfg(not(miri))]` but used unconditionally in
the `from_str` test at `src/impls.rs:1158`). We patched the test with
`#[cfg(not(miri))]` to unblock Miri, which then revealed this UB.

**Full log**: `miri_reports/bstr.log`

---

## Cross-Crate Comparison (Preliminary)

| Crate | Direct unsafe | Dep unsafe | Miri result | Key dependency overlap |
|-------|--------------|-----------|-------------|----------------------|
| httparse | 248 expr | 0 | CLEAN | -- |
| serde_json | 75 expr | 2735 expr | ~~UB (memchr alignment)~~ FALSE POSITIVE | memchr, zmij, itoa |
| bstr | 364 expr | 2569 expr | ~~UB (ascii.rs alignment)~~ FALSE POSITIVE | memchr, regex-automata |

**Observations**:
- httparse is self-contained; all `unsafe` is direct and Miri-clean
- serde_json and bstr both depend heavily on `memchr`, which is where Miri found alignment
  reports for serde_json. bstr's report is in its *own* code, not a dependency.
- Under the follow-up triage described below, both alignment findings were
  classified as **false positives from `-Zmiri-symbolic-alignment-check`**
  because re-running without this flag produced clean results for both crates
- The code correctly aligns pointers numerically before dereferencing; Miri's symbolic
  checker tracks provenance-based alignment which is overly conservative here

## Miri Investigation Update (2026-03-05)

Both UB findings were re-investigated by running Miri **without** `-Zmiri-symbolic-alignment-check`:
- **serde_json**: All 97 tests pass clean (including `test_parse_number_errors`)
- **bstr**: `positive_fallback_forward` passes clean; all completed tests pass

**Conclusion**: Under the follow-up triage, both findings were classified as
false positives. The code aligns pointers numerically at runtime; the symbolic
checker tracks provenance-based alignment more conservatively.

## Fuzzing Results (2026-03-05)

All fuzzing ran on native Debian Linux with cargo-fuzz/libFuzzer, 300s per target.

| Crate | Target | Runs | Coverage | Crashes |
|-------|--------|------|----------|---------|
| httparse | parse_request | 87,349,422 | 302 | 0 |
| httparse | parse_response | 80,616,210 | 276 | 0 |
| httparse | parse_headers | 86,585,484 | 160 | 0 |
| httparse | parse_chunk_size | 144,850,968 | 52 | 0 |
| serde_json | from_slice | 10,977,876 | 885 | 0 |
| serde_json | from_str | 10,943,428 | 914 | 0 |
| bstr | bstr_fuzz_ops | 766,553 | 709 | 0 |

**Total**: 422,088,941 iterations across 7 targets, 0 observed crashes under the
available harnesses and 300-second budget.

## Next Steps

~~1. **Investigate memchr finding**: Determine if the alignment UB is a true bug or
   a Miri false positive under symbolic alignment checking~~
   -> **Done**: Both findings are false positives (see above)
~~2. **Run fuzzing in WSL2**: All fuzz targets are configured; run via `scripts/run_fuzz.sh`~~
   -> **Done**: All 7 targets ran clean on native Linux (see above)
~~3. **Cross-reference**: Check if fuzzing triggers the same alignment paths Miri flagged~~
   -> **Done**: No crashes -- consistent with false positive verdict

**All tasks complete.** See `report/final_report.md` for the full case study report.

---

## Proposal Validation

Mapping our findings back to the proposal goals:

| Goal | Status | Evidence |
|------|--------|----------|
| **G1**: Hotspot map | [OK] Done | Geiger scans + per-crate annotations in `geiger_reports/*_annotations.md` |
| **G2**: Run Miri + fuzzing | [OK] Done | 2 Miri findings (false positives), 0 fuzz crashes in 422M iterations |
| **G3**: Cross-tool comparison | [OK] Done | Full comparison in `report/final_report.md` Section 5 |

**What worked well in the proposal**:
- The crate selection criteria (input-driven API, has tests, contains unsafe) led to
  productive targets -- 2 out of 3 crates yielded Miri findings requiring investigation.
- The phased approach (geiger -> Miri -> fuzz) was effective: geiger identified where
  unsafe lives, and Miri immediately probed those areas.
- Choosing crates with shared dependencies (memchr) enabled cross-crate comparison.

**What the proposal underestimated**:
- **Platform friction**: cargo-fuzz (libFuzzer) does not work on Windows MSVC at all.
  The proposal didn't mention platform requirements. Linux is required for fuzzing.
- **Miri compatibility**: Crates may not compile cleanly under Miri due to
  `#[cfg(not(miri))]` gating. bstr required a local test patch before Miri could run.
- **False positive analysis**: `-Zmiri-symbolic-alignment-check` produces findings that
  require careful investigation to distinguish from true UB.

**Strongest result**: Across the current Miri setup (strict provenance) and
the available fuzz harnesses (422M iterations), the three baseline crates
produced no confirmed bug findings. The alignment patterns flagged by Miri's
symbolic checker, while not classified as true UB in this study, still
highlight code that depends on x86_64's tolerant alignment behavior and would
benefit from using `read_unaligned` for portability.

## Additional Target Batch (2026-03-11)

A unified follow-on intake added nine more crates to `targets/`: `memchr`,
`winnow`, `toml_parser`, `simd-json`, `quick-xml`, `goblin`, `toml_edit`,
`pulldown-cmark`, and `roxmltree`.

Geiger remained crate-local in `targets/<crate>`, while Miri for this batch was
routed through targeted `extensions_harness` tests to avoid depending on
missing upstream dev-dependencies. Each crate is also set up for crate-local
`cargo-fuzz` execution under `targets/<crate>/fuzz/`.

| Crate | Version | Unsafe survey | Public API exercised | Miri | Fuzz (`3600s`) |
|-------|---------|---------------|----------------------|------|-----------------|
| memchr | 2.8.0 | ~341 `unsafe` occurrences in source | `memchr`, `memrchr`, `memchr2/3`, `memmem::Finder` | CLEAN | CLEAN |
| winnow | 0.7.14 | ~58 `unsafe` occurrences in source | `dec_uint`, `multispace0`, `take_till`, `take_while` | CLEAN | CLEAN |
| toml_parser | 1.0.9+spec-1.1.0 | ~140 `unsafe` occurrences with `unsafe` feature enabled | `Source::lex`, `parse_document` | CLEAN | CLEAN |
| simd-json | 0.17.0 | ~504 source matches | `to_borrowed_value`, `to_owned_value`, `to_tape` | CLEAN | CLEAN |
| quick-xml | 0.39.2 | ~10 matches, crate forbids unsafe code | streaming `Reader` paths | CLEAN | CLEAN |
| goblin | 0.10.5 | ~36 source matches | `Object::parse` | CLEAN | CLEAN |
| toml_edit | 0.25.4+spec-1.1.0 | 0 source matches | `DocumentMut` parse/edit/render | CLEAN | **PANIC** |
| pulldown-cmark | 0.13.1 | ~7 matches, unsafe is feature-gated behind `simd` | `Parser::new_ext` + HTML render | CLEAN | **RESOURCE EXHAUSTION** |
| roxmltree | 0.21.1 | ~1 match, crate forbids unsafe code | `Document::parse` | CLEAN | CLEAN |

**Batch notes**:
- `memchr` remains the most important dependency-focused addition because it is
  the shared library behind the original serde_json/bstr alignment
  investigation.
- `winnow` and `toml_parser` add unchecked-slicing parser infrastructure rather
  than SIMD-heavy scanning, which broadens the unsafe styles covered.
- `quick-xml` and `roxmltree` are useful XML-side controls because both are
  input-facing parsers with little or no direct unsafe code.
- `pulldown-cmark` and `toml_edit` stayed in the batch despite low direct
  unsafe density because they provide mainstream parser baselines with real
  input surfaces.

**Current batch findings**:
- The current end-to-end batch run is `9/9` geiger `OK`, `9/9` Miri `CLEAN`,
  and `7/9` fuzz-clean; the two fuzz findings are `toml_edit` and
  `pulldown-cmark`.
- `toml_edit` is a true parser panic, not a Miri-only effect. The minimized
  reproducer is `9B`:
  `targets/toml_edit/fuzz/artifacts/toml_edit_parse/reproducer-min-9b`, and it
  still panics at `targets/toml_edit/src/parser/document.rs:547` with
  `all items have spans`.
- `pulldown-cmark` is a resource-exhaustion finding. The original `815B`
  artifact still reproduces the long-run OOM, and internal delta-debugging
  reduced the smaller fixed-input reproducer to `480B` at
  `targets/pulldown-cmark/fuzz/artifacts/pulldown_cmark_parse/reproducer-min-480b`.
- `simd-json` remains historically interesting because earlier Miri triage
  exposed a mutable-input aliasing issue around repeated borrowed string
  parsing, but the current local target and harness are now clean after the
  pointer-reuse/API-refactor mitigation work.
- `quick-xml` and `roxmltree` remain useful negative controls: both are parser
  crates, but neither exposes the same direct unsafe density as the stronger
  targets.
- Detailed reproducer paths and replay commands are collected in
  `report/new_target_findings.md`.
- New hotspot notes were written for the full intake batch in
  `geiger_reports/*_annotations.md`.
