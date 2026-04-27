# Unsafe Study -- Final Case Study Report

> Status note (April 21, 2026; corrected April 27, 2026): this document is currently a historical writeup. The executable study protocol is `study/manifest.toml` plus native `unsafe-audit <manifest-path>` execution, and the current implementation writes `schema_version = 1` reports. Where this document's prose conflicts with the current runner, treat the implementation and generated `report.json` as authoritative.

**Author:** (redacted)
**Date:** 2026-04-05 (last updated)
**Toolchain:** nightly-2026-02-01 (rustc 1.95.0-nightly, 905b92696 2026-01-31)

---

## 1. Introduction

This report presents a case study on `unsafe`-related findings in real-world, input-facing Rust crates. We applied a three-phase methodology -- hotspot mining, Miri-based UB detection, and coverage-guided fuzzing -- and compared the evidence each tool produced.

The study proceeded in two rounds. A **baseline study** (Sections 3--6) covers three crates at full depth (Tier 1). An **extension batch** (Section 10) adds nine more crates at targeted depth (Tier 2). All 12 crates share the same three-phase pipeline shape, but differ in coverage depth as detailed in Section 2.5.

### Crate Selection Rationale

We selected crates that satisfy: (1) an input-driven public API suitable for fuzzing, (2) an existing test suite, (3) measurable `unsafe` usage either directly or via dependencies, and (4) Miri compatibility (no hard FFI).

| Crate | Version | Domain | Direct unsafe | Dep unsafe | Key deps |
|-------|---------|--------|---------------|-----------|----------|
| httparse | 1.10.1 | HTTP/1.1 parsing | 248 expr | 0 | (standalone) |
| serde_json | 1.0.149 | JSON deserialization | 75 expr | 2,883 expr | memchr, zmij, itoa |
| bstr | 1.12.1 | Byte string handling | 364 expr | 2,722 expr | memchr, regex-automata |

Cross-crate dependency overlap: both serde_json and bstr depend on **memchr 2.8.0**, enabling direct comparison of how the same dependency's `unsafe` interacts with different consumers.

---

## 2. Methodology

This study does not attempt to prove that a crate is safe or unsafe in the
absolute sense. Instead, it measures how `unsafe` is distributed in a crate,
how much of that `unsafe` is dynamically exercised, and whether exercised
`unsafe` sites produce abnormal signals under dynamic analysis. The key
methodological choice is that the unit of analysis is not the crate, test
suite, or fuzz target alone, but the **root-crate unsafe site**.

### 2.1 Unsafe-Site-Centered Study Design

For each crate, we define an **unsafe site universe**. An unsafe site is a
statically identifiable source-level unit associated with `unsafe` behavior,
including:

- `unsafe` blocks
- `unsafe fn` declarations
- `unsafe impl` declarations
- `extern` items
- risky unsafe-relevant operations detected by the AST analyzer

Each site is assigned a stable identifier and a source range. This universe
forms the denominator for all subsequent unsafe-coverage measurements.

The study then combines four evidence sources:

| Evidence source | Tooling | Question answered | Output role |
|----------------|---------|-------------------|-------------|
| Unsafe surface | `cargo geiger` | How much `unsafe` syntax appears in the root crate and dependency set? | Dependency-aware surface metric |
| Unsafe-site inventory | `unsafe-audit` pattern analyzer | Which root-crate unsafe sites exist, and where are they? | Defines the site-level denominator |
| Miri | `cargo miri test` plus companion coverage | Which unsafe sites are exercised by the selected test paths, and do they produce UB signals? | Dynamic UB-oriented evidence |
| Fuzzing | `cargo fuzz` plus companion coverage replay | Which unsafe sites are exercised by existing input-driven harnesses, and do they produce failures? | Dynamic input-driven evidence |

The static denominator therefore comes from the pattern analyzer, not from
Geiger totals. Geiger remains useful, but only as a surface-area metric.

### 2.2 Static Evidence: Surface vs. Universe

The study deliberately separates two kinds of static evidence:

1. **Geiger surface accounting.**
   Geiger is used to describe the amount of `unsafe` syntax in the root crate
   and its dependency set. This is a dependency-aware measure of unsafe
   surface, not a direct coverage denominator.

2. **Unsafe site universe construction.**
   The project’s AST analyzer identifies root-crate unsafe sites, classifies
   them structurally, and records source ranges. This produces the
   `unsafe_site_universe` used for site-level reach calculations.

This distinction is important. Geiger can report large dependency-level
unsafe totals, but those totals do not define how many root-crate sites were
actually exercised by Miri or fuzzing.

### 2.3 Dynamic Evidence and Unsafe Coverage States

Dynamic analysis is interpreted at the unsafe-site level rather than only at
the run-result level. A Miri or fuzz run does not simply count as “coverage”
because it executed; instead, it contributes evidence about which unsafe
sites were reached.

The dynamic layer distinguishes three states:

| State | Meaning |
|------|---------|
| `static_universe_only` | Only the static unsafe-site denominator is available; no dynamic mapping was performed, or the requested dynamic phase had no executable target |
| `triggered_evidence_only` | Dynamic execution ran, but only abnormal dynamic locations (Miri UB locations, fuzz panic/crash locations) could be mapped back to unsafe sites; clean-path reach remains unknown |
| `computed` | Source coverage was available and executed source ranges were mapped onto unsafe-site source ranges |

This makes the dynamic evidence hierarchy explicit. Trigger-only evidence is
useful, but weaker than computed unsafe-site reach derived from source
coverage.

### 2.4 Miri Protocol

Miri is used to obtain UB-oriented evidence on executed test paths. The
primary run uses:

```text
MIRIFLAGS="-Zmiri-symbolic-alignment-check -Zmiri-strict-provenance"
```

If the strict run reports UB, a baseline rerun is performed with:

```text
MIRIFLAGS="-Zmiri-strict-provenance"
```

This yields the following interpretation:

| Strict run | Baseline run | Interpretation |
|------------|--------------|----------------|
| CLEAN | -- | No UB observed on the exercised test paths |
| UB | UB | Strong UB signal under both configurations |
| UB | CLEAN | Strict-only signal; requires code-level triage |
| UB | failed / inconclusive | UB signal not cleanly confirmed or dismissed |

Miri coverage is then lifted from run-level evidence to unsafe-site evidence.
When source coverage is available, the same selected test scope is replayed
under coverage instrumentation and the executed ranges are mapped onto the
unsafe-site universe. This produces Miri unsafe reach in addition to raw UB
signals.

### 2.5 Fuzzing Protocol

Fuzzing is used to obtain input-driven failure evidence under existing fuzz
harnesses. Each fuzz target is interpreted as a dynamic probe of a public API
or related input path. The primary fuzz result remains an operational result
(`CLEAN`, `PANIC`, `OOM`, `TIMEOUT`, `ENVIRONMENT ERROR`, etc.), but the
coverage question is handled separately.

For unsafe coverage, fuzzing uses a companion replay protocol:

1. rebuild the selected fuzz target(s) with coverage instrumentation
2. replay existing corpus inputs and saved artifact inputs
3. export source coverage
4. map executed source ranges onto the unsafe-site universe

This replay does **not** redefine the primary fuzz verdict. It only upgrades
dynamic reach accounting from trigger-only evidence to computed unsafe-site
reach when sufficient artifacts are available.

### 2.6 Source-Coverage-Derived Unsafe Reach

Computed unsafe coverage is obtained by intersecting executed source ranges
with unsafe-site source ranges. This yields:

- Miri reach
- fuzz reach
- combined reach
- triggered sites
- unmapped triggered locations

The study therefore reports not only how many unsafe sites exist, but how
many were dynamically exercised and how many exercised sites produced
abnormal evidence.

This method should be understood as **source-coverage-derived unsafe-site
reach**. It is materially stronger than raw harness counting, but it is still
based on source-range overlap rather than runtime semantic instrumentation at
every unsafe site.

### 2.7 Coverage Tiers

Not all crates received equal dynamic-analysis depth. To prevent misleading
aggregation, the study retains explicit tier labels:

| Tier | Miri scope | Fuzz scope | Applies to |
|------|-----------|------------|------------|
| **Tier 1 (full)** | Upstream crate’s complete `cargo test` suite | Dedicated per-API harnesses, shorter but broader baseline budgets | httparse, serde_json, bstr |
| **Tier 2 (targeted)** | `extensions_harness` or targeted smoke/matrix cases | Crate-local harness groups with longer budgets | memchr, winnow, toml_parser, simd-json, quick-xml, goblin, toml_edit, pulldown-cmark, roxmltree |

Tier labels describe evidence depth, not a difference in core semantics. In
both tiers, the denominator is the root-crate unsafe-site universe and the
dynamic result is interpreted as unsafe-site reach, subject to the available
coverage depth.

### 2.8 Study Execution Structure

The executable protocol is manifest-driven. Each crate is analyzed through
three normalized layers:

1. `shared/`
   Geiger + pattern analysis establish the static denominator once per crate.
2. `miri/<case>/`
   Each Miri case contributes one explicit scope of dynamic UB evidence.
3. `fuzz/<group>/`
   Each fuzz group contributes one explicit scope of input-driven evidence.

At aggregation time, crate-level unsafe coverage is derived by combining the
shared unsafe-site universe with all case- and group-level dynamic evidence.
This avoids the methodological error of treating each dynamic run as though
it independently defined its own static denominator.

### 2.9 Limitations of the Coverage Method

Two limitations remain important:

1. **Computed unsafe coverage is source-range-based.**
   It represents overlap between executed source ranges and unsafe-site source
   ranges, not runtime semantic instrumentation of each unsafe site.

2. **Automatic fuzz coverage is replay-based.**
   It reflects the observed corpus and artifact input set, not the full
   coverage of the entire fuzz search process.

Despite these limits, the method is substantially more precise than treating
crate-level test execution, harness execution, or Geiger totals as direct
coverage proxies for `unsafe`.

---

## 3. Hotspot Map (G1)

> **Coverage tier:** All crates in this section are **Tier 1**.

Full annotations are in `geiger_reports/*_annotations.md`. Below is a summary of the top unsafe modules per crate.

### httparse

All `unsafe` is direct -- no transitive dependencies contribute.

| Module | Unsafe expressions | Pattern |
|--------|-------------------|---------|
| `src/simd/sse42.rs` | ~120 | SSE4.2 byte scanning intrinsics |
| `src/simd/swar.rs` | ~80 | SWAR word-at-a-time fallback |
| `src/lib.rs` | ~48 | Pointer arithmetic, `from_utf8_unchecked` |

### serde_json

Most `unsafe` lives in dependencies (97% of total).

| Package | Unsafe items (used) | Top pattern |
|---------|-------------------|-------------|
| memchr | 2,111 | SIMD search intrinsics |
| zmij | 655 | Proc-macro internals |
| itoa | 112 | Integer-to-string conversion |
| serde_json (direct) | 75 | `from_utf8_unchecked`, pointer arithmetic, transmute |

Key direct modules: `src/read.rs` (35 expr, fast scanning), `src/ser.rs` (25 expr, serialization), `src/raw.rs` (15 expr, RawValue transmute).

### bstr

bstr has the highest direct unsafe count of the three crates.

| Package | Unsafe items (used) | Top pattern |
|---------|-------------------|-------------|
| bstr (direct) | 372 | Word-at-a-time ASCII, unchecked indexing, UTF-8 tricks |
| memchr | 2,111 | SIMD search intrinsics (shared with serde_json) |
| regex-automata | 611 | DFA table construction |

Key direct modules: `src/ext_slice.rs` + `src/ext_vec.rs` (~160 expr, byte string ops), `src/ascii.rs` (~90 expr, ASCII detection -- **Miri FP found here**), `src/unicode/` + `src/utf8.rs` (~60 expr, UTF-8 decoding).

### Cross-Crate Dependency Overlap

The `memchr` crate contributes 2,111 unsafe items to **both** serde_json and bstr. This shared dependency is where Miri detected an alignment violation in serde_json's test suite (see Section 4).

---

## 4. Miri Findings (G2a)

> **Coverage tier:** Tier 1 (full upstream test suite). Triage follows the
> two-pass protocol defined in Section 2.2.

Miri was run with `MIRIFLAGS="-Zmiri-symbolic-alignment-check -Zmiri-strict-provenance"` on each crate's full test suite (Pass 1). Where UB was reported, a Pass 2 re-run without `-Zmiri-symbolic-alignment-check` was performed, followed by code-level audit.

### httparse -- CLEAN

All tests passed under Miri. No undefined behavior detected.

This is consistent with httparse's current exercised test paths, which include careful use of unaligned loads (`_mm_lddqu_si128`, `read_unaligned`) in its SIMD and SWAR code paths.

### serde_json -- Alignment UB in memchr (FALSE POSITIVE)

**Initial finding** (with `-Zmiri-symbolic-alignment-check`):

```
error: Undefined Behavior: accessing memory based on pointer with alignment 1,
       but alignment 16 is required
 -> core_arch/src/x86/sse2.rs:1320:5  (_mm_load_si128)
```

**Stack trace**: `_mm_load_si128` <- `memchr::vector::x86sse2::load_aligned` <- `memchr::memrchr` <- `serde_json::de::SliceRead::position_of_index` <- `test_parse_number_errors`

**Investigation**: We re-ran Miri **without** `-Zmiri-symbolic-alignment-check` (using only `-Zmiri-strict-provenance`). Result: **all 97 tests passed clean**, including `test_parse_number_errors`.

**Verdict**: **False positive.** The memchr library's `load_aligned` function is only called on pointers that have been numerically aligned to 16-byte boundaries. However, Miri's symbolic alignment checker tracks provenance-based alignment (the pointer was derived from a `&[u8]` with alignment 1), not the numeric value. Since the actual pointer value is correctly aligned at runtime, this is a known limitation of `-Zmiri-symbolic-alignment-check`, which Miri itself warns about: "alignment errors can also be false positives."

**Log**: `miri_reports/serde_json.log` (original), `miri_reports/serde_json_no_symcheck.log` (clean re-run)

### bstr -- Alignment UB in ascii.rs (FALSE POSITIVE)

**Initial finding** (with `-Zmiri-symbolic-alignment-check`):

```
error: Undefined Behavior: accessing memory based on pointer with alignment 1,
       but alignment 8 is required
 -> src/ascii.rs:80:25  (*(ptr as *const usize))
```

**Stack trace**: `*(ptr as *const usize)` <- `ascii::first_non_ascii_byte_fallback` <- `ascii::tests::positive_fallback_forward`

**Investigation**: Re-ran Miri without `-Zmiri-symbolic-alignment-check`. Result: **`positive_fallback_forward` passed clean** (along with all other tests that completed before timeout).

**Verdict**: **False positive.** The `first_non_ascii_byte_fallback` function at `ascii.rs:80` performs a word-at-a-time read by casting `*const u8` to `*const usize` and dereferencing. The code contains alignment logic that bumps the pointer to a usize-aligned boundary before entering the tight loop. The symbolic checker flags the provenance-based alignment (1), not the actual pointer value (which is correctly aligned).

**Note**: Unlike httparse's use of `read_unaligned`, bstr's fallback uses `*(ptr as *const usize)` which *does* require alignment -- but the code ensures alignment before reaching this point. Using `read_unaligned` would be a more defensive approach.

**Note on Miri test coverage**: Miri stops at the first UB, so with `-Zmiri-symbolic-alignment-check` enabled, bstr's Miri run was cut short after the `ascii.rs` finding. The bstr -> memchr SSE2 path (same as serde_json's finding) was never reached. Without the symbolic checker, Miri ran all the way through (though some regex-automata-backed tests timed out due to Miri's interpretation overhead).

**Log**: `miri_reports/bstr.log` (original), `miri_reports/bstr_no_symcheck.log` (clean re-run)

### Miri Summary

| Crate | Pass 1 (strict + symbolic) | Pass 2 (strict only) | Classification |
|-------|---------------------------|---------------------|----------------|
| httparse | CLEAN | -- | No UB observed on exercised paths |
| serde_json | UB: memchr SSE2 `load_aligned` | **CLEAN** | **Confirmed FP** (audit: pointer numerically aligned) |
| bstr | UB: `ascii.rs:80` word-at-a-time | **CLEAN** | **Confirmed FP** (audit: pointer bumped to usize boundary before loop) |

Both UB findings were classified as **confirmed false positives** under the
two-pass triage protocol (Section 2.2). Pass 1 flagged provenance-based
alignment, Pass 2 confirmed no UB without the symbolic checker, and
code-level audit verified that both sites numerically align pointers before
dereference. Under the exercised Tier 1 test coverage, we did not confirm a
true UB finding in any of the three crates.

---

## 5. Fuzzing Findings (G2b)

> **Coverage tier:** Tier 1 (dedicated per-API harnesses, 300s exploratory
> budget). Finding classification follows Section 2.3.

All fuzzing was run on Debian Linux with cargo-fuzz (libFuzzer backend), 300 seconds per target. Previously blocked by Windows MSVC incompatibility with libFuzzer.

### httparse

| Target | Runs (300s) | Coverage (edges) | Features | Crashes |
|--------|------------|-------------------|----------|---------|
| parse_request | 87,349,422 | 302 | 880 | 0 |
| parse_response | 80,616,210 | 276 | 815 | 0 |
| parse_headers | 86,585,484 | 160 | 596 | 0 |
| parse_chunk_size | 144,850,968 | 52 | 183 | 0 |

**Seed corpus**: Hand-crafted valid GET/POST requests and HTTP responses.

**Result**: No crashes, panics, or memory safety issues in ~399M total iterations.

### serde_json

| Target | Runs (300s) | Coverage (edges) | Features | Crashes |
|--------|------------|-------------------|----------|---------|
| from_slice | 10,977,876 | 885 | 4,865 | 0 |
| from_str | 10,943,428 | 914 | 5,105 | 0 |

**Seed corpus**: Valid JSON objects/arrays, malformed JSON, edge-case floats, string escapes.

**Key question answered**: The fuzzer did NOT trigger any crashes related to the memchr SSE2 aligned-load path. This is consistent with the Miri finding being a false positive -- on real x86_64 hardware, the aligned loads operate on properly aligned memory at runtime.

**Result**: No crashes in ~22M total iterations under the available harnesses and 300-second budget.

### bstr

| Target | Runs (300s) | Coverage (edges) | Features | Crashes |
|--------|------------|-------------------|----------|---------|
| bstr_fuzz_ops | 766,553 | 709 | 2,423 | 0 |

**Seed corpus**: Various byte strings with ASCII, UTF-8, and mixed content.

**Key question answered**: Fuzzing did NOT trigger any crash from the `first_non_ascii_byte_fallback` alignment path. On x86_64, misaligned usize reads are handled transparently by the CPU (performance penalty only, no fault), so even if the pointer were truly misaligned, no crash would result on this architecture. This further supports the Miri finding being a symbolic-check false positive.

**Result**: No crashes in ~767K iterations. Lower iteration count is expected due to bstr_fuzz_ops exercising multiple API calls per input (grapheme/word/line iteration, find operations, UTF-8 validation), so the clean result carries less confidence than the higher-throughput targets.

### Fuzzing Summary

| Crate | Targets | Total runs | Total time | Crashes | Confidence note |
|-------|---------|-----------|------------|---------|-----------------|
| httparse | 4 | 399,401,084 | 20 min | 0 | High -- ~100M runs/target, low edge counts indicate saturation |
| serde_json | 2 | 21,921,304 | 10 min | 0 | Moderate -- ~11M runs/target, higher edge counts suggest remaining search space |
| bstr | 1 | 766,553 | 5 min | 0 | Lower -- multi-API harness limits throughput; 709 edges with <1M runs |
| **Total** | **7** | **422,088,941** | **35 min** | **0** | |

No crashes or panics were observed across 422M fuzz iterations. Per Section 2.4, the confidence of each crate's clean result varies with throughput, edge coverage, and harness scope.

---

## 6. Miri vs. Fuzzing Comparison (G3)

### What Each Tool Found

| Aspect | Miri | Fuzzing |
|--------|------|---------|
| **Findings** | 2 alignment UB reports (both false positives from symbolic checker) | 0 crashes across 422M iterations |
| **Detection model** | Interprets MIR; catches UB on executed test paths | Generates random inputs; catches crashes/panics from unexpected inputs |
| **Path coverage** | Bounded by existing test suite | Explores input space beyond hand-written tests |
| **Sensitivity** | Very high -- catches subtle UB even without visible symptoms | Lower for memory safety (UB may not manifest as crash on x86_64) |
| **False positive risk** | `-Zmiri-symbolic-alignment-check` can over-report alignment issues | Very low (a crash is a crash) |

### Effort Comparison

| Task | Miri | Fuzzing |
|------|------|---------|
| Setup | Minimal -- `cargo miri test` on existing tests | Moderate -- write harnesses, create seed corpus, platform requirements |
| Platform | Cross-platform (works on Windows + Linux) | **Linux-only** (libFuzzer incompatible with MSVC) |
| Runtime | Minutes per crate (but slow on large test suites) | Fixed budget (5 min/target here); production runs use hours |
| Interpretation | Requires understanding UB semantics, Miri flags, false positive analysis | Straightforward -- crash = bug |

### Complementarity

- **Miri excels at**: Reporting semantic UB signals (alignment, provenance, uninitialized memory) on exercised paths, including cases that may never cause observable symptoms on real hardware. Even the false positives in this study flagged code patterns worth reviewing.
- **Fuzzing excels at**: Finding robustness issues, panics, and logic errors from inputs no human wrote. Coverage-guided fuzzing reaches code paths that existing test suites may miss.
- **Neither produced a confirmed bug finding in the baseline crates under the current study setup**: this is encouraging evidence for these mature, well-maintained libraries, but not proof of absence. However, the extension batch (Section 10) produced two fuzz findings (`toml_edit` panic, `pulldown-cmark` OOM) despite all-clean Miri results -- the strongest evidence in this study for Miri/fuzzing complementarity.

### Key Insight: Architecture Masks UB

A recurring theme: alignment UB in Rust `unsafe` code often has **no observable effect on x86_64** because the CPU handles misaligned reads transparently. This means:
- Fuzzing on x86_64 cannot detect alignment UB (it doesn't crash)
- Miri's symbolic checker can detect it but may over-report
- Miri without the symbolic checker misses it if the pointer is numerically aligned
- True detection requires either `-Zmiri-symbolic-alignment-check` (with false positive risk) or testing on architectures that fault on misalignment (e.g., ARM strict mode)

---

## 7. Threats to Validity

### 7.1 Internal Validity

Internal validity concerns whether the observed results accurately reflect
the properties of the studied crates, rather than artifacts of our tooling
or procedure.

1. **Miri symbolic-alignment false positives.** Both baseline Miri UB
   reports were classified as confirmed false positives under the two-pass triage protocol
   (Section 2.2). The `-Zmiri-symbolic-alignment-check` flag tracks
   provenance-based alignment, which can disagree with numeric alignment.
   Our classification protocol mitigates this, but a risk remains that a
   real alignment bug could be dismissed if the code-level audit is
   incorrect. We provide full logs for independent verification.

2. **Miri first-failure abort.** Miri stops at the first UB on each run.
   With the symbolic checker enabled, bstr's run was cut short after the
   `ascii.rs` finding, preventing discovery of whether the shared `memchr`
   SSE2 path would also trigger. The two-pass protocol partially addresses
   this: Pass 2 (without the symbolic checker) runs the full suite.
   However, any true UB masked by an earlier false positive in Pass 1
   would only be caught if it also manifests without the symbolic checker.

3. **Miri interpretation overhead.** Some bstr tests backed by
   `regex-automata` timed out under Miri. This means Miri's coverage of
   bstr's transitive dependency graph is incomplete, and UB in those paths
   would go undetected.

4. **Unequal fuzz throughput.** bstr's single multi-API harness achieved
   ~767K iterations vs. httparse's ~87M per target in the same 300-second
   budget. The "0 crashes" result for bstr therefore carries substantially
   less confidence. We mitigate this by reporting iteration counts and edge
   coverage alongside crash counts (Section 2.4), but readers should weigh
   clean results by throughput.

5. **Fuzz harness completeness.** The baseline fuzz harnesses cover primary
   input-facing APIs but not all code paths reachable from `unsafe` blocks.
   A harness that never calls a particular API cannot find bugs in it.
   Hotspot annotations (Section 3) guided harness design, but complete
   coverage of all `unsafe`-adjacent APIs was not achieved.

### 7.2 External Validity

External validity concerns whether the findings generalize beyond the
studied crates.

1. **Selection bias.** All 12 target crates are mature, well-maintained,
   and heavily depended upon. This biases toward high code quality. The
   clean results should not be interpreted as evidence that `unsafe` Rust
   code is generally safe -- less-maintained crates may exhibit different
   failure rates. Our selection criteria (Section 1) were designed for
   study feasibility, not statistical representativeness.

2. **x86_64-only testing.** Both Miri and fuzzing ran exclusively on
   x86_64 Linux. Alignment UB that would fault on strict-alignment
   architectures (e.g., ARM, MIPS) is invisible here. The Miri symbolic
   checker partially compensates (it caught two alignment patterns), but
   the two-pass protocol may classify architecture-dependent UB as false
   positives when the code is numerically aligned on x86_64.

3. **Single-threaded analysis.** Miri was run in its default
   single-threaded mode. Data races and concurrency-related UB in crates
   that support concurrent use (e.g., `memchr` called from parallel
   iterators) are outside the scope of this study.

### 7.3 Construct Validity

Construct validity concerns whether our measurements capture what we
intend to measure.

1. **Coverage tier disparity.** Tier 1 crates (baseline) received full
   upstream test suites under Miri, while Tier 2 crates (extension/batch)
   received only API smoke tests through `extensions_harness` (Section 2.5).
   Aggregating these as equivalent "CLEAN" results overstates the
   confidence for Tier 2 crates. The coverage-tier labels introduced in
   Section 2.5 mitigate this at the reporting level.

2. **`cargo-geiger` vs. `rg "unsafe"` counts.** The baseline crates used
   `cargo-geiger` (which counts unsafe expressions in the dependency
   graph), while the extension crates used manual `rg "unsafe"` (which
   counts source-level matches including comments, attributes, and string
   literals). These metrics are not directly comparable. Cross-batch unsafe
   counts should be treated as order-of-magnitude estimates, not precise
   measurements.

3. **"No finding" confidence.** A clean fuzz run is not proof of absence.
   The practical confidence of a "0 crashes" result depends on iteration
   count, edge coverage, and harness completeness. We report these
   contextual metrics but do not compute formal coverage percentages
   (which would require instrumented builds not included in this study).

---

## 8. Reproducibility

### Requirements

- Debian/Ubuntu Linux (or any Linux distribution)
- Rust nightly-2026-02-01 (pinned via `rust-toolchain.toml`)
- `cargo-fuzz` (installed via `cargo install cargo-fuzz`)

### Quick Start

```bash
# Install Rust and tools
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
# rust-toolchain.toml will auto-select nightly-2026-02-01
cargo install cargo-fuzz

# Run the full pipeline
bash scripts/run_all.sh

# Or run individual phases
bash scripts/run_all.sh --skip-fuzz    # Geiger + Miri only
bash scripts/run_all.sh --skip-geiger --skip-miri  # Fuzz only
bash scripts/run_fuzz.sh httparse parse_request 300  # Single target
```

### Key Files

| File | Purpose |
|------|---------|
| `scripts/run_all.sh` | Full pipeline automation (Linux) |
| `scripts/run_fuzz.sh` | Fuzzing automation (Linux) |
| `scripts/summarize_geiger.py` | Geiger JSON to Markdown summary |
| `geiger_reports/*_annotations.md` | Unsafe hotspot annotations per crate |
| `miri_reports/*.log` | Miri output logs (regenerate locally via `run_all.sh`) |
| `miri_reports/simd_json_triage.md` | Focused Miri triage for simd-json |
| `report/simd_json_stacked_borrows_explainer.md` | Technical explainer for simd-json Stacked Borrows finding |
| `fuzz_findings/*.log` | Fuzzing output logs (regenerate locally via `run_all.sh`) |
| `fuzz_corpus/` | Seed inputs for all fuzz targets |

---

## 9. Proposal Validation

| Goal | Status | Evidence |
|------|--------|----------|
| **G1**: Hotspot map | [OK] Complete | Geiger scans + per-crate annotations in `geiger_reports/*_annotations.md` |
| **G2**: Run Miri + fuzzing | [OK] Complete | 2 Miri findings (false positives), 0 fuzz crashes across 422M iterations |
| **G3**: Cross-tool comparison | [OK] Complete | Section 6 above; Miri reports UB signals on executed paths, fuzzing tests robustness, neither produced a confirmed baseline bug finding under the current setup |

### What the proposal got right

- Crate selection criteria led to productive targets -- 2 of 3 crates triggered Miri findings that required substantive investigation
- The phased approach (geiger -> Miri -> fuzz) was effective: geiger identified where unsafe lives, Miri immediately probed those areas
- Choosing crates with shared dependencies (memchr) enabled cross-crate comparison as promised

### What the proposal underestimated

- **Platform friction**: cargo-fuzz (libFuzzer) does not work on Windows MSVC. The proposal didn't mention platform requirements. Migration to Linux was required.
- **Miri compatibility**: Crates may not compile cleanly under Miri. bstr required a test patch (`#[cfg(not(miri))]`) before Miri could run.
- **False positive analysis**: The `-Zmiri-symbolic-alignment-check` flag produces actionable-looking findings that require careful investigation. Distinguishing true UB from false positives is non-trivial.
- **Miri's slow interpretation**: Some tests time out under Miri, limiting coverage of dependency code paths.

### Strongest result

The baseline study shows that three widely-used Rust crates (httparse, serde_json, bstr) with combined 687 direct unsafe expressions and ~5,600 dependency unsafe items produced no confirmed bug findings under the current Miri and fuzz setups. The alignment patterns flagged by Miri's symbolic checker, while technically concerning from a portability standpoint (they depend on x86_64's tolerant alignment behavior), were classified as false positives in this study because code-level audit found that the pointers are aligned before dereference.

The extension batch strengthened the Miri-vs-fuzzing complementarity finding: 9/9 crates were Miri-clean under the current Tier 2 harnesses, yet fuzzing discovered a parser panic in `toml_edit` and resource exhaustion in `pulldown-cmark` -- both in safe Rust, and neither observed under the Miri setup used here. This is the clearest evidence in the study that the two tools surface different kinds of evidence.

---

## 10. Extension Batch (2026-03-11)

> **Coverage tier:** All crates in this section are **Tier 2** (targeted
> harness; see Section 2.5). Miri triage followed the two-pass protocol
> (Section 2.2). Fuzz findings were classified per Section 2.3.

After completing the baseline three-crate study, we expanded the workspace
with nine additional crates: `memchr`, `winnow`, `toml_parser`, `simd-json`,
`quick-xml`, `goblin`, `toml_edit`, `pulldown-cmark`, and `roxmltree`.

### 10.1 Methodological Differences from Baseline

The extension crates ran through the same three-phase pipeline shape as the
baseline, with the following adaptations:

- **Hotspot survey**: manual `rg "unsafe"` counts instead of `cargo-geiger`,
  because `cargo-geiger` was not installed in this environment. Counts are
  source-level matches (not expression-level like geiger) and should be
  treated as order-of-magnitude estimates (see Section 7.3).
- **Miri scope**: `cargo miri test --offline --test api_smoke` in a dedicated
  local crate (`extensions_harness`) with
  `MIRIFLAGS="-Zmiri-symbolic-alignment-check -Zmiri-strict-provenance"`.
  This exercises public API smoke coverage rather than each crate's full
  upstream test suite, because some registry dev-dependencies were
  unavailable offline.
- **Fuzzing**: crate-local `cargo-fuzz` harnesses, 3,600s per target
  (12x the baseline budget, compensating for single-harness design).

An initial Miri-only pass on `memchr`, `winnow`, and `toml_parser` was
performed before the full batch was assembled. Those three crates later
received the full Tier 2 treatment (Miri + 3,600s fuzz). The results below
reflect the definitive full-batch run.

**Early-pass artifacts** (retained for methodological transparency):
`miri_reports/extensions_harness.log`,
`extensions_harness/tests/api_smoke.rs`.

### 10.2 Results

The current high-budget batch result is:
- geiger: `9/9 OK`
- Miri: `9/9 CLEAN`
- fuzz (`3600s` per target): `7/9 CLEAN`, `2/9 findings`

| Crate | Version | Direct `unsafe` survey | Miri | Fuzz (`3600s`) |
|-------|---------|------------------------|------|-----------------|
| memchr | 2.8.0 | ~341 source matches | CLEAN | CLEAN |
| winnow | 0.7.14 | ~58 source matches | CLEAN | CLEAN |
| toml_parser | 1.0.9+spec-1.1.0 | ~140 source matches with `unsafe` feature | CLEAN | CLEAN |
| simd-json | 0.17.0 | ~504 source matches | CLEAN | CLEAN |
| quick-xml | 0.39.2 | ~10 matches, crate forbids unsafe code | CLEAN | CLEAN |
| goblin | 0.10.5 | ~36 source matches | CLEAN | CLEAN |
| toml_edit | 0.25.4+spec-1.1.0 | 0 matches in `src/` | CLEAN | **PANIC** |
| pulldown-cmark | 0.13.1 | ~7 matches, behind optional `simd` feature | CLEAN | **RESOURCE EXHAUSTION** |
| roxmltree | 0.21.1 | ~1 match, crate forbids unsafe code | CLEAN | CLEAN |

### 10.3 Interpretation

- **The batch produced two real fuzz findings despite all-clean Miri results**.
  This is the clearest contrast with the original three-crate study: the added
  targets did not surface new UB under the current Miri harness, but long fuzz
  budgets still exposed parser robustness failures.
- **`toml_edit`: logic/robustness bug (panic).** The long fuzz run found a
  panic at `targets/toml_edit/src/parser/document.rs:547` with the message
  `all items have spans`. Delta-debugging reduced the input to a `9B`
  reproducer:
  `targets/toml_edit/fuzz/artifacts/toml_edit_parse/reproducer-min-9b`.
  *Root cause:* assertion failure in safe Rust. *Unsafe relevance:* none
  (toml_edit has 0 `unsafe` in `src/`). *Severity:* moderate (panic on
  crafted input, no memory safety impact).
- **`pulldown-cmark`: resource exhaustion (OOM/DoS).** The original long-run
  artifact triggers `libFuzzer: out-of-memory (malloc(2147483648))`.
  Internal delta-debugging then reduced a smaller fixed replay case to
  `480B` at
  `targets/pulldown-cmark/fuzz/artifacts/pulldown_cmark_parse/reproducer-min-480b`,
  which still drives a single execution to roughly `36-38s`.
  *Root cause:* algorithmic complexity in safe Rust. *Unsafe relevance:*
  none (direct `unsafe` is behind the optional `simd` feature, not
  enabled). *Severity:* moderate (DoS vector, no memory safety impact).
- **`simd-json` remains historically interesting, but its current local target is
  clean**. Earlier triage isolated a mutable-input aliasing issue around
  repeated borrowed string parsing, and the local pointer-reuse/API-refactor
  mitigation now makes the active harness and crate-local triage clean under
  Miri.
- **The rest of the batch behaved as intended comparison cases.** Notable
  per-crate observations:
  - **memchr** remained clean even when targeted directly, consistent with
    the baseline conclusion that the serde_json alignment report was a Miri
    symbolic-alignment FP rather than a defect in memchr's search routines.
  - **winnow** broadens the study's unsafe profile: its risk is unchecked
    zero-copy slice management rather than SIMD/alignment-heavy code.
  - **toml_parser** shows an explicit opt-in unsafe design (`unsafe`
    feature gate); the exercised API surface remained Miri-clean.
  - `quick-xml`, `goblin`, and `roxmltree` all ran clean across geiger,
    targeted Miri, and the long fuzz budget.

### 10.4 Artifacts

- Batch pipeline summary:
  `report/new_targets_pipeline.md`
- Focused finding write-up:
  `report/new_target_findings.md`
- `toml_edit` minimized reproducer:
  `targets/toml_edit/fuzz/artifacts/toml_edit_parse/reproducer-min-9b`
- `pulldown-cmark` minimized reproducer:
  `targets/pulldown-cmark/fuzz/artifacts/pulldown_cmark_parse/reproducer-min-480b`
- simd-json Stacked Borrows technical explainer:
  `report/simd_json_stacked_borrows_explainer.md`
- Historical simd-json triage note:
  `miri_reports/simd_json_triage.md`
- Upstream issue draft:
  `report/simd_json_upstream_issue_draft.md`
- Hotspot notes (extension batch):
  `geiger_reports/simd-json_annotations.md`,
  `geiger_reports/goblin_annotations.md`,
  `geiger_reports/quick-xml_annotations.md`,
  `geiger_reports/toml_edit_annotations.md`,
  `geiger_reports/pulldown-cmark_annotations.md`,
  `geiger_reports/roxmltree_annotations.md`
- Hotspot notes (baseline, referenced in Section 3):
  `geiger_reports/httparse_annotations.md`,
  `geiger_reports/serde_json_annotations.md`,
  `geiger_reports/bstr_annotations.md`

---

## References

1. Ana Nora Evans, Bradford Campbell, and Mary Lou Soffa. *Is Rust Used Safely by Software Developers?* ICSE, 2020.
2. Vytautas Astrauskas et al. *How Do Programmers Use Unsafe Rust?* OOPSLA, 2020.
3. Boqin Qin et al. *Understanding Memory and Thread Safety Practices and Issues in Real-World Rust Programs.* PLDI, 2020.
4. Yechan Bae et al. *RUDRA: Finding Memory Safety Bugs in Rust at the Ecosystem Scale.* SOSP, 2021.
5. Ralf Jung et al. *Miri: Practical Undefined Behavior Detection for Rust.* POPL, 2026.
