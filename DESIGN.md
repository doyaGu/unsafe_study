# unsafe-audit Design

## Architecture

```
                    +----------+
                    |  CLI     |
                    | (clap)   |
                    +----+-----+
                         |
              discover_crates()
                         |
           +-------------+-------------+
           |             |             |
      Crate 1       Crate 2  ...   Crate N
           |             |             |
     audit_crate() audit_crate()  audit_crate()
           |
     +-----+-----+-----+------+
     |     |     |     |      |
   Phase  Phase Phase Phase  Report
     1     2     3     4     Gen
   Geiger Miri  Fuzz  Pattern
     |     |     |     |
     v     v     v     v
  metrics UB?  crashes risk
                   score
```

Each phase is independent and can be skipped via `--skip-*` flags. Results accumulate in `CrateAuditResult` and get serialized at the end.

## Phase Details

### Phase 1: Geiger Scan

Uses the `geiger` crate as a library (not subprocess). Calls `geiger::find_unsafe_in_file()` on every `.rs` file under `src/`. Aggregates counts for functions, expressions, impls, traits, and methods (safe vs unsafe).

Limitation: the library API does not distinguish used vs unused counts, so the `unused` fields in `GeigerResult` are always zero.

### Phase 2: Miri Test

Shells out to `cargo miri test` with configurable `MIRIFLAGS`. Parses combined stdout+stderr for:

- Test summary line: `test result: ok. N passed; M failed`
- UB detection: regex-free keyword matching for "undefined behavior", "stacked borrow", "pointer being freed", "out-of-bounds", "data race"

Writes full log to the output directory. Returns pass/fail with UB details.

Limitation: only runs Pass 1 (strict). The two-pass triage protocol from the study (strict -> baseline re-run -> code audit -> classify) is not automated. Implementing it would require a second Miri invocation with reduced flags and a diff of the two log files.

### Phase 3: Fuzz Run

**Current state: discovers and runs existing `fuzz/` targets.**

Flow:
1. Check `fuzz/Cargo.toml` exists -> if not, return `NoFuzzDir`
2. Run `cargo fuzz list` to discover targets
3. For each target: `cargo fuzz run <target> -- -max_total_time=N`
4. Parse output for status (Clean, Panic, OOM, Timeout, BuildFailed)
5. Parse libFuzzer stats (runs, edge coverage)
6. Look for reproducer artifacts in `fuzz/artifacts/<target>/`

**Gap: no auto-generation of fuzz harnesses.** This is the biggest missing piece. See below.

### Phase 4: Pattern Analysis

Uses `syn` with `visit` trait to walk the full AST. The `UnsafeVisitor` tracks `unsafe_depth` (incremented on `unsafe fn`, `ExprUnsafe`, `unsafe impl`) and classifies every expression inside unsafe contexts into one of 13 categories.

Classification is done by rendering the expression to a token stream via `quote::quote!()` and matching known patterns as substrings. This is fast but imprecise -- it can misclassify in edge cases (e.g., a variable named `transmute` that isn't the `std::mem` function).

Risk score: severity-weighted count / file count, sqrt-scaled, capped at 100.

## Fuzz Auto-Generation (Planned, Not Implemented)

### Problem

Most Rust crates do not ship with a `fuzz/` directory. Writing a fuzz harness requires:
1. Knowing which public API to fuzz
2. Knowing the input type (`&[u8]`, `&str`, or a custom type)
3. Writing harness boilerplate that calls the API with fuzzer-provided input
4. Setting up `fuzz/Cargo.toml` with the right dependencies

### Planned Design

```
API Discovery (syn AST scan)
    |
    v
For each pub fn / pub method:
  - Extract parameter types
  - Filter to fuzzable signatures:
      fn(&[u8]) -> _
      fn(&str) -> _
      fn(T) where T: Arbitrary
  - Rank by: direct unsafe in body > calls unsafe > input-facing
    |
    v
Harness Template Selection:
  - &[u8] -> fuzz_bytes.rs template
  - &str  -> fuzz_str.rs template
  - other -> try Arbitrary derive, else skip
    |
    v
Generate:
  fuzz/
    Cargo.toml    (depends on crate under test + libfuzzer-sys)
    fuzz_targets/
      <api_name>.rs
    corpus/
      <api_name>/
        seed_empty
        seed_valid
        seed_boundary
    |
    v
cargo fuzz run <api_name>
```

### Template Examples

**Bytes input** (parsers, decoders):
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use my_crate;

fuzz_target!(|data: &[u8]| {
    let _ = my_crate::parse(data);
});
```

**String input** (JSON, TOML, XML parsers):
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use my_crate;

fuzz_target!(|data: &str| {
    let _ = my_crate::from_str(data);
});
```

### Seed Corpus Generation

For each discovered API:
- Empty input (0 bytes)
- Valid minimal input (if type name contains "json" -> `{}`, "xml" -> `<a/>`, "http" -> `GET / HTTP/1.1\r\n\r\n`, etc.)
- Boundary inputs: max-length, all-zeros, all-0xFF, single byte, truncated valid input

### Why This Is Hard

1. **Type inference**: `syn` gives you the AST of function signatures, but not resolved types. `fn parse(input: &[u8])` is obvious, but `fn decode(buf: B) where B: Buf` is not fuzzable without understanding what `Buf` is.

2. **Stateful APIs**: Many crates require setup (e.g., `serde_json::Deserializer::from_reader` needs an io::Read). The harness needs to construct valid state before calling the target function.

3. **Generic functions**: `fn from_str<'a, T: Deserialize<'a>>(s: &'a str)` needs a concrete `T` to fuzz. You'd need to pick a type or use `serde_json::Value` as a default.

4. **False positives from panics**: Many crates have `debug_assert!` or `panic!` on invalid input in debug mode. These are "expected" panics, not bugs, but the fuzzer can't tell the difference without annotations.

### What Would Work For The 12 Study Crates

10 of 12 study crates have parser-like public APIs that fit the `&[u8]` or `&str` template:

| Crate | Auto-fuzzable? | Input Type | API |
|-------|---------------|------------|-----|
| httparse | Yes | `&[u8]` | `Request::parse(&mut &[u8])` |
| serde_json | Yes | `&[u8]` / `&str` | `from_slice` / `from_str` |
| bstr | Yes | `&[u8]` | `BStr::new`, various ops |
| memchr | Yes | `&[u8]` | `memchr::memchr`, `memmem::find` |
| simd-json | Yes | `&[u8]` | `to_borrowed_value`, `to_owned_value` |
| quick-xml | Yes | `&[u8]` | `Reader::from_reader` |
| toml_parser | Yes | `&str` | `toml_parser::parse` |
| goblin | Yes | `&[u8]` | `goblin::Object::parse` |
| toml_edit | Yes | `&str` | `toml_edit::parse` |
| pulldown-cmark | Yes | `&str` | `Parser::new` |
| winnow | Partial | `&str` | needs custom combinator setup |
| roxmltree | Yes | `&str` | `roxmltree::Document::parse` |

## Miri Two-Pass Triage (Planned Enhancement)

The study used a two-pass protocol:
1. Pass 1 (strict): `-Zmiri-symbolic-alignment-check -Zmiri-strict-provenance`
2. If UB found, Pass 2 (baseline): `-Zmiri-strict-provenance` only
3. Classify: both UB = true positive, only Pass 1 = suspected FP, Pass 2 clean = confirmed FP

Currently Phase 2 only runs Pass 1. Automating the full protocol would add a second Miri invocation and log comparison.

## Report Format

`StudyReport` is the top-level type. It serializes to JSON (machine-readable) and Markdown (human-readable). The Markdown generator produces:

- Summary table (one row per crate)
- Per-phase detail sections with tables
- UB detail subsections when Miri finds issues
- Pattern breakdown tables when Phase 4 runs
- Fuzz reproducer paths when crashes are found
