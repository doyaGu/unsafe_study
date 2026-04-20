# unsafe_study -- Finding and Understanding `unsafe`-Related Failures in Real Rust Crates

CSE 5349 project: hotspot mining, Miri, and coverage-guided fuzzing on 12 real-world Rust crates.

## What I Built

### 1. `cargo-unsafe-audit` -- An Automated Unsafe Rust Audit Tool

A real, reusable Rust CLI that automates the entire three-phase analysis pipeline for **any** Rust crate:

```
$ unsafe-audit <crate-path> [options]
```

**Features:**
- **Static analysis** -- syn-based AST walker classifies unsafe patterns (transmute, SIMD intrinsics, pointer deref, unchecked conversions, uninit memory, union access, etc.) with source-level snippets
- **API discovery** -- automatically finds fuzzable public APIs by scanning function signatures
- **Fuzz harness generation** -- generates ready-to-run `cargo fuzz` harnesses matched to input types (`&[u8]`, `&str`, custom)
- **Seed corpus generation** -- auto-generates structured seed inputs (empty, ascending, boundary values, search patterns, etc.)
- **Miri orchestration** -- two-pass UB triage (strict provenance -> baseline -> classify)
- **Fuzz orchestration** -- runs cargo-fuzz, captures crashes/artifacts
- **Reporting** -- structured JSON + human-readable Markdown with risk scores

```bash
# Quick audit (static analysis only)
unsafe-audit ./my-crate --static-only

# Discover fuzzable APIs
unsafe-audit ./my-crate --list-targets

# Generate harnesses without running
unsafe-audit ./my-crate --dry-run

# Full pipeline: static + Miri + fuzz (60s per target)
unsafe-audit ./my-crate --fuzz-time 60

# Full pipeline with verbose output
unsafe-audit ./my-crate -v
```

### 2. Study Results (12 Real-World Crates)

| Phase | Tool | What It Tests |
|-------|------|---------------|
| Hotspot Mining | `cargo-geiger` | Maps where `unsafe` concentrates |
| UB Detection | `cargo miri test` | Finds undefined behavior on executed paths |
| Fuzzing | `cargo-fuzz` (libFuzzer) | Crashes/panics from novel inputs |

**Target Crates:**

**Tier 1 (full depth):** httparse, serde_json, bstr
**Tier 2 (targeted depth):** memchr, simd-json, quick-xml, winnow, toml_parser, goblin, toml_edit, pulldown-cmark, roxmltree

### Key Results

| Crate | unsafe exprs | Risk Score | Miri | Fuzz |
|-------|-------------|------------|------|------|
| httparse | 901 | 68.4 (HIGH) | CLEAN | 399M runs, 0 crashes |
| simd-json | 6117 | 62.5 (HIGH) | Stacked Borrows UB | CLEAN |
| memchr | 7191 | 70.3 (HIGH) | CLEAN | CLEAN |
| bstr | 758 | 34.9 (MED) | FP: alignment | 767K runs, 0 crashes |
| serde_json | 156 | 15.5 (LOW) | FP: memchr alignment | 22M runs, 0 crashes |
| toml_edit | 0 | 0.0 (LOW) | CLEAN | **PANIC** (9B reproducer) |
| pulldown-cmark | 201 | 27.8 (MED) | CLEAN | **OOM** (480B reproducer) |
| all others | varies | varies | CLEAN | CLEAN |

**Main findings:**
- **simd-json**: True positive Stacked Borrows violation (pointer retagging conflict). Documented in `report/simd_json_stacked_borrows_explainer.md` with upstream issue draft.
- **serde_json & bstr**: False positive alignment UB from Miri. Confirmed by two-pass triage.
- **toml_edit & pulldown-cmark**: Fuzz found bugs in safe Rust despite all-clean Miri. Strongest evidence for Miri/fuzzing complementarity.

## Project Structure

```
cargo-unsafe-audit/           # The audit tool (this is the main deliverable)
  src/
    main.rs                   # CLI entry point (clap)
    analyzer.rs               # syn-based static unsafe pattern classifier
    api_discovery.rs          # Fuzzable API scanner
    harness_gen.rs            # Fuzz harness code generator
    corpus_gen.rs             # Seed corpus generator
    fuzz_runner.rs            # cargo-fuzz orchestration
    miri_runner.rs            # Two-pass Miri triage
    report_gen.rs             # JSON + Markdown reports
    models.rs                 # Shared data types
scripts/run_all.sh            # Original pipeline (shell version)
scripts/run_fuzz.sh           # Original fuzz automation
extensions_harness/           # Miri/test harness for Tier 2 crates
report/final_report.md        # Full 672-line study report
```

## Reproduce

### Option A: Using `cargo-unsafe-audit`

```bash
# Build the tool
cd cargo-unsafe-audit && cargo build --release

# Audit any crate
./target/release/unsafe-audit ../targets/httparse --static-only
./target/release/unsafe-audit ../targets/simd-json -v

# Dry-run: generate harnesses without fuzzing
./target/release/unsafe-audit ../targets/bstr --dry-run

# Full pipeline
./target/release/unsafe-audit ../targets/httparse --fuzz-time 60
```

### Option B: Docker

```bash
docker build -t unsafe-study .
docker run --rm -it unsafe-study
# Default: runs Geiger + Miri + 60s fuzz on httparse only
docker run --rm -it unsafe-study bash scripts/run_all.sh
```

### Option C: Shell Scripts (Original)

```bash
rustup toolchain install nightly-2026-02-01
rustup component add miri rust-src --toolchain nightly-2026-02-01
cargo install cargo-geiger cargo-fuzz
bash scripts/run_all.sh --crates httparse --fuzz-time 60
```

## Demo Video

`demo_video.mp4` -- 8-slide walkthrough of the pipeline and results (~43s).

## Links

- **GitHub:** https://github.com/doyaGu/unsafe_study
- **Full report:** `report/final_report.md` (672 lines)
- **simd-json deep-dive:** `report/simd_json_stacked_borrows_explainer.md`
- **simd-json upstream issue draft:** `report/simd_json_upstream_issue_draft.md`

## Toolchain

- Rust nightly-2026-02-01 (rustc 1.95.0-nightly)
- Miri (nightly component)
- cargo-geiger, cargo-fuzz
- Linux x86_64 required for fuzzing; Miri works cross-platform
