# unsafe_study -- Finding and Understanding `unsafe`-Related Failures in Real Rust Crates

CSE 5349 project: hotspot mining, Miri, and coverage-guided fuzzing on 12 real-world Rust crates.

## What I Did

Applied a three-phase pipeline to study how `unsafe` Rust code behaves under dynamic analysis:

| Phase | Tool | What It Tests |
|-------|------|---------------|
| Hotspot Mining | `cargo-geiger` | Maps where `unsafe` concentrates |
| UB Detection | `cargo miri test` | Finds undefined behavior on executed paths |
| Fuzzing | `cargo-fuzz` (libFuzzer) | Crashes/panics from novel inputs |

### Target Crates

**Tier 1 (full depth):** httparse, serde_json, bstr  
**Tier 2 (targeted depth):** memchr, simd-json, quick-xml, winnow, toml_parser, goblin, toml_edit, pulldown-cmark, roxmltree

Control cases (forbid unsafe_code): quick-xml, roxmltree

### Key Results

| Crate | unsafe exprs | Miri | Fuzz |
|-------|-------------|------|------|
| httparse | 248 | CLEAN | 399M runs, 0 crashes |
| serde_json | 75 (+2883 deps) | FP: memchr alignment | 22M runs, 0 crashes |
| bstr | 364 (+2722 deps) | FP: ascii.rs alignment | 767K runs, 0 crashes |
| simd-json | ~504 | Stacked Borrows UB | CLEAN |
| toml_edit | 0 | CLEAN | **PANIC** (9B reproducer) |
| pulldown-cmark | 0 (opt-in) | CLEAN | **OOM** (480B reproducer) |
| all others | varies | CLEAN | CLEAN |

**Main findings:**
- **simd-json**: True positive Stacked Borrows violation (pointer retagging conflict). Documented in `report/simd_json_stacked_borrows_explainer.md` with an upstream-ready issue draft at `report/simd_json_upstream_issue_draft.md`.
- **serde_json & bstr**: False positive alignment UB from Miri's symbolic checker. Confirmed by two-pass triage (strict -> baseline -> code audit).
- **toml_edit & pulldown-cmark**: Fuzz found bugs in safe Rust (panic, OOM) despite all-clean Miri. Strongest evidence for Miri/fuzzing complementarity.

## Code / Project Structure

```
scripts/run_all.sh           # Full pipeline automation
scripts/run_fuzz.sh          # Fuzzing automation  
scripts/summarize_geiger.py  # Geiger JSON -> Markdown
extensions_harness/          # Offline Miri/test harness for Tier 2 crates
  Cargo.toml                 # Path deps to all 9 extension crates
  tests/api_smoke.rs         # Smoke tests
  tests/more_crates.rs       # Targeted tests (memchr, winnow, toml_parser)
  tests/simd_json_triage.rs  # Focused simd-json Miri test
fuzz_corpus/                 # Seed inputs for all fuzz targets
fuzz_targets/                # Fuzz harness source (baseline crates)
geiger_reports/              # Geiger scans (JSON + TXT + annotations)
miri_reports/                # Miri logs + triage documents
report/final_report.md       # Full 672-line study report
```

## Reproduce

### Option A: Docker (recommended)

```bash
docker build -t unsafe-study .
docker run --rm -it unsafe-study
# Default: runs Geiger + Miri + 60s fuzz on httparse only
# Override for full run:
docker run --rm -it unsafe-study bash scripts/run_all.sh
```

### Option B: Linux directly

```bash
# 1. Install toolchain (rust-toolchain.toml auto-selects nightly-2026-02-01)
rustup toolchain install nightly-2026-02-01
rustup component add miri rust-src --toolchain nightly-2026-02-01
cargo install cargo-geiger cargo-fuzz

# 2. Quick demo (httparse, 60s fuzz)
bash scripts/run_all.sh --crates httparse --fuzz-time 60

# 3. Full pipeline (all 12 crates, 3600s fuzz per target)
bash scripts/run_all.sh --fuzz-time 3600

# 4. Single phase
bash scripts/run_all.sh --skip-fuzz                    # Geiger + Miri only
bash scripts/run_fuzz.sh httparse parse_request 300    # Single fuzz target
```

### Pre-existing Results

All study outputs are already in the repo:
- `geiger_reports/` -- geiger scans + annotations
- `miri_reports/` -- Miri logs + simd-json triage
- `fuzz_findings/` -- fuzz output logs
- `fuzz_corpus/` -- seed corpora
- `report/final_report.md` -- the full report

Note: `targets/` (upstream crate clones) and build artifacts are gitignored. The pipeline re-downloads them. `extensions_harness/` depends on path deps into `targets/`, so the crates must be cloned first (handled by `run_all.sh`).

## Demo Video

`demo_video.mp4` -- 8-slide walkthrough of the pipeline and results (~43s).

## Links

- **GitHub:** https://github.com/doyaGu/unsafe_study
- **Full report:** `report/final_report.md` (672 lines)
- **simd-json deep-dive:** `report/simd_json_stacked_borrows_explainer.md`
- **simd-json upstream issue draft:** `report/simd_json_upstream_issue_draft.md`

## Toolchain

- Rust nightly-2026-02-01 (rustc 1.95.0-nightly 905b92696 2026-01-31)
- Miri (nightly component)
- cargo-geiger (unsafe hotspot scanner)
- cargo-fuzz (libFuzzer-based coverage-guided fuzzer)
- Linux x86_64 required for fuzzing; Miri works cross-platform
