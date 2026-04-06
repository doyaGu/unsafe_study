# unsafe_study -- Finding and Understanding `unsafe`-Related Failures in Real Rust Crates

CSE 5349 project: hotspot mining, Miri, and coverage-guided fuzzing on real-world Rust crates.

## Current Status (2026-03-24)

- Core study pipeline is complete.
- Primary write-up is available at `report/final_report.md`.
- Extension batch (9 crates) artifacts are present under `geiger_reports/`,
  `miri_reports/`, and `fuzz_findings/`.
- Local Git repo has been initialized and root `.gitignore` is in place.

## Quick Start

```bash
# 1. Install the pinned nightly toolchain (reads rust-toolchain.toml)
rustup show

# 2. Install cargo-geiger and cargo-fuzz
cargo install cargo-geiger
cargo install cargo-fuzz

# 3. Run the full study pipeline (Linux required for fuzzing)
bash scripts/run_all.sh

# Or run individual phases
bash scripts/run_all.sh --skip-fuzz       # Geiger + Miri only
bash scripts/run_all.sh --skip-geiger --skip-miri  # Fuzz only
bash scripts/run_fuzz.sh httparse parse_request 300  # Single target
```

## Directory Layout

```
unsafe_study/
|-- rust-toolchain.toml   # pinned nightly for Miri + cargo-fuzz
|-- README.md
|-- targets/              # git clones of target crates (not committed)
|-- geiger_reports/       # cargo-geiger JSON output + annotations
|-- miri_reports/         # Miri test logs + triage documents
|-- fuzz_targets/         # fuzz harness source per crate
|-- fuzz_corpus/          # seed corpus per crate/target
|-- fuzz_findings/        # minimized crash artifacts
|-- extensions_harness/   # offline Miri/test harness for extension crates
|-- scripts/              # automation (run_all.sh, run_fuzz.sh, summarize_geiger.py)
|-- report/               # final write-up, explainers, crate_selection.md
|-- proposal/             # CSE 5349 proposal (.md, .tex, .pdf)
```

## Toolchain

- Rust nightly-2026-02-01 (pinned in `rust-toolchain.toml`)
- Miri (installed as nightly component)
- cargo-geiger (unsafe hotspot scanner)
- cargo-fuzz (libFuzzer-based coverage-guided fuzzer)

## Target Crates

### Baseline (Tier 1 -- full depth)

| Crate | Domain | Selection Rationale |
|-------|--------|---------------------|
| `httparse` | HTTP parsing | Small, perf-critical, direct `unsafe` in hot path |
| `serde_json` | JSON deserialization | Ubiquitous; `unsafe` in hot path + via `serde` |
| `bstr` | Byte strings | `unsafe` for UTF-8 boundary tricks; input-facing |

### Extension Batch (Tier 2 -- targeted depth, added 2026-03-11)

| Crate | Domain | Selection Rationale |
|-------|--------|---------------------|
| `memchr` | Byte/substring search | Shared SIMD dependency of serde_json and bstr |
| `simd-json` | SIMD JSON parsing | Direct comparison to serde_json; heavy `unsafe` |
| `quick-xml` | Streaming XML | `#![forbid(unsafe_code)]`; safe-Rust control case |
| `winnow` | Parser combinators | Zero-copy slice `unsafe`, different from SIMD style |
| `toml_parser` | TOML lexing/parsing | Opt-in `unsafe` feature gate |
| `goblin` | Binary format parsing | Alignment/endianness/layout `unsafe` patterns |
| `toml_edit` | Format-preserving TOML | Zero direct `unsafe`; safe-Rust control case |
| `pulldown-cmark` | CommonMark parsing | `unsafe` behind optional `simd` feature only |
| `roxmltree` | Read-only XML tree | `#![forbid(unsafe_code)]`; negative control |

Geiger runs per crate in `targets/`, Miri for the extension batch is exercised
through targeted tests in `extensions_harness/`, and each crate has a
crate-local `cargo-fuzz` harness under `targets/<crate>/fuzz/`.

The deepest added-target finding is `simd-json`: the study includes a
crate-local Miri triage, a local mitigation based on input-handle reuse, a
technical explainer at `report/simd_json_stacked_borrows_explainer.md`, and an
upstream-ready issue draft at `report/simd_json_upstream_issue_draft.md`.

## Repository Notes

- Root `.gitignore` excludes build/runtime outputs such as `**/target/`,
  crate-local `**/fuzz/artifacts/`, `**/fuzz/coverage/`, logs, and `tmp/`.
- Study data directories like `fuzz_corpus/`, `fuzz_findings/`,
  `geiger_reports/`, and `miri_reports/` remain tracked by default.
- For ongoing status and only-remaining decisions, see `REMAINING_TASKS.md`.

## Commit Scope Policy

Commit:
- Source and automation: `scripts/`, `extensions_harness/src`, `extensions_harness/tests`
- Reproducibility inputs: `fuzz_corpus/`, `fuzz_targets/`, `rust-toolchain.toml`
- Study outputs and analysis: `geiger_reports/`, `miri_reports/*.md`, `report/`, `README.md`
- Proposal sources: `proposal/*.md`, `proposal/*.tex`, `proposal/*.txt`

Do not commit:
- Upstream clone cache: `targets/`
- Build outputs and runtime artifacts: `**/target/`, `**/fuzz/artifacts/`, `**/fuzz/coverage/`
- Local temporary/noise files: `*.log`, `tmp/`, IDE configs, swap files
- LaTeX intermediates: `*.aux`, `*.fdb_latexmk`, `*.fls`, `*.out`, `*.synctex.gz`

Conditional:
- `proposal/proposal.pdf` can be committed for release snapshots; otherwise
  regenerate from source when needed.

## Pipeline Phases

1. **Phase 1 -- Crate Selection**: cargo-geiger feasibility scan, Miri dry run
2. **Phase 2 -- Hotspot Mining**: `cargo geiger --output-format=json` + summary script
3. **Phase 3 -- Miri Testing**: `cargo miri test` with strict provenance flags
4. **Phase 4 -- Fuzzing**: `cargo fuzz run` with seeded corpus, fixed time budget
5. **Phase 5 -- Reporting**: cross-crate comparison, write-up

## Reproducing

All steps are automated by `scripts/run_all.sh` (Linux). See the script
header for parameter documentation. The script generates a Markdown report
in `report/`.
