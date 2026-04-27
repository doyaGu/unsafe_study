# unsafe_study

A research project and CLI tool ([`unsafe-audit`](unsafe-audit/)) that inventories Rust `unsafe` sites, exercises them via Miri and fuzzing, and produces structured evidence (JSON + Markdown) to guide human review.

The canonical study covers **12 crates**; the protocol is defined in [study/manifest.toml](study/manifest.toml).

---

## Study cohort

## Study cohort

| Crate | Domain |
|-------|--------|
| [httparse](targets/httparse) | HTTP/1.x parser |
| [serde_json](targets/serde_json) | JSON serialisation |
| [bstr](targets/bstr) | Byte-string / UTF-8 utilities |
| [memchr](targets/memchr) | SIMD byte search |
| [winnow](targets/winnow) | Parser combinators |
| [toml_parser](targets/toml_parser) | TOML lexer/parser (`unsafe` feature) |
| [simd-json](targets/simd-json) | SIMD JSON parser |
| [quick-xml](targets/quick-xml) | Streaming XML |
| [goblin](targets/goblin) | Binary object parser (ELF, PE, Mach-O) |
| [toml_edit](targets/toml_edit) | Format-preserving TOML editor |
| [pulldown-cmark](targets/pulldown-cmark) | CommonMark parser |
| [roxmltree](targets/roxmltree) | Read-only XML tree |

---

## Quick start

**Docker** (recommended - toolchain, patches, and target clones handled automatically):

```bash
docker build -t unsafe-study .
docker run --rm -v "$(pwd)/output:/workspace/unsafe_study/study/output" \
  unsafe-study bash scripts/run_all.sh --profile smoke --jobs 4
```

**Native** - requires Rust `nightly-2026-02-01`, `cargo-geiger`, `cargo-fuzz`, `clang`:

```bash
# Patch simd-json before first run (nightly compile-fix)
cd targets/simd-json && git apply ../../patches/simd-json/0001-fix-nightly-unused-imports.patch && cd ../..

bash scripts/run_all.sh --profile smoke --jobs 4 --output /tmp/smoke-out   # quick validation
bash scripts/run_all.sh --profile full  --jobs 4 --output /tmp/full-out    # canonical study
bash scripts/run_all.sh --dry-run                                           # print plan only
```

---

## Pipeline

```text
input (crate dir | manifest.toml)
        │
        ▼
   load_plan ──► RunPlan (normalized, dry-run-able)
        │
        ▼
   per-crate execution (parallel via --jobs)
        │
        ├── scan      syn AST walk - stable UnsafeSite IDs
        ├── geiger    cargo geiger --output-format Json
        ├── miri      cargo miri test (one or more cases per crate)
        └── fuzz      cargo-fuzz targets (existing harnesses only)
        │
        ▼
   <output>/report.json · report.md · crates/<crate>/logs/*.log
```

All four phases are independent and individually skippable.

---

## Phases

**`scan`** - `syn` AST walk over `*.rs` files. Detects: `unsafe_block`, `unsafe_fn`, `unsafe_impl`, `extern_block`, `ptr_op`, `transmute`, `unchecked_op`, `inline_asm`, `other`. Each site gets a stable `U0001…` ID.

**`geiger`** - `cargo geiger --output-format Json`. Records `root_unsafe` / `dependency_unsafe` counts; full log at `logs/geiger.root.log`.

**`miri`** - One or more `cargo miri test` invocations per crate, driven by `[[crate.miri_case]]` entries. Supports `harness_dir`, test name filters, per-case `MIRIFLAGS`, and optional `--miri-triage` (strict → baseline re-run with UB classification). Serialized across crates.

**`fuzz`** - Discovers targets via `cargo fuzz list` or an explicit list, builds sequentially, runs in parallel under `-max_total_time=N`. Backfills corpus from `fuzz_harnesses/<crate>/corpus/` when empty. Results: `clean` · `finding` · `tool_error` · `environment_error`.

---

## CLI

```bash
bash scripts/run_all.sh [flags]                          # recommended entrypoint
cargo run --manifest-path unsafe-audit/Cargo.toml -- … # fallback
```

| Flag | Purpose |
|------|---------|
| `--output <DIR>` | Output directory. |
| `--crates A,B,…` | Restrict to named crates. |
| `--dry-run` | Print `RunPlan` as JSON; execute nothing. |
| `--profile smoke\|baseline\|full` | Cap fuzz budget to 30s / 300s / manifest value. |
| `--jobs N` / `--fuzz-jobs N` | Crate-level / target-level parallelism. |
| `--skip-scan` / `--skip-geiger` / `--skip-miri` / `--skip-fuzz` | Phase toggles. |
| `--miri-triage` | Strict + baseline Miri re-run with UB classification. |
| `--fuzz-time SECS` | Override default fuzz budget. |
| `--fuzz-env KEY=VALUE` | Fuzz env override (repeatable). |
| `--format json\|markdown` | Output formats (default: both). |

---

## Repository layout

| Path | Contents |
|------|----------|
| [unsafe-audit/](unsafe-audit/) | CLI implementation: scan, geiger, miri, fuzz, report. |
| [study/](study/) | `manifest.toml` and variant manifests. |
| [targets/](targets/) | Local crate checkouts (12 crates). |
| [miri_harnesses/](miri_harnesses/) | Per-crate targeted Miri test packages. |
| [fuzz_harnesses/](fuzz_harnesses/) | Custom fuzz targets and seed corpora. |
| [patches/simd-json/](patches/simd-json/) | Nightly compile-fix for `simd-json 0.17.0`. |

---

## Notes

- Clean Miri = no UB observed on exercised paths. Clean fuzz = no crash within the configured budget and harnesses. Neither proves soundness.
- `simd-json` requires the patch in [patches/simd-json/](patches/simd-json/) before every run on `nightly-2026-02-01` (`#![deny(warnings)]` + five new unused-import warnings).
- Toolchain pinned at `nightly-2026-02-01` in [rust-toolchain.toml](rust-toolchain.toml).

