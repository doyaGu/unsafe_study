# unsafe_study

`unsafe_study` is a research project that asks one question:

> Can we build an evidence-driven workflow that identifies which Rust `unsafe`
> sites exist in a crate, which ones are actually exercised by tests and
> fuzzers, and which ones deserve human review first?

The deliverable is [`unsafe-audit`](unsafe-audit/), a CLI that runs a small,
reproducible study protocol against one crate or against a manifest-defined
crate cohort, then writes structured evidence (JSON + Markdown) plus per-phase
logs to a single output directory.

The canonical study covers **12 crates** spanning HTTP, JSON, byte/string
search, parser combinators, TOML, XML, Markdown, and binary-object parsing.
The full protocol is defined in [study/manifest.toml](study/manifest.toml).

---

## Pipeline at a glance

```text
input (crate dir | manifest.toml)
        │
        ▼
   load_plan ──► RunPlan (normalized, dry-run-able)
        │
        ▼
   per-crate execution (optionally parallel via --jobs)
        │
        ├── scan      AST inventory of unsafe sites (syn)
        ├── geiger    cargo geiger --output-format Json
        ├── miri      one or more cargo miri test cases
        └── fuzz      one or more cargo-fuzz target groups
        │
        ▼
   Report  ──►  out/report.json
              out/report.md
              out/crates/<crate>/logs/*.log
```

The four execution phases are independent and can each be skipped via flags.
`scan` is local-only and always cheap. `geiger`, `miri`, and `fuzz` shell out
to external tools and produce per-crate log files alongside the structured
report.

---

## What `unsafe-audit` does

### 1. Static unsafe inventory (`scan`)

A `syn` AST walk over the crate's `*.rs` files (excluding `target/`, `.git/`,
`fuzz/`, `vendor/`, `.cargo/`). Each occurrence becomes a stable
`UnsafeSite` with id `U0001…U9999`, file, line, kind, and pattern label.

Recorded kinds and patterns:

| Kind / pattern | Detected from |
|----------------|---------------|
| `unsafe_block` | `unsafe { … }` expression statements |
| `unsafe_fn`    | `unsafe fn` items |
| `unsafe_impl`  | `unsafe impl` items |
| `extern_block` | `extern { … }` foreign blocks |
| `ptr_op`       | raw-pointer deref / address-of |
| `transmute`    | calls resolving to `std::mem::transmute` |
| `unchecked_op` | `*_unchecked` method calls |
| `inline_asm`   | `asm!` macro invocations |
| `other`        | anything else inside an unsafe context |

Files that fail to parse with `syn::parse_file` are skipped with a warning so
one malformed source file does not abort an entire crate scan.

### 2. Geiger (`geiger`)

```bash
cargo geiger --output-format Json
```

The compact summary stored in the report keeps `root_unsafe` and
`dependency_unsafe` counts plus a tail excerpt; the full output is preserved
under `crates/<crate>/logs/geiger.root.log`.

### 3. Miri (`miri`)

Runs one or more configured `cargo miri test` invocations per crate. Each
invocation comes from a `[[crate.miri_case]]` entry in the manifest (or a
default case when running a single crate directory). Supported semantics:

- full upstream test suite,
- `--test <target>` to scope to one integration test,
- a name filter, optionally with `-- --exact`,
- a working-directory override (`harness_dir`) to point at the per-crate
  packages in [miri_harnesses/](miri_harnesses/),
- per-case environment overrides (e.g. `MIRIFLAGS`),
- optional **strict-vs-baseline triage** (`--miri-triage`) that re-runs with
  default Miri flags on a strict-mode UB report and classifies the outcome
  (`Clean`, `TruePositiveUb`, `StrictOnlySuspectedFalsePositive`, `FailedNoUb`,
  `Inconclusive`).

Miri executions are serialized via a process-wide mutex to avoid
`miri-server` lock contention even with `--jobs > 1`.

### 4. Fuzz (`fuzz`)

`unsafe-audit` runs **existing** `cargo-fuzz` targets only. It does not
synthesize harnesses. For each `[[crate.fuzz_group]]`:

1. Discover targets via `cargo fuzz list` (or honor an explicit `targets =
   [...]` list).
2. `cargo fuzz build --release <target>` for each target (sequential).
3. Run the built libFuzzer binary directly with `-max_total_time=N` (parallel
   across targets when `--fuzz-jobs > 1`).
4. Before launch, backfill `targets/<crate>/fuzz/corpus/<target>/` from
   `fuzz_harnesses/<crate>/corpus/<target>/` if the local corpus is empty.

Each result records an `error_kind`:

- `clean`              - budget elapsed, no crash, no findings;
- `finding`            - libFuzzer reported a crash/panic/timeout/OOM and an
  artifact from this run is attached;
- `tool_error`         - `cargo fuzz` itself failed (build error, missing
  target, etc.);
- `environment_error`  - sanitizer/runtime refused to start (e.g. ptrace,
  Address Space Layout sandboxing).

Artifact attribution is **current-run only**: stale `crash-*` files from
earlier runs are never attached to a clean run.

### 5. Report

Every run writes a single self-contained output directory:

```text
<output>/
  report.json          # schema_version = 1
  report.md            # human-readable summary
  crates/<crate>/logs/
    geiger.root.log
    miri.<case>.log
    fuzz.<group>.<target>.log
```

`report.json` includes the top-level execution config (profile, jobs,
fuzz_jobs, enabled phases, miri_triage, fuzz_time, fuzz_env), then per crate:

- the unsafe-site inventory and pattern summary,
- one `PhaseReport` per (kind, name) with status, command, duration, log
  path, summary, and a phase-specific `evidence` payload,
- a `review_priority` table ranking sites for human review.

`report.md` mirrors the same data in prose-and-table form.

---

## What `unsafe-audit` does **not** do

The core is intentionally compact. Out of scope for this codebase:

- exploration scheduler / coverage-driven replanning,
- LLVM coverage replay or coverage-based reach merging,
- daemon-mode resume/status/stop runtime control,
- LLM-driven harness generation,
- crates.io / git acquisition (targets are local checkouts in
  [targets/](targets/)),
- HTML reporting,
- soundness proofs, invariant recovery, or exploitability scoring.

A clean `miri` result means *no UB observed on the exercised paths*. A clean
`fuzz` result means *no failure observed under the configured harnesses and
budget*. The report is structured so a reader can always see what was
exercised and infer what was not.

---

## CLI

Build:

```bash
cd unsafe-audit
cargo build --release
```

Two input shapes:

```bash
# Single crate (directory input)
./target/release/unsafe-audit ../targets/httparse --output /tmp/httparse-report

# Manifest-driven study (file input)
./target/release/unsafe-audit ../study/manifest.toml --output /tmp/study-report
```

Recommended Linux entrypoint:

```bash
bash scripts/run_all.sh [unsafe-audit args ...]
```

`run_all.sh` builds the repo-local `unsafe-audit` crate, resolves the emitted
binary path from `cargo build --message-format=json-render-diagnostics`, and
falls back to `cargo run --manifest-path unsafe-audit/Cargo.toml --` otherwise.

### Flags

| Flag | Purpose |
|------|---------|
| `--output <DIR>` | Output directory (default: derived from manifest). |
| `--crates A,B,…` | Restrict a manifest run to selected crates (kebab-case names match `[[crate]].name`). |
| `--dry-run` | Print the normalized `RunPlan` as JSON; execute nothing. |
| `--profile <P>` | `smoke` (cap fuzz to 30s) · `baseline` (cap to 300s) · `full` (preserve manifest budget). |
| `--jobs N` | Parallelism across crates. |
| `--fuzz-jobs N` | Parallelism across fuzz targets within one crate. |
| `--skip-scan` / `--skip-geiger` / `--skip-miri` / `--skip-fuzz` | Phase toggles. |
| `--miri-triage` | Re-run baseline Miri after a strict UB report and classify. |
| `--fuzz-time SECONDS` | Override the manifest's default fuzz budget. |
| `--fuzz-env KEY=VALUE` | Extra fuzz env var; repeatable. Merged after manifest `fuzz_env` and per-group `env`. |
| `--format <F>` | `json` or `markdown`; repeatable. Default writes both. |

Single-crate runs default to `ASAN_OPTIONS=detect_leaks=0` to suppress the
"LeakSanitizer does not work under ptrace" noise common in sandboxed hosts.

### Common invocations

```bash
# Full canonical study, parallelized.
bash scripts/run_all.sh --profile full --jobs 4 --fuzz-jobs 4 \
  --output /tmp/unsafe-study-full

# Smoke validation across all 12 crates (≈30s fuzz cap per target).
bash scripts/run_all.sh --profile smoke --jobs 4 --fuzz-jobs 4 \
  --output /tmp/unsafe-study-smoke

# Subset re-run with only Miri.
bash scripts/run_all.sh --crates serde_json,bstr \
  --skip-scan --skip-geiger --skip-fuzz --miri-triage \
  --output /tmp/unsafe-study-miri-only

# Plan only — useful before committing a long run.
bash scripts/run_all.sh --dry-run
```

---

## Progress output

Long runs print explicit progress to stderr. Representative excerpt:

```text
[1/1] crate httparse: fuzz start
  fuzz group existing_targets: start
    fuzz target parse_chunk_size: build start (budget 30s)
    fuzz target parse_chunk_size: build done
    fuzz target parse_chunk_size: run start (budget 30s)
    fuzz target parse_chunk_size: clean (31.1s/30s)
```

---

## Repository layout

| Path | Role |
|------|------|
| [unsafe-audit/](unsafe-audit/) | Rust crate implementing CLI parsing, plan loading, `scan` / `geiger` / `miri` / `fuzz`, and report writing. |
| [study/](study/) | Canonical study inputs: `manifest.toml`, `manifest.accept.toml`, `manifest.env-rerun.toml`. |
| [targets/](targets/) | Local checkouts of the 12 crates under study. |
| [miri_harnesses/](miri_harnesses/) | Per-crate Cargo packages containing targeted Miri integration tests. |
| [fuzz_harnesses/](fuzz_harnesses/) | Per-crate fuzz harness mirrors plus canonical seed corpora at `corpus/<target>/`. |
| [evidence/](evidence/) | Archived geiger, miri, and fuzz artifacts from prior runs. |
| [scripts/](scripts/) | Helper scripts: `run_all.sh`, `run_fuzz.sh`, `make_demo_video.sh`, `summarize_geiger.py`. |
| [patches/simd-json/](patches/simd-json/) | Local compile-fix patch required for `simd-json 0.17.0` on the pinned nightly toolchain. |

Read the repository in this order when orienting yourself:

1. this README;
2. [study/manifest.toml](study/manifest.toml);
3. [unsafe-audit/src/](unsafe-audit/src/), in module order `main -> lib -> config -> runner -> scan -> phases -> report -> fs`;
4. [miri_harnesses/](miri_harnesses/) or [fuzz_harnesses/](fuzz_harnesses/) for added dynamic coverage;
5. [evidence/](evidence/) for archived outputs.

---

## Toolchain

The project pins:

```toml
# rust-toolchain.toml
[toolchain]
channel = "nightly-2026-02-01"
components = ["rustfmt", "clippy", "miri", "rust-src"]
```

External tools required for full execution:

- `cargo-geiger` (install: `cargo install cargo-geiger --locked`)
- `cargo-fuzz`   (install: `cargo install cargo-fuzz --locked`)
- a working clang/libFuzzer toolchain on the host

[Dockerfile](Dockerfile) provides a known-good Ubuntu 22.04 environment that
installs the toolchain, the cargo plugins, fetches the 12 target crates,
applies the simd-json compile-fix patch, and runs the unsafe-audit test suite.

---

## Study manifests

Three manifest variants are kept under [study/](study/):

| File | Purpose |
|------|---------|
| [study/manifest.toml](study/manifest.toml) | Canonical 12-crate study with `fuzz_time = 3600` and the full Miri/fuzz wiring. |
| [study/manifest.accept.toml](study/manifest.accept.toml) | Smaller acceptance-style run for validating the pipeline without committing to the full budget. |
| [study/manifest.env-rerun.toml](study/manifest.env-rerun.toml) | Re-run variant used when reproducing behavior with different fuzz environment settings. |

Manifest structure:

- `[study]` holds `name`, `output_root`, `fuzz_time`, and `fuzz_env`.
- Each `[[crate]]` entry defines `name`, `path`, `cohort`, and `coverage_tier`.
- Nested `[[crate.miri_case]]` entries define one `cargo miri test` invocation.
- Nested `[[crate.fuzz_group]]` entries define one fuzz target set, either via
  `all = true` or an explicit `targets = [...]` list.

Fuzz environment merge order is:

1. inherited process environment;
2. `study.fuzz_env`;
3. per-group `env`;
4. CLI `--fuzz-env KEY=VALUE`.

Before launching a fuzz target, the runner backfills an empty
`targets/<crate>/fuzz/corpus/<target>/` from
`fuzz_harnesses/<crate>/corpus/<target>/` when canonical seeds exist.

---

## Runbook

### Required preflight

```bash
rustup show active-toolchain
cargo geiger --version
cargo fuzz --help >/dev/null
cargo miri --help >/dev/null
cargo test --manifest-path unsafe-audit/Cargo.toml
```

Expected state:

- active toolchain is `nightly-2026-02-01`;
- `cargo-geiger`, `cargo-fuzz`, and `cargo miri` are installed;
- the `unsafe-audit` test suite passes.

### Required local patch for `simd-json`

Before any rerun that touches `targets/simd-json`, apply:

```bash
cd targets/simd-json
git apply --check ../../patches/simd-json/0001-fix-nightly-unused-imports.patch
git apply ../../patches/simd-json/0001-fix-nightly-unused-imports.patch
```

Reason: `simd-json 0.17.0` uses `#![deny(warnings)]`, and the pinned nightly
surfaces five `unused_imports` / unused re-export warnings as hard errors.

### Recommended execution order

Dry run the plan first:

```bash
bash scripts/run_all.sh --dry-run
```

Then run a smoke pass across all phases and crates:

```bash
bash scripts/run_all.sh --profile smoke --jobs 4 --fuzz-jobs 4 \
  --output /tmp/unsafe-study-smoke
```

Then run the full manifest budgets:

```bash
bash scripts/run_all.sh --profile full --jobs 4 --fuzz-jobs 4 \
  --output /tmp/unsafe-study-full
```

Optional strict-vs-baseline Miri triage:

```bash
bash scripts/run_all.sh --profile full --jobs 4 --fuzz-jobs 4 \
  --miri-triage --output /tmp/unsafe-study-full-triage
```

### Post-run checks

```bash
jq '.schema_version, (.crates | length)' /tmp/unsafe-study-full/report.json

jq -r '.crates[] | .name as $c | .phases[]
       | select(.status=="error")
       | [$c, .kind, .name, .summary] | @tsv' \
  /tmp/unsafe-study-full/report.json

jq -r '.crates[]
       | [.name, (.unsafe_sites | length),
          .pattern_summary.unsafe_blocks,
          .pattern_summary.ptr_ops,
          .pattern_summary.transmutes] | @tsv' \
  /tmp/unsafe-study-full/report.json
```

---

## Current status and explicit non-goals

Implemented today:

- AST-based unsafe inventory with stable site IDs and a compact pattern taxonomy;
- `cargo geiger` root/dependency unsafe summary;
- configured `cargo miri test` cases, including optional strict-vs-baseline triage;
- existing-target `cargo-fuzz` execution with sequential build / parallel run;
- current-run-only artifact attribution and explicit fuzz `error_kind` classification;
- JSON + Markdown reports with per-crate logs.

Still not implemented:

- fuzz reproducer -> Miri replay;
- automatic harness generation, even for narrow parser-like APIs;
- seed corpus auto-generation;
- typed pattern analysis (for example, union-field access detection);
- crates.io / git auto-acquisition;
- HTML reporting.

Interpretation boundaries remain strict:

- clean `miri` means no UB was observed on the exercised paths;
- clean `fuzz` means no failure was observed under the configured harnesses and budget;
- the tool does not prove soundness, recover invariants, or score exploitability.
