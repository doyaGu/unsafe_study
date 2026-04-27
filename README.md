# unsafe_study

`unsafe_study` is a research project around one question:

> Can we build an evidence-driven workflow that identifies which Rust `unsafe`
> sites exist, which ones are dynamically exercised, and which ones deserve
> human review first?

The main executable deliverable is `unsafe-audit`, a local CLI that runs a
compact study protocol over one crate or a manifest-defined crate cohort.

## Workspace Layout

The repository is easiest to navigate if you read it in terms of the research
workflow rather than as one flat collection of folders.

Canonical layout guide:

- [WORKSPACE_MAP.md](WORKSPACE_MAP.md)

Short version:

- `unsafe-audit/`: the study runner
- `study/` + `targets/`: the canonical study inputs
- `miri_harnesses/` + `fuzz_harnesses/`: added dynamic harnesses for targeted
  Miri coverage and active extracted fuzz harnesses
- `evidence/geiger/` + `evidence/miri/` + `evidence/fuzz/`: archived evidence
- `docs/report/` + `docs/proposal/`: writing and research outputs
- `scripts/` + `tmp/`: utility and scratch space

## Current Tool Shape

`unsafe-audit` is now a compact study runner, not the earlier exploration-heavy
platform.

Unified workflow:

```text
input
-> RunPlan
-> per-crate execution
-> scan / geiger / miri / fuzz
-> structured evidence
-> report.json + report.md
```

Input forms:

```bash
unsafe-audit path/to/crate --output out/
unsafe-audit study/manifest.toml --output out/
```

A crate path becomes a single-crate `RunPlan`. A manifest file becomes a
multi-crate study plan with normalized Miri cases and fuzz groups.

## What `unsafe-audit` Does

### 1. Unsafe Inventory

AST-based scan over local Rust sources using `syn`.

The current compact taxonomy records:

- `unsafe_block`
- `unsafe_fn`
- `unsafe_impl`
- `extern_block`
- `ptr_op`
- `transmute`
- `unchecked_op`
- `inline_asm`

The report stores a stable site id, file, line, kind, and compact pattern.

### 2. Geiger

Runs:

```bash
cargo geiger --output-format Json
```

The current parser keeps a compact root/dependency unsafe summary plus full
logs.

### 3. Miri

Runs configured `cargo miri test` invocations from the manifest or the single
crate default plan.

Supported semantics:

- full upstream suite
- explicit `--test <target>`
- case filter
- `-- --exact`
- harness working directory override
- strict-vs-baseline triage

Recorded evidence includes:

- verdict
- coarse UB category
- summary
- duration
- log path

### 4. Fuzz

Runs existing fuzz targets only. The tool does not synthesize harnesses.

Execution model:

1. discover targets with `cargo fuzz list` or use manifest target list
2. build each target with `cargo fuzz build`
3. run built libFuzzer binaries directly
4. optionally run multiple targets in parallel with `--fuzz-jobs`

Recorded evidence includes:

- status
- target
- budget
- run count
- artifact path
- error kind
- duration
- log path

Fuzz `error_kind` is now explicit:

- `environment_error`
- `tool_error`
- `finding`

Artifact attribution is also current-run only: historical `crash-*` files are
not attached to a clean run.

### 5. Report

Each run writes:

```text
out/
  report.json
  report.md
  crates/<crate>/logs/*.log
```

`report.json` includes:

- top-level execution config
- per-crate unsafe inventory
- per-phase status and summary
- phase-specific evidence
- review-priority rows

`report.md` includes:

- execution config
- study overview
- per-crate unsafe inventory
- dynamic evidence table
- review priority

## What `unsafe-audit` Does Not Do

The current core intentionally does not include:

- exploration scheduler
- LLVM coverage replay/parsing
- unsafe-site reach merging from coverage
- resume/status/stop runtime management
- LLM harness generation
- crates.io/git acquisition
- HTML reporting
- soundness proof or exploitability analysis

## CLI

Build:

```bash
cd unsafe-audit
cargo build --release
```

Single crate:

```bash
./target/release/unsafe-audit ../targets/httparse \
  --output /tmp/httparse-report
```

Study manifest:

```bash
./target/release/unsafe-audit ../study/manifest.toml \
  --output /tmp/study-report
```

Dry run:

```bash
./target/release/unsafe-audit ../study/manifest.toml --dry-run
```

Useful flags:

```text
--output <DIR>          Output directory
--crates <A,B,...>      Restrict manifest input to selected crates
--dry-run               Print normalized plan without running tools
--skip-scan             Skip AST unsafe inventory
--skip-geiger           Skip Geiger
--skip-miri             Skip Miri
--skip-fuzz             Skip fuzz
--miri-triage           Re-run baseline Miri when strict Miri reports UB
--fuzz-time <SECONDS>   Default fuzz time budget
--fuzz-env KEY=VALUE    Extra env var for fuzz; repeatable
--format <FORMAT>       `json` or `markdown`; repeatable
--profile <PROFILE>     `smoke`, `baseline`, or `full`
--jobs <N>              Parallelism across crates
--fuzz-jobs <N>         Parallelism across fuzz targets within one crate
```

Profile semantics:

- `smoke`: caps fuzz budget to `30s`
- `baseline`: caps fuzz budget to `300s`
- `full`: preserves requested/manifest budget

Single-crate fuzz runs also default to:

```text
ASAN_OPTIONS=detect_leaks=0
```

That avoids the current sandbox's `LeakSanitizer ... does not work under
ptrace` noise.

## Progress Output

Long runs now print explicit progress to stderr:

- crate start/done
- geiger start/done
- miri case start/done
- fuzz group start/done
- fuzz target build start/done
- fuzz target run start
- fuzz target final status with elapsed/budget

Representative output:

```text
[1/1] crate httparse: fuzz start
  fuzz group existing_targets: start
    fuzz target parse_chunk_size: build start (budget 30s)
    fuzz target parse_chunk_size: build done
    fuzz target parse_chunk_size: run start (budget 30s)
    fuzz target parse_chunk_size: clean (31.1s/30s)
```

## Study Protocol

The canonical 12-crate protocol lives in:

- [study/manifest.toml](study/manifest.toml)
- [study/README.md](study/README.md)
- [study/FULL_RUN_GUIDE.md](study/FULL_RUN_GUIDE.md)

The recommended Linux entrypoint is [scripts/run_all.sh](scripts/run_all.sh).
It builds the repo-local `unsafe-audit` crate, resolves the emitted executable
path from Cargo metadata when possible, and falls back to `cargo run`
otherwise. For prerequisites, profiles, and end-to-end examples, use
[study/FULL_RUN_GUIDE.md](study/FULL_RUN_GUIDE.md). The low-level equivalent
remains:

```bash
cargo run --manifest-path unsafe-audit/Cargo.toml -- study/manifest.toml
```

## Repository Layout

```text
unsafe-audit/           current CLI/library implementation
study/                  manifest-driven research protocol
targets/                local target crates
miri_harnesses/         active targeted Miri harnesses used by the study
evidence/               archived Geiger, Miri, and fuzz artifacts
docs/                   report and proposal materials
fuzz_harnesses/         active extracted fuzz harnesses
scripts/                repo-local runner wrappers and helper scripts
```

## Current Status

The current compact implementation is centered on:

- `unsafe-audit/src/main.rs`
- `unsafe-audit/src/lib.rs`
- `unsafe-audit/src/config.rs`
- `unsafe-audit/src/runner.rs`
- `unsafe-audit/src/scan.rs`
- `unsafe-audit/src/phases.rs`
- `unsafe-audit/src/report.rs`
- `unsafe-audit/src/fs.rs`

Recent verified behavior:

- `cargo test` passes
- manifest-driven study execution works
- crate-level parallelism works via `--jobs`
- fuzz-target parallelism works via `--fuzz-jobs`
- clean fuzz runs no longer inherit stale artifact paths
- JSON and Markdown both expose execution config and fuzz error details
