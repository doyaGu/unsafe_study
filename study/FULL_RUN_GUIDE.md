# Full Run Guide

This document describes how to run the current 12-crate study end to end using
the implementation that exists in this repository today.

The source of truth is:

- `study/manifest.toml` for crate selection, Miri cases, and fuzz groups
- `unsafe-audit` for execution behavior and report format
- `scripts/run_all.sh` for the recommended Linux entrypoint

If any older report or note disagrees with this guide, prefer the current
runner and generated `report.json`.

## Scope

The full pipeline is:

1. static unsafe inventory (`scan`)
2. `cargo geiger` (`geiger`)
3. configured `cargo miri test` cases (`miri`)
4. existing `cargo-fuzz` targets (`fuzz`)
5. top-level `report.json` and `report.md`

The manifest currently covers 12 crates:

- baseline: `httparse`, `serde_json`, `bstr`
- extension: `memchr`, `winnow`, `toml_parser`, `simd-json`, `quick-xml`, `goblin`, `toml_edit`, `pulldown-cmark`, `roxmltree`

## Prerequisites

### Repository state

The study assumes these directories already exist locally:

- `targets/<crate>/` for all 12 selected crates
- `miri_harnesses/`
- `unsafe-audit/`

### Toolchain

The repository pins:

```text
nightly-2026-02-01
```

Required Rust components:

- `miri`
- `rust-src`
- `rustfmt`
- `clippy`

Install them with:

```bash
rustup toolchain install nightly-2026-02-01 \
  --profile default \
  --component miri,rust-src,rustfmt,clippy
rustup default nightly-2026-02-01
```

### Cargo tools

Install:

```bash
cargo install cargo-geiger --locked
cargo install cargo-fuzz --locked
```

### System packages

The exact package set depends on the host, but a Linux environment should have
at least:

- `clang` or an equivalent C/C++ toolchain usable by libFuzzer
- `build-essential`
- `cmake`
- `pkg-config`
- `libssl-dev`
- `git`
- `python3` (recommended: `run_all.sh` uses it for binary-path discovery but can fall back to `cargo run`)
- `jq` for report inspection

The included [Dockerfile](/home/touyou/workspace/unsafe_study/Dockerfile:1)
shows one known-good environment.

## Recommended Execution Order

Do not start with a full 12-crate run if the machine or environment has not
been validated. Use this sequence.

### Entry point behavior

Use `bash scripts/run_all.sh ...` as the normal Linux entrypoint.

It builds the repo-local `unsafe-audit` crate, resolves the emitted executable
path from Cargo when possible, and falls back to `cargo run` otherwise. This
avoids hardcoding a `target/` path while keeping execution pinned to the
checked-out repository.

If you want the low-level form, replace the wrapper with:

```bash
cargo run --manifest-path unsafe-audit/Cargo.toml -- study/manifest.toml ...
```

### 1. Preflight checks

From the repo root:

```bash
rustup show active-toolchain
cargo geiger --version
cargo fuzz --help >/dev/null
cargo miri --help >/dev/null
cargo test --manifest-path unsafe-audit/Cargo.toml
```

Expected outcome:

- the active toolchain is `nightly-2026-02-01`
- `unsafe-audit` tests pass
- `cargo geiger`, `cargo fuzz`, and `cargo miri` are installed

### 2. Dry run the manifest

This confirms crate selection, Miri case wiring, and fuzz target groups without
running analysis tools.

```bash
bash scripts/run_all.sh --dry-run
```

Expected outcome:

- 12 crates appear in the plan
- `serde_json` has its targeted `api_smoke` Miri cases
- `simd-json` uses `miri_harnesses/tests/simd_json_triage.rs`
- each crate shows at least one fuzz group

### 3. Run a full smoke pass first

This is the minimum end-to-end health check for all phases and all crates.

```bash
bash scripts/run_all.sh \
  --profile smoke \
  --jobs 4 \
  --fuzz-jobs 4 \
  --output /tmp/unsafe-study-smoke
```

Smoke semantics:

- fuzz budgets are capped at `30s`
- all configured crates still run
- Miri and Geiger still run normally

Use smoke to answer one question only:

> Can every configured phase start, execute, and write a report on this machine?

### 4. Run the full study

Once smoke is clean at the infrastructure level, run the study with the full
manifest budgets.

Wrapper script:

```bash
bash scripts/run_all.sh \
  --profile full \
  --jobs 4 \
  --fuzz-jobs 4 \
  --output /tmp/unsafe-study-full
```

Important details:

- `full` preserves manifest/requested fuzz budgets instead of capping them
- the manifest currently sets top-level `fuzz_time = 3600`
- `--jobs` controls parallelism across crates
- `--fuzz-jobs` controls parallelism across fuzz targets inside one crate

### 5. Optional: rerun with Miri triage

If you want the runner to automatically perform a baseline Miri rerun after a
strict UB report, add:

```bash
--miri-triage
```

Example:

```bash
bash scripts/run_all.sh \
  --profile full \
  --jobs 4 \
  --fuzz-jobs 4 \
  --miri-triage \
  --output /tmp/unsafe-study-full-triage
```

## Output Layout

A run writes:

```text
<output>/
  report.json
  report.md
  crates/<crate>/logs/*.log
```

Examples:

- `/tmp/unsafe-study-smoke/report.json`
- `/tmp/unsafe-study-full/report.md`
- `/tmp/unsafe-study-full/crates/serde_json/logs/miri.upstream_full.log`

## Post-Run Validation

### Basic sanity checks

Check the top-level report exists:

```bash
ls /tmp/unsafe-study-full
```

Check schema and crate count:

```bash
jq '.schema_version, (.crates | length)' /tmp/unsafe-study-full/report.json
```

Expected today:

- `schema_version` is `1`
- crate count is `12`

### Phase status summary

```bash
jq -r '[.crates[].phases[] | .status] | group_by(.) | map({status: .[0], count: length})' \
  /tmp/unsafe-study-full/report.json
```

List any errors:

```bash
jq -r '.crates[] | .name as $c | .phases[] |
  select(.status=="error") |
  [$c, .kind, .name, .summary] | @tsv' \
  /tmp/unsafe-study-full/report.json
```

List findings:

```bash
jq -r '.crates[] | .name as $c | .phases[] |
  select(.status=="finding") |
  [$c, .kind, .name, .summary, (.evidence.verdict // .evidence.error_kind // "-")] | @tsv' \
  /tmp/unsafe-study-full/report.json
```

### Fuzz-specific checks

List fuzz statuses and run counts:

```bash
jq -r '.crates[] | .name as $c | .phases[] |
  select(.kind=="fuzz") |
  [$c, .name, .status, (.evidence.error_kind // "-"), .summary] | @tsv' \
  /tmp/unsafe-study-full/report.json
```

Watch for:

- `status == "error"`
- `error_kind == "environment_error"`
- missing targets
- suspiciously tiny run counts on targets that should be fast

### Static inventory checks

```bash
jq -r '.crates[] |
  [.name, (.unsafe_sites | length), .pattern_summary.unsafe_blocks, .pattern_summary.ptr_ops, .pattern_summary.transmutes] |
  @tsv' /tmp/unsafe-study-full/report.json
```

This confirms `scan` actually populated the unsafe-site inventory rather than
just the dynamic phases.

## Useful Variants

### Restrict to one or two crates

```bash
bash scripts/run_all.sh \
  --crates httparse,serde_json \
  --profile full \
  --output /tmp/unsafe-study-subset
```

### Re-run only fuzz

```bash
bash scripts/run_all.sh \
  --skip-scan \
  --skip-geiger \
  --skip-miri \
  --profile full \
  --output /tmp/unsafe-study-fuzz-only
```

### Re-run only Miri on a subset

```bash
bash scripts/run_all.sh \
  --crates serde_json,bstr \
  --skip-scan \
  --skip-geiger \
  --skip-fuzz \
  --miri-triage \
  --output /tmp/unsafe-study-miri-only
```

## Common Failure Modes

### `cargo geiger` missing

Symptom:

- Geiger phases fail immediately

Fix:

```bash
cargo install cargo-geiger --locked
```

### `cargo fuzz` missing or libFuzzer build failures

Symptom:

- fuzz build never starts
- fuzz phases return `tool_error`

Fix:

```bash
cargo install cargo-fuzz --locked
```

Also confirm a working native toolchain is available for sanitizer/libFuzzer
builds.

### `cargo miri` missing

Symptom:

- Miri phases fail immediately

Fix:

```bash
rustup component add miri rust-src --toolchain nightly-2026-02-01
```

### Environment-specific LeakSanitizer / ptrace failures

Symptom:

- fuzz phases report `environment_error`

The runner already uses `ASAN_OPTIONS=detect_leaks=0` in this study manifest.
If you still see ptrace-related failures, prefer a normal Linux host or the
provided Docker environment instead of a restricted sandbox.

### Old historical reports disagree with the new run

This is expected. Use:

- the current `study/manifest.toml`
- the current `unsafe-audit` binary
- the new `report.json`

as the authoritative execution record.

## Recommended Recordkeeping

For a full rerun, keep:

- the exact command line
- the output directory path
- the git commit of this repo
- any local changes in `targets/`
- whether `--miri-triage` was enabled

At minimum:

```bash
git rev-parse HEAD
git status --short
```

Save that alongside the output directory.
