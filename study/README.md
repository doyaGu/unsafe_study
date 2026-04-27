# Study Protocol

`study/manifest.toml` is the canonical manifest for the 12-crate study.

For a full end-to-end execution runbook, see
[FULL_RUN_GUIDE.md](FULL_RUN_GUIDE.md).

The recommended Linux entrypoint is:

```bash
bash scripts/run_all.sh
```

Current rerun note: before a formal study rerun, apply
`patches/simd-json/0001-fix-nightly-unused-imports.patch` to
`targets/simd-json`. The pinned nightly toolchain currently turns five
otherwise-benign `unused_imports` / unused re-export warnings into hard errors
because upstream `simd-json 0.17.0` uses `#![deny(warnings)]`.

That wrapper keeps execution pinned to this repository's `unsafe-audit` crate,
resolves the emitted executable path from Cargo when possible, and falls back
to `cargo run` otherwise. The low-level equivalent is:

```bash
cargo run --manifest-path unsafe-audit/Cargo.toml -- \
  study/manifest.toml
```

The current runner treats:

- a directory input as a single crate run
- a file input as a manifest-driven study run

## Manifest Shape

The schema is intentionally small:

- one `[[crate]]` entry per study crate
- zero or more `[[crate.miri_case]]` entries
- zero or more `[[crate.fuzz_group]]` entries

Top-level study fields currently used by the compact runner:

- `name`
- `output_root`
- `fuzz_time`
- `fuzz_env`

## `miri_case`

Each `miri_case` describes one explicit `cargo miri test` run:

- `name`: report label
- `scope`: human interpretation label in the report
- `harness_dir`: optional working directory override
- `test`: optional integration test target
- `case`: optional case filter
- `exact`: whether to pass `-- --exact`

These are normalized into one `PhaseReport` per case.

## `fuzz_group`

Each `fuzz_group` describes one fuzz target set:

- `name`: report label
- `harness_dir`: optional fuzz harness root; defaults to the crate path
- `all = true`: discover and run all existing targets
- `targets = [...]`: run only the listed targets
- `time`: optional per-group time budget
- `budget_label`: optional label carried in the plan
- `env = { KEY = "VALUE" }`: per-group environment overrides

The compact runner executes existing targets only. It does not generate new
fuzz harnesses.

Before launching a fuzz target, the runner now ensures that
`targets/<crate>/fuzz/corpus/<target>/` exists. If that directory is empty and
`fuzz_harnesses/<crate>/corpus/<target>/` exists, the runner copies the seed
files from the per-crate `fuzz_harnesses` corpus store into the local crate
corpus directory.

Current runner behavior when local fuzz assets are incomplete:

- missing or non-canonical `harness_dir` paths are treated as an empty target set
- missing `fuzz/` workspaces or `cargo fuzz list` failures are recorded as `skipped`
- explicit targets absent from the local workspace are recorded as `skipped`
- per-target `cargo fuzz build` failures are recorded as fuzz `error` reports,
  while the remaining targets in the same group continue to run

This behavior was added during the 2026-04-27 rerun so the study can complete
even when local `targets/<crate>/fuzz/` trees are incomplete or diverge from
the intended manifest wiring.

## Environment Merge Order

Fuzz environment merge order is:

1. study `fuzz_env`
2. per-group `env`
3. CLI `--fuzz-env`

For single-crate runs, the tool also defaults to:

```text
ASAN_OPTIONS=detect_leaks=0
```

That default is there to suppress the current sandbox's LeakSanitizer/ptrace
noise.

## Profiles And Parallelism

The current CLI supports:

- `--profile smoke|baseline|full`
- `--jobs N`
- `--fuzz-jobs N`

Profile semantics:

- `smoke`: cap fuzz budgets to `30s`
- `baseline`: cap fuzz budgets to `300s`
- `full`: preserve requested/manifest budgets

Parallelism semantics:

- `--jobs`: parallelism across crates
- `--fuzz-jobs`: parallelism across fuzz targets within one crate/group

Fuzz parallelism is implemented as:

1. sequential `cargo fuzz build`
2. parallel execution of built libFuzzer binaries

This avoids parallel `cargo fuzz run` lock contention.

## Output Layout

The current output layout is compact:

```text
out/
  report.json
  report.md
  crates/<crate>/logs/*.log
```

The top-level report includes execution metadata:

- `schema_version` (currently `1`)
- `profile`
- `jobs`
- `fuzz_jobs`
- enabled phases
- `miri_triage`
- `fuzz_time`
- `fuzz_env`

## Scan Robustness

The static scan walks `*.rs` files under each crate root, excluding `target/`,
`.git/`, `fuzz/`, `vendor/`, and `.cargo/` directories.

If an individual Rust file is unreadable by `syn::parse_file`, the runner now
emits a warning and skips that file instead of aborting the entire crate scan.
This was needed for the 2026-04-27 rerun because
`targets/memchr/benchmarks/haystacks/code/rust-library.rs` is not a normal
crate compilation unit even though it has an `.rs` extension.

## Examples

Dry run:

```bash
bash scripts/run_all.sh --dry-run
```

Restricted study subset:

```bash
bash scripts/run_all.sh \
  --crates httparse,simd-json \
  --profile smoke \
  --jobs 2 \
  --fuzz-jobs 2 \
  --output /tmp/study-smoke
```
