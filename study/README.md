# Study Protocol

`study/manifest.toml` is the canonical manifest for the 12-crate study.

The protocol is executed natively by passing the manifest path to
`unsafe-audit`:

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

- `profile`
- `jobs`
- `fuzz_jobs`
- enabled phases
- `miri_triage`
- `fuzz_time`
- `fuzz_env`

## Examples

Dry run:

```bash
cargo run --manifest-path unsafe-audit/Cargo.toml -- \
  study/manifest.toml \
  --dry-run
```

Restricted study subset:

```bash
cargo run --manifest-path unsafe-audit/Cargo.toml -- \
  study/manifest.toml \
  --crates httparse,simd-json \
  --profile smoke \
  --jobs 2 \
  --fuzz-jobs 2 \
  --output /tmp/study-smoke
```
