# Study Protocol

[study/manifest.toml](manifest.toml) is the canonical manifest for the
12-crate study. This document is the schema reference; for end-to-end
execution, follow [FULL_RUN_GUIDE.md](FULL_RUN_GUIDE.md).

`unsafe-audit` treats:

- a **directory** input as a single-crate run with a default plan,
- a **file** input as a manifest-driven study run.

Recommended Linux entrypoint:

```bash
bash scripts/run_all.sh [args]
```

Low-level equivalent:

```bash
cargo run --manifest-path unsafe-audit/Cargo.toml -- study/manifest.toml [args]
```

---

## Manifest variants in this directory

| File | Purpose |
|------|---------|
| [manifest.toml](manifest.toml) | The canonical 12-crate study with full fuzz budgets (`fuzz_time = 3600`) and every targeted Miri case wired in. Use this for the formal study run. |
| [manifest.accept.toml](manifest.accept.toml) | A minimal acceptance-style subset: fewer harnesses and shorter budgets. Use it to validate that the runner, output layout, and report writer behave correctly without committing to a full multi-hour run. |
| [manifest.env-rerun.toml](manifest.env-rerun.toml) | Same crate set, configured for re-runs that override fuzz environment variables (e.g. ASAN settings). Use it when reproducing a finding under a different runtime environment. |

---

## Pre-rerun requirement: `simd-json` compile-fix patch

Before any rerun that touches `targets/simd-json`, apply
[../patches/simd-json/0001-fix-nightly-unused-imports.patch](../patches/simd-json/0001-fix-nightly-unused-imports.patch):

```bash
cd targets/simd-json
git apply --check ../../patches/simd-json/0001-fix-nightly-unused-imports.patch
git apply ../../patches/simd-json/0001-fix-nightly-unused-imports.patch
```

The pinned `nightly-2026-02-01` toolchain promotes five
`unused_imports`/unused-re-export warnings in `simd-json 0.17.0` to hard
errors (`#![deny(warnings)]`). The patch is intentionally minimal and only
fixes the compile break; it does not change parser logic or any targeted Miri
case. The [Dockerfile](../Dockerfile) applies it automatically.

---

## Manifest schema

The schema is intentionally small. Top-level study fields used by the runner:

```toml
[study]
name        = "unsafe-study"
output_root = "study/output"               # default; override with --output
fuzz_time   = 3600                          # default per fuzz group, in seconds
fuzz_env    = { ASAN_OPTIONS = "detect_leaks=0" }
```

One `[[crate]]` per study crate, with zero or more nested
`[[crate.miri_case]]` and `[[crate.fuzz_group]]` entries:

```toml
[[crate]]
name           = "httparse"
path           = "targets/httparse"
cohort         = "baseline"     # "baseline" | "extension" — labels only
coverage_tier  = "tier1"        # "tier1"    | "tier2"     — labels only
```

`cohort` and `coverage_tier` are descriptive labels copied into the report;
they do not change runner behavior.

### `[[crate.miri_case]]`

Each entry describes one `cargo miri test` invocation:

| Field | Required | Meaning |
|-------|----------|---------|
| `name`        | yes | Report label. |
| `scope`       | yes | Human-interpretation label (`full_suite`, `targeted`, `targeted_smoke`, …). Carried into the report. |
| `harness_dir` | no  | Working directory for the invocation. Defaults to the crate `path`. Set to `miri_harnesses/<crate>` to use the per-crate Miri harness package. |
| `test`        | no  | `--test <target>` integration test name. |
| `case`        | no  | Test name filter passed positionally. |
| `exact`       | no  | If true, append `-- --exact`. |
| `env`         | no  | Per-case env table (e.g. `MIRIFLAGS = "-Zmiri-disable-isolation"`). |

Each case becomes one `PhaseReport` with `kind = "miri"`, name = the case
`name`, and a `PhaseEvidence::Miri { verdict, ub_category, excerpt }`.

### `[[crate.fuzz_group]]`

Each entry describes one fuzz target set:

| Field | Required | Meaning |
|-------|----------|---------|
| `name`         | yes | Report label. |
| `harness_dir`  | no  | Fuzz harness root. Defaults to the crate `path`. Set to `fuzz_harnesses/<crate>` to use the mirrored fuzz harness directory. |
| `all = true`   | one of these two | Discover and run every existing target via `cargo fuzz list`. |
| `targets = [...]` | one of these two | Run only the listed target names. |
| `time`         | no  | Per-group time budget in seconds. Defaults to top-level `fuzz_time`. |
| `budget_label` | no  | Free-form label (e.g. `smoke`, `baseline`, `extension`) carried into the report. |
| `env`          | no  | Per-group env table merged after `study.fuzz_env`. |

Each target inside a group becomes one `PhaseReport` with `kind = "fuzz"`,
name = `<group>.<target>`, and a
`PhaseEvidence::Fuzz { target, budget_secs, artifact, error_kind, runs, excerpt }`.

The runner executes **existing** targets only — no harness synthesis.

---

## Corpus backfill

Before launching a fuzz target, the runner ensures
`targets/<crate>/fuzz/corpus/<target>/` exists. If that directory is empty
and `fuzz_harnesses/<crate>/corpus/<target>/` contains seeds, the runner
copies them in. This keeps the canonical seed corpus checked into
[../fuzz_harnesses/](../fuzz_harnesses/) while letting `cargo fuzz` write
mutations into the per-crate workspace.

---

## Robustness behaviors

These behaviors keep a study completable when local checkouts are imperfect:

- A non-existent or non-canonical `harness_dir` is treated as an empty target
  set (status `skipped`), not a hard error.
- A missing `fuzz/` workspace or a `cargo fuzz list` failure is recorded as
  `skipped`.
- A `targets = [...]` entry naming a target that does not exist locally is
  recorded as `skipped` for that target only; sibling targets continue.
- Per-target `cargo fuzz build` failures are recorded as `error` with
  `error_kind = "tool_error"` for that target only; the rest of the group
  continues.
- Static scan: a single `.rs` file unparsable by `syn::parse_file` is
  reported as a warning and skipped (e.g.
  `targets/memchr/benchmarks/haystacks/code/rust-library.rs`); the rest of
  the crate scan completes.

These were added during the 2026-04-27 rerun so that a partial environment
still produces a meaningful report.

---

## Environment merge order

For each fuzz target, the final environment is composed as:

1. inherited process environment,
2. `study.fuzz_env`,
3. per-group `env`,
4. CLI `--fuzz-env KEY=VALUE` (repeatable).

For single-crate (directory-input) runs, the runner additionally defaults to
`ASAN_OPTIONS=detect_leaks=0` to suppress the
*"LeakSanitizer does not work under ptrace"* failure mode common in
sandboxed CI hosts.

---

## Profiles and parallelism

```text
--profile smoke|baseline|full
--jobs N
--fuzz-jobs N
```

| Profile | Effect |
|---------|--------|
| `smoke`    | Cap every fuzz budget to **30s**. |
| `baseline` | Cap every fuzz budget to **300s**. |
| `full`     | Preserve the manifest/CLI-requested budget. |

| Flag | Scope |
|------|-------|
| `--jobs N`      | Parallelism across crates (`std::thread::scope`). |
| `--fuzz-jobs N` | Parallelism across fuzz targets within one crate / group. |

Fuzz parallelism uses sequential `cargo fuzz build` followed by parallel
execution of the produced libFuzzer binaries — this avoids the lock
contention that parallel `cargo fuzz run` would trigger.

Miri executions are serialized via a process-wide mutex regardless of
`--jobs`, because `miri-server` does not tolerate concurrent invocations.

---

## Output layout

A run writes a single self-contained directory:

```text
<output>/
  report.json          # schema_version = 1
  report.md
  crates/<crate>/logs/
    geiger.root.log
    miri.<case>.log
    fuzz.<group>.<target>.log
```

The top-level `report.json` includes execution metadata: `schema_version`,
`profile`, `jobs`, `fuzz_jobs`, enabled phases, `miri_triage`, `fuzz_time`,
`fuzz_env`. The Markdown render mirrors the same data in human-readable form.

---

## Examples

Dry run (validate the plan, no execution):

```bash
bash scripts/run_all.sh --dry-run
```

Restricted smoke subset:

```bash
bash scripts/run_all.sh \
  --crates httparse,simd-json \
  --profile smoke \
  --jobs 2 --fuzz-jobs 2 \
  --output /tmp/study-smoke
```

Acceptance variant (uses the smaller manifest):

```bash
cargo run --manifest-path unsafe-audit/Cargo.toml -- \
  study/manifest.accept.toml \
  --output /tmp/study-accept
```

Env-rerun variant (override fuzz environment for a focused reproduction):

```bash
cargo run --manifest-path unsafe-audit/Cargo.toml -- \
  study/manifest.env-rerun.toml \
  --crates simd-json \
  --skip-scan --skip-geiger --skip-miri \
  --fuzz-env ASAN_OPTIONS="detect_leaks=0:abort_on_error=1" \
  --output /tmp/study-env-rerun
```
