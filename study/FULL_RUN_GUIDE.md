# Full Run Guide

This is the operational runbook for executing the canonical 12-crate study
end-to-end against the implementation in this repository.

Sources of truth:

- [study/manifest.toml](manifest.toml) — crates, Miri cases, fuzz groups.
- [unsafe-audit/](../unsafe-audit/) — execution behavior and report format.
- [scripts/run_all.sh](../scripts/run_all.sh) — recommended Linux entrypoint.

If any older note or report disagrees with this guide, prefer the current
runner and the freshly generated `report.json`.

---

## What "the full pipeline" means

Five stages, all driven by one `unsafe-audit` invocation:

1. `scan`    — AST-based inventory of unsafe sites (cheap, local).
2. `geiger`  — `cargo geiger --output-format Json`.
3. `miri`    — every configured `cargo miri test` case.
4. `fuzz`    — every existing `cargo-fuzz` target in each configured group.
5. `report`  — top-level `report.json` (`schema_version = 1`) and `report.md`.

The 12 crates currently covered:

- **Baseline:** `httparse`, `serde_json`, `bstr`.
- **Extension:** `memchr`, `winnow`, `toml_parser`, `simd-json`, `quick-xml`,
  `goblin`, `toml_edit`, `pulldown-cmark`, `roxmltree`.

---

## Prerequisites

### Repository state

These directories must exist locally:

- `targets/<crate>/` for all 12 crates (the [Dockerfile](../Dockerfile) shows
  the canonical fetch process),
- [miri_harnesses/](../miri_harnesses/) (per-crate Cargo workspaces),
- [fuzz_harnesses/](../fuzz_harnesses/) (per-crate harness mirrors + canonical
  seed corpora),
- [unsafe-audit/](../unsafe-audit/) (the runner crate).

### Required local patch for `simd-json`

Apply before any rerun that touches `targets/simd-json`:

```bash
cd targets/simd-json
git apply --check ../../patches/simd-json/0001-fix-nightly-unused-imports.patch
git apply ../../patches/simd-json/0001-fix-nightly-unused-imports.patch
```

Why: the pinned nightly toolchain promotes 5 `unused_imports` warnings in
`simd-json 0.17.0` to hard errors because the crate uses
`#![deny(warnings)]`. Without the patch, the
[miri_harnesses/simd_json/](../miri_harnesses/simd_json/) package will not
build during the rerun. The patch is intentionally minimal and does not
change parser logic.

### Toolchain

Pinned in [rust-toolchain.toml](../rust-toolchain.toml):

```text
nightly-2026-02-01
components: miri, rust-src, rustfmt, clippy
```

Install (idempotent):

```bash
rustup toolchain install nightly-2026-02-01 \
  --profile default \
  --component miri,rust-src,rustfmt,clippy
rustup default nightly-2026-02-01
```

### Cargo plugins

```bash
cargo install cargo-geiger --locked
cargo install cargo-fuzz   --locked
```

### System packages (Linux)

A working libFuzzer-capable toolchain is required:

- `clang` (or equivalent), `build-essential`, `cmake`, `pkg-config`,
- `libssl-dev`, `git`, `python3`, `jq`, `xz-utils`.

The bundled [Dockerfile](../Dockerfile) is the reference environment.

---

## Execution order

Do **not** start with a full 12-crate run on an unvalidated host. Walk
through the steps below in order.

`run_all.sh` is the normal entrypoint: it builds the repo-local
`unsafe-audit` crate, resolves the emitted binary path from
`cargo build --message-format=json-render-diagnostics`, and falls back to
`cargo run --manifest-path unsafe-audit/Cargo.toml --` if the JSON parse
fails. The low-level form is:

```bash
cargo run --manifest-path unsafe-audit/Cargo.toml -- study/manifest.toml [args]
```

### 1. Preflight

```bash
rustup show active-toolchain
cargo geiger --version
cargo fuzz --help >/dev/null
cargo miri --help >/dev/null
cargo test --manifest-path unsafe-audit/Cargo.toml
```

Expected:

- active toolchain is `nightly-2026-02-01`,
- the `unsafe-audit` test suite is green,
- all three cargo plugins respond,
- `targets/simd-json` already has the compile-fix patch applied.

### 2. Dry-run the manifest

Validates crate selection, Miri-case wiring, and fuzz-group composition
without invoking any analysis tools.

```bash
bash scripts/run_all.sh --dry-run
```

Expected in the printed plan:

- 12 crates,
- `serde_json` carries its targeted Miri cases under
  `miri_harnesses/serde_json/`,
- `simd-json` uses
  `miri_harnesses/simd_json/tests/simd_json_triage.rs`,
- every crate has at least one fuzz group.

### 3. Smoke pass

The minimum end-to-end health check across all phases and all crates.

```bash
bash scripts/run_all.sh \
  --profile smoke \
  --jobs 4 --fuzz-jobs 4 \
  --output /tmp/unsafe-study-smoke
```

Smoke semantics:

- fuzz budgets capped at 30s,
- Miri and Geiger run normally.

Smoke answers exactly one question:

> Can every configured phase start, execute, and write a report on this
> machine?

### 4. Full study

Once smoke is clean, run the manifest with full budgets.

```bash
bash scripts/run_all.sh \
  --profile full \
  --jobs 4 --fuzz-jobs 4 \
  --output /tmp/unsafe-study-full
```

Notes:

- `full` preserves the manifest budgets (`fuzz_time = 3600`).
- `--jobs` parallelizes across crates.
- `--fuzz-jobs` parallelizes fuzz targets within one crate.
- Miri is serialized internally regardless of `--jobs`.

### 5. Optional Miri triage rerun

Re-run baseline Miri after a strict UB report and classify the verdict:

```bash
bash scripts/run_all.sh \
  --profile full --jobs 4 --fuzz-jobs 4 \
  --miri-triage \
  --output /tmp/unsafe-study-full-triage
```

---

## Output layout

```text
<output>/
  report.json
  report.md
  crates/<crate>/logs/
    geiger.root.log
    miri.<case>.log
    fuzz.<group>.<target>.log
```

Examples:

- `/tmp/unsafe-study-full/report.md`
- `/tmp/unsafe-study-full/crates/serde_json/logs/miri.upstream_full.log`
- `/tmp/unsafe-study-full/crates/httparse/logs/fuzz.existing_parser_targets.parse_request.log`

---

## Post-run validation

### Schema and crate count

```bash
jq '.schema_version, (.crates | length)' /tmp/unsafe-study-full/report.json
```

Expected: `1` and `12`.

### Phase status histogram

```bash
jq -r '[.crates[].phases[] | .status]
       | group_by(.) | map({status: .[0], count: length})' \
  /tmp/unsafe-study-full/report.json
```

### Errors

```bash
jq -r '.crates[] | .name as $c | .phases[]
       | select(.status=="error")
       | [$c, .kind, .name, .summary] | @tsv' \
  /tmp/unsafe-study-full/report.json
```

### Findings

```bash
jq -r '.crates[] | .name as $c | .phases[]
       | select(.status=="finding")
       | [$c, .kind, .name, .summary,
          (.evidence.verdict // .evidence.error_kind // "-")] | @tsv' \
  /tmp/unsafe-study-full/report.json
```

### Fuzz drill-down

```bash
jq -r '.crates[] | .name as $c | .phases[]
       | select(.kind=="fuzz")
       | [$c, .name, .status,
          (.evidence.error_kind // "-"), .summary] | @tsv' \
  /tmp/unsafe-study-full/report.json
```

Watch for: `status == "error"`, `error_kind == "environment_error"`, missing
targets, or suspiciously tiny run counts on targets that should be fast.

### Static inventory

```bash
jq -r '.crates[]
       | [.name, (.unsafe_sites | length),
          .pattern_summary.unsafe_blocks,
          .pattern_summary.ptr_ops,
          .pattern_summary.transmutes] | @tsv' \
  /tmp/unsafe-study-full/report.json
```

This confirms the `scan` phase actually populated each crate's inventory.

---

## Useful variants

### Restrict to a subset of crates

```bash
bash scripts/run_all.sh \
  --crates httparse,serde_json \
  --profile full \
  --output /tmp/unsafe-study-subset
```

### Re-run only fuzz

```bash
bash scripts/run_all.sh \
  --skip-scan --skip-geiger --skip-miri \
  --profile full \
  --output /tmp/unsafe-study-fuzz-only
```

### Re-run only Miri (with triage)

```bash
bash scripts/run_all.sh \
  --crates serde_json,bstr \
  --skip-scan --skip-geiger --skip-fuzz \
  --miri-triage \
  --output /tmp/unsafe-study-miri-only
```

### Acceptance manifest (smaller surface)

```bash
cargo run --manifest-path unsafe-audit/Cargo.toml -- \
  study/manifest.accept.toml \
  --output /tmp/unsafe-study-accept
```

### Env-rerun manifest (override sanitizer settings)

```bash
cargo run --manifest-path unsafe-audit/Cargo.toml -- \
  study/manifest.env-rerun.toml \
  --crates simd-json \
  --fuzz-env ASAN_OPTIONS="detect_leaks=0:abort_on_error=1" \
  --output /tmp/unsafe-study-env-rerun
```

---

## Common failure modes

### `cargo geiger` missing

Symptom: every Geiger phase fails immediately.

Fix:

```bash
cargo install cargo-geiger --locked
```

### `cargo fuzz` missing or libFuzzer build fails

Symptom: fuzz never starts, or every fuzz phase reports
`error_kind = "tool_error"`.

Fix:

```bash
cargo install cargo-fuzz --locked
```

Confirm a working clang / native toolchain is available for the libFuzzer
sanitizer build.

### `cargo miri` missing

Symptom: Miri phases fail immediately.

Fix:

```bash
rustup component add miri rust-src --toolchain nightly-2026-02-01
```

### Sandbox / ptrace failures

Symptom: fuzz phases report `error_kind = "environment_error"`.

The runner already injects `ASAN_OPTIONS=detect_leaks=0`. If failures
persist, switch to a normal Linux host or use the bundled
[Dockerfile](../Dockerfile) instead of a restricted sandbox.

### `simd-json` Miri harness fails to build

Symptom: `miri.simd_json_triage` reports `tool_error` with
`error[E0432]`/`unused_imports` lines.

Fix: apply
[../patches/simd-json/0001-fix-nightly-unused-imports.patch](../patches/simd-json/0001-fix-nightly-unused-imports.patch)
to `targets/simd-json` (see Prerequisites).

### Old historical reports disagree with the new run

Expected. Authoritative artifacts for any rerun are:

- the current [study/manifest.toml](manifest.toml),
- the current `unsafe-audit` binary,
- the freshly generated `report.json`.

---

## Recordkeeping

For every rerun, archive at minimum:

- the exact command line,
- the `--output` directory path,
- the git commit and working-tree status of this repo:

  ```bash
  git rev-parse HEAD
  git status --short
  ```

- any local modifications under `targets/` (notably the `simd-json` patch),
- whether `--miri-triage` was enabled.

Save that metadata alongside the output directory so the run is reproducible.
