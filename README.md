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
The full protocol is defined in [study/manifest.toml](study/manifest.toml) and
documented in [study/README.md](study/README.md) and
[study/FULL_RUN_GUIDE.md](study/FULL_RUN_GUIDE.md).

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

- `clean`              – budget elapsed, no crash, no findings;
- `finding`            – libFuzzer reported a crash/panic/timeout/OOM and an
  artifact from this run is attached;
- `tool_error`         – `cargo fuzz` itself failed (build error, missing
  target, etc.);
- `environment_error`  – sanitizer/runtime refused to start (e.g. ptrace,
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

```text
unsafe-audit/        Rust crate – CLI + library implementing the workflow.
study/               Manifest-driven study protocol (3 manifest variants).
targets/             Local checkouts of the 12 study crates.
miri_harnesses/      Per-crate workspaces with targeted Miri integration tests.
fuzz_harnesses/      Per-crate fuzz harness mirrors + canonical seed corpora.
evidence/            Archived geiger/miri/fuzz artifacts from prior runs.
docs/                Proposal, final report, and supporting writeups.
scripts/             run_all.sh, run_fuzz.sh, make_demo_video.sh, summarize_geiger.py.
patches/simd-json/   Compile-fix patch required for nightly + simd-json 0.17.0.
```

See [WORKSPACE_MAP.md](WORKSPACE_MAP.md) for how to navigate the tree by
research role rather than by directory name.

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

## Documentation map

| Read this | When you need to |
|-----------|------------------|
| [README.md](README.md) | Get a one-page overview of the tool and pipeline. |
| [DESIGN.md](DESIGN.md) | Understand architecture, phase semantics, and report interpretation. |
| [WORKSPACE_MAP.md](WORKSPACE_MAP.md) | Navigate the repository by research role. |
| [study/README.md](study/README.md) | Learn the manifest schema and how Miri/fuzz cases are wired. |
| [study/FULL_RUN_GUIDE.md](study/FULL_RUN_GUIDE.md) | Execute the 12-crate study end-to-end. |
| [REMAINING_TASKS.md](REMAINING_TASKS.md) | See open work and explicit non-goals. |
| [REFACTOR_PLAN.md](REFACTOR_PLAN.md) | Historical record of the refactor that produced today's code. |
| [docs/report/final_report.md](docs/report/final_report.md) | Read the case-study writeup of the 12-crate findings. |
