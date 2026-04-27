# Remaining Tasks

_Last updated: 2026-04-28._

This file tracks the **current** state of `unsafe_study` and what is still
open. Compare against [REFACTOR_PLAN.md](REFACTOR_PLAN.md) for the historical
arc and against [DESIGN.md](DESIGN.md) for the implemented design.

---

## Current state

- `unsafe-audit/` is the compact study runner described in
  [README.md](README.md): one normalized `RunPlan` for both directory and
  manifest input; phases `scan`, `geiger`, `miri`, `fuzz`; one report writer
  producing `report.json` (`schema_version = 1`) and `report.md` plus
  per-crate logs.
- The exploration scheduler, LLVM coverage replay, LLM harness drafter,
  resume/status/stop runtime, and the old `--classic` mode have been removed
  from the core. Anything that returns must come back as a script under
  [scripts/](scripts/).
- The canonical 12-crate study lives in [study/manifest.toml](study/manifest.toml)
  (plus `manifest.accept.toml` and `manifest.env-rerun.toml` variants) and is
  driven by [scripts/run_all.sh](scripts/run_all.sh).
- `cargo test --manifest-path unsafe-audit/Cargo.toml` passes against the
  pinned `nightly-2026-02-01` toolchain.
- All 12 target crates are checked out under [targets/](targets/) and have
  been exercised end-to-end. Latest output directories:
  `unsafe-study-full-20260428-012200/` (full run) and
  `unsafe-study-geigercheck-20260428-011956/` (geiger-only checkpoint).
- `targets/simd-json` requires
  [patches/simd-json/0001-fix-nightly-unused-imports.patch](patches/simd-json/0001-fix-nightly-unused-imports.patch)
  before any rerun; the [Dockerfile](Dockerfile) applies it automatically.

---

## Done

- AST-based unsafe-site inventory with stable site IDs and the compact
  pattern taxonomy (`unsafe_block`, `unsafe_fn`, `unsafe_impl`,
  `extern_block`, `ptr_op`, `transmute`, `unchecked_op`, `inline_asm`,
  `other`).
- Robust scan: a single unparsable `.rs` file (e.g.
  `targets/memchr/benchmarks/haystacks/code/rust-library.rs`) emits a
  warning instead of aborting the crate.
- `cargo geiger` adapter producing the compact root/dependency unsafe summary.
- `cargo miri test` adapter supporting:
  - full upstream suite,
  - `--test <target>` and `--exact` filters,
  - `harness_dir` overrides pointing at [miri_harnesses/](miri_harnesses/),
  - per-case `MIRIFLAGS` and other env overrides,
  - process-wide serialization to avoid `miri-server` lock contention,
  - optional strict-vs-baseline triage with verdict classification.
- `cargo fuzz` adapter with:
  - target discovery via `cargo fuzz list` or explicit `targets = [...]`,
  - sequential build / parallel run model under `--fuzz-jobs`,
  - corpus backfill from `fuzz_harnesses/<crate>/corpus/<target>/`,
  - explicit `error_kind` (`clean`, `finding`, `tool_error`,
    `environment_error`),
  - current-run-only artifact attribution.
- `Report` model with execution metadata (profile, jobs, fuzz_jobs, phases,
  miri_triage, fuzz_time, fuzz_env), per-crate inventory, per-phase
  `PhaseEvidence`, and a `review_priority` table.
- JSON and Markdown rendering, both shipping the same execution config and
  fuzz error details.
- Crate-level `--jobs` parallelism via `std::thread::scope`.
- Manifest variants (`manifest.toml`, `manifest.accept.toml`,
  `manifest.env-rerun.toml`) for full / minimal acceptance / env-tweaked runs.
- Operational [study/FULL_RUN_GUIDE.md](study/FULL_RUN_GUIDE.md) covering
  preflight, smoke, full, triage, and post-run validation with `jq` recipes.
- Per-crate Miri harness packages under [miri_harnesses/](miri_harnesses/)
  (one Cargo workspace per crate).
- Per-crate fuzz harness mirrors and canonical seed corpora under
  [fuzz_harnesses/](fuzz_harnesses/).

---

## Not done

1. **Fuzz reproducer → Miri replay.** No first-class path that takes a
   minimized libFuzzer artifact, builds an ephemeral Miri harness in the
   audit output dir (or `/tmp`), and records the replay verdict in the report.
2. **Narrow-scope automatic harness generation.** Even the "parser-like APIs
   only" version — `fn(&[u8]) -> _`, `fn(&str) -> _` — is not implemented.
3. **Seed corpus auto-generation.** No crate-aware seed synthesis.
4. **Typed pattern analysis.** All patterns are syntactic. There is no
   type-aware union-field-access detection (intentionally — it would require
   resolving types, which `syn` alone cannot do).
5. **Crates.io / git auto-acquisition.** The runner expects local crate
   directories; it does not fetch packages by name.
6. **HTML reporting.** Only JSON and Markdown are produced.
7. **Fuzz parallelism within `cargo fuzz run`.** The current model builds
   sequentially and runs the produced libFuzzer binaries in parallel; we
   have not switched to `cargo fuzz cmin/run` parallel modes.

---

## Priority order

### P0 — pre-submission consistency

- Final consistency pass across [README.md](README.md), [DESIGN.md](DESIGN.md),
  [docs/report/final_report.md](docs/report/final_report.md), and the
  generated `report.md`. Every "clean" must be scoped (no proof, no
  exploitability, no invariant recovery claims).
- Smoke run of the manifest path with `--dry-run` and a Miri-only subset
  before each formal rerun (commands in
  [study/FULL_RUN_GUIDE.md](study/FULL_RUN_GUIDE.md)).
- Re-confirm the `simd-json` patch is applied before any rerun that touches
  `targets/simd-json`.

### P1 — most useful follow-on capability

- Fuzz-reproducer → Miri replay path.
- Narrow-scope automatic harness generation for parser-like APIs.
- Seed corpus generation for parser-like APIs.

### P2 — useful but lower payoff

- Typed analysis for union field access and other type-dependent patterns.
- HTML reporting.
- Crates.io / git target acquisition.

---

## Open decisions

1. Whether to ship narrow-scope automatic harness generation for parser-like
   APIs before the next submission.
2. Whether to file the `simd-json` upstream issue draft
   ([docs/report/simd_json_upstream_issue_draft.md](docs/report/simd_json_upstream_issue_draft.md)).
3. Whether to add typed analysis for union-field access despite the
   complexity cost.
4. Whether the demo video produced by
   [scripts/make_demo_video.sh](scripts/make_demo_video.sh) is part of the
   submission package or a side artifact.

---

## Acceptance criteria for the project as a whole

- No project-facing document and no generated report implies proof, precise
  invariant recovery, TCB measurement, or exploitability analysis.
- For every clean result a reader can determine:
  - what was exercised at crate / target granularity,
  - what was *not* exercised when that follows from the recorded scope,
  - what evidence-bounded interpretation is justified.
- `cargo test --manifest-path unsafe-audit/Cargo.toml` stays green.
- At least one fuzz-reproducer → Miri replay must be demonstrated before any
  broader replay automation work begins.
