# unsafe-audit Refactor — Historical Record

> **Status: completed.** This document is kept for provenance. The refactor it
> describes has fully landed; today's `unsafe-audit/src/` already matches the
> "target architecture" section. For *current* open work, see
> [REMAINING_TASKS.md](REMAINING_TASKS.md). For the implemented design, see
> [DESIGN.md](DESIGN.md).

## Why this refactor happened

`unsafe-audit` was originally an exploration-heavy platform: a coverage-driven
scheduler, an LLM harness drafter, runtime resume/status/stop machinery, an
LLVM coverage replayer, and a multi-layer rendering pipeline — roughly 9–10k
lines of code orbiting a research question that only needed a small fraction
of that surface.

The research question is narrow:

> Can we build an evidence-driven workflow that identifies which Rust `unsafe`
> sites exist, are reachable, are dynamically exercised, and deserve human
> review first?

Most of the framework code did not directly support that chain. The refactor
collapsed it down to a compact study runner.

## Target shape (now the actual shape)

```text
unsafe-audit/src/
  main.rs          CLI parsing and command dispatch
  lib.rs           public facade and top-level orchestration
  config.rs        manifest, CLI options, normalized RunPlan
  runner.rs        command construction and process execution
  scan.rs          AST unsafe inventory + compact pattern summary
  phases.rs        Geiger / Miri / fuzz phase adapters
  report.rs        report model + JSON & Markdown rendering
  fs.rs            output paths, log files, IO helpers
```

Original line budget vs landed reality: targeted ~5k lines (4–4.5k production
+ 0.5–0.8k tests). No production source file should exceed ~900 lines; any
file above 700 lines must have a clear reason.

## What was kept

- manifest-driven crate cohort execution,
- AST-based unsafe-site inventory with stable site IDs and a compact pattern
  taxonomy used by the study tables,
- `cargo geiger` orchestration with a compact root/dependency summary,
- one or more `cargo miri test` cases per crate, with strict-vs-baseline
  triage available behind `--miri-triage`,
- existing-fuzz-target execution (build sequential, run parallel),
- explicit fuzz `error_kind` classification (`clean`, `finding`,
  `tool_error`, `environment_error`),
- current-run-only fuzz artifact attribution,
- JSON + Markdown report with a stable `schema_version = 1` shape,
- crate-level `--jobs` and per-fuzz-group `--fuzz-jobs` parallelism,
- `--profile smoke|baseline|full` budget capping,
- a stable output layout (`<output>/{report.json,report.md,crates/<name>/logs/}`).

## What was removed from the core

- exploration scheduler,
- LLVM coverage replay and coverage-based reach merging,
- LLM-driven harness draft integration,
- daemon-mode resume/status/stop runtime control,
- crates.io / git auto-acquisition (targets are now local checkouts),
- HTML reporting,
- multi-file phase domain hierarchies replaced by the compact `PhaseEvidence`
  enum,
- `--classic` legacy mode (a single normalized workflow now serves both
  directory and manifest input).

Any of these may return as external scripts; none of them should re-enter the
core.

## Stage-by-stage history

| Stage | Outcome |
|-------|---------|
| 0 — Freeze | Pre-refactor snapshot committed (`8c4327d refactor unsafe audit modules`). |
| 1 — Focused facade | New `config.rs` / `runner.rs` / `scan.rs` / `phases.rs` / `report.rs` / `fs.rs` added beside the old code; one crate dir scannable, manifest dry-run-able. |
| 2 — Replace study path | Manifest runner re-routed through the focused modules; runtime, resume, and coverage replay paths cut. |
| 3 — Replace single-crate path | Directory and manifest input share the same `RunPlan`; `--classic` removed. |
| 4 — Delete framework layers | `coverage/`, `coverage_backend/`, `explore/`, most of `render/phases/`, `study/runtime.rs`, `study/resume.rs`, and the old `domain/` tree deleted. |
| 5 — 5k consolidation | Type hierarchies collapsed into `PhaseEvidence`; render logic unified into a single Markdown writer; tests pruned to the protocol-protecting set. |

## Test strategy that survived

Tests are scoped to research reproducibility, not framework coverage:

- manifest parsing and normalization,
- command construction,
- AST unsafe inventory on a small fixture,
- Geiger / Miri / fuzz log parsing on sample logs,
- strict-vs-baseline Miri triage classification,
- JSON and Markdown rendering,
- one fake-run integration test using a mocked `CommandExecutor`.

Tests that only protected removed framework behavior were deleted.

## Acceptance criteria — all met

- Code size landed near the 5k target without hiding logic in scripts.
- The core workflow follows the evidence chain end-to-end.
- Every report row can be traced to an observed command, log, or source
  location.
- Removed features are either documented as out of scope (here and in
  [REMAINING_TASKS.md](REMAINING_TASKS.md)) or kept as external utilities in
  [scripts/](scripts/).
- `cargo test --manifest-path unsafe-audit/Cargo.toml` is green.

## Where work continues

This document does not track ongoing work. Open items, deferred capabilities,
and explicit non-goals live in [REMAINING_TASKS.md](REMAINING_TASKS.md). The
authoritative description of the post-refactor design lives in
[DESIGN.md](DESIGN.md).
