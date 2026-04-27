# unsafe-audit Refactor Plan

## Main Research Line

`unsafe-audit` should serve one research question:

> Can we build an evidence-driven audit workflow that helps identify which Rust
> `unsafe` sites are present, reachable, dynamically exercised, and worth human
> review first?

The tool is not the research result by itself. It is the experimental vehicle
for producing comparable evidence across crates.

## Current Status

The compact refactor is no longer just a plan. The current implementation has
already converged on the reduced study-runner shape:

```text
src/main.rs
src/lib.rs
src/config.rs
src/runner.rs
src/scan.rs
src/phases.rs
src/report.rs
src/fs.rs
```

What is already implemented:

- one normalized workflow for crate input and manifest input
- AST-based unsafe inventory
- compact pattern summary
- Geiger / Miri / fuzz orchestration
- Miri strict-vs-baseline triage
- crate-level parallelism via `--jobs`
- fuzz-target parallelism via `--fuzz-jobs`
- `--profile smoke|baseline|full`
- JSON + Markdown reports
- explicit report execution metadata
- fuzz `error_kind` classification
- current-run-only fuzz artifact attribution
- progress output with build/run state and elapsed/budget summaries

What has already been removed from the core:

- exploration scheduler
- LLVM coverage replay/parsing
- unsafe reach merging from coverage
- LLM harness generation
- resume/status/stop runtime management
- old multi-layer render pipeline

So the remaining work is no longer "replace the old system." It is mostly:

- sharpen reporting and prioritization
- improve study observability for long runs
- keep the code size and behavior bounded

The evidence chain should stay narrow:

```text
unsafe site inventory
-> reachability evidence
-> dynamic execution evidence
-> observed failure evidence
-> review priority
```

Any feature that does not strengthen this chain should be removed from the core
tool or moved to an external script.

## Refactor Goal

Current code size is roughly 9k-10k lines. That is too large for a research
organization tool whose primary job is to run a reproducible study protocol and
summarize evidence.

Target size:

- core production code: 4k-4.5k lines
- tests: 500-800 lines
- total: about 5k lines

The goal is no longer to minimize the tool into a tiny wrapper. A 5k-line
target lets the project keep the evidence chain strong enough for a research
study while still removing framework-like complexity that does not directly
support the paper's claims.

## Scope Decision

Keep:

- manifest-driven crate cohort execution
- target discovery from local paths
- AST-based unsafe site inventory
- a small unsafe pattern taxonomy for study tables and review prioritization
- command orchestration for Geiger, Miri, and existing fuzz targets
- Miri strict-vs-baseline triage if it stays compact and evidence-bounded
- fuzz result classification for clean, crash, panic, timeout, OOM, build error,
  and generic error states
- lightweight dynamic evidence capture at crate/test/fuzz-target scope
- JSON and Markdown summary output
- stable output layout for the 12-crate study
- enough tests to protect the protocol and report format

Remove from core:

- exploration scheduler
- automatic coverage replay and LLVM coverage parsing
- unsafe-site reach merging based on coverage
- external LLM harness draft integration
- resume/status/stop daemon-like runtime management
- rich cross-phase report rendering beyond a compact evidence summary
- fine-grained AST pattern taxonomy not used by the study table
- complex phase-specific domain models
- HTML or future report formats
- crates.io/git acquisition
- broad automatic harness generation

Optional follow-up scripts may reintroduce some removed capabilities outside
the core crate, but they should not shape the central codebase.

## Target Architecture

The 5k version should use a small number of feature modules. It should avoid the
current deep framework shape, but it does not need to collapse everything into a
single-file implementation.

```text
src/main.rs          CLI parsing and command dispatch
src/lib.rs           public facade and top-level run orchestration
src/config.rs        manifest, CLI options, normalized run plan
src/runner.rs        command construction and process execution
src/scan.rs          AST unsafe inventory and compact pattern summary
src/phases.rs        Geiger, Miri, and fuzz phase adapters
src/report.rs        report model plus JSON/Markdown rendering
src/fs.rs            paths, logs, output directories, small IO helpers
```

Suggested line budget:

```text
main.rs       150-250
lib.rs        250-400
config.rs     400-600
runner.rs     400-550
scan.rs       500-700
phases.rs     900-1200
report.rs     700-900
fs.rs         150-250
tests         500-800
```

No production source file should exceed 900 lines, and any file above 700 lines
must have a clear reason.

## Simplified Data Model

Replace the current large domain model with a compact evidence model. The model
can retain enough structure for research tables, but it should avoid separate
type hierarchies for every phase-specific detail.

```rust
pub struct Report {
    pub schema_version: u32,
    pub crates: Vec<CrateReport>,
}

pub struct CrateReport {
    pub name: String,
    pub path: String,
    pub unsafe_sites: Vec<UnsafeSite>,
    pub pattern_summary: PatternSummary,
    pub phases: Vec<PhaseReport>,
}

pub struct UnsafeSite {
    pub id: String,
    pub file: String,
    pub line: usize,
    pub kind: String,
}

pub struct PhaseReport {
    pub phase: String,
    pub status: PhaseStatus,
    pub command: Vec<String>,
    pub duration_ms: u128,
    pub summary: String,
    pub log_path: Option<String>,
    pub evidence: PhaseEvidence,
}
```

The model should preserve observable evidence, not attempt to encode every
possible interpretation.

## Phase Semantics

### Unsafe Inventory

Purpose:

- list unsafe blocks, unsafe functions, unsafe impls, extern blocks, and obvious
  high-risk operations where cheaply visible

Implementation:

- keep the `syn` AST walk
- record a stable site id, file, line, kind, and compact pattern label
- keep only pattern labels that are useful in the final study analysis

Non-goals:

- type-aware reasoning
- invariant recovery
- precise soundness judgment

### Geiger

Purpose:

- provide dependency-aware unsafe surface context

Implementation:

- run `cargo geiger`
- store a short root/dependency summary and full log
- parse only fields needed by the final study table

### Miri

Purpose:

- record whether configured test paths expose UB-like failures

Implementation:

- run configured `cargo miri test` commands
- record pass/fail/error
- keep strict-vs-baseline triage when configured
- extract a compact UB category and raw excerpt
- store full logs

Non-goals:

- deep diagnosis of Miri findings
- claiming that clean Miri runs prove soundness

### Fuzz

Purpose:

- record whether existing fuzz targets crash, timeout, or finish cleanly under
  the study budget

Implementation:

- run configured or discovered existing targets
- record status, duration, artifact path if present, and log path

Non-goals:

- harness synthesis
- seed corpus generation
- reproducer-to-Miri replay in the core refactor

## Migration Plan

### Stage 0: Freeze Current Research Snapshot

Status: done.

Current code has been committed as:

```text
8c4327d refactor unsafe audit modules
```

This gives us a recovery point before destructive simplification.

### Stage 1: Create Focused Facade

Add the target modules next to the existing implementation:

- `config.rs`
- `runner.rs`
- `scan.rs`
- `phases.rs`
- `report.rs`
- `fs.rs`

Wire a focused command path through them while leaving the old modules present.

Acceptance:

- one local crate can be scanned
- one manifest can be dry-run
- JSON and Markdown reports are generated
- unsafe site inventory and pattern summary are present in the report
- tests pass

### Stage 2: Replace Study Path

Make the manifest-driven study runner use the focused modules only.

Cut behavior:

- runtime detach/status/stop
- resume machinery
- coverage replay
- exploration scheduler
- LLM harness draft generation

Acceptance:

- `study/manifest.toml --dry-run` prints the normalized run plan
- selected crates can be executed with Miri/fuzz skipped
- configured Miri cases and fuzz groups still execute under stable output paths
- output layout remains reproducible

### Stage 3: Replace Single-Crate Path

Route normal crate input through the same focused run plan as the study path.

Acceptance:

- directory input and manifest input share the same internal execution model
- `--classic` and default exploration distinctions are removed
- CLI help describes one workflow, not multiple product modes

### Stage 4: Delete Old Framework Layers

Delete or collapse:

- `coverage/`
- `coverage_backend/`
- `explore/`
- most of `render/phases/`
- `render/cross_phase.rs`
- `render/exploration.rs`
- `study/runtime.rs`
- `study/resume.rs`
- most split study orchestration modules after their behavior moves into
  `config.rs` and `phases.rs`
- most of `domain/`, after the compact evidence model replaces it
- analyzer visitor submodules that are not needed by the compact inventory

Acceptance:

- total source size drops below 6k lines
- report output still answers the research chain
- Miri triage and fuzz status classification remain available
- tests pass

### Stage 5: 5k Consolidation Pass

Reduce abstractions that only exist because of the old framework, but keep
research-useful evidence extraction.

Actions:

- collapse one-off model types into the compact evidence model
- remove compatibility fields not used by the study
- replace multi-file render logic with one compact report renderer
- keep a compact AST pattern summary
- keep compact Miri/fuzz parsers when they feed study tables
- keep only high-signal tests

Acceptance:

- total code size is around 5k lines
- no production file exceeds 900 lines
- no module tree exists only to support a removed feature
- generated reports remain enough for the final study table

## Test Strategy

Keep tests focused on research reproducibility:

- manifest parsing and normalization
- command construction
- unsafe inventory on a tiny fixture
- Miri/geiger/fuzz status parsing from sample logs
- strict-vs-baseline Miri triage classification
- JSON and Markdown rendering
- one fake-run integration test using a mock command runner

Delete tests that only protect removed framework behavior.

## Final Acceptance Criteria

The refactor is complete when:

- the codebase is around 5k lines without hiding large logic in scripts
- the core workflow directly follows the research evidence chain
- every report row can be traced to an observed command, log, or source location
- removed features are either documented as out of scope or kept as external
  experimental scripts
- `cargo fmt` and `cargo test` pass in `unsafe-audit`

## Guiding Rule

When deciding whether to keep a feature, ask:

> Does this feature make the 12-crate study evidence clearer, more reproducible,
> or more defensible?

If the answer is no, it does not belong in the core tool.
