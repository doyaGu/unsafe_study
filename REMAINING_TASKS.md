# Remaining Tasks -- Unsafe Study Project

Last updated: 2026-04-25

## Current State

- `unsafe-audit/` implements a multi-evidence auditing workflow: Geiger, Miri, fuzz runner, pattern analysis, and the default exploration scheduler.
- The previous one-shot four-phase workflow remains available through `--classic`.
- The codebase is now library-first: the CLI is thin, while discovery, phase execution, report modeling, rendering, coverage mapping, exploration, and study execution live in testable library modules.
- All Rust modules build and run under the current test suite.
- Study data for 12 crates is archived in `evidence/geiger/`, `evidence/miri/`, and `evidence/fuzz/findings/`.
- `study/manifest.toml` is now the canonical 12-crate study protocol, and `unsafe-audit` treats a manifest file path as a native study input.
- `README.md` and `DESIGN.md` describe the tool as a multi-evidence auditing system, not as a proof, invariant-recovery, TCB-measurement, or exploitability analyzer.

## Done

- Geiger scan via library API
- Miri test runner + UB log parser, with optional strict-vs-baseline triage
- Fuzz runner for existing `fuzz/` targets, with explicit exit-code/error reporting
- AST-based finding extraction with finding kinds, pattern categories, and a heuristic risk score
- Root-crate unsafe-site universe with stable site IDs
- Dynamic unsafe-site reach mapping from Miri/fuzz trigger locations and optional llvm-cov JSON
- Optional companion coverage replay for selected Miri and fuzz executions
- Coverage artifact recording for generated or explicit coverage JSON
- JSON + Markdown report generation
- Report semantics that distinguish skipped phases from phase errors
- Coarse cross-phase linkage: static hotspot files, Miri scope, fuzz target scope, and best-effort log-derived file hints
- CLI with batch mode, skip flags, output format selection, coverage flags, study manifest mode, detach/status/stop support, and exploration controls
- Exploration scheduler over the root-crate unsafe-site universe
- Optional external LLM provider integration for auditable harness patch drafts; the tool records drafts but does not modify target crates automatically
- Native manifest-driven study runner with normalized shared, Miri, and fuzz output layers
- External `miri_harnesses` tests for additional Miri/API coverage
- Study results for 12 crates

## Not Done

1. **Auto fuzz harness generation**
   The tool can request auditable harness drafts from an external provider, but it does not yet perform built-in API discovery and template-based harness synthesis.

2. **Seed corpus auto-generation**
   No crate-aware seed generation is implemented.

3. **Typed pattern analysis**
   Pattern analysis is still mostly syntax/shape based. It does not recover high-level invariants and does not perform type-aware union access detection.

4. **Crates.io / git auto-download**
   The tool expects local crate directories and does not fetch packages by name.

5. **HTML report**
   Only JSON and Markdown output are supported.

6. **Fuzz reproducer to Miri replay**
   The report can link dynamic evidence at coarse scope and map trigger locations when available, but there is not yet a first-class replay path that turns a fuzz artifact into an ephemeral Miri harness and records the replay verdict.

## Open Decisions

1. Whether to implement narrow-scope auto harness generation for parser-like APIs before submission.
2. Whether to submit the `simd-json` upstream issue draft.
3. Whether to add stronger typed analysis for union field access and other type-dependent patterns.
4. Whether the default submission artifact should include the current exploration scheduler path or primarily present `--classic` for simpler reproducibility.

## Improvement Plan

Goal: improve `unsafe-audit` as a research-grade multi-evidence auditing tool while keeping the evidence boundaries explicit and avoiding overclaim in both implementation and reporting.

### Phase 1 -- Calibrate Semantics

Focus: make the tool and reports easier to interpret correctly.

Tasks:
- Done: keep all project-facing materials aligned on the same vocabulary:
  - `proxy`
  - `heuristic`
  - `signal`
  - `observed failure`
- Done: make every "clean" result explicitly scoped:
  - Miri clean means no UB observed on the exercised paths
  - Fuzz clean means no failure observed under the current harnesses and budget
  - Pattern risk means heuristic prioritization, not a security metric
- Done: add a short interpretation guide wherever report readers are most likely to start (`README.md`, report summaries, generated markdown where appropriate)

Expected outcome:
- Readers can tell what each phase means without inferring stronger claims than the code supports.

### Phase 2 -- Improve Evidence Quality

Focus: strengthen the quality and interpretability of each evidence source.

Tasks:
- Done: add coverage and confidence metadata to reports:
  - Miri scope (`full_suite`, `targeted`, `smoke`)
  - fuzz scope / harness source
  - keep confidence as explanatory notes derived from observable facts such as scope, targets run, and time budget; do not introduce unsupported low/medium/high scoring
- Done: address naming drift in the report model:
  - treat `total_unsafe_exprs` as a legacy compatibility field
  - introduce or document a clearer "finding count" interpretation
- Done: improve Miri result detail:
  - summarize strict vs baseline differences
  - classify UB report categories when possible (`alignment`, `provenance`, `out_of_bounds`, `uninitialized`, `other`)
- Done: improve Pattern Analyzer precision:
  - reduce fragile heuristic matching where possible
  - expand tests for alias/import/macro boundary cases
- Done: improve fuzz result semantics:
  - clearly distinguish `NoFuzzDir`, `NoTargets`, `Error`, and `Clean`
  - always surface the relevant error excerpt in markdown for failure states

Expected outcome:
- Reports explain both the observed result and the conditions under which that result should be trusted.

### Phase 3 -- Strengthen Cross-Phase Linkage

Focus: turn the phases from parallel outputs into a clearer evidence chain.

Tasks:
- Done: use Geiger + Pattern Analyzer to identify hotspot files/modules and surface them in reports
- Done: record only coarse dynamic linkage that can be supported responsibly:
  - crate-level scope
  - test-target-level Miri scope when available
  - fuzz-target-level execution
  - any file/module linkage must be labeled best-effort and log-derived, not treated as coverage
- Remaining: build a fuzz-to-Miri replay path for minimized reproducers:
  - generate a replay harness as an ephemeral artifact under the audit output directory or `/tmp`, not inside the target crate
  - run Miri on the replayed path
  - capture whether Miri reports additional UB signals

Expected outcome:
- The system can better answer not just "what was found" but also, at crate and target granularity, what was exercised and how dynamic findings relate to static hotspots.

### Phase 4 -- Expand Capability Conservatively

Focus: extend functionality without turning the tool into an over-general, brittle framework.

Tasks:
- Add narrow-scope automatic harness generation only for parser-like APIs with simple input shapes:
  - `fn(&[u8]) -> _`
  - `fn(&str) -> _`
- Keep generated harness support explicitly experimental and auditable
- Revisit typed analysis only where it has clear payoff, such as future union access handling

Expected outcome:
- New automation increases coverage for a narrow, high-value class of crates without overstating generality.

## Priority Order

### P0

- Final pre-submission consistency pass across README, DESIGN, final report, and generated report wording
- Smoke run of the native study manifest path with `--dry-run`
- Smoke run of a single target with Miri/fuzz skipped to validate report generation without external tools

### P1

- fuzz -> Miri replay for minimized artifacts
- Narrow-scope built-in harness generation for parser-like APIs
- Seed corpus generation for parser-like APIs

### P2

- Typed analysis for union field access and other type-dependent patterns
- HTML report
- Crates.io / git target acquisition

## Acceptance Criteria

- No project-facing document or generated report implies proof, precise invariant recovery, TCB measurement, or exploitability analysis unless the implementation actually supports it.
- A reader can determine for every clean result:
  - what was exercised at crate or target granularity,
  - what was not exercised when that follows directly from recorded scope,
  - and what evidence-bounded interpretation is justified.
- `cargo test` remains green throughout the roadmap.
- At least one replay path from fuzz reproducer to Miri can be demonstrated before broader automation work begins.
