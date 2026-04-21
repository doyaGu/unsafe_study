# Remaining Tasks -- Unsafe Study Project

Last updated: 2026-04-20

## Current State

- `unsafe-audit/` implements a 4-phase evidence collection workflow: Geiger, Miri, fuzz runner, and pattern analysis.
- All modules build and run.
- Study data for 12 crates is archived in `geiger_reports/`, `miri_reports/`, and `fuzz_findings/`.
- `README.md` and `DESIGN.md` now describe the tool as a multi-evidence auditing system, not as a proof or exploitability analyzer.

## Done

- Geiger scan via library API
- Miri test runner + UB log parser, with optional strict-vs-baseline triage
- Fuzz runner for existing `fuzz/` targets, with explicit exit-code/error reporting
- AST-based finding extraction with finding kinds, pattern categories, and a heuristic risk score
- JSON + Markdown report generation
- CLI with batch mode, skip flags, and output format selection
- Study results for 12 crates

## Not Done

1. **Auto fuzz harness generation**
   The tool still depends on existing crate-local `fuzz/` directories. It does not yet discover APIs and synthesize harnesses.

2. **Seed corpus auto-generation**
   No crate-aware seed generation is implemented.

3. **Typed pattern analysis**
   Pattern analysis is still mostly syntax/shape based. It does not recover high-level invariants and does not perform type-aware union access detection.

4. **Crates.io / git auto-download**
   The tool expects local crate directories and does not fetch packages by name.

5. **HTML report**
   Only JSON and Markdown output are supported.

## Open Decisions

1. Whether to implement narrow-scope auto harness generation for parser-like APIs before submission.
2. Whether to submit the `simd-json` upstream issue draft.
3. Whether to add stronger typed analysis for union field access and other type-dependent patterns.

## Improvement Plan

Goal: improve `unsafe-audit` as a research-grade multi-evidence auditing tool while keeping the evidence boundaries explicit and avoiding overclaim in both implementation and reporting.

### Phase 1 -- Calibrate Semantics

Focus: make the tool and reports easier to interpret correctly.

Tasks:
- Keep all project-facing materials aligned on the same vocabulary:
  - `proxy`
  - `heuristic`
  - `signal`
  - `observed failure`
- Make every "clean" result explicitly scoped:
  - Miri clean means no UB observed on the exercised paths
  - Fuzz clean means no failure observed under the current harnesses and budget
  - Pattern risk means heuristic prioritization, not a security metric
- Add a short interpretation guide wherever report readers are most likely to start (`README.md`, report summaries, generated markdown where appropriate)

Expected outcome:
- Readers can tell what each phase means without inferring stronger claims than the code supports.

### Phase 2 -- Improve Evidence Quality

Focus: strengthen the quality and interpretability of each evidence source.

Tasks:
- Add coverage and confidence metadata to reports:
  - Miri scope (`full_suite`, `targeted`, `smoke`)
  - fuzz scope / harness source
  - keep confidence as explanatory notes derived from observable facts such as scope, targets run, and time budget; do not introduce unsupported low/medium/high scoring
- Address naming drift in the report model:
  - treat `total_unsafe_exprs` as a legacy compatibility field
  - introduce or document a clearer "finding count" interpretation
- Improve Miri result detail:
  - summarize strict vs baseline differences
  - classify UB report categories when possible (`alignment`, `provenance`, `out_of_bounds`, `uninitialized`, `other`)
- Improve Pattern Analyzer precision:
  - reduce fragile heuristic matching where possible
  - expand tests for alias/import/macro boundary cases
- Improve fuzz result semantics:
  - clearly distinguish `NoFuzzDir`, `NoTargets`, `Error`, and `Clean`
  - always surface the relevant error excerpt in markdown for failure states

Expected outcome:
- Reports explain both the observed result and the conditions under which that result should be trusted.

### Phase 3 -- Strengthen Cross-Phase Linkage

Focus: turn the phases from parallel outputs into a clearer evidence chain.

Tasks:
- Use Geiger + Pattern Analyzer to identify hotspot files/modules and surface them in reports
- Record only coarse dynamic linkage that can be supported responsibly:
  - crate-level scope
  - test-target-level Miri scope when available
  - fuzz-target-level execution
  - any file/module linkage must be labeled best-effort and log-derived, not treated as coverage
- Build a fuzz-to-Miri replay path for minimized reproducers:
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
- Keep generated harness support explicitly experimental
- Revisit typed analysis only where it has clear payoff, such as future union access handling

Expected outcome:
- New automation increases coverage for a narrow, high-value class of crates without overstating generality.

## Priority Order

### P0

- Semantic/documentation alignment
- Coverage/confidence reporting
- Naming cleanup for finding-count semantics

### P1

- Miri result refinement
- Pattern Analyzer precision improvements
- Fuzz result semantics improvements

### P2

- Cross-phase hotspot linkage
- fuzz -> Miri replay
- Narrow-scope automatic harness generation

## Acceptance Criteria

- No project-facing document or generated report implies proof, precise invariant recovery, TCB measurement, or exploitability analysis unless the implementation actually supports it.
- A reader can determine for every clean result:
  - what was exercised at crate or target granularity,
  - what was not exercised when that follows directly from recorded scope,
  - and what evidence-bounded interpretation is justified.
- `cargo test` remains green throughout the roadmap.
- At least one replay path from fuzz reproducer to Miri can be demonstrated before broader automation work begins.
