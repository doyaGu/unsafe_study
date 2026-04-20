# Remaining Tasks -- Unsafe Study Project

Last updated: 2026-04-20

## Current State

- `cargo-unsafe-audit/` implements the current scoped 4-phase workflow: Geiger, Miri, Fuzz runner, and Pattern analysis.
- All modules build and run. Smoke test on httparse works.
- Study data (12 crates) archived in geiger_reports/, miri_reports/, fuzz_findings/.
- Final report at report/final_report.md.
- DESIGN.md documents tool architecture and the planned auto-generation gap.
- README.md updated to reflect actual tool capabilities and known gaps.

## What Is Done vs. What Is Not

### Done

- Geiger scan via library API (Phase 1)
- Miri test runner + UB log parser (Phase 2, single pass)
- Fuzz runner for existing fuzz/ targets (Phase 3)
- Syn-based unsafe pattern classifier with 13 categories + risk score (Phase 4)
- JSON + Markdown report generation
- CLI with batch mode, skip flags, output format selection
- Study results for 12 crates

### Not Done (Known Gaps)

1. **Auto fuzz harness generation** -- the biggest gap. Tool can only run fuzz targets that already exist under the target crate's fuzz/ directory. Does not auto-discover public APIs and generate harness code. See DESIGN.md for the planned approach.

2. **Miri two-pass triage** -- only runs Pass 1 (strict flags). Does not automatically re-run with reduced flags and classify the result. The study did this manually.

3. **Seed corpus auto-generation** -- tool has no logic to create seed inputs from API semantics.

4. **Crates.io / git auto-download** -- tool expects crates to already be cloned locally under the given path. Does not fetch from registry by name.

5. **HTML report** -- only JSON and Markdown output.

## Open Decisions

1. Whether to implement auto harness generation (see DESIGN.md) before submission.
2. Whether to submit the simd-json upstream issue draft.
3. Whether to implement Miri two-pass triage automation.
