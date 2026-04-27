# unsafe-audit Design

## Scope and Interpretation

`unsafe-audit` is a **multi-evidence auditing tool** for Rust crates. It does not attempt to prove a crate sound or recover its full semantic invariants. Instead, it collects several complementary signals that help a human auditor prioritize and interpret risk:

- a syntactic proxy for `unsafe` surface area,
- heuristic AST-based findings for `unsafe`-adjacent code,
- execution-based Miri UB signals on exercised test paths,
- and observable failures under existing fuzz harnesses.

The design goal is to keep these signals separate enough that their limitations remain visible in the final report.

## Architecture

```text
              +----------------+
              | main.rs (CLI)  |
              | clap + console |
              +--------+-------+
                       |
                 lib.rs facade
                       |
        +--------------+---------------+
        |              |               |
     app.rs        infra.rs        render/
   options +    discovery +       JSON/MD
   orchestration command IO       sections
        |
        +-------------------------------+
        |               |               |
     phases/         analyzer/       domain.rs
   geiger miri       visitor +       typed report
   fuzz runners      summary         model
```

The CLI is intentionally thin. It parses arguments, prints progress, and writes final artifacts. Discovery, phase execution, report modeling, and rendering live in the library so they can be tested independently and reused outside the binary.

The default single-crate CLI path is now an exploration workflow. It starts with the same static evidence phases, then schedules dynamic follow-up over the root-crate unsafe-site universe. The previous one-shot phase execution remains available with `--classic`.

## Phase Details

### Phase 1: Geiger Scan

Runs `cargo geiger --output-format Json` as a subprocess and parses the trailing JSON payload from the combined cargo output. This preserves the dependency-aware package model used by the study, while still surfacing root-package metrics cleanly in the CLI and Markdown report.

What this phase provides:

- a dependency-aware syntactic proxy for how much `unsafe` syntax appears,
- root-package and dependency-package unsafe counts in one result model,
- packages missing metrics and files used but not scanned.

What it does **not** provide:

- a semantic measure of risk,
- a complete measure of the crate's trust boundary,
- or a semantic measure of why that unsafe exists.

### Phase 2: Miri Test

Shells out to `cargo miri test` with configurable `MIRIFLAGS`. Parses combined stdout+stderr for:

- test summary lines (`test result: ok. N passed; M failed`)
- UB indicators via keyword matching (`undefined behavior`, `stacked borrow`, `pointer being freed`, `out-of-bounds`, `data race`)

Writes full logs to the output directory and stores a structured result.

What this phase provides:

- execution-based UB signals on the paths reached by tests,
- explicit scope metadata for how the Miri result should be read,
- coarse UB categories inferred from Miri output text,
- a factual strict-vs-baseline triage summary,
- not proof that the crate is UB-free.

By default this is a single strict pass. With `--miri-triage`, the tool re-runs Miri with baseline flags when the strict pass reports UB:

1. Strict: `-Zmiri-symbolic-alignment-check -Zmiri-strict-provenance`
2. Baseline: `-Zmiri-strict-provenance`
3. Verdict: `Clean`, `TruePositiveUb`, `StrictOnlySuspectedFalsePositive`, `FailedNoUb`, or `Inconclusive`

This verdict is intentionally conservative. For example, `StrictOnlySuspectedFalsePositive` means the strict-only result looks model-sensitive under the current triage rule; it is not a code-level proof that the report is false.

The result model also records the exact `cargo` args and working directory used for the run, because the study uses a mix of full upstream suites and targeted `miri_harnesses` tests.

### Phase 3: Fuzz Run

Current implementation: discovers and runs existing `cargo fuzz` targets from either the crate itself or an explicit harness directory.

Flow:

1. Pick the harness root: the crate by default, or an explicit fuzz harness directory when configured
2. Check `<harness-root>/fuzz/Cargo.toml` exists; otherwise return `NoFuzzDir`
3. Run `cargo fuzz list` to discover targets
4. For each target, run `cargo fuzz run <target> -- -max_total_time=N`
5. Parse output for status (`Clean`, `Panic`, `OOM`, `Timeout`, `BuildFailed`, `Error`)
6. Parse basic libFuzzer stats (runs, edge coverage)
7. Look for the newest reproducer artifact in `<harness-root>/fuzz/artifacts/<target>/`

What this phase provides:

- evidence of visible failures under the available harnesses and budgets,
- explicit harness-scope, selected-target, and budget-label metadata in the report,
- not a general measure of attacker reachability or exploitability.

`Clean` requires a successful process exit. A non-zero exit with unknown text is reported as `Error`, with exit code and log excerpt in the report. If `cargo fuzz list` fails, the phase returns an explicit `Error` row instead of silently treating the crate as having no targets. The Markdown report also surfaces captured excerpts for other non-clean states such as build failures, panic/crash outcomes, OOM, and timeout when text is available.

### Phase 4: Pattern Analysis

Uses `syn` with the `visit` trait to walk the AST and record structured findings:

- `UnsafeBlock`
- `UnsafeFnDecl`
- `UnsafeImplDecl`
- `RiskyOperation`
- `ExternItem`

Risky operations are classified from AST shapes such as:

- `Expr::Call`
- `Expr::MethodCall`
- `Expr::Unary`
- `Expr::Cast`
- macro nodes

This avoids the earlier behavior of counting every harmless expression inside an `unsafe` context.
The analyzer also resolves simple `use` aliases and module renames, so patterns such as `use std::mem::transmute as t;` and `use std::mem as mem;` still classify on the underlying imported operation.

Current pattern categories:

- `PtrDereference`
- `PtrReadWrite`
- `Transmute`
- `UncheckedConversion`
- `UncheckedIndex`
- `UnreachableUnchecked`
- `SimdIntrinsic`
- `UninitMemory`
- `UnionAccess` (reserved; not emitted by the current pure-AST pass)
- `AddrOf`
- `InlineAsm`
- `ExternBlock`
- `OtherUnsafe`

What this phase provides:

- a heuristic structural classification of `unsafe`-related code shapes,
- a prioritization-oriented risk score.

What it does **not** provide:

- precise invariant recovery,
- full name resolution across arbitrary scopes,
- type-aware reasoning,
- or proof that a given finding is actually unsound.

`UnionAccess` is intentionally not emitted by the current pure-AST pass. A union declaration is not unsafe access, and reliably detecting union field reads requires type information.

Risk score is computed from finding counts and severity weights, then scaled and capped. It is a rough prioritization aid, not a formal security metric. Static scan failures are now recorded explicitly so the report can distinguish "no finding" from "file not successfully scanned."

### Phase 5: Exploration Scheduler

Default crate execution wraps the phase runners in a coverage-prioritized scheduler:

1. Run Geiger for dependency-aware unsafe surface context.
2. Run Pattern Analyzer to define the root-crate unsafe-site universe.
3. Rank unreached root-crate unsafe sites by heuristic severity.
4. Run discovered Miri test cases as isolated exact invocations so one UB does not stop exploration of later cases.
5. Run existing fuzz targets at target granularity.
6. Optionally request auditable Miri/fuzz harness patch drafts from an external LLM provider command.

The scheduler stops when it reaches the configured round/time budget or when consecutive rounds no longer add unsafe-site reach. It does not treat dependency unsafe as a site-level coverage denominator; dependency unsafe remains Geiger context.

LLM integration is intentionally conservative. The provider receives structured prompt JSON and must return candidate JSON. The tool records patch drafts, rationale, target site IDs, and suggested commands in the report; it does not modify target crate files automatically.

## Report Model

`StudyReport` is the top-level type. It serializes to JSON (machine-readable) and Markdown (human-readable). The current schema is explicitly versioned as `schema_version = 6`.

The JSON report preserves the rawer evidence:

- Geiger counts
- Miri scope, invocation metadata, coarse UB category, strict/baseline runs, triage summary, and verdict
- Fuzz scope, requested time budget, budget label, selected targets, status, exit code, artifacts, runs, and edge coverage
- Pattern findings, finding kinds, pattern counts, scan failures, `total_findings`, and risk score
- Exploration rounds, scheduler decisions, isolated Miri cases, fuzz runs, optional harness candidates, and exploration issues when the default workflow is used

The Markdown report summarizes the same information for human review. It is intentionally a summary layer, not a replacement for the underlying logs.
It now also includes a coarse cross-phase linkage section: hotspot files come from static findings, while dynamic linkage is reported only at crate/test-scope or fuzz-target granularity unless a file-name hint is explicitly labeled best-effort and log-derived.
Requested phases that fail before producing normal evidence are recorded explicitly as phase issues so the report can distinguish `ERROR` from a deliberate skip.

## Study Protocol

The 12-crate case study now has its own manifest-driven layer:

- [`study/manifest.toml`](study/manifest.toml) defines crate cohort plus normalized `miri_case` and `fuzz_group` entries.
- `unsafe-audit` now has one path-based entrypoint: directory input means crate/batch execution, file input means manifest-driven study execution.
- [`study/README.md`](study/README.md) documents the normalized protocol shape.
- [`scripts/run_all.sh`](scripts/run_all.sh) is the repo-local Linux wrapper for that runner: it asks Cargo for the emitted `unsafe-audit` executable path when possible and otherwise falls back to `cargo run`.

This keeps `unsafe-audit` readable as a generic single-crate tool while making the research protocol explicit and reproducible for the 12-crate study.

## Planned, Not Implemented

### Auto-Generation of Fuzz Harnesses

This remains the biggest functional gap.

Problem:

1. Many crates do not ship a `fuzz/` directory
2. A harness requires API selection, input-type handling, and dependency setup
3. Generic or stateful APIs are hard to drive automatically

The current planned direction is intentionally narrow:

- start with parser-like APIs that take `&[u8]` or `&str`,
- generate simple template-based harnesses,
- keep the rest out of scope until the signal quality is known.

### Stronger Pattern Semantics

Future work may add:

- typed analysis for union field access,
- better alias/import handling,
- and less heuristic interpretation of operation categories.

These would improve precision, but they are not part of the current implementation.
