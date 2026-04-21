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
                    +----------+
                    |  CLI     |
                    | (clap)   |
                    +----+-----+
                         |
              discover_crates()
                         |
           +-------------+-------------+
           |             |             |
      Crate 1       Crate 2  ...   Crate N
           |             |             |
     audit_crate() audit_crate()  audit_crate()
           |
     +-----+-----+-----+------+
     |     |     |     |      |
   Phase  Phase Phase Phase  Report
     1     2     3     4     Gen
   Geiger Miri  Fuzz  Pattern
     |     |     |     |
     v     v     v     v
 syntactic UB   visible AST-shaped
 unsafe  signals failures findings
 proxy
```

Each phase is independent and can be skipped via `--skip-*` flags. Results accumulate in `CrateAuditResult` and are serialized at the end.

## Phase Details

### Phase 1: Geiger Scan

Uses the `geiger` crate as a library (not a subprocess). Calls `geiger::find_unsafe_in_file()` on every `.rs` file under `src/`, then aggregates counts for functions, expressions, impls, traits, and methods.

What this phase provides:

- a crate-local syntactic proxy for how much `unsafe` syntax appears,
- rough distribution across syntax categories,
- whether `forbid(unsafe_code)` appears.

What it does **not** provide:

- a semantic measure of risk,
- a complete measure of the crate's trust boundary,
- or dependency-level accounting outside the scanned crate-local source files.

Limitation: the library API does not distinguish used vs unused counts, so the `unused` fields in `GeigerResult` are always zero.

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

### Phase 3: Fuzz Run

Current implementation: discovers and runs existing `fuzz/` targets.

Flow:

1. Check `fuzz/Cargo.toml` exists; otherwise return `NoFuzzDir`
2. Run `cargo fuzz list` to discover targets
3. For each target, run `cargo fuzz run <target> -- -max_total_time=N`
4. Parse output for status (`Clean`, `Panic`, `OOM`, `Timeout`, `BuildFailed`, `Error`)
5. Parse basic libFuzzer stats (runs, edge coverage)
6. Look for the newest reproducer artifact in `fuzz/artifacts/<target>/`

What this phase provides:

- evidence of visible failures under the available harnesses and budgets,
- explicit harness-scope and budget metadata in the report,
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

Risk score is computed from finding counts and severity weights, then scaled and capped. It is a rough prioritization aid, not a formal security metric.

## Report Model

`StudyReport` is the top-level type. It serializes to JSON (machine-readable) and Markdown (human-readable).

The JSON report preserves the rawer evidence:

- Geiger counts
- Miri scope, coarse UB category, strict/baseline runs, triage summary, and verdict
- Fuzz scope, requested time budget, status, exit code, artifacts, runs, and edge coverage
- Pattern findings, finding kinds, pattern counts, `total_findings`, and risk score

The Markdown report summarizes the same information for human review. It is intentionally a summary layer, not a replacement for the underlying logs.
It now also includes a coarse cross-phase linkage section: hotspot files come from static findings, while dynamic linkage is reported only at crate/test-scope or fuzz-target granularity unless a file-name hint is explicitly labeled best-effort and log-derived.

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
