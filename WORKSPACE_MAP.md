# Workspace Map

This repository is easier to understand if it is organized around the research
question instead of around individual tool outputs.

The core question is:

> Can we build an evidence-driven workflow that identifies which Rust `unsafe`
> sites exist, which ones are dynamically exercised, and which ones deserve
> human review first?

That yields a simple evidence chain:

```text
study inputs
-> target crates
-> dynamic harnesses
-> unsafe-audit execution
-> archived evidence
-> paper/report artifacts
```

## Canonical Top-Level Groups

### 1. Study Inputs

These directories define what the study runs.

- `study/`: canonical 12-crate protocol, manifests, runbook, and default study
  output location.
- `targets/`: local checkouts of the crates being studied.

If a new crate, Miri case, or fuzz group becomes part of the study design, the
change should usually start here.

### 2. Execution Core

This directory executes the protocol.

- `unsafe-audit/`: the CLI and library that run scan, Geiger, Miri, fuzz, and
  final report generation.

If a change affects orchestration, report schema, output format, or phase
behavior, it belongs here.

### 3. Added Dynamic Harnesses

These directories contain test or fuzz entrypoints that supplement upstream
crates.

- `miri_harnesses/`: added integration tests used mainly for targeted Miri
  coverage across multiple crates.
- `fuzz_harnesses/`: active extracted copies of custom fuzz harnesses that were
  added inside `targets/*` repositories. These are maintained separately from
  the crate-local `targets/<crate>/fuzz/` trees that the manifest-driven study
  executes by default.
- `evidence/fuzz/corpus/`: seed corpora used by fuzz targets.

If the question is "what extra execution paths did we add beyond upstream
tests?", start with this group.

### 4. Archived Evidence

These directories store the results produced by the study workflow.

- `evidence/geiger/`: static unsafe-surface outputs and annotations.
- `evidence/miri/`: Miri logs, triage notes, and UB investigation artifacts.
- `evidence/fuzz/findings/`: fuzz logs, findings, and reproducer-oriented notes.
- `study/output/`: per-run study outputs in the current manifest-driven layout.

These are evidence archives, not the canonical inputs. They document what a run
observed.

### 5. Writing And Research Artifacts

These directories explain or present the study.

- `docs/report/`: final report, study writeups, issue drafts, and result summaries.
- `docs/proposal/`: proposal sources and compiled artifacts.

These are the paper-facing outputs. They should summarize evidence, not define
execution behavior.

### 6. Utility And Scratch Space

These directories support local execution but are not part of the main evidence
chain.

- `scripts/`: wrappers and helper scripts. In particular,
  `scripts/run_all.sh` resolves the repo-local `unsafe-audit` binary from Cargo
  output instead of hardcoding a `target/` path.
- `tmp/`: temporary intake, scratch projects, and disposable working material.

If something is experimental, local-only, or transient, it should land here
instead of being mixed into the canonical study inputs.

## Folder-By-Folder Reading Order

For most work, read the repository in this order:

1. `README.md`
2. `WORKSPACE_MAP.md`
3. `study/README.md`
4. `study/manifest.toml`
5. `unsafe-audit/`
6. `miri_harnesses/` or `fuzz_harnesses/` when investigating added
  dynamic coverage
7. `evidence/geiger/`, `evidence/miri/`, `evidence/fuzz/findings/`, and `docs/report/` when
   interpreting results

## What Is Canonical Vs Derived

Canonical directories:

- `study/`
- `targets/`
- `unsafe-audit/`
- `miri_harnesses/`
- `fuzz_harnesses/`

Mostly derived, archived, or presentation-oriented directories:

- `evidence/geiger/`
- `evidence/miri/`
- `evidence/fuzz/`
- `docs/report/`
- `docs/proposal/`
- `study/output/`

Utility or transient directories:

- `scripts/`
- `tmp/`
- crate-local `target/` directories

## Placement Rules

Use these rules to keep future additions aligned with the research goal.

1. If it changes what the study runs, put it in `study/` or `targets/`.
2. If it changes how the study runs, put it in `unsafe-audit/`.
3. If it adds execution coverage beyond upstream tests, put it in
  `miri_harnesses/` or `fuzz_harnesses/`.
4. If it records evidence from a run, put it in `evidence/geiger/`,
  `evidence/miri/`, `evidence/fuzz/`, or `study/output/`.
5. If it explains results to a reader, put it in `docs/report/` or
  `docs/proposal/`.
6. If it is disposable or local-only, keep it in `tmp/`.

## Practical Cleanup Direction

When the root feels crowded, the right mental compression is:

- inputs: `study/`, `targets/`
- execution: `unsafe-audit/`
- added harnesses: `miri_harnesses/`, `fuzz_harnesses/`
- evidence: `evidence/geiger/`, `evidence/miri/`, `evidence/fuzz/`
- writing: `docs/report/`, `docs/proposal/`
- support: `scripts/`, `tmp/`

That is the intended repository shape from the perspective of the research
objective.