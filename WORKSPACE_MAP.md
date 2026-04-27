# Workspace Map

This repository is organized around the research workflow, not around tool
output formats. Reading it that way makes it much easier to find what you
need.

The core question is:

> Can we build an evidence-driven workflow that identifies which Rust `unsafe`
> sites exist, which ones are dynamically exercised, and which ones deserve
> human review first?

That yields a five-step evidence chain, and every top-level directory belongs
to exactly one step:

```text
study inputs (what we run)
        │
        ▼
target crates (what we run it against)
        │
        ▼
added dynamic harnesses (extra coverage we wired in)
        │
        ▼
unsafe-audit execution (how we run it)
        │
        ▼
archived evidence + writing (what we observed and what it means)
```

---

## Top-level groups

### 1. Study inputs — *what the study runs*

| Path | Purpose |
|------|---------|
| [study/](study/) | Canonical 12-crate protocol. Holds `manifest.toml` (full study), `manifest.accept.toml` (minimal acceptance run), `manifest.env-rerun.toml` (env-tweaked rerun), the protocol reference [README.md](study/README.md), and the operational [FULL_RUN_GUIDE.md](study/FULL_RUN_GUIDE.md). Default `output_root = study/output`. |
| [targets/](targets/) | Local checkouts of the 12 study crates. The runner expects every `path = "targets/<crate>"` from a manifest to resolve here. |

If a new crate, Miri case, or fuzz group becomes part of the study design,
the change starts here.

### 2. Execution core — *how the study runs*

| Path | Purpose |
|------|---------|
| [unsafe-audit/](unsafe-audit/) | Rust crate (binary + library) that loads a plan from a crate dir or manifest, runs `scan` / `geiger` / `miri` / `fuzz`, and writes the report. See `unsafe-audit/src/{main,lib,config,runner,scan,phases,report,fs}.rs`. |

Anything that affects orchestration, the manifest schema, the report schema,
or phase behavior belongs here.

### 3. Added dynamic harnesses — *coverage beyond upstream tests*

| Path | Purpose |
|------|---------|
| [miri_harnesses/](miri_harnesses/) | One Cargo package per study crate, with integration tests targeted at unsafe-heavy code paths. Manifest entries point at these via `harness_dir`. |
| [fuzz_harnesses/](fuzz_harnesses/) | Mirror copies of fuzz harnesses we added upstream, plus the canonical checked-in seed corpora at `fuzz_harnesses/<crate>/corpus/<target>/`. The runner backfills the crate-local `targets/<crate>/fuzz/corpus/<target>/` from these on demand. |
| [patches/simd-json/](patches/simd-json/) | Minimal nightly compile-fix patch for `targets/simd-json` (5 unused-import errors caused by upstream `#![deny(warnings)]`). Required before any rerun touches `simd-json`. |

If the question is *"what extra execution paths did we add beyond upstream
tests?"*, start here.

### 4. Archived evidence — *what runs observed*

| Path | Purpose |
|------|---------|
| [evidence/geiger/](evidence/geiger/) | Per-crate `cargo-geiger` JSON + text outputs and human annotations. |
| [evidence/miri/](evidence/miri/) | Miri logs, triage notes, UB investigation artifacts (notably the `simd_json` stacked-borrows writeup). |
| [evidence/fuzz/](evidence/fuzz/) | Per-crate fuzz logs and reproducer-oriented notes. |
| `study/output/` | Default destination of a manifest run (created on demand). |
| `unsafe-study-full-*` / `unsafe-study-geigercheck-*` | Timestamped, ad-hoc run outputs from `--output /tmp/...` or `--output ./unsafe-study-*` invocations. Treat as artifacts, not inputs. |

These are read-only archives. Active runs always write to a fresh output
directory.

### 5. Writing & research artifacts — *what the evidence means*

| Path | Purpose |
|------|---------|
| [docs/report/](docs/report/) | The final case-study writeup ([final_report.md](docs/report/final_report.md)), per-crate selection rationale, the simd-json explainer, the upstream issue draft, and supporting notes. |
| [docs/proposal/](docs/proposal/) | CSE 5349 proposal sources (md / tex / txt / pdf). |

These summarize evidence; they do not define execution behavior.

### 6. Utility & scratch — *not part of the evidence chain*

| Path | Purpose |
|------|---------|
| [scripts/run_all.sh](scripts/run_all.sh) | Recommended Linux entrypoint. Builds `unsafe-audit`, resolves the binary path, forwards args. |
| [scripts/run_fuzz.sh](scripts/run_fuzz.sh) | Standalone libFuzzer runner — bypass `unsafe-audit` for ad-hoc fuzz sessions. |
| [scripts/summarize_geiger.py](scripts/summarize_geiger.py) | Aggregates `evidence/geiger/*.json` into a Markdown hotspot table. |
| [scripts/make_demo_video.sh](scripts/make_demo_video.sh) | Renders a demo MP4 from a `report.json` (ffmpeg + python). |
| [Dockerfile](Dockerfile) | Reproducible Ubuntu 22.04 build environment. |
| [rust-toolchain.toml](rust-toolchain.toml) | Pins `nightly-2026-02-01` + `miri`, `rust-src`, `rustfmt`, `clippy`. |

---

## Recommended reading order

1. [README.md](README.md) — one-page overview of the tool and pipeline.
2. [WORKSPACE_MAP.md](WORKSPACE_MAP.md) — this file.
3. [DESIGN.md](DESIGN.md) — architecture, phase semantics, report
   interpretation.
4. [study/README.md](study/README.md) — manifest schema reference.
5. [study/manifest.toml](study/manifest.toml) — the canonical 12-crate plan.
6. [study/FULL_RUN_GUIDE.md](study/FULL_RUN_GUIDE.md) — operational runbook.
7. [unsafe-audit/src/](unsafe-audit/src/) — implementation, in module order
   `main → lib → config → runner → scan → phases → report → fs`.
8. [miri_harnesses/](miri_harnesses/) or [fuzz_harnesses/](fuzz_harnesses/) —
   when investigating added dynamic coverage for a specific crate.
9. [evidence/](evidence/) and [docs/report/](docs/report/) — when
   interpreting results.

---

## Canonical vs derived vs transient

**Canonical** (defines or executes the study; treat as source-of-truth):

- [study/](study/) · [targets/](targets/) · [unsafe-audit/](unsafe-audit/) ·
  [miri_harnesses/](miri_harnesses/) · [fuzz_harnesses/](fuzz_harnesses/) ·
  [patches/](patches/) · [Dockerfile](Dockerfile) ·
  [rust-toolchain.toml](rust-toolchain.toml).

**Derived / archived / presentation** (records or explanations of past runs):

- [evidence/](evidence/) · [docs/report/](docs/report/) ·
  [docs/proposal/](docs/proposal/) · `study/output/`.

**Utility / transient** (helpful but disposable):

- [scripts/](scripts/) · `target/` directories anywhere in the tree ·
  `unsafe-study-*-<timestamp>/` ad-hoc run outputs.

---

## Placement rules for new content

1. Changes the **what** of the study → [study/](study/) or [targets/](targets/).
2. Changes the **how** of execution → [unsafe-audit/](unsafe-audit/).
3. Adds execution coverage beyond upstream tests →
   [miri_harnesses/](miri_harnesses/) or [fuzz_harnesses/](fuzz_harnesses/).
4. Records evidence from a run → [evidence/](evidence/) or `study/output/`.
5. Explains results to a reader → [docs/report/](docs/report/) or
   [docs/proposal/](docs/proposal/).
6. Disposable, local-only, or experimental → keep out of the canonical
   directories; ad-hoc run outputs are fine at the repo root prefixed with
   `unsafe-study-*-<timestamp>/` or under `/tmp/`.

That is the intended repository shape from the perspective of the research
objective.
