# unsafe_study -- Multi-Evidence Auditing of `unsafe` Rust Crates

CSE 5349 final project. The main deliverable is `unsafe-audit`, a Rust CLI that collects several complementary kinds of evidence about `unsafe` code in a crate.

The project does **not** prove a crate safe or unsafe. Instead, it combines:

- a syntactic proxy for `unsafe` surface area,
- heuristic pattern classification for `unsafe`-related code,
- Miri signals on exercised test paths,
- and observable failures from existing fuzz harnesses.

That evidence is then reported together so a human auditor can interpret scope, severity, and remaining uncertainty.

## The Tool: `unsafe-audit`

A CLI tool that takes a crate path and runs the audit workflow:

```bash
$ unsafe-audit ../targets/httparse --fuzz-time 60 --output /tmp/report
```

### What It Does

| Phase | What it provides | Current implementation |
|-------|-------------------|------------------------|
| **1. Geiger scan** | A crate-local syntactic proxy for `unsafe` surface area | `geiger` library API over crate source files under `src/` |
| **2. Miri test** | Execution-based UB signals on paths reached by tests | `cargo miri test`, with optional strict-vs-baseline triage |
| **3. Fuzz run** | Observable failures under existing fuzz harnesses | discovers existing `cargo fuzz` targets, records exit status, artifacts, and basic stats |
| **4. Pattern analysis** | Heuristic classification of `unsafe`-related code shapes | `syn` AST visitor, finding kinds, pattern categories, and a risk score |

### What It Does NOT Do

- It does **not** prove the absence of UB.
- It does **not** recover high-level invariants precisely.
- It does **not** measure exploitability.
- It does **not** auto-generate fuzz harnesses.
- It does **not** auto-download crates from crates.io or git.

### How To Read The Results

The phases answer different questions:

- **Geiger**: how much `unsafe` syntax is present, and where?
- **Pattern analysis**: what kinds of `unsafe`-adjacent operations appear?
- **Miri**: did Miri report UB on the paths reached by tests?
- **Fuzz**: do the available fuzz harnesses trigger visible failures?

The outputs are intentionally **evidence**, not verdicts. For example:

- A clean Miri run means no UB was observed on the exercised test paths, not that the crate is UB-free.
- A clean fuzz run means no visible failure was found under the current harnesses and budget, not that the crate is robust against all inputs.
- A high Geiger count means there is more `unsafe` syntax to inspect, not that the crate is necessarily less sound.

## Pattern Analysis

The AST analyzer emits structured findings. `FindingKind` distinguishes:

- unsafe blocks,
- unsafe function declarations,
- unsafe impl declarations,
- risky operations,
- and extern items.

`RiskyOperation` findings are classified into these categories:

| Pattern | Severity | Example |
|---------|----------|---------|
| `Transmute` | High | `std::mem::transmute::<u32, i32>(x)` |
| `UninitMemory` | High | `std::mem::zeroed()`, `MaybeUninit::assume_init()` |
| `UnreachableUnchecked` | High | `std::hint::unreachable_unchecked()` |
| `InlineAsm` | High | `core::arch::asm!("mov {}, {}", ...)` |
| `UncheckedConversion` | High | `str::from_utf8_unchecked(bytes)` |
| `PtrDereference` | Medium | `*ptr`, `raw as *mut T` |
| `PtrReadWrite` | Medium | `std::ptr::read(ptr)`, `ptr::copy_nonoverlapping` |
| `UncheckedIndex` | Medium | `slice.get_unchecked(i)` |
| `SimdIntrinsic` | Medium | `_mm_load_si128(...)`, `_mm256_cmpeq_epi8` |
| `UnionAccess` | Medium | Reserved for future typed union-field detection |
| `ExternBlock` | Medium | `extern "C" { fn malloc(size: usize); }` |
| `AddrOf` | Low | `std::ptr::addr_of!(field)` |
| `OtherUnsafe` | Low | unsafe block/declaration marker or uncategorized unsafe context |

Important limitation: these categories are **heuristic structural classifications**. They hint at the kinds of assumptions the code may rely on, but they do not reconstruct those assumptions precisely.

Risk score is a heuristic summary computed from finding counts and severity weights. It is useful for rough prioritization, not as a security metric.

## Usage

```bash
cd unsafe-audit
cargo build --release

# Smoke test (Geiger + patterns only, no external tools needed)
./target/release/unsafe-audit ../targets/httparse \
  --skip-miri --skip-fuzz --output /tmp/smoke

# Full run on one crate (needs Miri + cargo-fuzz installed)
./target/release/unsafe-audit ../targets/httparse \
  --fuzz-time 60 --output /tmp/full

# Batch mode over all crates
./target/release/unsafe-audit ../targets --batch \
  --skip-fuzz --output /tmp/batch

# List discovered crates without running
./target/release/unsafe-audit ../targets --batch --list

# Strict-vs-baseline Miri triage
./target/release/unsafe-audit ../targets/serde_json \
  --miri-triage --skip-fuzz --output /tmp/serde-triage
```

CLI flags:

```text
PATH                          Crate dir, or parent dir with --batch
--batch                       Treat PATH as directory of crates
--skip-geiger                 Skip Phase 1
--skip-miri                   Skip Phase 2
--skip-fuzz                   Skip Phase 3
--skip-patterns               Skip Phase 4
--miri-flags <FLAGS>          MIRIFLAGS (default: strict provenance + symbolic alignment)
--miri-triage                 Re-run baseline Miri when strict Miri reports UB
--fuzz-time <SECONDS>         Per-target fuzz budget (default: 60)
--fuzz-env <KEY=VALUE>        Extra env vars for fuzz (repeatable)
--output <DIR>                Report output directory (default: <path>/unsafe-audit-report)
--format <json|markdown|both> Output format (default: both)
--list                        List crates, don't run
-v, --verbose                 Show pattern details
```

## Output

Two files per run:

- `report.json`: machine-readable structured evidence
- `report.md`: human-readable summary with per-phase sections

Representative fields in `report.json` include:

- Geiger counts (`functions`, `exprs`, `item_impls`, ...)
- Miri verdict plus strict/baseline run details
- Fuzz status, exit code, artifact path, run count, and edge coverage
- Pattern findings, finding kinds, pattern counts, and risk score

## Study Results

The repository includes study data and reports for 12 crates. Those artifacts should be read with the same interpretation rules above:

- Geiger counts are a syntactic proxy for `unsafe` surface.
- Miri findings apply to the test paths that actually executed.
- Fuzz findings apply to the existing harnesses and budgets that were run.

They are useful comparative evidence, but not complete security judgments.

## Project Structure

```text
unsafe-audit/           # Main deliverable
  src/
    main.rs             # CLI entry, crate discovery, phase orchestration
    analyzer.rs         # AST-based finding extraction and pattern classification
    geiger.rs           # geiger library integration
    miri.rs             # cargo miri runner + strict/baseline verdicts
    fuzz.rs             # cargo-fuzz discovery, runner, exit/artifact capture
    report_gen.rs       # JSON + Markdown report generation
    models.rs           # Shared result types
  Cargo.toml

extensions_harness/     # Targeted smoke tests for Tier 2 crates
fuzz_corpus/            # Seed corpora
fuzz_findings/          # Fuzz artifacts
geiger_reports/         # Archived geiger outputs + annotations
miri_reports/           # Miri logs + triage notes
report/                 # Final report + supporting writeups
scripts/                # Original shell pipeline
Dockerfile              # Reproducible environment
demo_video.mp4          # Walkthrough video
```

## Reproduce

### Quick: Build and Smoke Test

```bash
cd unsafe-audit
cargo build
cargo run -- ../targets/httparse \
  --skip-miri --skip-fuzz --output /tmp/smoke
cat /tmp/smoke/report.md
```

### Full: One Crate With Miri + Fuzz

```bash
# Prerequisites
rustup toolchain install nightly-2026-02-01
rustup component add miri rust-src --toolchain nightly-2026-02-01
cargo install cargo-fuzz

cd unsafe-audit
cargo run -- ../targets/httparse \
  --miri-triage \
  --fuzz-time 60 \
  --output /tmp/full
```

### Docker

```bash
docker build -t unsafe-study .
docker run --rm -it unsafe-study
```

## Toolchain

- Rust nightly-2026-02-01 (rustc 1.95.0-nightly)
- Miri component + rust-src
- cargo-fuzz (Phase 3)
- Linux x86_64 for fuzzing; Miri works cross-platform

## Links

- GitHub: https://github.com/doyaGu/unsafe_study
- Full report: `report/final_report.md`
- Tool design notes: `DESIGN.md`
