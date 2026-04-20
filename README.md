# unsafe_study -- Finding and Understanding `unsafe`-Related Failures in Real Rust Crates

CSE 5349 final project. The deliverable is `unsafe-audit`, a Rust CLI that audits crates for unsafe code through four automated phases.

## The Tool: `unsafe-audit`

A CLI tool that takes a crate path and runs the audit pipeline:

```
$ unsafe-audit ../targets/httparse --fuzz-time 60 --output /tmp/report
```

### What It Does

| Phase | What | How |
|-------|------|-----|
| **1. Geiger scan** | Count unsafe functions/exprs/impls/traits/methods | `geiger` library API, walks crate source files under `src/` |
| **2. Miri test** | Detect undefined behavior | Shells out `cargo miri test`, parses UB from log output |
| **3. Fuzz run** | Find crashes, panics, OOMs | Discovers existing `cargo fuzz` targets, runs each with libFuzzer |
| **4. Pattern analysis** | Classify unsafe code patterns by risk | `syn` AST visitor, 13 pattern categories, risk score 0-100 |

### What It Does NOT Do (Known Gap)

**Automatic fuzz harness generation.** Phase 3 discovers and runs existing `fuzz/` directories that are already present in the target crate. It does not auto-generate harness code from API signatures. This means:

- Crates that already have a local `fuzz/` directory work out of the box.
- Crates without a `fuzz/` directory skip Phase 3 with a `NoFuzzDir` status.
- To fuzz a new crate, you currently write the harness by hand or use `cargo fuzz init` + manual editing.

This is the biggest remaining gap. See `DESIGN.md` for the planned auto-generation approach.

### Pattern Categories (Phase 4)

The AST analyzer classifies unsafe expressions into 13 categories:

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
| `UnionAccess` | Medium | `my_union.field` |
| `ExternBlock` | Medium | `extern "C" { fn malloc(size: usize); }` |
| `AddrOf` | Low | `std::ptr::addr_of!(field)` |
| `OtherUnsafe` | Low | catch-all for remaining unsafe expressions |

Risk score formula: weighted severity sum / file count, square-root scaled, capped at 100. Bands: <20 LOW, <50 MEDIUM, >=50 HIGH.

### Usage

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

# Custom Miri flags
./target/release/unsafe-audit ../targets/serde_json \
  --miri-flags "-Zmiri-strict-provenance" \
  --skip-fuzz --output /tmp/serde-no-sym
```

CLI flags:

```
PATH                          Crate dir, or parent dir with --batch
--batch                       Treat PATH as directory of crates
--skip-geiger                 Skip Phase 1
--skip-miri                   Skip Phase 2
--skip-fuzz                   Skip Phase 3
--skip-patterns               Skip Phase 4
--miri-flags <FLAGS>          MIRIFLAGS (default: strict provenance + symbolic alignment)
--fuzz-time <SECONDS>         Per-target fuzz budget (default: 60)
--fuzz-env <KEY=VALUE>        Extra env vars for fuzz (repeatable)
--output <DIR>                Report output directory (default: <path>/unsafe-audit-report)
--format <json|markdown|both> Output format (default: both)
--list                        List crates, don't run
-v, --verbose                 Show pattern details
```

### Output

Two files per run:

**report.json** -- machine-readable, full structured data. Shortened example from the smoke-test output:
```json
{
  "timestamp": "2026-04-20T01:09:36.208481574-04:00",
  "crates": [{
    "target": {
      "name": "httparse",
      "dir": "/path/to/targets/httparse"
    },
    "geiger": {
      "crate_name": "httparse",
      "crate_version": "?.?.?",
      "used": {
        "exprs": { "safe": 702, "unsafe_": 335 }
      },
      "forbids_unsafe": false,
      "files_scanned": 9
    },
    "miri": null,
    "fuzz": [],
    "pattern_analysis": {
      "crate_name": "httparse",
      "crate_version": "1.10.1",
      "total_unsafe_exprs": 901,
      "files_with_unsafe": 8,
      "files_scanned": 9,
      "risk_score": 68.4,
      "patterns": [
        { "pattern": "OtherUnsafe", "count": 791 },
        { "pattern": "SimdIntrinsic", "count": 80 }
      ]
    }
  }]
}
```

**report.md** -- human-readable summary with tables, one section per phase.

## Study Results (12 Crates)

| Crate | Unsafe Exprs | Risk | Miri | Fuzz |
|-------|-------------|------|------|------|
| httparse | 901 | 68.4 HIGH | CLEAN | 399M runs, 0 crashes |
| simd-json | 6117 | 62.5 HIGH | Stacked Borrows UB | CLEAN |
| memchr | 7191 | 70.3 HIGH | CLEAN | CLEAN |
| bstr | 758 | 34.9 MED | FP: alignment | 767K runs, 0 crashes |
| serde_json | 156 | 15.5 LOW | FP: memchr align | 22M runs, 0 crashes |
| pulldown-cmark | 201 | 27.8 MED | CLEAN | OOM, 480B reproducer |
| toml_edit | 0 | 0.0 LOW | CLEAN | PANIC, 9B reproducer |
| others | varies | varies | CLEAN | CLEAN |

Key findings:

- **simd-json**: True positive Stacked Borrows violation. See `report/simd_json_stacked_borrows_explainer.md` and upstream issue draft `report/simd_json_upstream_issue_draft.md`.
- **serde_json & bstr**: Miri alignment false positives confirmed by two-pass triage.
- **toml_edit & pulldown-cmark**: Fuzz found bugs in safe Rust despite clean Miri -- strongest complementarity evidence.

## Project Structure

```
unsafe-audit/           # Main deliverable
  src/
    main.rs                   # CLI entry, crate discovery, phase orchestration
    analyzer.rs               # syn AST unsafe pattern classifier (Phase 4)
    geiger.rs                 # geiger library integration (Phase 1)
    miri.rs                   # cargo miri test runner + UB log parser (Phase 2)
    fuzz.rs                   # cargo-fuzz target discovery + runner (Phase 3)
    report_gen.rs             # JSON + Markdown report generation
    models.rs                 # Shared types (CrateAuditResult, MiriResult, etc.)
  Cargo.toml

extensions_harness/           # Targeted smoke tests for Tier 2 crates
fuzz_corpus/                  # Seed corpora
fuzz_findings/                # Fuzz artifacts
geiger_reports/               # Archived geiger outputs + annotations
miri_reports/                 # Miri logs + triage notes
report/                       # Final report + supporting writeups
scripts/                      # Original shell pipeline (run_all.sh, run_fuzz.sh)
Dockerfile                    # Reproducible environment
demo_video.mp4                # Walkthrough video
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
  --fuzz-time 60 --output /tmp/full
```

### Docker

```bash
docker build -t unsafe-study .
docker run --rm -it unsafe-study
```

### Original Shell Pipeline

```bash
bash scripts/run_all.sh --crates httparse --fuzz-time 60
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
