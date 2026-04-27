# Study Protocol

[manifest.toml](manifest.toml) is the canonical manifest for the 12-crate study.

```bash
bash scripts/run_all.sh [args]                                          # recommended
cargo run --manifest-path unsafe-audit/Cargo.toml -- study/manifest.toml [args]  # low-level
```

---

---

## Manifest schema

```toml
[study]
name        = "unsafe-study"
output_root = "study/output"
fuzz_time   = 3600
fuzz_env    = { ASAN_OPTIONS = "detect_leaks=0" }

[[crate]]
name          = "httparse"
path          = "targets/httparse"
cohort        = "baseline"   # label only
coverage_tier = "tier1"      # label only

[[crate.miri_case]]
name        = "upstream_full"
scope       = "full_suite"
# harness_dir, test, case, exact, env  - all optional

[[crate.fuzz_group]]
name    = "existing_targets"
all     = true               # or: targets = ["name1", "name2"]
# harness_dir, time, budget_label, env  - all optional
```

Fuzz env merge order: process env → `study.fuzz_env` → group `env` → CLI `--fuzz-env`.

Corpus backfill: if `targets/<crate>/fuzz/corpus/<target>/` is empty, seeds are copied from `fuzz_harnesses/<crate>/corpus/<target>/` before launch.

---

## `simd-json` patch (required before every run)

```bash
cd targets/simd-json
git apply ../../patches/simd-json/0001-fix-nightly-unused-imports.patch
```

`simd-json 0.17.0` uses `#![deny(warnings)]`; the pinned `nightly-2026-02-01` toolchain turns five unused-import warnings into hard errors. The Dockerfile applies this automatically.

---

## Examples

```bash
# Dry run - validate plan without executing
bash scripts/run_all.sh --dry-run

# Smoke subset
bash scripts/run_all.sh --crates httparse,simd-json --profile smoke --jobs 2 --output /tmp/smoke

# Fuzz-only re-run with env override
bash scripts/run_all.sh --crates simd-json --skip-scan --skip-geiger --skip-miri \
  --fuzz-env ASAN_OPTIONS="detect_leaks=0:abort_on_error=1" --output /tmp/env-rerun
```

