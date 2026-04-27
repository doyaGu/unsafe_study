# Active Fuzz Harnesses

This directory collects the active study-specific fuzz harnesses that were
added inside `targets/*` repositories and keeps them in one top-level
workspace.

Current active sets:

- `bstr`: standalone copy of the custom fuzz harness package and targets.
- `serde_json`: standalone copy of the added `from_str` fuzz target.

Seed corpus layout:

- `fuzz_harnesses/<crate>/corpus/<target>/...`

This directory is the normalized copy of the checked-in seed inputs that were
previously archived under `evidence/fuzz/corpus/`. During the 2026-04-27 rerun,
the runner was updated to backfill local `targets/<crate>/fuzz/corpus/<target>/`
directories from these per-crate stores before launching libFuzzer. If no seed
files exist for a target, the runner still creates an empty corpus directory so
the fuzz target can start.

These manifests point back to the local crate checkouts under
`targets/<crate>` so they can be validated from this repository root.

Validation commands:

```bash
cargo check --manifest-path fuzz_harnesses/Cargo.toml --workspace
cargo check --manifest-path fuzz_harnesses/bstr/Cargo.toml --bins
cargo check --manifest-path fuzz_harnesses/serde_json/Cargo.toml --bin from_str
```