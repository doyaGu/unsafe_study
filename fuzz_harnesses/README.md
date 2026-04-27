# Active Fuzz Harnesses

This directory collects the active study-specific fuzz harnesses that were
added inside `targets/*` repositories and keeps them in one top-level
workspace.

Current active sets:

- `bstr`: standalone copy of the custom fuzz harness package and targets.
- `serde_json`: standalone copy of the added `from_str` fuzz target.

These manifests point back to the local crate checkouts under
`targets/<crate>` so they can be validated from this repository root.

Validation commands:

```bash
cargo check --manifest-path fuzz_harnesses/Cargo.toml --workspace
cargo check --manifest-path fuzz_harnesses/bstr/Cargo.toml --bins
cargo check --manifest-path fuzz_harnesses/serde_json/Cargo.toml --bin from_str
```