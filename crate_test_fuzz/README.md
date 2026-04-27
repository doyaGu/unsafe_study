# Extracted Crate Fuzz Artifacts

This directory collects the study-specific fuzz harnesses that were added inside
`targets/*` repositories and copies them into one top-level location.

Current extracted sets:

- `bstr`: standalone copy of the custom fuzz harness package and targets.
- `serde_json`: standalone copy of the added `from_str` fuzz target.

These extracted manifests point back to the local crate checkouts under
`targets/<crate>` so they can be validated from this repository root.

Validation commands:

```bash
cargo check --manifest-path crate_test_fuzz/bstr/Cargo.toml --bins
cargo check --manifest-path crate_test_fuzz/serde_json/Cargo.toml --bin from_str
```