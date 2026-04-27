# Active Fuzz Harnesses

This directory collects the active study-specific fuzz harnesses that were
added inside `targets/*` repositories and keeps them in one top-level
workspace.

Only custom study harnesses belong here. We do not mirror a crate's existing
fuzz package into this directory; each package should add coverage that the
upstream crate does not already ship.

Current active sets:

- `bstr`: standalone copy of the custom fuzz harness package and targets.
- `goblin`: custom binary parser targets for object, ELF, PE, and Mach parsing.
- `memchr`: custom unaligned and boundary-focused search targets beyond the crate's built-in fuzz set.
- `pulldown-cmark`: custom render, merged-event, and offset-iterator targets beyond the crate's built-in parser fuzzers.
- `quick-xml`: custom reader, attribute, and namespace-resolution targets beyond the crate's built-in roundtrip fuzzers.
- `roxmltree`: custom child-navigation, node-id, and text-position targets beyond the crate's built-in parse/traverse/options set.
- `serde_json`: standalone copy of the added `from_str` fuzz target.
- `simd-json`: Miri-guided custom targets for borrowed, owned, tape, and unaligned parsing paths.
- `toml_edit`: custom parse/mutate/roundtrip targets for the format-preserving editor path.
- `toml_parser`: custom lexer/parser/decoder targets with the `unsafe` feature enabled.
- `winnow`: custom stream-slicing targets beyond the crate's built-in arithmetic fuzz target.

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
cargo check --manifest-path fuzz_harnesses/goblin/Cargo.toml --bins
cargo check --manifest-path fuzz_harnesses/memchr/Cargo.toml --bins
cargo check --manifest-path fuzz_harnesses/pulldown-cmark/Cargo.toml --bins
cargo check --manifest-path fuzz_harnesses/quick-xml/Cargo.toml --bins
cargo check --manifest-path fuzz_harnesses/roxmltree/Cargo.toml --bins
cargo check --manifest-path fuzz_harnesses/serde_json/Cargo.toml --bins
cargo check --manifest-path fuzz_harnesses/simd-json/Cargo.toml --bins
cargo check --manifest-path fuzz_harnesses/toml_edit/Cargo.toml --bins
cargo check --manifest-path fuzz_harnesses/toml_parser/Cargo.toml --bins
cargo check --manifest-path fuzz_harnesses/winnow/Cargo.toml --bins
```