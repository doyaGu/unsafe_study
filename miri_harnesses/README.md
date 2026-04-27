# Active Miri Harnesses

This directory mirrors the organization used by `fuzz_harnesses`: each study
crate gets its own dedicated Miri harness package under
`miri_harnesses/<crate>/`.

Why this layout:

- each `cargo miri test` invocation resolves only the dependency graph for the
  crate being studied
- no integration test binary mixes APIs from multiple crates
- a broken dependency or nightly regression in one harness package does not
  block targeted Miri runs for the other crates

Current layout:

- `miri_harnesses/bstr`
- `miri_harnesses/goblin`
- `miri_harnesses/memchr`
- `miri_harnesses/pulldown-cmark`
- `miri_harnesses/quick-xml`
- `miri_harnesses/roxmltree`
- `miri_harnesses/serde_json`
- `miri_harnesses/simd_json`
- `miri_harnesses/toml_edit`
- `miri_harnesses/toml_parser`
- `miri_harnesses/winnow`

The study manifest points each targeted Miri case at the corresponding
`harness_dir`, so `unsafe-audit` runs `cargo miri test --test <crate-specific
test>` inside the dedicated package for that crate.

Validation commands:

```bash
cargo test --manifest-path miri_harnesses/Cargo.toml --workspace --exclude miri_harnesses_simd_json --no-run
cargo test --manifest-path miri_harnesses/serde_json/Cargo.toml --no-run
cargo test --manifest-path miri_harnesses/simd_json/Cargo.toml --no-run
```
