# roxmltree 0.21.1 - Hotspot Notes

## Intake Summary

- Version studied: `0.21.1`
- Local target: `targets/roxmltree`
- `src/lib.rs` declares `#![forbid(unsafe_code)]`
- Direct `unsafe` survey: ~1 source match, from crate-level attributes rather
  than an active unsafe block
- Harness: `miri_harnesses/roxmltree/tests/roxmltree.rs`

## Assessment

roxmltree is a negative control. It is still useful in the workspace because it
gives a tree-oriented XML parser comparison point with no direct unsafe code in
the studied crate sources. The exercised path was Miri-clean.
