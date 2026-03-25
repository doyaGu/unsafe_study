# pulldown-cmark 0.13.1 - Hotspot Notes

## Intake Summary

- Version studied: `0.13.1`
- Local target: `targets/pulldown-cmark`
- Direct `unsafe` survey: ~7 source matches
- `src/lib.rs` forbids unsafe unless the optional `simd` feature is enabled
- Harness: `extensions_harness/tests/more_crates.rs`

## Main Unsafe Concentration

- `src/firstpass.rs` contains the SIMD-specialized scanning helpers.
- In the current intake configuration, the exercised path stayed Miri-clean.

## Assessment

This crate is a lower-priority unsafe target because its interesting unsafe is
feature-gated rather than fundamental to the default API surface.
