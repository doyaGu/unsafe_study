# quick-xml 0.39.2 - Hotspot Notes

## Intake Summary

- Version studied: `0.39.2`
- Local target: `targets/quick-xml`
- `src/lib.rs` declares `#![forbid(unsafe_code)]`
- Direct `unsafe` survey: ~10 source matches, all comments / notes rather than
  live unsafe blocks
- Harness: `extensions_harness/tests/more_crates.rs`

## Assessment

quick-xml is an XML parser comparison case, not a primary unsafe target in this
study. The exercised streaming reader path was Miri-clean.
