# goblin 0.10.5 - Hotspot Notes

## Intake Summary

- Version studied: `0.10.5`
- Local target: `targets/goblin`
- Direct `unsafe` survey: ~36 `unsafe` source matches
- Harness: `miri_harnesses/goblin/tests/goblin.rs`

## Main Unsafe Concentration

- ELF and Mach-O layout modules dominate the direct `unsafe`.
- Common pattern:
  - `unsafe impl plain::Plain for ...`
  - `slice::from_raw_parts(...)` over externally supplied binary data
  - zero-copy casting of binary headers and relocation tables

Representative files:

- `src/elf/program_header.rs`
- `src/elf/reloc.rs`
- `src/elf/sym.rs`
- `src/mach/header.rs`

## Assessment

This is a good next-step unsafe target because it exercises binary layout and
zero-copy table walking rather than text parsing. The current harness smoke test
was Miri-clean.
