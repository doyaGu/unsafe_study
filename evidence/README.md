# Evidence Layout

This directory groups archived execution evidence produced by the study.

- `geiger/`: cargo-geiger outputs and hotspot annotations.
- `miri/`: Miri logs, triage notes, and UB investigation artifacts.
- `fuzz/corpus/`: seed inputs used for fuzz targets.
- `fuzz/findings/`: fuzz logs, findings, and reproducer-oriented artifacts.

These files are evidence archives. The active execution inputs and harness
workspaces live under `study/`, `targets/`, `miri_harnesses/`, and
`fuzz_harnesses/`. The manifest-driven study still executes crate-local fuzz
harnesses under `targets/<crate>/fuzz/` unless a `fuzz_group` overrides
`harness_dir`.