# simd-json Compile Fix Patch

This directory contains the minimal patch needed to make the local
`targets/simd-json` checkout compile again on the pinned nightly toolchain,
without modifying the vendored target in place.

What the patch does:

- removes five unused imports / re-exports that are promoted to hard errors by
  `#![deny(warnings)]`
- does not change parsing logic, Miri behavior, or test semantics

Patch file:

- `0001-fix-nightly-unused-imports.patch`

Apply on a working copy:

```bash
cd /home/seclab/unsafe_study/targets/simd-json
git apply ../../patches/simd-json/0001-fix-nightly-unused-imports.patch
```

Dry-run check without modifying files:

```bash
cd /home/seclab/unsafe_study/targets/simd-json
git apply --check ../../patches/simd-json/0001-fix-nightly-unused-imports.patch
```

Validation commands after applying:

```bash
cd /home/seclab/unsafe_study/targets/simd-json
cargo test --offline --test miri_triage --no-run

cd /home/seclab/unsafe_study
cargo test --manifest-path miri_harnesses/simd_json/Cargo.toml --no-run
```

Notes:

- this patch is meant to be applied to `targets/simd-json` only
- it is kept outside `targets/` so the repository preserves the user's
  constraint that vendored target sources are not edited directly
- this compile-fix patch is required for the current pinned-nightly study
  rerun because `simd-json 0.17.0` otherwise fails before the targeted Miri
  harness can even build