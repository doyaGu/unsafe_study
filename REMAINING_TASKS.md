# Remaining Tasks -- Unsafe Study Project

Last updated: 2026-03-24

## Current Situation

- End-to-end study outputs are complete and archived in `report/final_report.md`.
- Baseline crate set (`httparse`, `serde_json`, `bstr`) and extension batch
  outputs exist for hotspot scan, Miri, and fuzzing.
- `simd-json` has a focused triage note in `miri_reports/simd_json_triage.md`
  and an upstream-ready draft in `report/simd_json_upstream_issue_draft.md`.
- Repository has been initialized as a local Git repo on `main` with root
  `.gitignore`.

## Remaining Decisions (Actual Open Items)

1. Decide whether to submit the prepared `simd-json` upstream issue draft.
2. Decide whether the local `simd-json` mitigation should remain as a study-only
   patch or be proposed upstream.
3. Decide whether to classify the `simd-json` behavior as a reportable upstream
   bug or as a Miri-model incompatibility in external communication.
4. Finalize repository publishing workflow:
   - create initial commit
   - optionally set remote `origin`
   - choose whether to include large research artifacts in first push

## Suggested Next Action

- If this repository will be shared, do item 4 first (commit policy + remote),
  then do items 1-3 based on how public-facing you want the `simd-json`
  follow-up to be.
