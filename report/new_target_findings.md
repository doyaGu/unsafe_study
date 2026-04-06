# New Target Fuzz Findings

High-budget (`3600s` per target) fuzzing for the 2026-03-11 added target batch
produced two non-clean results.

## `toml_edit` panic

- Target: `toml_edit_parse`
- Classification: panic
- Trigger site: `targets/toml_edit/src/parser/document.rs:547`
- Panic message: `all items have spans`
- Original crash artifact:
  `targets/toml_edit/fuzz/artifacts/toml_edit_parse/crash-bfa99aad83fb6f70dc04597a15164d1e7a80b9c4`
- Minimized reproducer (9 bytes):
  `targets/toml_edit/fuzz/artifacts/toml_edit_parse/reproducer-min-9b`
- Minimized bytes (hex): `3d 5b 7b 7b 7d ff 7b 0d 2e`

Observed stack root:

```text
thread '<unnamed>' panicked at .../document.rs:547:56:
all items have spans
```

Reproduce:

```bash
cd targets/toml_edit
CARGO_NET_OFFLINE=true ASAN_OPTIONS=detect_odr_violation=0:detect_leaks=0 \
  cargo fuzz run toml_edit_parse \
  fuzz/artifacts/toml_edit_parse/reproducer-min-9b
```

Current interpretation: parser error reporting assumes every existing
`Item::Value` has a span, but the fuzzer found an input that violates that
invariant and turns error construction into a panic.

## `pulldown-cmark` OOM

- Target: `pulldown_cmark_parse`
- Classification: out-of-memory / resource exhaustion
- Signal: `libFuzzer: out-of-memory (malloc(2147483648))`
- Artifacts:
  - `targets/pulldown-cmark/fuzz/artifacts/pulldown_cmark_parse/oom-e741511a69765f50d13812013597c01d23ae8994`
  - `targets/pulldown-cmark/fuzz/artifacts/pulldown_cmark_parse/slow-unit-29d12895ef8a06b82ce7578958223cc6fd01e10a`
- Minimized reproducer:
  `targets/pulldown-cmark/fuzz/artifacts/pulldown_cmark_parse/reproducer-min-480b`
- Minimization note: manual delta-debugging reduced the original `815B`
  OOM artifact to `480B` by deleting internal ranges `96-128`, `224-256`,
  `320-384`, and `448-480` from the earlier `640B` prefix candidate. The
  reduced input still drives a fixed-input replay to roughly `38s`.

Observed failure summary:

```text
ERROR: libFuzzer: out-of-memory (malloc(2147483648))
SUMMARY: libFuzzer: out-of-memory
```

Reproduce:

```bash
cd targets/pulldown-cmark
CARGO_NET_OFFLINE=true ASAN_OPTIONS=detect_odr_violation=0:detect_leaks=0 \
  cargo fuzz run pulldown_cmark_parse \
  fuzz/artifacts/pulldown_cmark_parse/oom-e741511a69765f50d13812013597c01d23ae8994
```

Reduced reproducer:

```bash
cd targets/pulldown-cmark
ASAN_OPTIONS=detect_odr_violation=0:detect_leaks=0 \
  fuzz/target/x86_64-unknown-linux-gnu/release/pulldown_cmark_parse \
  fuzz/artifacts/pulldown_cmark_parse/reproducer-min-480b
```

Current interpretation: the Markdown parse/render path can be driven into
pathological memory growth by crafted input. The full `815B` artifact is the
direct OOM reproducer from the long fuzz run; the `480B` reduced artifact is a
smaller fixed-input reproducer for the same resource-exhaustion behavior.
