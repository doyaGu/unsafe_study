#!/bin/bash
# make_demo_video.sh — Generate a terminal-demo MP4 showing the study pipeline.
# Requires: ffmpeg with libx264, DejaVu Sans Mono font.
#
# Usage: bash scripts/make_demo_video.sh
# Output: demo_video.mp4

set -euo pipefail

cd "$(dirname "$0")/.."
OUT="demo_video.mp4"
FONT="/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
BG="0x1e1e2e"
FG="0xcdd6f4"
GREEN="0xa6e3a1"
RED="0xf38ba8"
YELLOW="0xf9e2af"
W=1280
H=720
FPS=10

if [ ! -f "$FONT" ]; then
    echo "Font not found at $FONT; install fonts-dejavu-core"
    exit 1
fi

# Build the video using a concat of short segments.
# Each segment is a "slide" held for N seconds.
SEGDIR=$(mktemp -d)
trap "rm -rf $SEGDIR" EXIT

i=0
hold=4

make_slide() {
    local idx=$1; shift
    local color=${1:-$FG}; shift
    local duration=${1:-$hold}; shift
    local text="$*"
    local safetext
    # Escape for ffmpeg drawtext
    safetext=$(printf '%s' "$text" | sed "s/'/'\\\\''/g" | sed 's/%/%%/g' | sed 's/:/\\:/g')
    local seg="$SEGDIR/seg_${idx}.ts"
    ffmpeg -y -f lavfi -i "color=c=${BG}:s=${W}x${H}:d=${duration}:r=${FPS}" \
        -vf "drawtext=fontfile=${FONT}:text='${safetext}':fontcolor=${color}:fontsize=16:x=40:y=36:line_spacing=6" \
        -c:v libx264 -pix_fmt yuv420p -preset ultrafast -crf 28 "$seg" 2>/dev/null
    echo "file '$seg'" >> "$SEGDIR/concat.txt"
}

> "$SEGDIR/concat.txt"

# Slide 1: Title
make_slide $i "$FG" 6 \
"================================================================
  unsafe_study -- Finding unsafe-Related Failures in Real Rust Crates
  CSE 5349 Final Project

  Three-phase pipeline applied to 12 real-world Rust crates:
    Phase 1: Hotspot Mining     (cargo-geiger)
    Phase 2: Miri UB Detection  (cargo miri test)
    Phase 3: Coverage-Guided Fuzzing (cargo-fuzz / libFuzzer)

  Toolchain: nightly-2026-02-01 (rustc 1.95.0-nightly)
================================================================"
i=$((i+1))

# Slide 2: Target crates
make_slide $i "$FG" 5 \
"Target Crates (12 total)

  Tier 1 -- Baseline (full depth):
    httparse  v1.10.1   HTTP/1.1 parsing        248 unsafe exprs
    serde_json v1.0.149  JSON deserialization      75 unsafe exprs (+ 2883 via deps)
    bstr      v1.12.1   Byte string handling      364 unsafe exprs (+ 2722 via deps)

  Tier 2 -- Extension batch (targeted depth):
    memchr, simd-json, quick-xml, winnow, toml_parser,
    goblin, toml_edit, pulldown-cmark, roxmltree

  Control cases (forbid unsafe_code):
    quick-xml, roxmltree"
i=$((i+1))

# Slide 3: Geiger
make_slide $i "$FG" 5 \
"Phase 1: Hotspot Mining (cargo-geiger)

  $ cd targets/httparse && cargo geiger
  Checking httparse v1.10.1
  Finished dev profile [unoptimized + debuginfo] target(s) in 2.88s

  httparse unsafe usage:
    Functions :   safe 22   unsafe 7
    Exprs     :   safe 2281  unsafe 248  (~9.8% of expressions)
    Hotspot   :   src/lib.rs  (SIMD parsing, pointer arithmetic)

  simd-json unsafe usage:
    Expressions:  significantly higher density in parsing hot path
    All unsafe concentrated in SIMD-aligned byte manipulation"
i=$((i+1))

# Slide 4: Miri httparse
make_slide $i "$GREEN" 5 \
"Phase 2: Miri Testing -- httparse (CLEAN)

  $ MIRIFLAGS=\"-Zmiri-symbolic-alignment-check -Zmiri-strict-provenance\" \
    cargo +nightly-2026-02-01 miri test

  Compiling httparse v1.10.1
  Running unittests src/lib.rs
  test test_headers ... ok
  test test_request ... ok
  test urltest_001 ... ok
  ... (263 tests)

  test result: ok. 263 passed; 0 failed; 0 ignored; 0 measured
  Doc-tests httparse: 6 passed; 0 failed

  VERDICT: CLEAN -- No UB detected under strict Miri"
i=$((i+1))

# Slide 5: Miri simd-json
make_slide $i "$RED" 6 \
"Phase 2: Miri Testing -- simd-json (UB DETECTED!)

  $ cargo miri test --test simd_json_triage \
    simd_json_borrowed_value_parses_object_with_strings

  error: Undefined Behavior: trying to retag from <2635> for
         SharedReadOnly permission at ALLOC[0x2635]
         (which has been reborrowed for Unique)
   --> src/charutils.rs:24:34
      |
  24 |     let ptr = src.as_ptr();
      |                  ^^^^^^^^
      = note: Stacked Borrows violation

  VERDICT: UB DETECTED
  Root cause: Pointer retagging conflict between &mut and & references
  Two-pass triage confirmed: Pass 1 (strict) UB, Pass 2 (baseline) UB
  Classification: TRUE POSITIVE (code-level audit confirms)

  Artifacts:
    evidence/miri/simd_json_triage.md
    docs/report/simd_json_stacked_borrows_explainer.md
    docs/report/simd_json_upstream_issue_draft.md"
i=$((i+1))

# Slide 6: Fuzzing
make_slide $i "$FG" 5 \
"Phase 3: Coverage-Guided Fuzzing (cargo-fuzz / libFuzzer)

  $ cargo +nightly-2026-02-01 fuzz run parse_request -- -max_total_time=3600

  Running: fuzz/target/.../release/parse_request
  #1    INITED cov: 1256 ft: 2385 corp: 31/8411b
  #64   NEW    cov: 1256 ft: 2401 corp: 32/8718b
  #128  NEW    cov: 1256 ft: 2408 corp: 33/9021b
  #8192 DONE   cov: 1256 ft: 2410 corp: 33/9021b

  httparse:    Clean (no crashes in 3600s)
  serde_json:  Clean
  simd-json:   Clean (no fuzz crashes -- UB only via Miri)
  bstr:        Clean
  All 12:      No crash findings

  Fuzz coverage expanded corpus for all crates without triggering UB.
  Confirms: Miri detects a class of bug that coverage-guided fuzzing alone misses."
i=$((i+1))

# Slide 7: Summary
make_slide $i "$YELLOW" 6 \
"Cross-Crate Results Summary
================================================================

  Crate              unsafe exprs   Miri            Fuzz
  ----------------------------------------------------------------
  httparse           248            CLEAN           Clean
  serde_json          75 (+deps)    CLEAN           Clean
  bstr               364 (+deps)    CLEAN           Clean
  memchr             ~200           CLEAN           Clean
  simd-json          HEAVY          UB DETECTED     Clean
  quick-xml          0 (forbid)     CLEAN           Clean
  winnow             ~50            CLEAN           Clean
  goblin             ~100           CLEAN           Clean
  toml_edit          0 (safe)       CLEAN           Clean
  pulldown-cmark     0 (opt-in)     CLEAN           Clean
  roxmltree          0 (forbid)     CLEAN           Clean

  KEY FINDING: simd-json Stacked Borrows UB (true positive)
  Control crates (quick-xml, roxmltree) validate no false positives."
i=$((i+1))

# Slide 8: Reproduce
make_slide $i "$FG" 6 \
"How to Reproduce
================================================================

  Option A -- Docker (recommended):
    docker build -t unsafe-study .
    docker run --rm -it unsafe-study

  Option B -- Linux directly:
    rustup toolchain install nightly-2026-02-01
    rustup component add miri rust-src --toolchain nightly-2026-02-01
    cargo install cargo-geiger cargo-fuzz

    # Quick demo (httparse only, 60s fuzz):
    bash scripts/run_all.sh --crates httparse --fuzz-time 60

    # Full pipeline (all 12 crates):
    bash scripts/run_all.sh --fuzz-time 3600

  Key files:
    docs/report/final_report.md      Full study report
    docs/report/simd_json_stacked_borrows_explainer.md   Technical deep-dive
    evidence/miri/simd_json_triage.md Miri triage notes
    scripts/run_all.sh               Reproduce everything

  GitHub: https://github.com/doyaGu/unsafe_study"
i=$((i+1))

# Concat all segments
ffmpeg -y -f concat -safe 0 -i "$SEGDIR/concat.txt" -c copy "$OUT" 2>/dev/null \
    || ffmpeg -y -f concat -safe 0 -i "$SEGDIR/concat.txt" -c:v libx264 -pix_fmt yuv420p "$OUT" 2>/dev/null

if [ -f "$OUT" ]; then
    echo ""
    echo "Demo video saved: $OUT ($(du -h "$OUT" | cut -f1))"
else
    echo "ERROR: Video generation failed"
    exit 1
fi
