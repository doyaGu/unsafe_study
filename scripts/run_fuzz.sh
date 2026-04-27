#!/bin/bash
# run_fuzz.sh — Run fuzzing on Linux (cargo-fuzz / libFuzzer).
#
# Usage:
#   bash scripts/run_fuzz.sh [crate] [target] [seconds]
#
# Examples:
#   bash scripts/run_fuzz.sh httparse parse_request 3600
#   bash scripts/run_fuzz.sh serde_json from_slice 3600
#   bash scripts/run_fuzz.sh          # runs all targets, 3600s each

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGETS_DIR="$PROJECT_ROOT/targets"
FINDINGS_DIR="$PROJECT_ROOT/evidence/fuzz/findings"
CANONICAL_CORPUS_DIR="$PROJECT_ROOT/fuzz_harnesses"
DEFAULT_TIME=3600
STUDY_CRATES=(
    httparse
    serde_json
    bstr
    memchr
    winnow
    toml_parser
    simd-json
    quick-xml
    goblin
    toml_edit
    pulldown-cmark
    roxmltree
)

# Ensure nightly toolchain is available
TOOLCHAIN="nightly-2026-02-01"
if ! rustup toolchain list | grep -q "$TOOLCHAIN"; then
    echo "Installing $TOOLCHAIN toolchain..."
    rustup toolchain install "$TOOLCHAIN"
    rustup component add rust-src --toolchain "$TOOLCHAIN"
fi

FUZZ_RUSTFLAGS="-Cpasses=sancov-module -Zsanitizer=address --cfg fuzzing -Cdebug-assertions -Ccodegen-units=1"
TARGET_TRIPLE="$(rustc +"$TOOLCHAIN" -vV | sed -n 's/^host: //p')"
TARGET_RUSTFLAGS_VAR="CARGO_TARGET_$(printf '%s' "$TARGET_TRIPLE" | tr '[:lower:]-' '[:upper:]_')_RUSTFLAGS"

list_fuzz_targets() {
    local crate="$1"
    local crate_dir="$TARGETS_DIR/$crate"

    if [ ! -d "$crate_dir" ]; then
        echo "ERROR: Crate directory not found: $crate_dir" >&2
        return 1
    fi

    if [ ! -f "$crate_dir/fuzz/Cargo.toml" ]; then
        return 0
    fi

    (
        cd "$crate_dir"
        cargo +"$TOOLCHAIN" fuzz list 2>/dev/null
    ) | sed '/^$/d'
}

run_fuzz_target() {
    local crate="$1"
    local target="$2"
    local time_secs="${3:-$DEFAULT_TIME}"
    local crate_dir="$TARGETS_DIR/$crate"
    local log_file="$FINDINGS_DIR/${crate}_${target}.log"

    if [ ! -d "$crate_dir" ]; then
        echo "ERROR: Crate directory not found: $crate_dir"
        return 1
    fi

    echo "════════════════════════════════════════════════════"
    echo "  Fuzzing: $crate / $target for ${time_secs}s"
    echo "════════════════════════════════════════════════════"

    cd "$crate_dir"

    if [ ! -f "fuzz/Cargo.toml" ]; then
        echo "  SKIP: missing fuzz workspace at $crate_dir/fuzz"
        echo ""
        return 0
    fi

    if ! list_fuzz_targets "$crate" | grep -Fxq "$target"; then
        echo "  SKIP: target $target is not present in the local workspace"
        echo ""
        return 0
    fi

    local fuzz_corpus="fuzz/corpus/$target"
    local artifacts_dir="fuzz/artifacts/$target"
    local target_dir="fuzz/target"
    local binary_path="$target_dir/$TARGET_TRIPLE/release/$target"
    mkdir -p "$fuzz_corpus"
    mkdir -p "$artifacts_dir"

    # Copy seed corpus if available from the canonical per-crate store.
    local seed_dir="$CANONICAL_CORPUS_DIR/$crate/corpus/$target"
    if [ -d "$seed_dir" ] && [ -n "$(find "$seed_dir" -mindepth 1 -print -quit 2>/dev/null)" ]; then
        cp -Rn "$seed_dir"/. "$fuzz_corpus"/ 2>/dev/null || true
        echo "  Seeded corpus from $seed_dir"
    fi

    export CARGO_NET_OFFLINE=true
    export ASAN_OPTIONS="detect_odr_violation=0:detect_leaks=0"

    echo "  Building fuzz target..."
    env "$TARGET_RUSTFLAGS_VAR=$FUZZ_RUSTFLAGS" cargo +"$TOOLCHAIN" build \
        --manifest-path fuzz/Cargo.toml \
        --target "$TARGET_TRIPLE" \
        --target-dir "$target_dir" \
        --release \
        --config 'profile.release.debug="line-tables-only"' \
        --bin "$target" 2>&1 | tee "$log_file"
    local build_exit=${PIPESTATUS[0]}
    if [ $build_exit -ne 0 ]; then
        echo "  BUILD FAILED"
        echo ""
        return $build_exit
    fi

    if [ ! -x "$binary_path" ]; then
        echo "  BUILD FAILED: missing binary at $binary_path" | tee -a "$log_file"
        echo ""
        return 1
    fi

    # Run the fuzzer
    echo "  Starting fuzzer..."
    "$binary_path" \
        "-artifact_prefix=${artifacts_dir}/" \
        "-max_total_time=${time_secs}" \
        "$fuzz_corpus" 2>&1 | tee -a "$log_file"
    local exit_code=${PIPESTATUS[0]}

    if [ $exit_code -ne 0 ]; then
        echo "  CRASH FOUND — check $log_file and fuzz/artifacts/$target/"

        # Copy artifacts to findings directory
        if [ -d "$artifacts_dir" ] && [ "$(ls -A "$artifacts_dir")" ]; then
            mkdir -p "$FINDINGS_DIR/$crate"
            cp "$artifacts_dir"/* "$FINDINGS_DIR/$crate/" 2>/dev/null || true
            echo "  Artifacts copied to $FINDINGS_DIR/$crate/"
        fi
    else
        echo "  Clean run (no crashes in ${time_secs}s)"
    fi

    echo ""
    return $exit_code
}

if [ $# -ge 2 ]; then
    # Run specific target
    run_fuzz_target "$1" "$2" "${3:-$DEFAULT_TIME}"
elif [ $# -eq 1 ]; then
    # Run all targets for a specific crate
    crate="$1"
    if [ ! -d "$TARGETS_DIR/$crate" ]; then
        echo "Unknown crate: $crate"
        echo "Available: ${STUDY_CRATES[*]}"
        exit 1
    fi
    mapfile -t targets < <(list_fuzz_targets "$crate")
    if [ ${#targets[@]} -eq 0 ]; then
        echo "No fuzz targets discovered for $crate"
        exit 0
    fi
    for target in "${targets[@]}"; do
        run_fuzz_target "$crate" "$target" "$DEFAULT_TIME" || true
    done
else
    # Run all targets for all crates
    echo "Running all fuzz targets (${DEFAULT_TIME}s each)..."
    echo ""
    for crate in "${STUDY_CRATES[@]}"; do
        mapfile -t targets < <(list_fuzz_targets "$crate")
        if [ ${#targets[@]} -eq 0 ]; then
            echo "Skipping $crate: no fuzz targets discovered"
            echo ""
            continue
        fi
        for target in "${targets[@]}"; do
            run_fuzz_target "$crate" "$target" "$DEFAULT_TIME" || true
        done
    done
fi

echo "════════════════════════════════════════════════════"
echo "  Fuzzing complete. Check $FINDINGS_DIR/ for results."
echo "════════════════════════════════════════════════════"
