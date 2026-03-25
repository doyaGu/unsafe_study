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
FINDINGS_DIR="$PROJECT_ROOT/fuzz_findings"
CORPUS_DIR="$PROJECT_ROOT/fuzz_corpus"
DEFAULT_TIME=3600

# Ensure nightly toolchain is available
TOOLCHAIN="nightly-2026-02-01"
if ! rustup toolchain list | grep -q "$TOOLCHAIN"; then
    echo "Installing $TOOLCHAIN toolchain..."
    rustup toolchain install "$TOOLCHAIN"
    rustup component add rust-src --toolchain "$TOOLCHAIN"
fi

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

    # Initialize fuzz if needed
    if [ ! -d "fuzz" ]; then
        echo "  Initializing cargo-fuzz..."
        cargo +"$TOOLCHAIN" fuzz init
    fi

    # Copy seed corpus if available
    local seed_dir="$CORPUS_DIR/${crate}_${target}"
    if [ -d "$seed_dir" ] && [ "$(ls -A "$seed_dir")" ]; then
        local fuzz_corpus="fuzz/corpus/$target"
        mkdir -p "$fuzz_corpus"
        cp -n "$seed_dir"/* "$fuzz_corpus"/ 2>/dev/null || true
        echo "  Seeded corpus from $seed_dir"
    fi

    export CARGO_NET_OFFLINE=true
    export ASAN_OPTIONS="detect_odr_violation=0:detect_leaks=0"

    # Run the fuzzer
    echo "  Starting fuzzer..."
    cargo +"$TOOLCHAIN" fuzz run "$target" -- -max_total_time="$time_secs" 2>&1 | tee "$log_file"
    local exit_code=${PIPESTATUS[0]}

    if [ $exit_code -ne 0 ]; then
        echo "  CRASH FOUND — check $log_file and fuzz/artifacts/$target/"

        # Copy artifacts to findings directory
        local artifacts_dir="fuzz/artifacts/$target"
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

# Define all fuzz targets (names must match [[bin]] names in fuzz/Cargo.toml)
declare -A FUZZ_TARGETS=(
    ["httparse"]="parse_request parse_response parse_headers parse_chunk_size parse_request_multspaces parse_response_multspaces"
    ["serde_json"]="from_slice from_str"
    ["bstr"]="bstr_fuzz_ops"
    ["memchr"]="memchr_search"
    ["winnow"]="winnow_parse"
    ["toml_parser"]="toml_parser_parse"
    ["simd-json"]="simd_json_parse"
    ["quick-xml"]="quick_xml_read"
    ["goblin"]="goblin_object_parse"
    ["toml_edit"]="toml_edit_parse"
    ["pulldown-cmark"]="pulldown_cmark_parse"
    ["roxmltree"]="roxmltree_parse"
)

if [ $# -ge 2 ]; then
    # Run specific target
    run_fuzz_target "$1" "$2" "${3:-$DEFAULT_TIME}"
elif [ $# -eq 1 ]; then
    # Run all targets for a specific crate
    crate="$1"
    if [ -z "${FUZZ_TARGETS[$crate]+x}" ]; then
        echo "Unknown crate: $crate"
        echo "Available: ${!FUZZ_TARGETS[@]}"
        exit 1
    fi
    for target in ${FUZZ_TARGETS[$crate]}; do
        run_fuzz_target "$crate" "$target" "$DEFAULT_TIME" || true
    done
else
    # Run all targets for all crates
    echo "Running all fuzz targets (${DEFAULT_TIME}s each)..."
    echo ""
    for crate in "${!FUZZ_TARGETS[@]}"; do
        for target in ${FUZZ_TARGETS[$crate]}; do
            run_fuzz_target "$crate" "$target" "$DEFAULT_TIME" || true
        done
    done
fi

echo "════════════════════════════════════════════════════"
echo "  Fuzzing complete. Check $FINDINGS_DIR/ for results."
echo "════════════════════════════════════════════════════"
