#!/bin/bash
# run_all.sh — Run the full unsafe-study pipeline: cargo-geiger, Miri, fuzzing, report.
#
# Usage:
#   bash scripts/run_all.sh [OPTIONS]
#
# Options:
#   --crates CRATE1,CRATE2   Comma-separated crate names (default: auto-detect)
#   --fuzz-time SECONDS      Seconds per fuzz target (default: 3600)
#   --skip-geiger            Skip cargo-geiger phase
#   --skip-miri              Skip Miri phase
#   --skip-fuzz              Skip fuzzing phase
#   --report PATH            Output report path (default: report/study_report.md)

set -euo pipefail

# ── Parse arguments ────────────────────────────────────────────────────────
TARGET_CRATES=()
FUZZ_TIME=3600
SKIP_GEIGER=false
SKIP_MIRI=false
SKIP_FUZZ=false
REPORT_PATH=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --crates)
            IFS=',' read -ra TARGET_CRATES <<< "$2"
            shift 2
            ;;
        --fuzz-time)
            FUZZ_TIME="$2"
            shift 2
            ;;
        --skip-geiger)
            SKIP_GEIGER=true
            shift
            ;;
        --skip-miri)
            SKIP_MIRI=true
            shift
            ;;
        --skip-fuzz)
            SKIP_FUZZ=true
            shift
            ;;
        --report)
            REPORT_PATH="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ── Paths ──────────────────────────────────────────────────────────────────
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGETS_DIR="$PROJECT_ROOT/targets"
GEIGER_DIR="$PROJECT_ROOT/geiger_reports"
MIRI_DIR="$PROJECT_ROOT/miri_reports"
FINDINGS_DIR="$PROJECT_ROOT/fuzz_findings"
CORPUS_DIR="$PROJECT_ROOT/fuzz_corpus"
REPORT_DIR="$PROJECT_ROOT/report"
EXTENSIONS_HARNESS_DIR="$PROJECT_ROOT/extensions_harness"

if [[ -z "$REPORT_PATH" ]]; then
    REPORT_PATH="$REPORT_DIR/study_report.md"
fi

NOW=$(date "+%Y-%m-%d %H:%M:%S")

# ── Discover target crates ─────────────────────────────────────────────────
if [[ ${#TARGET_CRATES[@]} -eq 0 ]]; then
    if [[ -d "$TARGETS_DIR" ]]; then
        for d in "$TARGETS_DIR"/*/; do
            TARGET_CRATES+=("$(basename "$d")")
        done
    fi
fi

if [[ ${#TARGET_CRATES[@]} -eq 0 ]]; then
    echo "ERROR: No target crates found. Clone crates into targets/ or pass --crates."
    exit 1
fi

echo "═══════════════════════════════════════════════════════════"
echo " unsafe_study pipeline"
echo " Date     : $NOW"
echo " Targets  : ${TARGET_CRATES[*]}"
echo " Fuzz time: ${FUZZ_TIME}s per target"
echo "═══════════════════════════════════════════════════════════"

# ── Report accumulator ─────────────────────────────────────────────────────
REPORT_LINES=()
report_add() {
    REPORT_LINES+=("$1")
}
report_section() {
    local heading="$1"
    shift
    report_add ""
    report_add "## $heading"
    report_add ""
    for line in "$@"; do
        report_add "$line"
    done
    report_add ""
}

report_add "# Unsafe Study Report"
report_add ""
report_add "- Generated: $NOW"
report_add "- Crates: ${TARGET_CRATES[*]}"
report_add "- Summary: (pending)"
report_add ""

# ── Associative arrays for results ─────────────────────────────────────────
declare -A GEIGER_RESULTS
declare -A MIRI_RESULTS
declare -A FUZZ_RESULTS
declare -A HARNESS_TEST_FILES=(
    ["memchr"]="more_crates"
    ["winnow"]="more_crates"
    ["toml_parser"]="more_crates"
    ["simd-json"]="simd_json_triage"
    ["quick-xml"]="api_smoke"
    ["goblin"]="api_smoke"
    ["toml_edit"]="api_smoke"
    ["pulldown-cmark"]="api_smoke"
    ["roxmltree"]="api_smoke"
)
declare -A HARNESS_TEST_NAMES=(
    ["memchr"]="memchr_handles_unaligned_public_inputs"
    ["winnow"]="winnow_parses_ascii_and_unicode_boundaries"
    ["toml_parser"]="toml_parser_lexes_and_parses_nested_inputs"
    ["simd-json"]="simd_json_borrowed_value_parses_object_with_strings"
    ["quick-xml"]="quick_xml_streams_events"
    ["goblin"]="goblin_parses_minimal_object_bytes"
    ["toml_edit"]="toml_edit_parses_and_mutates_document"
    ["pulldown-cmark"]="pulldown_cmark_renders_html"
    ["roxmltree"]="roxmltree_builds_tree"
)

# ══════════════════════════════════════════════════════════════════════════
# PHASE 2: Cargo-Geiger
# ══════════════════════════════════════════════════════════════════════════
if [[ "$SKIP_GEIGER" == "false" ]]; then
    echo ""
    echo "──── Phase 2: cargo-geiger ────"
    mkdir -p "$GEIGER_DIR"

    if ! cargo geiger --help > /dev/null 2>&1; then
        echo "  cargo-geiger is not installed; marking geiger phase as unavailable"
        for crate in "${TARGET_CRATES[@]}"; do
            GEIGER_RESULTS[$crate]="MISSING TOOL"
        done
    else
        for crate in "${TARGET_CRATES[@]}"; do
            crate_dir="$TARGETS_DIR/$crate"
            if [[ ! -d "$crate_dir" ]]; then
                echo "  WARNING: Crate directory not found: $crate_dir — skipping geiger"
                continue
            fi

            json_out="$GEIGER_DIR/$crate.json"
            text_out="$GEIGER_DIR/$crate.txt"

            echo "  [$crate] Running cargo geiger..."
            pushd "$crate_dir" > /dev/null

            if cargo geiger --output-format Json > "$json_out" 2>&1; then
                GEIGER_RESULTS[$crate]="OK"
            else
                GEIGER_RESULTS[$crate]="FAILED"
                echo "  [$crate] Geiger failed (JSON)"
            fi

            cargo geiger > "$text_out" 2>&1 || true

            echo "  [$crate] Geiger output → $json_out"
            popd > /dev/null
        done
    fi

    geiger_lines=()
    geiger_lines+=("| Crate | Geiger Status | Report |")
    geiger_lines+=("|-------|---------------|--------|")
    for crate in "${TARGET_CRATES[@]}"; do
        status="${GEIGER_RESULTS[$crate]:-SKIPPED}"
        geiger_lines+=("| $crate | $status | geiger_reports/$crate.json |")
    done
    report_section "Phase 2: Hotspot Mining (cargo-geiger)" "${geiger_lines[@]}"
fi

# ══════════════════════════════════════════════════════════════════════════
# PHASE 3: Miri
# ══════════════════════════════════════════════════════════════════════════
if [[ "$SKIP_MIRI" == "false" ]]; then
    echo ""
    echo "──── Phase 3: Miri ────"
    mkdir -p "$MIRI_DIR"

    export MIRIFLAGS="-Zmiri-symbolic-alignment-check -Zmiri-strict-provenance"

    for crate in "${TARGET_CRATES[@]}"; do
        crate_dir="$TARGETS_DIR/$crate"
        if [[ ! -d "$crate_dir" ]]; then
            echo "  WARNING: Crate directory not found: $crate_dir — skipping Miri"
            continue
        fi
        log_file="$MIRI_DIR/$crate.log"
        test_file="${HARNESS_TEST_FILES[$crate]:-}"
        test_name="${HARNESS_TEST_NAMES[$crate]:-}"

        if [[ -n "$test_file" && -n "$test_name" ]]; then
            echo "  [$crate] Running targeted cargo miri test via extensions_harness..."
            pushd "$EXTENSIONS_HARNESS_DIR" > /dev/null

            if cargo miri test --test "$test_file" "$test_name" -- --exact > "$log_file" 2>&1; then
                MIRI_RESULTS[$crate]="CLEAN"
                echo "  [$crate] Miri clean"
            else
                exit_code=$?
                MIRI_RESULTS[$crate]="UB DETECTED (exit $exit_code)"
                echo "  [$crate] Miri found issues — see $log_file"
            fi
        else
            echo "  [$crate] Running cargo miri test..."
            pushd "$crate_dir" > /dev/null

            if cargo miri test > "$log_file" 2>&1; then
                MIRI_RESULTS[$crate]="CLEAN"
                echo "  [$crate] Miri clean"
            else
                exit_code=$?
                MIRI_RESULTS[$crate]="UB DETECTED (exit $exit_code)"
                echo "  [$crate] Miri found issues — see $log_file"
            fi
        fi

        popd > /dev/null
    done

    miri_lines=()
    miri_lines+=("| Crate | Miri Result | Log |")
    miri_lines+=("|-------|-------------|-----|")
    for crate in "${TARGET_CRATES[@]}"; do
        status="${MIRI_RESULTS[$crate]:-SKIPPED}"
        miri_lines+=("| $crate | $status | miri_reports/$crate.log |")
    done
    miri_lines+=("")
    miri_lines+=("MIRIFLAGS: \`-Zmiri-symbolic-alignment-check -Zmiri-strict-provenance\`")
    report_section "Phase 3: Miri Testing" "${miri_lines[@]}"
fi

# ══════════════════════════════════════════════════════════════════════════
# PHASE 4: Fuzzing
# ══════════════════════════════════════════════════════════════════════════
if [[ "$SKIP_FUZZ" == "false" ]]; then
    echo ""
    echo "──── Phase 4: Fuzzing ────"
    mkdir -p "$FINDINGS_DIR"
    export CARGO_NET_OFFLINE=true
    export ASAN_OPTIONS="detect_odr_violation=0:detect_leaks=0"

    for crate in "${TARGET_CRATES[@]}"; do
        crate_dir="$TARGETS_DIR/$crate"
        if [[ ! -d "$crate_dir" ]]; then
            echo "  WARNING: Crate directory not found: $crate_dir — skipping fuzz"
            continue
        fi

        fuzz_dir="$crate_dir/fuzz"
        if [[ ! -d "$fuzz_dir" ]]; then
            echo "  [$crate] No fuzz/ directory — skipping"
            FUZZ_RESULTS[$crate]="NO FUZZ DIR"
            continue
        fi

        pushd "$crate_dir" > /dev/null

        # Discover fuzz targets
        targets_list=$(cargo fuzz list 2>/dev/null || echo "")
        if [[ -z "$targets_list" ]]; then
            echo "  [$crate] No fuzz targets found"
            FUZZ_RESULTS[$crate]="NO TARGETS"
            popd > /dev/null
            continue
        fi

        crate_findings=""
        while IFS= read -r target; do
            target=$(echo "$target" | tr -d '[:space:]')
            [[ -z "$target" ]] && continue

            echo "  [$crate] Fuzzing target '$target' for ${FUZZ_TIME}s..."
            log_file="$FINDINGS_DIR/${crate}_${target}.log"

            # Copy seed corpus if available
            seed_dir="$CORPUS_DIR/${crate}_${target}"
            if [[ -d "$seed_dir" ]] && [[ "$(ls -A "$seed_dir" 2>/dev/null)" ]]; then
                fuzz_corpus="fuzz/corpus/$target"
                mkdir -p "$fuzz_corpus"
                cp -n "$seed_dir"/* "$fuzz_corpus"/ 2>/dev/null || true
                echo "    Seeded corpus from $seed_dir"
            fi

            if cargo fuzz run "$target" -- -max_total_time="$FUZZ_TIME" > "$log_file" 2>&1; then
                crate_findings+="$target: clean; "
                echo "  [$crate/$target] Clean run"
            else
                if rg -q 'failed to build fuzz script|failed to get `libfuzzer-sys`|download of config.json failed' "$log_file"; then
                    crate_findings+="$target: BUILD FAILED; "
                    echo "  [$crate/$target] Fuzz build failed — see $log_file"
                else
                    crate_findings+="$target: CRASH; "
                    echo "  [$crate/$target] Crash found — see $log_file"
                fi

                # Copy artifacts
                artifacts_dir="fuzz/artifacts/$target"
                if [[ -d "$artifacts_dir" ]] && [[ "$(ls -A "$artifacts_dir" 2>/dev/null)" ]]; then
                    mkdir -p "$FINDINGS_DIR/$crate"
                    cp "$artifacts_dir"/* "$FINDINGS_DIR/$crate/" 2>/dev/null || true
                fi
            fi
        done <<< "$targets_list"

        FUZZ_RESULTS[$crate]="${crate_findings:-NO RESULTS}"
        popd > /dev/null
    done

    fuzz_lines=()
    fuzz_lines+=("| Crate | Fuzz Results |")
    fuzz_lines+=("|-------|-------------|")
    for crate in "${TARGET_CRATES[@]}"; do
        status="${FUZZ_RESULTS[$crate]:-SKIPPED}"
        fuzz_lines+=("| $crate | $status |")
    done
    fuzz_lines+=("")
    fuzz_lines+=("Time budget per target: ${FUZZ_TIME}s")
    report_section "Phase 4: Fuzzing" "${fuzz_lines[@]}"
fi

# ══════════════════════════════════════════════════════════════════════════
# PHASE 5: Summary & Write Report
# ══════════════════════════════════════════════════════════════════════════
echo ""
echo "──── Phase 5: Writing report ────"

summary_lines=()
summary_lines+=("| Crate | Geiger | Miri | Fuzz |")
summary_lines+=("|-------|--------|------|------|")
for crate in "${TARGET_CRATES[@]}"; do
    g="${GEIGER_RESULTS[$crate]:-—}"
    m="${MIRI_RESULTS[$crate]:-—}"
    f="${FUZZ_RESULTS[$crate]:-—}"
    summary_lines+=("| $crate | $g | $m | $f |")
done
report_section "Cross-Crate Summary" "${summary_lines[@]}"

# Update summary line
REPORT_LINES[4]="- Summary: ${#TARGET_CRATES[@]} crates processed"

# Write report
mkdir -p "$(dirname "$REPORT_PATH")"
printf '%s\n' "${REPORT_LINES[@]}" > "$REPORT_PATH"
echo "Report written to $REPORT_PATH"
echo ""
echo "═══════════════════════════════════════════════════════════"
echo " Done. ${#TARGET_CRATES[@]} crates processed."
echo "═══════════════════════════════════════════════════════════"
