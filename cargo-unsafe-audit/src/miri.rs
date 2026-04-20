use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use crate::models::{MiriMode, MiriResult};

// =========================================================================
// Phase 2: Miri -- direct mode or extensions_harness mode
// =========================================================================

/// Mapping from Tier 2 crate names to (test_file, test_name) in extensions_harness.
const TIER2_HARNESS_MAP: &[(&str, &str, &str)] = &[
    ("memchr",         "more_crates",       "memchr_handles_unaligned_public_inputs"),
    ("winnow",         "more_crates",       "winnow_parses_ascii_and_unicode_boundaries"),
    ("toml_parser",    "more_crates",       "toml_parser_lexes_and_parses_nested_inputs"),
    ("simd-json",      "simd_json_triage",  "simd_json_borrowed_value_parses_object_with_strings"),
    ("quick-xml",      "api_smoke",         "quick_xml_streams_events"),
    ("goblin",         "api_smoke",         "goblin_parses_minimal_object_bytes"),
    ("toml_edit",      "api_smoke",         "toml_edit_parses_and_mutates_document"),
    ("pulldown-cmark", "api_smoke",         "pulldown_cmark_renders_html"),
    ("roxmltree",      "api_smoke",         "roxmltree_builds_tree"),
];

/// Determine if a crate has a harness mapping (Tier 2).
pub fn harness_for(crate_name: &str) -> Option<(&'static str, &'static str)> {
    TIER2_HARNESS_MAP
        .iter()
        .find(|(name, _, _)| *name == crate_name)
        .map(|(_, file, test)| (*file, *test))
}

/// Find the extensions_harness directory by walking up from the crate dir.
/// Looks for a sibling `extensions_harness/` directory.
pub fn find_extensions_harness(crate_dir: &Path) -> Option<PathBuf> {
    // crate_dir is typically <project>/targets/<crate>
    // extensions_harness is at <project>/extensions_harness/
    let parent = crate_dir.parent()?; // targets/
    let project_root = parent.parent()?; // project root
    let harness_dir = project_root.join("extensions_harness");
    if harness_dir.join("Cargo.toml").exists() {
        Some(harness_dir)
    } else {
        None
    }
}

/// Run Miri on a crate. Uses harness mode for Tier 2 crates (if harness exists),
/// otherwise falls back to direct `cargo miri test`.
pub fn run_miri(
    crate_name: &str,
    crate_dir: &Path,
    miri_log_dir: &Path,
) -> Result<MiriResult> {
    if let Some((test_file, test_name)) = harness_for(crate_name) {
        if let Some(harness_dir) = find_extensions_harness(crate_dir) {
            return run_miri_harness(
                crate_name,
                &harness_dir,
                test_file,
                test_name,
                miri_log_dir,
            );
        }
    }

    // Fallback: direct mode
    run_miri_direct(crate_name, crate_dir, miri_log_dir)
}

fn run_miri_direct(
    crate_name: &str,
    crate_dir: &Path,
    miri_log_dir: &Path,
) -> Result<MiriResult> {
    let log_path = miri_log_dir.join(format!("{}.log", crate_name));
    let start = Instant::now();

    let output = Command::new("cargo")
        .args(["miri", "test"])
        .current_dir(crate_dir)
        .env("MIRIFLAGS", "-Zmiri-symbolic-alignment-check -Zmiri-strict-provenance")
        .output()
        .context("running cargo miri test")?;

    let duration = start.elapsed().as_secs_f64();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}\n{}", stdout, stderr);

    // Write log
    std::fs::write(&log_path, &combined)?;

    let passed = output.status.success();
    let (tests_run, tests_passed, tests_failed) = parse_test_summary(&combined);
    let (ub_detected, ub_message, ub_location) = extract_ub(&combined);

    Ok(MiriResult {
        mode: MiriMode::Direct,
        passed,
        tests_run,
        tests_passed,
        tests_failed,
        ub_detected,
        ub_message,
        ub_location,
        log_path,
        duration_secs: duration,
    })
}

fn run_miri_harness(
    crate_name: &str,
    harness_dir: &Path,
    test_file: &str,
    test_name: &str,
    miri_log_dir: &Path,
) -> Result<MiriResult> {
    let log_path = miri_log_dir.join(format!("{}.log", crate_name));
    let start = Instant::now();

    let output = Command::new("cargo")
        .args([
            "miri", "test",
            "--test", test_file,
            test_name,
            "--",
            "--exact",
        ])
        .current_dir(harness_dir)
        .env("MIRIFLAGS", "-Zmiri-symbolic-alignment-check -Zmiri-strict-provenance")
        .output()
        .context("running cargo miri test via extensions_harness")?;

    let duration = start.elapsed().as_secs_f64();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}\n{}", stdout, stderr);

    std::fs::write(&log_path, &combined)?;

    let passed = output.status.success();
    let (tests_run, tests_passed, tests_failed) = parse_test_summary(&combined);
    let (ub_detected, ub_message, ub_location) = extract_ub(&combined);

    Ok(MiriResult {
        mode: MiriMode::Harness {
            test_file: test_file.to_string(),
            test_name: test_name.to_string(),
        },
        passed,
        tests_run,
        tests_passed,
        tests_failed,
        ub_detected,
        ub_message,
        ub_location,
        log_path,
        duration_secs: duration,
    })
}

/// Parse "test result: ok. X passed; Y failed; ..." lines.
fn parse_test_summary(output: &str) -> (Option<usize>, Option<usize>, Option<usize>) {
    let mut total_run = None;
    let mut total_passed = None;
    let mut total_failed = None;

    for line in output.lines() {
        if line.contains("test result:") {
            // e.g. "test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out"
            let passed = extract_number(line, "passed");
            let failed = extract_number(line, "failed");
            if let Some(p) = passed {
                total_passed = Some(total_passed.unwrap_or(0) + p);
            }
            if let Some(f) = failed {
                total_failed = Some(total_failed.unwrap_or(0) + f);
            }
        }
    }

    if let (Some(p), Some(f)) = (total_passed, total_failed) {
        total_run = Some(p + f);
    }

    (total_run, total_passed, total_failed)
}

fn extract_number(line: &str, keyword: &str) -> Option<usize> {
    // Find "... X keyword ..."
    let s = line.to_lowercase();
    let pos = s.find(keyword)?;
    let prefix = &line[..pos];
    let num_str: String = prefix
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    num_str.parse().ok()
}

/// Extract UB information from Miri output.
fn extract_ub(output: &str) -> (bool, Option<String>, Option<String>) {
    let mut ub_detected = false;
    let mut ub_message = None;
    let mut ub_location = None;

    for line in output.lines() {
        let lower = line.to_lowercase();
        if lower.contains("undefined behavior")
            || lower.contains("stacked borrow")
            || lower.contains("pointer being freed")
            || lower.contains("out-of-bounds")
            || lower.contains("data race")
        {
            if !ub_detected {
                ub_detected = true;
                ub_message = Some(line.trim().to_string());
            }
        }
        // Miri locations look like: --> src/foo.rs:42:10
        if line.contains("-->") && ub_message.is_some() && ub_location.is_none() {
            ub_location = Some(
                line.split("-->")
                    .nth(1)
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default(),
            );
        }
    }

    (ub_detected, ub_message, ub_location)
}
