use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;
use std::time::Instant;

use crate::models::MiriResult;

// =========================================================================
// Phase 2: Miri — run `cargo miri test` and parse output for UB
// =========================================================================

pub fn run_miri(
    crate_dir: &Path,
    miri_flags: &str,
    log_path: &Path,
) -> Result<MiriResult> {
    let start = Instant::now();

    let output = Command::new("cargo")
        .args(["miri", "test"])
        .current_dir(crate_dir)
        .env("MIRIFLAGS", miri_flags)
        .output()
        .context("running cargo miri test")?;

    let duration = start.elapsed().as_secs_f64();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}\n{}", stdout, stderr);

    std::fs::write(log_path, &combined)?;

    let passed = output.status.success();
    let (tests_run, tests_passed, tests_failed) = parse_test_summary(&combined);
    let (ub_detected, ub_message, ub_location) = extract_ub(&combined);

    Ok(MiriResult {
        passed,
        tests_run,
        tests_passed,
        tests_failed,
        ub_detected,
        ub_message,
        ub_location,
        log_path: log_path.to_path_buf(),
        duration_secs: duration,
    })
}

fn parse_test_summary(output: &str) -> (Option<usize>, Option<usize>, Option<usize>) {
    let mut total_passed = None;
    let mut total_failed = None;

    for line in output.lines() {
        if line.contains("test result:") {
            if let Some(p) = extract_number(line, "passed") {
                total_passed = Some(total_passed.unwrap_or(0) + p);
            }
            if let Some(f) = extract_number(line, "failed") {
                total_failed = Some(total_failed.unwrap_or(0) + f);
            }
        }
    }

    let total_run = match (total_passed, total_failed) {
        (Some(p), Some(f)) => Some(p + f),
        (Some(p), None) => Some(p),
        _ => None,
    };

    (total_run, total_passed, total_failed)
}

fn extract_number(line: &str, keyword: &str) -> Option<usize> {
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

fn extract_ub(output: &str) -> (bool, Option<String>, Option<String>) {
    let mut ub_detected = false;
    let mut ub_message = None;
    let mut ub_location = None;

    for line in output.lines() {
        let lower = line.to_lowercase();
        if !ub_detected
            && (lower.contains("undefined behavior")
                || lower.contains("stacked borrow")
                || lower.contains("pointer being freed")
                || lower.contains("out-of-bounds")
                || lower.contains("data race"))
        {
            ub_detected = true;
            ub_message = Some(line.trim().to_string());
        }
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
