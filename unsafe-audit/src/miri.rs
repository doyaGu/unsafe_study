use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;
use std::time::Instant;

use crate::models::{MiriResult, MiriRun, MiriScope, MiriUbCategory, MiriVerdict};

// =========================================================================
// Phase 2: Miri — run `cargo miri test` and parse output for UB
// =========================================================================

pub fn run_miri(crate_dir: &Path, miri_flags: &str, log_path: &Path) -> Result<MiriResult> {
    let strict = run_miri_once(crate_dir, miri_flags, log_path)?;
    Ok(result_from_runs(strict, None))
}

pub fn run_miri_with_triage(
    crate_dir: &Path,
    strict_flags: &str,
    baseline_flags: &str,
    strict_log_path: &Path,
    baseline_log_path: &Path,
) -> Result<MiriResult> {
    let strict = run_miri_once(crate_dir, strict_flags, strict_log_path)?;
    let baseline = if strict.ub_detected {
        Some(run_miri_once(crate_dir, baseline_flags, baseline_log_path)?)
    } else {
        None
    };
    Ok(result_from_runs(strict, baseline))
}

fn run_miri_once(crate_dir: &Path, miri_flags: &str, log_path: &Path) -> Result<MiriRun> {
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
    let (ub_detected, ub_category, ub_message, ub_location) = extract_ub(&combined);

    Ok(MiriRun {
        flags: miri_flags.to_string(),
        passed,
        tests_run,
        tests_passed,
        tests_failed,
        ub_detected,
        ub_category,
        ub_message,
        ub_location,
        log_path: log_path.to_path_buf(),
        duration_secs: duration,
    })
}

fn result_from_runs(strict: MiriRun, baseline: Option<MiriRun>) -> MiriResult {
    let verdict = classify_verdict(&strict, baseline.as_ref());
    let triage_summary = summarize_triage(&strict, baseline.as_ref(), verdict);
    let duration_secs = strict.duration_secs
        + baseline
            .as_ref()
            .map(|run| run.duration_secs)
            .unwrap_or(0.0);

    MiriResult {
        scope: MiriScope::FullSuite,
        verdict,
        triage_summary,
        passed: strict.passed,
        tests_run: strict.tests_run,
        tests_passed: strict.tests_passed,
        tests_failed: strict.tests_failed,
        ub_detected: strict.ub_detected,
        ub_category: strict.ub_category,
        ub_message: strict.ub_message.clone(),
        ub_location: strict.ub_location.clone(),
        log_path: strict.log_path.clone(),
        duration_secs,
        strict,
        baseline,
    }
}

fn classify_verdict(strict: &MiriRun, baseline: Option<&MiriRun>) -> MiriVerdict {
    if strict.passed && !strict.ub_detected {
        return MiriVerdict::Clean;
    }

    if !strict.ub_detected {
        return MiriVerdict::FailedNoUb;
    }

    match baseline {
        Some(baseline) if baseline.ub_detected => MiriVerdict::TruePositiveUb,
        Some(baseline) if baseline.passed => MiriVerdict::StrictOnlySuspectedFalsePositive,
        Some(_) => MiriVerdict::Inconclusive,
        None => MiriVerdict::Inconclusive,
    }
}

fn summarize_triage(
    strict: &MiriRun,
    baseline: Option<&MiriRun>,
    verdict: MiriVerdict,
) -> Option<String> {
    match (strict.ub_detected, baseline, verdict) {
        (false, _, MiriVerdict::Clean) => Some(
            "Strict Miri completed without a UB signal on the exercised test paths.".into(),
        ),
        (false, _, MiriVerdict::FailedNoUb) => {
            Some("Strict Miri failed without an extracted UB signal.".into())
        }
        (true, Some(baseline), MiriVerdict::TruePositiveUb) => Some(format!(
            "Strict and baseline Miri both reported UB; strict={} baseline={}.",
            category_or_dash(strict.ub_category),
            category_or_dash(baseline.ub_category)
        )),
        (true, Some(_), MiriVerdict::StrictOnlySuspectedFalsePositive) => Some(
            "Strict Miri reported UB, but the baseline rerun completed without a UB signal."
                .into(),
        ),
        (true, Some(_), MiriVerdict::Inconclusive) => Some(
            "Strict Miri reported UB, but the baseline rerun did not cleanly confirm or dismiss it."
                .into(),
        ),
        (true, None, MiriVerdict::Inconclusive) => Some(
            "Strict Miri reported UB and no baseline rerun was recorded for comparison.".into(),
        ),
        _ => None,
    }
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
    let prefix = line[..pos].trim_end();
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

fn extract_ub(output: &str) -> (bool, Option<MiriUbCategory>, Option<String>, Option<String>) {
    let mut ub_detected = false;
    let mut ub_category = None;
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
            ub_category = classify_ub_category(&lower);
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

    (ub_detected, ub_category, ub_message, ub_location)
}

fn classify_ub_category(line: &str) -> Option<MiriUbCategory> {
    if line.contains("alignment") {
        Some(MiriUbCategory::Alignment)
    } else if line.contains("stacked borrow") || line.contains("provenance") || line.contains("retag") {
        Some(MiriUbCategory::Provenance)
    } else if line.contains("out-of-bounds") || line.contains("out of bounds") {
        Some(MiriUbCategory::OutOfBounds)
    } else if line.contains("uninitialized") {
        Some(MiriUbCategory::Uninitialized)
    } else if line.contains("undefined behavior") || line.contains("data race") {
        Some(MiriUbCategory::Other)
    } else {
        None
    }
}

fn category_or_dash(category: Option<MiriUbCategory>) -> String {
    category
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn run(passed: bool, ub_detected: bool) -> MiriRun {
        MiriRun {
            flags: String::new(),
            passed,
            tests_run: None,
            tests_passed: None,
            tests_failed: None,
            ub_detected,
            ub_category: if ub_detected {
                Some(MiriUbCategory::Other)
            } else {
                None
            },
            ub_message: None,
            ub_location: None,
            log_path: PathBuf::from("miri.log"),
            duration_secs: 0.0,
        }
    }

    #[test]
    fn parses_clean_test_summary() {
        let output = "test result: ok. 3 passed; 0 failed; 1 ignored";

        assert_eq!(parse_test_summary(output), (Some(3), Some(3), Some(0)));
    }

    #[test]
    fn extracts_ub_and_location() {
        let output = "error: Undefined Behavior: out-of-bounds pointer use\n --> src/lib.rs:10:5";

        let (ub, category, message, location) = extract_ub(output);

        assert!(ub);
        assert_eq!(category, Some(MiriUbCategory::OutOfBounds));
        assert_eq!(
            message.as_deref(),
            Some("error: Undefined Behavior: out-of-bounds pointer use")
        );
        assert_eq!(location.as_deref(), Some("src/lib.rs:10:5"));
    }

    #[test]
    fn classifies_alignment_and_provenance_categories() {
        let alignment = "error: Undefined Behavior: accessing memory based on pointer with alignment 1";
        let provenance = "error: Undefined Behavior: trying to retag from <908696> for SharedReadOnly permission";

        let (_, alignment_category, _, _) = extract_ub(alignment);
        let (_, provenance_category, _, _) = extract_ub(provenance);

        assert_eq!(alignment_category, Some(MiriUbCategory::Alignment));
        assert_eq!(
            classify_ub_category("stacked borrow violation"),
            Some(MiriUbCategory::Provenance)
        );
        assert_eq!(provenance_category, Some(MiriUbCategory::Provenance));
    }

    #[test]
    fn classifies_miri_verdicts() {
        assert_eq!(
            classify_verdict(&run(true, false), None),
            MiriVerdict::Clean
        );
        assert_eq!(
            classify_verdict(&run(false, false), None),
            MiriVerdict::FailedNoUb
        );
        assert_eq!(
            classify_verdict(&run(false, true), Some(&run(false, true))),
            MiriVerdict::TruePositiveUb
        );
        assert_eq!(
            classify_verdict(&run(false, true), Some(&run(true, false))),
            MiriVerdict::StrictOnlySuspectedFalsePositive
        );
        assert_eq!(
            classify_verdict(&run(false, true), Some(&run(false, false))),
            MiriVerdict::Inconclusive
        );
    }
}
