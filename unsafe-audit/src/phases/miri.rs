use anyhow::Result;
use std::collections::BTreeMap;
use std::path::Path;

use crate::domain::{
    CommandInvocation, MiriResult, MiriRun, MiriScope, MiriUbCategory, MiriVerdict,
};
use crate::infra::{CommandRunner, CommandSpec};

pub fn run(
    crate_dir: &Path,
    scope: MiriScope,
    harness_dir: Option<&Path>,
    cargo_args: &[String],
    miri_flags: &str,
    log_path: &Path,
) -> Result<MiriResult> {
    let invocation = invocation(crate_dir, harness_dir, cargo_args);
    let primary_run = run_once(&invocation, miri_flags, log_path)?;
    Ok(result_from_runs(scope, invocation, primary_run, None))
}

pub fn run_with_triage(
    crate_dir: &Path,
    scope: MiriScope,
    harness_dir: Option<&Path>,
    cargo_args: &[String],
    strict_flags: &str,
    baseline_flags: &str,
    strict_log_path: &Path,
    baseline_log_path: &Path,
) -> Result<MiriResult> {
    let invocation = invocation(crate_dir, harness_dir, cargo_args);
    let primary_run = run_once(&invocation, strict_flags, strict_log_path)?;
    let baseline_run = if primary_run.ub_detected {
        Some(run_once(&invocation, baseline_flags, baseline_log_path)?)
    } else {
        None
    };
    Ok(result_from_runs(
        scope,
        invocation,
        primary_run,
        baseline_run,
    ))
}

fn invocation(
    crate_dir: &Path,
    harness_dir: Option<&Path>,
    cargo_args: &[String],
) -> CommandInvocation {
    let args = if cargo_args.is_empty() {
        vec!["miri".into(), "test".into()]
    } else {
        cargo_args.to_vec()
    };
    CommandInvocation {
        working_dir: harness_dir.unwrap_or(crate_dir).to_path_buf(),
        args,
    }
}

fn run_once(invocation: &CommandInvocation, miri_flags: &str, log_path: &Path) -> Result<MiriRun> {
    let mut env = BTreeMap::new();
    env.insert("MIRIFLAGS".into(), miri_flags.to_string());
    let (execution, combined) = CommandRunner::run(&CommandSpec {
        program: "cargo".into(),
        args: invocation.args.clone(),
        env,
        current_dir: invocation.working_dir.clone(),
        log_path: log_path.to_path_buf(),
    })?;
    let (tests_run, tests_passed, tests_failed) = parse_test_summary(&combined);
    let (ub_detected, ub_category, ub_message, ub_location) = extract_ub(&combined);

    Ok(MiriRun {
        flags: miri_flags.to_string(),
        execution,
        tests_run,
        tests_passed,
        tests_failed,
        ub_detected,
        ub_category,
        ub_message,
        ub_location,
    })
}

fn result_from_runs(
    scope: MiriScope,
    invocation: CommandInvocation,
    primary_run: MiriRun,
    baseline_run: Option<MiriRun>,
) -> MiriResult {
    let verdict = classify_verdict(&primary_run, baseline_run.as_ref());
    let triage_summary = summarize_triage(&primary_run, baseline_run.as_ref(), verdict);
    MiriResult {
        scope,
        invocation,
        verdict,
        triage_summary,
        primary_run,
        baseline_run,
    }
}

fn classify_verdict(strict: &MiriRun, baseline: Option<&MiriRun>) -> MiriVerdict {
    if strict.execution.success && !strict.ub_detected {
        return MiriVerdict::Clean;
    }
    if !strict.ub_detected {
        return MiriVerdict::FailedNoUb;
    }
    match baseline {
        Some(baseline) if baseline.ub_detected => MiriVerdict::TruePositiveUb,
        Some(baseline) if baseline.execution.success => {
            MiriVerdict::StrictOnlySuspectedFalsePositive
        }
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
    } else if line.contains("stacked borrow")
        || line.contains("provenance")
        || line.contains("retag")
    {
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
    use crate::domain::ExecutionOutcome;
    use std::path::PathBuf;

    fn run(success: bool, ub_detected: bool) -> MiriRun {
        MiriRun {
            flags: String::new(),
            execution: ExecutionOutcome {
                success,
                exit_code: None,
                duration_secs: 0.0,
                log_path: PathBuf::from("miri.log"),
                log_excerpt: None,
            },
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
        let alignment =
            "error: Undefined Behavior: accessing memory based on pointer with alignment 1";
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

    #[test]
    fn defaults_invocation_when_no_args_are_provided() {
        let invocation = invocation(Path::new("/crate"), None, &[]);
        assert_eq!(invocation.working_dir, PathBuf::from("/crate"));
        assert_eq!(invocation.args, vec!["miri", "test"]);
    }
}
