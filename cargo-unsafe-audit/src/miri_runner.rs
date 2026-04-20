use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;
use std::time::Instant;

use crate::models::{
    MiriClassification, MiriPassResult, MiriResult,
};

// =========================================================================
// Miri Runner -- two-pass triage protocol
// =========================================================================

const PASS1_FLAGS: &str = "-Zmiri-symbolic-alignment-check -Zmiri-strict-provenance";
const PASS2_FLAGS: &str = "-Zmiri-strict-provenance";

/// Run the two-pass Miri triage on a crate.
pub fn run_miri_triage(
    crate_dir: &Path,
    test_filter: Option<&str>,
    offline: bool,
) -> Result<MiriResult> {
    // Check that Miri is available
    let check = Command::new("cargo")
        .args(&["miri", "--help"])
        .current_dir(crate_dir)
        .output();

    if check.is_err() || !check.unwrap().status.success() {
        bail!("cargo miri is not available. Install with: rustup component add miri");
    }

    // Pass 1: strict + symbolic alignment
    eprintln!("  [Miri] Pass 1 (strict + symbolic alignment)...");
    let pass1 = run_miri_pass(crate_dir, test_filter, PASS1_FLAGS, offline)?;

    if pass1.passed {
        return Ok(MiriResult {
            pass1,
            pass2: None,
            classification: MiriClassification::Clean,
            log_excerpt: String::new(),
        });
    }

    // Pass 1 found UB -- run Pass 2 without symbolic alignment
    eprintln!("  [Miri] Pass 1 found UB. Running Pass 2 (strict only)...");
    let pass2 = run_miri_pass(crate_dir, test_filter, PASS2_FLAGS, offline)?;

    let classification = classify(&pass1, &pass2);
    let excerpt = pass1
        .ub_message
        .as_deref()
        .unwrap_or("")
        .chars()
        .take(500)
        .collect();

    Ok(MiriResult {
        pass1,
        pass2: Some(pass2),
        classification,
        log_excerpt: excerpt,
    })
}

fn run_miri_pass(
    crate_dir: &Path,
    test_filter: Option<&str>,
    miriflags: &str,
    offline: bool,
) -> Result<MiriPassResult> {
    let start = Instant::now();

    let mut args = vec!["miri", "test"];
    if offline {
        args.push("--offline");
    }
    if let Some(filter) = test_filter {
        args.push("--");
        args.push(filter);
    }

    let output = Command::new("cargo")
        .args(&args)
        .current_dir(crate_dir)
        .env("MIRIFLAGS", miriflags)
        .output()
        .context("failed to run `cargo miri test`")?;

    let duration = start.elapsed().as_secs_f64();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}\n{}", stdout, stderr);

    let passed = output.status.success();

    // Parse test counts
    let (tests_run, tests_passed, tests_failed) = parse_test_counts(&combined);

    // Extract UB message
    let ub_message = extract_ub_message(&combined);
    let ub_location = extract_ub_location(&combined);

    Ok(MiriPassResult {
        passed,
        tests_run,
        tests_passed,
        tests_failed,
        ub_message,
        ub_location,
        duration_secs: duration,
    })
}

/// Classify based on two-pass protocol.
fn classify(pass1: &MiriPassResult, pass2: &MiriPassResult) -> MiriClassification {
    if pass1.passed {
        return MiriClassification::Clean;
    }

    if pass2.passed {
        // Pass 1 UB, Pass 2 clean -> suspected FP
        // (Would need code-level audit to confirm, but we flag it)
        return MiriClassification::SuspectedFalsePositive;
    }

    if let (Some(loc1), Some(loc2)) = (&pass1.ub_location, &pass2.ub_location) {
        if loc1 == loc2 {
            // Same UB location in both passes -> true positive
            return MiriClassification::TruePositive;
        }
        // Different locations -> Pass 2 site is a TP, Pass 1 may be FP
        return MiriClassification::TruePositive;
    }

    // Both failed but we can't compare locations
    MiriClassification::TruePositive
}

fn parse_test_counts(output: &str) -> (Option<usize>, Option<usize>, Option<usize>) {
    // Parse "test result: ok. 263 passed; 0 failed; 0 ignored"
    for line in output.lines() {
        if line.contains("test result:") {
            let passed = extract_number_after(line, "passed");
            let failed = extract_number_after(line, "failed");
            let run = passed.unwrap_or(0) + failed.unwrap_or(0);
            if run > 0 {
                return (Some(run), passed, failed);
            }
        }
    }
    (None, None, None)
}

fn extract_number_after(text: &str, keyword: &str) -> Option<usize> {
    if let Some(pos) = text.find(keyword) {
        let before = &text[..pos];
        // Find the number just before the keyword
        let num_str: String = before
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        return num_str.parse().ok();
    }
    None
}

fn extract_ub_message(output: &str) -> Option<String> {
    for line in output.lines() {
        if line.contains("Undefined Behavior") || line.contains("error:") && line.contains("miri") {
            return Some(line.trim().to_string());
        }
    }
    None
}

fn extract_ub_location(output: &str) -> Option<String> {
    // Look for "--> src/foo.rs:line:col"
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-->") {
            return Some(trimmed[3..].trim().to_string());
        }
    }
    None
}
