use anyhow::Result;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use crate::models::{FuzzStatus, FuzzTargetResult};

// =========================================================================
// Phase 3: Fuzz -- use existing fuzz/ dirs, cargo fuzz list + run
// =========================================================================

/// Run fuzzing on a single crate.
///
/// - Discovers targets via `cargo fuzz list`
/// - Runs each target for `fuzz_time` seconds
/// - Collects artifacts from `fuzz/artifacts/<target>/`
pub fn run_fuzz(
    crate_name: &str,
    crate_dir: &Path,
    fuzz_time: u64,
    log_dir: &Path,
    config: &crate::models::FuzzConfig,
) -> Result<Vec<FuzzTargetResult>> {
    let fuzz_dir = crate_dir.join("fuzz");
    if !fuzz_dir.exists() || !fuzz_dir.join("Cargo.toml").exists() {
        return Ok(vec![FuzzTargetResult {
            target_name: "(none)".into(),
            status: FuzzStatus::NoFuzzDir,
            total_runs: None,
            edges_covered: None,
            duration_secs: 0,
            artifact_path: None,
            reproducer_size_bytes: None,
            log_excerpt: None,
        }]);
    }

    // Discover fuzz targets
    let targets = list_fuzz_targets(crate_dir)?;
    if targets.is_empty() {
        return Ok(vec![FuzzTargetResult {
            target_name: "(none)".into(),
            status: FuzzStatus::NoTargets,
            total_runs: None,
            edges_covered: None,
            duration_secs: 0,
            artifact_path: None,
            reproducer_size_bytes: None,
            log_excerpt: None,
        }]);
    }

    let mut results = Vec::new();
    for target in &targets {
        let result = run_single_fuzz_target(
            crate_name,
            crate_dir,
            target,
            fuzz_time,
            log_dir,
            config,
        );
        results.push(result);
    }

    Ok(results)
}

fn list_fuzz_targets(crate_dir: &Path) -> Result<Vec<String>> {
    let output = Command::new("cargo")
        .args(["fuzz", "list"])
        .current_dir(crate_dir)
        .output()?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let targets: Vec<String> = stdout
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    Ok(targets)
}

fn run_single_fuzz_target(
    crate_name: &str,
    crate_dir: &Path,
    target: &str,
    fuzz_time: u64,
    log_dir: &Path,
    config: &crate::models::FuzzConfig,
) -> FuzzTargetResult {
    let log_path = log_dir.join(format!("{}_{}.log", crate_name, target));
    let start = Instant::now();

    let mut cmd = Command::new("cargo");
    cmd.args([
            "fuzz", "run", target,
            "--",
            &format!("-max_total_time={}", fuzz_time),
        ])
        .current_dir(crate_dir);

    // Apply environment variables from config
    for env_pair in &config.env {
        if let Some((key, value)) = env_pair.split_once('=') {
            cmd.env(key, value);
        }
    }

    let output = cmd.output();

    let duration = start.elapsed().as_secs();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            let combined = format!("{}\n{}", stdout, stderr);

            // Write log
            let _ = std::fs::write(&log_path, &combined);

            let (status, artifact_path) = classify_fuzz_result(&combined, crate_dir, target);
            let (total_runs, edges_covered) = parse_fuzz_stats(&combined);
            let reproducer_size = artifact_path
                .as_ref()
                .and_then(|p| std::fs::metadata(p).ok())
                .map(|m| m.len());

            FuzzTargetResult {
                target_name: target.to_string(),
                status,
                total_runs,
                edges_covered,
                duration_secs: duration,
                artifact_path,
                reproducer_size_bytes: reproducer_size,
                log_excerpt: extract_excerpt(&combined),
            }
        }
        Err(e) => FuzzTargetResult {
            target_name: target.to_string(),
            status: FuzzStatus::Error,
            total_runs: None,
            edges_covered: None,
            duration_secs: duration,
            artifact_path: None,
            reproducer_size_bytes: None,
            log_excerpt: Some(e.to_string()),
        },
    }
}

/// Classify fuzz result from output text.
fn classify_fuzz_result(
    combined: &str,
    crate_dir: &Path,
    target: &str,
) -> (FuzzStatus, Option<PathBuf>) {
    let lower = combined.to_lowercase();

    // Check for build failure first
    if lower.contains("failed to build fuzz script")
        || lower.contains("could not compile")
        || lower.contains("error: could not find")
    {
        return (FuzzStatus::BuildFailed, None);
    }

    // Check for panic
    if lower.contains("panicked") || lower.contains("deadly signal") {
        let artifact = find_artifact(crate_dir, target);
        return (FuzzStatus::Panic, artifact);
    }

    // Check for OOM
    if lower.contains("out of memory") || lower.contains("oom") {
        let artifact = find_artifact(crate_dir, target);
        return (FuzzStatus::Oom, artifact);
    }

    // Check for timeout
    if lower.contains("timeout") {
        let artifact = find_artifact(crate_dir, target);
        return (FuzzStatus::Timeout, artifact);
    }

    // If we got here with non-zero exit, it's a generic crash
    if lower.contains("summary: libfuzzer") && !lower.contains("corpus") {
        let artifact = find_artifact(crate_dir, target);
        if artifact.is_some() {
            return (FuzzStatus::Panic, artifact);
        }
    }

    (FuzzStatus::Clean, None)
}

/// Find crash artifact in fuzz/artifacts/<target>/.
fn find_artifact(crate_dir: &Path, target: &str) -> Option<PathBuf> {
    let artifacts_dir = crate_dir.join("fuzz").join("artifacts").join(target);
    if !artifacts_dir.is_dir() {
        return None;
    }
    std::fs::read_dir(&artifacts_dir)
        .ok()?
        .filter_map(|e| e.ok())
        .find(|e| e.path().is_file())
        .map(|e| e.path())
}

/// Parse libFuzzer stat lines for runs/edges.
fn parse_fuzz_stats(combined: &str) -> (Option<u64>, Option<u64>) {
    let mut total_runs = None;
    let mut edges = None;

    for line in combined.lines() {
        // libFuzzer outputs: "stat: ... number_of_executed_units: ... "
        if line.contains("number_of_executed_units") {
            total_runs = extract_fuzz_number(line, "number_of_executed_units");
        }
        if line.contains("edge_coverage") {
            edges = extract_fuzz_number(line, "edge_coverage");
        }
        // Alternative format: "X runs/s"
        if total_runs.is_none() && line.contains("runs/s") {
            // Try to get total from "cov: X ft: Y corpus: Z"
        }
        // Another format: "#X DONE" or "#X REDUCE"
        if let Some(pos) = line.find("DONE") {
            let prefix = &line[..pos];
            let num: String = prefix
                .chars()
                .rev()
                .take_while(|c| c.is_ascii_digit() || *c == ',')
                .collect::<String>()
                .chars()
                .rev()
                .collect();
            let num = num.replace(',', "");
            if let Ok(n) = num.parse::<u64>() {
                total_runs = Some(n);
            }
        }
    }

    (total_runs, edges)
}

fn extract_fuzz_number(line: &str, keyword: &str) -> Option<u64> {
    let pos = line.find(keyword)?;
    let after = &line[pos + keyword.len()..];
    let num_str: String = after
        .trim_start_matches(|c: char| c == ':' || c == ' ')
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    num_str.parse().ok()
}

fn extract_excerpt(combined: &str) -> Option<String> {
    // Last 500 chars
    if combined.len() > 500 {
        Some(format!("...{}", &combined[combined.len() - 500..]))
    } else if !combined.is_empty() {
        Some(combined.to_string())
    } else {
        None
    }
}
