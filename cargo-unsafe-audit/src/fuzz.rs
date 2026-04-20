use anyhow::Result;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

use crate::models::{FuzzStatus, FuzzTargetResult};

// =========================================================================
// Phase 3: Fuzz — discover and run existing fuzz targets
// =========================================================================

pub fn run_fuzz(
    crate_dir: &Path,
    fuzz_time: u64,
    env_pairs: &[(String, String)],
    log_dir: &Path,
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

    let targets = list_targets(crate_dir)?;
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
        results.push(run_single(crate_dir, target, fuzz_time, env_pairs, log_dir));
    }
    Ok(results)
}

fn list_targets(crate_dir: &Path) -> Result<Vec<String>> {
    let output = Command::new("cargo")
        .args(["fuzz", "list"])
        .current_dir(crate_dir)
        .output()?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    Ok(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect(),
    )
}

fn run_single(
    crate_dir: &Path,
    target: &str,
    fuzz_time: u64,
    env_pairs: &[(String, String)],
    log_dir: &Path,
) -> FuzzTargetResult {
    let log_path = log_dir.join(format!("{}.log", target));
    let start = Instant::now();

    let mut cmd = Command::new("cargo");
    cmd.args(["fuzz", "run", target, "--", &format!("-max_total_time={}", fuzz_time)])
        .current_dir(crate_dir);

    for (key, value) in env_pairs {
        cmd.env(key, value);
    }

    let output = cmd.output();
    let duration = start.elapsed().as_secs();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            let combined = format!("{}\n{}", stdout, stderr);

            let _ = std::fs::write(&log_path, &combined);

            let (status, artifact_path) = classify(&combined, crate_dir, target);
            let (total_runs, edges_covered) = parse_stats(&combined);
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
                log_excerpt: excerpt(&combined),
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

fn classify(combined: &str, crate_dir: &Path, target: &str) -> (FuzzStatus, Option<std::path::PathBuf>) {
    let lower = combined.to_lowercase();

    if lower.contains("could not compile") || lower.contains("error: could not find") {
        return (FuzzStatus::BuildFailed, None);
    }
    if lower.contains("panicked") || lower.contains("deadly signal") {
        return (FuzzStatus::Panic, find_artifact(crate_dir, target));
    }
    if lower.contains("out of memory") || lower.contains("oom") {
        return (FuzzStatus::Oom, find_artifact(crate_dir, target));
    }
    if lower.contains("timeout") {
        return (FuzzStatus::Timeout, find_artifact(crate_dir, target));
    }
    (FuzzStatus::Clean, None)
}

fn find_artifact(crate_dir: &Path, target: &str) -> Option<std::path::PathBuf> {
    let dir = crate_dir.join("fuzz").join("artifacts").join(target);
    std::fs::read_dir(&dir)
        .ok()?
        .filter_map(|e| e.ok())
        .find(|e| e.path().is_file())
        .map(|e| e.path())
}

fn parse_stats(combined: &str) -> (Option<u64>, Option<u64>) {
    let mut total_runs = None;
    let mut edges = None;

    for line in combined.lines() {
        if line.contains("number_of_executed_units") {
            total_runs = extract_fuzz_number(line, "number_of_executed_units");
        }
        if line.contains("edge_coverage") {
            edges = extract_fuzz_number(line, "edge_coverage");
        }
        if total_runs.is_none() {
            if let Some(pos) = line.find("DONE") {
                let num: String = line[..pos]
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

fn excerpt(combined: &str) -> Option<String> {
    if combined.len() > 500 {
        Some(format!("...{}", &combined[combined.len() - 500..]))
    } else if !combined.is_empty() {
        Some(combined.to_string())
    } else {
        None
    }
}
