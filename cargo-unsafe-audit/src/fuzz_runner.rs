use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use crate::models::{
    FindingType, FuzzFinding, FuzzResult, FuzzStatus,
};

// =========================================================================
// Fuzz Runner -- orchestrate cargo-fuzz
// =========================================================================

/// Run fuzzing on a single harness.
pub fn run_fuzz(
    crate_dir: &Path,
    harness_name: &str,
    duration_secs: u64,
    corpus_dir: Option<&Path>,
    max_total_time: Option<u64>,
) -> Result<FuzzResult> {
    let fuzz_dir = crate_dir.join("fuzz");
    if !fuzz_dir.exists() {
        bail!("fuzz/ directory not found at {}. Run harness generation first.", fuzz_dir.display());
    }

    let actual_time = max_total_time.unwrap_or(duration_secs);

    // Build the fuzz target first to check for compilation errors
    let build_output = Command::new("cargo")
        .args(&["fuzz", "build", harness_name])
        .current_dir(crate_dir)
        .env("CARGO_NET_OFFLINE", "true")
        .output()
        .context("failed to run `cargo fuzz build`")?;

    if !build_output.status.success() {
        let stderr = String::from_utf8_lossy(&build_output.stderr);
        return Ok(FuzzResult {
            target_name: harness_name.to_string(),
            harness_file: fuzz_dir.join("fuzz_targets").join(format!("{}.rs", harness_name)),
            duration_secs: 0,
            total_runs: None,
            edges_covered: None,
            crashes: 0,
            findings: vec![FuzzFinding {
                finding_type: FindingType::MemorySafety,
                reproducer_path: None,
                reproducer_size: None,
                message: format!("Build failed:\n{}", &stderr[..stderr.len().min(500)]),
            }],
            status: FuzzStatus::BuildFailed,
        });
    }

    // Copy seed corpus if provided
    if let Some(src_corpus) = corpus_dir {
        let dst_corpus = fuzz_dir.join("corpus").join(harness_name);
        let _ = copy_corpus(src_corpus, &dst_corpus);
    }

    // Run the fuzzer
    let start = Instant::now();
    let output = Command::new("cargo")
        .args(&[
            "fuzz", "run", harness_name,
            "--", &format!("-max_total_time={}", actual_time),
        ])
        .current_dir(crate_dir)
        .env("CARGO_NET_OFFLINE", "true")
        .env("ASAN_OPTIONS", "detect_odr_violation=0:detect_leaks=0")
        .output()
        .context("failed to run `cargo fuzz run`")?;

    let elapsed = start.elapsed().as_secs();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}\n{}", stdout, stderr);

    // Parse output
    let total_runs = parse_runs(&combined);
    let edges_covered = parse_edges(&combined);

    // Check for crashes
    let artifacts_dir = fuzz_dir.join("artifacts").join(harness_name);
    let crashes = find_crashes(&artifacts_dir);
    let findings = classify_findings(&combined, &artifacts_dir);

    let status = if !crashes.is_empty() {
        FuzzStatus::CrashFound
    } else if output.status.success() {
        FuzzStatus::Clean
    } else if combined.contains("SUMMARY: AddressSanitizer") || combined.contains("SEGV") {
        FuzzStatus::CrashFound
    } else {
        FuzzStatus::Error
    };

    Ok(FuzzResult {
        target_name: harness_name.to_string(),
        harness_file: fuzz_dir.join("fuzz_targets").join(format!("{}.rs", harness_name)),
        duration_secs: elapsed,
        total_runs,
        edges_covered,
        crashes: findings.iter().filter(|f| matches!(f.finding_type, FindingType::MemorySafety | FindingType::Panic)).count() as u64,
        findings,
        status,
    })
}

/// Run all fuzz targets in a crate.
pub fn run_all_fuzz(
    crate_dir: &Path,
    harness_names: &[String],
    duration_secs: u64,
    corpus_dirs: &std::collections::HashMap<String, PathBuf>,
) -> Result<Vec<FuzzResult>> {
    let mut results = Vec::new();

    for name in harness_names {
        let corpus = corpus_dirs.get(name).map(|p| p.as_path());
        match run_fuzz(crate_dir, name, duration_secs, corpus, None) {
            Ok(result) => {
                let status = result.status;
                results.push(result);
                if status == FuzzStatus::CrashFound {
                    eprintln!("  [!] Crash found in {}", name);
                }
            }
            Err(e) => {
                results.push(FuzzResult {
                    target_name: name.clone(),
                    harness_file: PathBuf::new(),
                    duration_secs: 0,
                    total_runs: None,
                    edges_covered: None,
                    crashes: 0,
                    findings: vec![FuzzFinding {
                        finding_type: FindingType::MemorySafety,
                        reproducer_path: None,
                        reproducer_size: None,
                        message: format!("Error: {}", e),
                    }],
                    status: FuzzStatus::Error,
                });
            }
        }
    }

    Ok(results)
}

// ---------------------------------------------------------------------------
// Output parsing helpers
// ---------------------------------------------------------------------------

fn parse_runs(output: &str) -> Option<u64> {
    // libFuzzer output: "#8192 DONE ..."
    for line in output.lines().rev() {
        if line.contains("DONE") || line.contains("BINGO") || line.contains("NEW") {
            if let Some(hash_pos) = line.find('#') {
                let rest = &line[hash_pos + 1..];
                let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                if let Ok(n) = num_str.parse::<u64>() {
                    return Some(n);
                }
            }
        }
    }
    None
}

fn parse_edges(output: &str) -> Option<u64> {
    // "cov: 1256 ft: 2385"
    for line in output.lines().rev() {
        if line.contains("cov:") {
            if let Some(pos) = line.find("cov:") {
                let rest = &line[pos + 4..];
                let num_str: String = rest.trim().chars().take_while(|c| c.is_ascii_digit()).collect();
                if let Ok(n) = num_str.parse::<u64>() {
                    return Some(n);
                }
            }
        }
    }
    None
}

fn find_crashes(artifacts_dir: &Path) -> Vec<PathBuf> {
    if !artifacts_dir.exists() {
        return Vec::new();
    }
    std::fs::read_dir(artifacts_dir)
        .ok()
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.is_file())
                .collect()
        })
        .unwrap_or_default()
}

fn classify_findings(output: &str, artifacts_dir: &Path) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();

    // Check for crash artifacts
    let crashes = find_crashes(artifacts_dir);
    for crash_path in &crashes {
        let size = std::fs::metadata(crash_path).ok().map(|m| m.len());
        let msg = if output.contains("SUMMARY: AddressSanitizer") {
            "AddressSanitizer violation"
        } else if output.contains("SEGV") {
            "Segmentation fault"
        } else if output.contains("SIGABRT") {
            "Abort signal"
        } else {
            "Crash found"
        };
        findings.push(FuzzFinding {
            finding_type: FindingType::MemorySafety,
            reproducer_path: Some(crash_path.clone()),
            reproducer_size: size,
            message: msg.to_string(),
        });
    }

    // Check for panics
    if output.contains("panicked at") {
        let msg = extract_panic_message(output);
        findings.push(FuzzFinding {
            finding_type: FindingType::Panic,
            reproducer_path: crashes.first().cloned(),
            reproducer_size: crashes.first().and_then(|p| std::fs::metadata(p).ok().map(|m| m.len())),
            message: msg,
        });
    }

    // Check for OOM
    if output.contains("out-of-memory") || output.contains("SUMMARY: libFuzzer") && output.contains("oom") {
        findings.push(FuzzFinding {
            finding_type: FindingType::Oom,
            reproducer_path: crashes.first().cloned(),
            reproducer_size: crashes.first().and_then(|p| std::fs::metadata(p).ok().map(|m| m.len())),
            message: "Out of memory".to_string(),
        });
    }

    // Check for timeout
    if output.contains("SUMMARY: libFuzzer") && output.contains("timeout") {
        findings.push(FuzzFinding {
            finding_type: FindingType::Timeout,
            reproducer_path: crashes.first().cloned(),
            reproducer_size: crashes.first().and_then(|p| std::fs::metadata(p).ok().map(|m| m.len())),
            message: "Timeout".to_string(),
        });
    }

    findings
}

fn extract_panic_message(output: &str) -> String {
    for line in output.lines() {
        if line.contains("panicked at") {
            return line.trim().to_string();
        }
    }
    "Panic detected".to_string()
}

fn copy_corpus(src: &Path, dst: &Path) -> Result<()> {
    if !src.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        if src_path.is_file() {
            let file_name = src_path.file_name().unwrap();
            let dst_path = dst.join(file_name);
            if !dst_path.exists() {
                std::fs::copy(&src_path, &dst_path)?;
            }
        }
    }
    Ok(())
}
