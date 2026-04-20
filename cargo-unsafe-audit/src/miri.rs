use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;
use std::time::Instant;

use crate::models::{AuditConfig, HarnessMapping, MiriMode, MiriResult};

// =========================================================================
// Phase 2: Miri
//
// Design:
//   1. Default: `cargo miri test` directly in the crate directory.
//   2. If config specifies a harness_dir, the tool auto-discovers
//      test→crate mappings by scanning tests/*.rs and extracting `use`
//      statements, OR uses explicit harness_map from config.
//   3. No hardcoded crate names, test files, or test names.
// =========================================================================

/// Resolved Miri invocation plan for a single crate.
struct MiriPlan {
    mode: MiriMode,
    miri_flags: String,
}

/// Determine how to run Miri for a given crate.
/// Priority:
///   1. config.miri.harness_map[crate_name] + config.miri.harness_dir
///   2. Auto-discovered mapping from harness_dir/tests/*.rs
///   3. Direct `cargo miri test` in crate directory
fn resolve_plan(crate_name: &str, _crate_dir: &Path, config: &AuditConfig) -> MiriPlan {
    let miri_cfg = &config.miri;
    let flags = miri_cfg.extra_flags.clone();

    // 1. Check explicit harness_map
    if let Some(mapping) = miri_cfg.harness_map.get(crate_name) {
        if let Some(ref harness_dir) = miri_cfg.harness_dir {
            return MiriPlan {
                mode: MiriMode::ExternalTest {
                    harness_dir: harness_dir.clone(),
                    test_file: mapping.test_file.clone(),
                    test_name: mapping.test_name.clone(),
                },
                miri_flags: flags,
            };
        }
    }

    // 2. Check per-crate override
    if let Some(override_cfg) = config.crate_overrides.get(crate_name) {
        if let Some(ref mapping) = override_cfg.miri_harness {
            if let Some(ref harness_dir) = miri_cfg.harness_dir {
                return MiriPlan {
                    mode: MiriMode::ExternalTest {
                        harness_dir: harness_dir.clone(),
                        test_file: mapping.test_file.clone(),
                        test_name: mapping.test_name.clone(),
                    },
                    miri_flags: flags,
                };
            }
        }
    }

    // 3. Auto-discover from harness_dir
    if let Some(ref harness_dir) = miri_cfg.harness_dir {
        if let Some(mapping) = auto_discover_harness_mapping(crate_name, harness_dir) {
            return MiriPlan {
                mode: MiriMode::ExternalTest {
                    harness_dir: harness_dir.clone(),
                    test_file: mapping.test_file,
                    test_name: mapping.test_name,
                },
                miri_flags: flags,
            };
        }
    }

    // 4. Fallback: direct mode
    MiriPlan {
        mode: MiriMode::Direct,
        miri_flags: flags,
    }
}

/// Auto-discover which test in the harness workspace exercises a given crate.
///
/// Strategy: scan all `tests/*.rs` in the harness directory, look for `use <crate_name>`
/// or `use <crate_name>::...` in the source. If exactly one test function is found
/// in a file that uses the crate, map to that file + function.
/// If multiple tests in the same file use the crate, map to the file only (no test_name).
fn auto_discover_harness_mapping(crate_name: &str, harness_dir: &Path) -> Option<HarnessMapping> {
    let tests_dir = harness_dir.join("tests");
    if !tests_dir.is_dir() {
        return None;
    }

    let mut matches: Vec<(String, Vec<String>)> = Vec::new(); // (test_file, [test_names])

    let entries = std::fs::read_dir(&tests_dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let file_name = path.file_stem()?.to_string_lossy().to_string();
        let content = std::fs::read_to_string(&path).ok()?;

        // Check if this file uses the target crate
        let uses_crate = content.lines().any(|line| {
            let trimmed = line.trim();
            // Match `use crate_name::` or `use crate_name;`
            trimmed.starts_with("use ") && {
                let after_use = trimmed.strip_prefix("use ").unwrap_or("");
                after_use.starts_with(&format!("{}:", crate_name.replace('-', "_")))
                    || after_use.starts_with(&format!("{}::", crate_name.replace('-', "_")))
                    || after_use == crate_name.replace('-', "_")
                    || after_use == format!("{};", crate_name.replace('-', "_"))
                    || after_use.starts_with(&format!("{}::", crate_name))
                    || after_use.starts_with(&format!("{}:", crate_name))
                    || after_use == crate_name
            }
        });

        if !uses_crate {
            continue;
        }

        // Extract all #[test] function names from this file
        let test_names = extract_test_names(&content);
        matches.push((file_name, test_names));
    }

    if matches.is_empty() {
        return None;
    }

    // If only one file matches and it has exactly one test, map to that test.
    // Otherwise map to the file only (run all tests in that file).
    if matches.len() == 1 && matches[0].1.len() == 1 {
        Some(HarnessMapping {
            test_file: matches[0].0.clone(),
            test_name: Some(matches[0].1[0].clone()),
        })
    } else if matches.len() == 1 {
        Some(HarnessMapping {
            test_file: matches[0].0.clone(),
            test_name: None,
        })
    } else {
        // Multiple files reference this crate — map to the first one, no specific test
        Some(HarnessMapping {
            test_file: matches[0].0.clone(),
            test_name: None,
        })
    }
}

/// Extract `#[test] fn name()` identifiers from Rust source.
fn extract_test_names(content: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut lines = content.lines().peekable();

    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        if trimmed == "#[test]" || trimmed.starts_with("#[test]") {
            // Next non-empty line should be `fn name(`
            while let Some(next) = lines.peek() {
                let next_trimmed = next.trim();
                if next_trimmed.is_empty() {
                    lines.next();
                    continue;
                }
                if let Some(name) = parse_fn_name(next_trimmed) {
                    names.push(name);
                }
                break;
            }
        }
    }
    names
}

fn parse_fn_name(line: &str) -> Option<String> {
    // "fn foo(" or "async fn foo("
    let after_async = line.strip_prefix("async ").unwrap_or(line);
    let after_fn = after_async.strip_prefix("fn ")?;
    let name: String = after_fn
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

// =========================================================================
// Public API
// =========================================================================

/// Run Miri on a crate according to the configuration.
pub fn run_miri(
    crate_name: &str,
    crate_dir: &Path,
    log_dir: &Path,
    config: &AuditConfig,
) -> Result<MiriResult> {
    let plan = resolve_plan(crate_name, crate_dir, config);

    match &plan.mode {
        MiriMode::Direct => run_miri_direct(crate_name, crate_dir, log_dir, &plan.miri_flags),
        MiriMode::ExternalTest {
            harness_dir,
            test_file,
            test_name,
        } => run_miri_external(
            crate_name,
            harness_dir,
            test_file,
            test_name.as_deref(),
            log_dir,
            &plan.miri_flags,
        ),
    }
}

fn run_miri_direct(
    crate_name: &str,
    crate_dir: &Path,
    log_dir: &Path,
    miri_flags: &str,
) -> Result<MiriResult> {
    let log_path = log_dir.join(format!("{}.log", crate_name));
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

fn run_miri_external(
    crate_name: &str,
    harness_dir: &Path,
    test_file: &str,
    test_name: Option<&str>,
    log_dir: &Path,
    miri_flags: &str,
) -> Result<MiriResult> {
    let log_path = log_dir.join(format!("{}.log", crate_name));
    let start = Instant::now();

    // Build the command
    let mut args: Vec<String> = vec![
        "miri".into(),
        "test".into(),
        "--test".into(),
        test_file.into(),
    ];
    if let Some(name) = test_name {
        args.push(name.into());
        args.push("--".into());
        args.push("--exact".into());
    }

    let output = Command::new("cargo")
        .args(&args)
        .current_dir(harness_dir)
        .env("MIRIFLAGS", miri_flags)
        .output()
        .context("running cargo miri test in external harness")?;

    let duration = start.elapsed().as_secs_f64();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}\n{}", stdout, stderr);

    std::fs::write(&log_path, &combined)?;

    let passed = output.status.success();
    let (tests_run, tests_passed, tests_failed) = parse_test_summary(&combined);
    let (ub_detected, ub_message, ub_location) = extract_ub(&combined);

    Ok(MiriResult {
        mode: MiriMode::ExternalTest {
            harness_dir: harness_dir.to_path_buf(),
            test_file: test_file.to_string(),
            test_name: test_name.map(String::from),
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

// =========================================================================
// Output parsing
// =========================================================================

fn parse_test_summary(output: &str) -> (Option<usize>, Option<usize>, Option<usize>) {
    let mut total_passed = None;
    let mut total_failed = None;

    for line in output.lines() {
        if line.contains("test result:") {
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

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_test_names() {
        let src = r#"
use memchr::memmem;

#[test]
fn memchr_handles_unaligned() {
    // ...
}

#[test]
fn memchr_finds_pattern() {
    // ...
}
"#;
        let names = extract_test_names(src);
        assert_eq!(names, vec!["memchr_handles_unaligned", "memchr_finds_pattern"]);
    }

    #[test]
    fn test_auto_discover() {
        // Create a temporary harness dir
        let tmp = std::env::temp_dir().join("unsafe_audit_test_harness");
        let tests = tmp.join("tests");
        std::fs::create_dir_all(&tests).unwrap();

        std::fs::write(
            tests.join("more_crates.rs"),
            r#"
use memchr::memmem;

#[test]
fn memchr_handles_unaligned_public_inputs() {
    let finder = memmem::Finder::new(b"foo");
    assert!(true);
}
"#,
        )
        .unwrap();

        let mapping = auto_discover_harness_mapping("memchr", &tmp);
        assert!(mapping.is_some());
        let m = mapping.unwrap();
        assert_eq!(m.test_file, "more_crates");
        assert_eq!(m.test_name, Some("memchr_handles_unaligned_public_inputs".into()));

        // Cleanup
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_auto_discover_hyphenated_crate() {
        let tmp = std::env::temp_dir().join("unsafe_audit_test_harness_hyphen");
        let tests = tmp.join("tests");
        std::fs::create_dir_all(&tests).unwrap();

        std::fs::write(
            tests.join("api_smoke.rs"),
            r#"
use quick_xml::events::Event;
use quick_xml::Reader;

#[test]
fn quick_xml_streams_events() {
    assert!(true);
}
"#,
        )
        .unwrap();

        // Crate name "quick-xml" should be found via "quick_xml" (Rust normalizes - to _)
        let mapping = auto_discover_harness_mapping("quick-xml", &tmp);
        assert!(mapping.is_some());
        assert_eq!(mapping.unwrap().test_file, "api_smoke");

        std::fs::remove_dir_all(&tmp).ok();
    }
}
