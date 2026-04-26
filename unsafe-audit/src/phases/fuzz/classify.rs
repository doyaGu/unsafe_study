use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::domain::FuzzStatus;

pub(super) fn classify(
    success: bool,
    combined: &str,
    crate_dir: &Path,
    target: &str,
) -> (FuzzStatus, Option<PathBuf>) {
    let lower = combined.to_lowercase();

    if lower.contains("leaksanitizer")
        && (lower.contains("ptrace") || lower.contains("does not work under ptrace"))
    {
        return (FuzzStatus::EnvironmentError, None);
    }
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
    if !success {
        return (FuzzStatus::Error, find_artifact(crate_dir, target));
    }
    (FuzzStatus::Clean, None)
}

fn find_artifact(crate_dir: &Path, target: &str) -> Option<PathBuf> {
    let dir = crate_dir.join("fuzz").join("artifacts").join(target);
    std::fs::read_dir(&dir)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .max_by_key(|e| {
            e.metadata()
                .and_then(|m| m.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH)
        })
        .map(|e| e.path())
}

pub(super) fn parse_stats(combined: &str) -> (Option<u64>, Option<u64>) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn nonzero_unrecognized_fuzz_output_is_error_not_clean() {
        let (status, artifact) = classify(
            false,
            "libfuzzer exited with status 77",
            Path::new("."),
            "target",
        );
        assert_eq!(status, FuzzStatus::Error);
        assert!(artifact.is_none());
    }

    #[test]
    fn successful_unremarkable_fuzz_output_is_clean() {
        let (status, artifact) = classify(true, "DONE 100 runs", Path::new("."), "target");
        assert_eq!(status, FuzzStatus::Clean);
        assert!(artifact.is_none());
    }

    #[test]
    fn lsan_ptrace_failure_is_environment_error() {
        let (status, artifact) = classify(
            false,
            "LeakSanitizer has encountered a fatal error\nLeakSanitizer does not work under ptrace",
            Path::new("."),
            "target",
        );
        assert_eq!(status, FuzzStatus::EnvironmentError);
        assert!(artifact.is_none());
    }

    #[test]
    fn find_artifact_uses_most_recent_file() {
        let dir = tempfile::tempdir().unwrap();
        let artifact_dir = dir.path().join("fuzz/artifacts/target");
        std::fs::create_dir_all(&artifact_dir).unwrap();
        let old = artifact_dir.join("old");
        let new = artifact_dir.join("new");
        std::fs::write(&old, b"old").unwrap();
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(&new, b"new").unwrap();

        assert_eq!(
            find_artifact(dir.path(), "target").as_deref(),
            Some(new.as_path())
        );
    }
}
