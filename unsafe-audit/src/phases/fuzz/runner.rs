use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::domain::{ExecutionOutcome, FuzzScope, FuzzStatus, FuzzTargetResult};
use crate::infra::{CommandRunner, CommandSpec};

use super::classify::{classify, parse_stats};

#[derive(Debug, Serialize)]
struct FuzzRunningState {
    target: String,
    harness_root: String,
    log_path: String,
    requested_time_budget_secs: u64,
    budget_label: Option<String>,
    started_at: String,
}

pub(super) fn run_single(
    harness_root: &Path,
    harness_dir: Option<PathBuf>,
    target: &str,
    fuzz_time: u64,
    env_pairs: &[(String, String)],
    budget_label: Option<&str>,
    log_dir: &Path,
) -> FuzzTargetResult {
    let mut env = BTreeMap::new();
    for (key, value) in env_pairs {
        env.insert(key.clone(), value.clone());
    }

    let log_path = log_dir.join(format!("{target}.log"));
    let running_path = log_dir.join("running.json");
    let spec = CommandSpec {
        program: "cargo".into(),
        args: vec![
            "fuzz".into(),
            "run".into(),
            target.into(),
            "--".into(),
            format!("-max_total_time={fuzz_time}"),
        ],
        env,
        current_dir: harness_root.to_path_buf(),
        log_path: log_path.clone(),
    };
    let _ = std::fs::write(
        &running_path,
        serde_json::to_string_pretty(&FuzzRunningState {
            target: target.to_string(),
            harness_root: harness_root.display().to_string(),
            log_path: log_path.display().to_string(),
            requested_time_budget_secs: fuzz_time,
            budget_label: budget_label.map(ToOwned::to_owned),
            started_at: chrono::Local::now().to_rfc3339(),
        })
        .unwrap_or_else(|_| "{}".into()),
    );

    let result = match CommandRunner::run(&spec) {
        Ok((execution, combined)) => {
            let (status, artifact_path) =
                classify(execution.success, &combined, harness_root, target);
            let (total_runs, edges_covered) = parse_stats(&combined);
            let reproducer_size = artifact_path
                .as_ref()
                .and_then(|p| std::fs::metadata(p).ok())
                .map(|m| m.len());

            FuzzTargetResult {
                target_name: target.to_string(),
                scope: FuzzScope::ExistingHarness,
                status,
                harness_dir: harness_dir.clone(),
                execution: Some(execution),
                requested_time_budget_secs: fuzz_time,
                budget_label: budget_label.map(ToOwned::to_owned),
                environment_overrides: env_pairs
                    .iter()
                    .map(|(key, value)| format!("{key}={value}"))
                    .collect(),
                total_runs,
                edges_covered,
                artifact_path,
                reproducer_size_bytes: reproducer_size,
            }
        }
        Err(error) => FuzzTargetResult {
            target_name: target.to_string(),
            scope: FuzzScope::ExistingHarness,
            status: FuzzStatus::Error,
            harness_dir,
            execution: Some(ExecutionOutcome {
                success: false,
                exit_code: None,
                duration_secs: 0.0,
                log_path,
                log_excerpt: Some(error.to_string()),
            }),
            requested_time_budget_secs: fuzz_time,
            budget_label: budget_label.map(ToOwned::to_owned),
            environment_overrides: env_pairs
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect(),
            total_runs: None,
            edges_covered: None,
            artifact_path: None,
            reproducer_size_bytes: None,
        },
    };
    let _ = std::fs::remove_file(&running_path);
    result
}
