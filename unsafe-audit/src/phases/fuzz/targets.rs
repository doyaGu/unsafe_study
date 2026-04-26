use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::domain::{ExecutionOutcome, FuzzScope, FuzzStatus, FuzzTargetResult};
use crate::infra::{CommandRunner, CommandSpec};

pub(super) fn list_targets(
    harness_root: &Path,
    log_dir: &Path,
    harness_dir: Option<PathBuf>,
) -> std::result::Result<Vec<String>, FuzzTargetResult> {
    let spec = CommandSpec {
        program: "cargo".into(),
        args: vec!["fuzz".into(), "list".into()],
        env: BTreeMap::new(),
        current_dir: harness_root.to_path_buf(),
        log_path: log_dir.join("target-list.log"),
    };

    let (execution, combined) = CommandRunner::run(&spec).map_err(|e| {
        let mut result = empty_result(
            "(list)",
            FuzzScope::DiscoveryOnly,
            FuzzStatus::Error,
            harness_dir.clone(),
            0,
            None,
        );
        result.execution = Some(ExecutionOutcome {
            success: false,
            exit_code: None,
            duration_secs: 0.0,
            log_path: spec.log_path.clone(),
            log_excerpt: Some(e.to_string()),
        });
        result
    })?;

    if !execution.success {
        let mut result = empty_result(
            "(list)",
            FuzzScope::DiscoveryOnly,
            FuzzStatus::Error,
            harness_dir,
            0,
            None,
        );
        result.execution = Some(execution);
        return Err(result);
    }

    Ok(combined
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect())
}

pub(super) fn empty_result(
    target_name: &str,
    scope: FuzzScope,
    status: FuzzStatus,
    harness_dir: Option<PathBuf>,
    requested_time_budget_secs: u64,
    budget_label: Option<&str>,
) -> FuzzTargetResult {
    FuzzTargetResult {
        target_name: target_name.into(),
        scope,
        status,
        harness_dir,
        execution: None,
        requested_time_budget_secs,
        budget_label: budget_label.map(ToOwned::to_owned),
        environment_overrides: Vec::new(),
        total_runs: None,
        edges_covered: None,
        artifact_path: None,
        reproducer_size_bytes: None,
    }
}

pub(super) fn missing_target_result(
    target_name: &str,
    harness_dir: Option<PathBuf>,
    requested_time_budget_secs: u64,
    budget_label: Option<&str>,
) -> FuzzTargetResult {
    FuzzTargetResult {
        target_name: target_name.into(),
        scope: FuzzScope::DiscoveryOnly,
        status: FuzzStatus::Error,
        harness_dir,
        execution: Some(ExecutionOutcome {
            success: false,
            exit_code: None,
            duration_secs: 0.0,
            log_path: PathBuf::from(format!("missing:{target_name}")),
            log_excerpt: Some("requested fuzz target was not discovered".into()),
        }),
        requested_time_budget_secs,
        budget_label: budget_label.map(ToOwned::to_owned),
        environment_overrides: Vec::new(),
        total_runs: None,
        edges_covered: None,
        artifact_path: None,
        reproducer_size_bytes: None,
    }
}

pub(super) fn external_harness_dir(crate_dir: &Path, harness_root: &Path) -> Option<PathBuf> {
    if harness_root == crate_dir {
        None
    } else {
        Some(harness_root.to_path_buf())
    }
}

pub(super) struct SelectedTargets {
    pub(super) runnable: Vec<String>,
    pub(super) missing: Vec<String>,
}

pub(super) fn select_targets(
    discovered_targets: &[String],
    selected_targets: &[String],
) -> SelectedTargets {
    if selected_targets.is_empty() {
        return SelectedTargets {
            runnable: discovered_targets.to_vec(),
            missing: Vec::new(),
        };
    }

    let discovered: BTreeSet<_> = discovered_targets.iter().cloned().collect();
    let mut runnable = Vec::new();
    let mut missing = Vec::new();

    for target in selected_targets {
        if discovered.contains(target) {
            runnable.push(target.clone());
        } else {
            missing.push(target.clone());
        }
    }

    SelectedTargets { runnable, missing }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_targets_report_missing_entries() {
        let selected = select_targets(
            &["a".into(), "b".into(), "c".into()],
            &["c".into(), "missing".into(), "a".into()],
        );
        assert_eq!(selected.runnable, vec!["c", "a"]);
        assert_eq!(selected.missing, vec!["missing"]);
    }

    #[test]
    fn external_harness_dir_only_records_nonlocal_root() {
        let crate_dir = Path::new("targets/demo");
        assert!(external_harness_dir(crate_dir, crate_dir).is_none());
        assert_eq!(
            external_harness_dir(crate_dir, Path::new("fuzz_harnesses/demo")).as_deref(),
            Some(Path::new("fuzz_harnesses/demo"))
        );
    }
}
