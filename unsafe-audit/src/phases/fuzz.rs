mod classify;
mod runner;
mod targets;

use anyhow::Result;
use std::path::Path;

use crate::domain::{FuzzScope, FuzzStatus, FuzzTargetResult};
use runner::run_single;
use targets::{
    empty_result, external_harness_dir, list_targets, missing_target_result, select_targets,
};

pub fn run(
    crate_dir: &Path,
    harness_dir: Option<&Path>,
    fuzz_time: u64,
    env_pairs: &[(String, String)],
    selected_targets: &[String],
    budget_label: Option<&str>,
    log_dir: &Path,
) -> Result<Vec<FuzzTargetResult>> {
    let harness_root = harness_dir.unwrap_or(crate_dir);
    let harness_display = external_harness_dir(crate_dir, harness_root);
    let fuzz_workspace = harness_root.join("fuzz");
    if !fuzz_workspace.exists() || !fuzz_workspace.join("Cargo.toml").exists() {
        return Ok(vec![empty_result(
            "(none)",
            FuzzScope::NoneAvailable,
            FuzzStatus::NoFuzzDir,
            harness_display.clone(),
            fuzz_time,
            budget_label,
        )]);
    }

    let discovered_targets = match list_targets(harness_root, log_dir, harness_display.clone()) {
        Ok(targets) => targets,
        Err(result) => return Ok(vec![result]),
    };
    if discovered_targets.is_empty() {
        return Ok(vec![empty_result(
            "(none)",
            FuzzScope::NoneAvailable,
            FuzzStatus::NoTargets,
            harness_display.clone(),
            fuzz_time,
            budget_label,
        )]);
    }

    let selected = select_targets(&discovered_targets, selected_targets);
    let mut results = Vec::new();
    for target in &selected.runnable {
        results.push(run_single(
            harness_root,
            harness_display.clone(),
            target,
            fuzz_time,
            env_pairs,
            budget_label,
            log_dir,
        ));
    }
    for missing in &selected.missing {
        results.push(missing_target_result(
            missing,
            harness_display.clone(),
            fuzz_time,
            budget_label,
        ));
    }
    Ok(results)
}
