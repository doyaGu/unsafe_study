use super::shared::append_phase_failures;
use crate::domain::{CrateAuditResult, FuzzScope, FuzzStatus, FuzzTargetResult, PhaseKind};

pub(crate) fn append_fuzz(md: &mut String, crates: &[CrateAuditResult]) {
    let fuzz_crates: Vec<_> = crates.iter().filter(|c| !c.fuzz.is_empty()).collect();
    let fuzz_failures: Vec<_> = crates
        .iter()
        .filter_map(|c| c.phase_issue(PhaseKind::Fuzz).map(|issue| (c, issue)))
        .collect();
    if fuzz_crates.is_empty() && fuzz_failures.is_empty() {
        return;
    }

    md.push_str("## Phase 3: Fuzz\n\n");
    for result in fuzz_crates {
        md.push_str(&format!("### {}\n\n", result.target.display_name()));
        if result.fuzz.len() == 1 && result.fuzz[0].target_name == "(none)" {
            let item = &result.fuzz[0];
            md.push_str(&format!("{}\n\n", item.status));
            md.push_str(&format!(
                "- **Scope:** `{}`\n- **Interpretation:** {}\n- **Status meaning:** {}\n\n",
                item.scope,
                fuzz_scope_note(item),
                fuzz_status_note(item)
            ));
            continue;
        }

        md.push_str(
            "| Target | Scope | Status | Exit | Budget | Label | Runs | Edges | Duration |\n",
        );
        md.push_str(
            "|--------|-------|--------|------|--------|-------|------|-------|----------|\n",
        );
        for fuzz in &result.fuzz {
            let execution = fuzz.execution.as_ref();
            md.push_str(&format!(
                "| {} | {} | {} | {} | {}s | {} | {} | {} | {}s |\n",
                fuzz.target_name,
                fuzz.scope,
                fuzz.status,
                execution
                    .and_then(|e| e.exit_code)
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "-".into()),
                fuzz.requested_time_budget_secs,
                fuzz.budget_label.as_deref().unwrap_or("-"),
                fuzz.total_runs
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "-".into()),
                fuzz.edges_covered
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "-".into()),
                execution
                    .map(|e| e.duration_secs.round() as u64)
                    .unwrap_or(0),
            ));
        }
        md.push('\n');
        for fuzz in &result.fuzz {
            md.push_str(&format!(
                "- **{} scope:** `{}`\n",
                fuzz.target_name, fuzz.scope
            ));
            md.push_str(&format!(
                "- **{} interpretation:** {}\n",
                fuzz.target_name,
                fuzz_scope_note(fuzz)
            ));
            md.push_str(&format!(
                "- **{} status meaning:** {}\n",
                fuzz.target_name,
                fuzz_status_note(fuzz)
            ));
            if let Some(path) = &fuzz.harness_dir {
                md.push_str(&format!(
                    "- **{} harness dir:** `{}`\n",
                    fuzz.target_name,
                    path.display()
                ));
            }
            if let Some(path) = &fuzz.artifact_path {
                md.push_str(&format!(
                    "- **{}**: reproducer `{}` ({} bytes)\n",
                    fuzz.target_name,
                    path.display(),
                    fuzz.reproducer_size_bytes.unwrap_or(0),
                ));
            }
            if let Some(execution) = &fuzz.execution {
                md.push_str(&format!(
                    "- **{} log:** `{}`\n",
                    fuzz.target_name,
                    execution.log_path.display()
                ));
                if matches!(
                    fuzz.status,
                    FuzzStatus::BuildFailed
                        | FuzzStatus::Panic
                        | FuzzStatus::Oom
                        | FuzzStatus::Timeout
                        | FuzzStatus::Error
                ) {
                    if let Some(excerpt) = &execution.log_excerpt {
                        md.push_str(&format!(
                            "- **{} excerpt:** `{}`\n",
                            fuzz.target_name, excerpt
                        ));
                    }
                }
            }
        }
        md.push('\n');
    }
    append_phase_failures(md, "Fuzz failures", &fuzz_failures);
}

fn fuzz_scope_note(result: &FuzzTargetResult) -> String {
    let harness_note = result
        .harness_dir
        .as_ref()
        .map(|path| format!(" from external harness dir `{}`", path.display()))
        .unwrap_or_default();
    match result.scope {
        FuzzScope::ExistingHarness => match result.budget_label.as_deref() {
            Some(label) => format!(
                "This result is limited to the existing fuzz harness{}, a {}s budget, and the `{}` budget label.",
                harness_note, result.requested_time_budget_secs, label
            ),
            None => format!(
                "This result is limited to the existing fuzz harness{} and a {}s budget.",
                harness_note, result.requested_time_budget_secs
            ),
        },
        FuzzScope::DiscoveryOnly => {
            "Only fuzz target discovery was attempted; no target execution coverage is implied."
                .into()
        }
        FuzzScope::NoneAvailable => {
            "No fuzz harness was available, so this phase provides no execution evidence.".into()
        }
    }
}

fn fuzz_status_note(result: &FuzzTargetResult) -> &'static str {
    match result.status {
        FuzzStatus::Clean => "No visible failure was observed under the recorded harness and budget.",
        FuzzStatus::Panic => "The harness observed a panic or crash-like termination under fuzz input.",
        FuzzStatus::Oom => "The run exhausted memory under the current fuzz setup.",
        FuzzStatus::Timeout => "The run hit a timeout-like condition under the current fuzz setup.",
        FuzzStatus::BuildFailed => "The fuzz target did not build, so this phase produced no execution evidence for that target.",
        FuzzStatus::EnvironmentError => "The run was blocked by the execution environment rather than target behavior; inspect the log and recorded env overrides.",
        FuzzStatus::NoFuzzDir => "No usable fuzz harness directory was available, so no fuzz target was available to run.",
        FuzzStatus::NoTargets => "A fuzz directory exists, but no runnable fuzz target was discovered.",
        FuzzStatus::Error => "The fuzz command failed without a cleaner classification; inspect the excerpt and log for details.",
    }
}
