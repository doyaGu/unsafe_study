use crate::domain::CrateAuditResult;

pub(crate) fn append_exploration(md: &mut String, crates: &[CrateAuditResult]) {
    let explored = crates
        .iter()
        .filter(|item| item.exploration.is_some())
        .collect::<Vec<_>>();
    if explored.is_empty() {
        return;
    }

    md.push_str("## Exploration\n\n");
    md.push_str("| Crate | Mode | Rounds | Isolated Miri Cases | Fuzz Runs | Harness Candidates | Issues |\n");
    md.push_str("|-------|------|--------|---------------------|-----------|--------------------|--------|\n");
    for result in &explored {
        let exploration = result.exploration.as_ref().unwrap();
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} |\n",
            result.target.display_name(),
            exploration.mode,
            exploration.rounds.len(),
            exploration.isolated_miri_cases.len(),
            exploration.fuzz_runs.len(),
            exploration.harness_candidates.len(),
            exploration.issues.len()
        ));
    }
    md.push('\n');

    for result in explored {
        let exploration = result.exploration.as_ref().unwrap();
        md.push_str(&format!("### {}\n\n", result.target.display_name()));
        md.push_str(&format!(
            "- **Stop policy:** max_rounds={}, max_time_secs={}, no_new_coverage_limit={}\n",
            exploration.max_rounds,
            exploration
                .max_time_secs
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".into()),
            exploration.no_new_coverage_limit
        ));
        if !exploration.rounds.is_empty() {
            md.push_str(
                "\n| Round | Action | New Reach | Reached Before | Reached After | Stop |\n",
            );
            md.push_str("|-------|--------|-----------|----------------|---------------|------|\n");
            for round in &exploration.rounds {
                md.push_str(&format!(
                    "| {} | {} | {} | {} | {} | {} |\n",
                    round.round,
                    round.planned_action,
                    round.new_reach,
                    round.reached_before,
                    round.reached_after,
                    if round.stop_after_round { "yes" } else { "no" }
                ));
            }
        }
        if !exploration.isolated_miri_cases.is_empty() {
            md.push_str("\n| Miri Case | Verdict | UB | Log | Error |\n");
            md.push_str("|-----------|---------|----|-----|-------|\n");
            for case in &exploration.isolated_miri_cases {
                md.push_str(&format!(
                    "| {} | {} | {} | {} | {} |\n",
                    case.name,
                    case.verdict
                        .map(|verdict| verdict.to_string())
                        .unwrap_or_else(|| "-".into()),
                    case.ub_detected
                        .map(|value| if value { "yes" } else { "no" }.to_string())
                        .unwrap_or_else(|| "-".into()),
                    case.log_path
                        .as_ref()
                        .map(|path| format!("`{}`", path.display()))
                        .unwrap_or_else(|| "-".into()),
                    case.error.as_deref().unwrap_or("-")
                ));
            }
        }
        if !exploration.harness_candidates.is_empty() {
            md.push_str("\n#### Harness Candidates\n\n");
            for candidate in &exploration.harness_candidates {
                md.push_str(&format!(
                    "- `{}` `{}` status=`{}` targets={}\n",
                    candidate.id,
                    candidate.kind,
                    candidate.validation_status,
                    candidate.target_site_ids.len()
                ));
                if !candidate.rationale.is_empty() {
                    md.push_str(&format!("  - rationale: {}\n", candidate.rationale));
                }
                if !candidate.suggested_command.is_empty() {
                    md.push_str(&format!(
                        "  - suggested command: `{}`\n",
                        candidate.suggested_command
                    ));
                }
            }
        }
        if !exploration.issues.is_empty() {
            md.push_str("\n#### Exploration Issues\n\n");
            for issue in &exploration.issues {
                md.push_str(&format!("- `{}`: {}\n", issue.stage, issue.message));
            }
        }
        md.push('\n');
    }
}
