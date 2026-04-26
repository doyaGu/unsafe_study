use super::shared::append_phase_failures;
use crate::domain::{CrateAuditResult, MiriResult, MiriRun, PhaseKind};

pub(crate) fn append_miri(md: &mut String, crates: &[CrateAuditResult]) {
    let miri_crates: Vec<_> = crates.iter().filter(|c| c.miri.is_some()).collect();
    let miri_failures: Vec<_> = crates
        .iter()
        .filter_map(|c| c.phase_issue(PhaseKind::Miri).map(|issue| (c, issue)))
        .collect();
    if miri_crates.is_empty() && miri_failures.is_empty() {
        return;
    }

    md.push_str("## Phase 2: Miri\n\n");
    md.push_str(
        "| Crate | Scope | Verdict | Category | Primary | Baseline | Tests | UB | Duration |\n",
    );
    md.push_str(
        "|-------|-------|---------|----------|---------|----------|-------|----|----------|\n",
    );
    for result in &miri_crates {
        let miri = result.miri.as_ref().unwrap();
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {:.1}s |\n",
            result.target.display_name(),
            miri.scope,
            miri.verdict,
            miri.primary_run
                .ub_category
                .map(|category| category.to_string())
                .unwrap_or_else(|| "-".into()),
            run_status(&miri.primary_run),
            miri.baseline_run
                .as_ref()
                .map(run_status)
                .unwrap_or_else(|| "-".into()),
            miri.primary_run
                .tests_run
                .map(|n| n.to_string())
                .unwrap_or_else(|| "-".into()),
            if miri.primary_run.ub_detected {
                "YES"
            } else {
                "no"
            },
            miri.duration_secs(),
        ));
    }
    md.push('\n');

    for result in miri_crates {
        let miri = result.miri.as_ref().unwrap();
        md.push_str(&format!("### {}\n\n", result.target.display_name()));
        md.push_str(&format!("- **Scope:** `{}`\n", miri.scope));
        md.push_str(&format!(
            "- **Invocation:** `cargo {}` in `{}`\n",
            miri.invocation.args.join(" "),
            miri.invocation.working_dir.display()
        ));
        md.push_str(&format!(
            "- **Interpretation:** {}\n",
            miri_scope_note(miri)
        ));
        if let Some(summary) = &miri.triage_summary {
            md.push_str(&format!("- **Triage:** {}\n", summary));
        }
        if miri.primary_run.ub_detected {
            if let Some(category) = miri.primary_run.ub_category {
                md.push_str(&format!("- **Category:** `{}`\n", category));
            }
            if let Some(msg) = &miri.primary_run.ub_message {
                md.push_str(&format!("- **Message:** {}\n", msg));
            }
            if let Some(loc) = &miri.primary_run.ub_location {
                md.push_str(&format!("- **Location:** `{}`\n", loc));
            }
        }
        md.push_str(&format!(
            "- **Primary log:** `{}`\n",
            miri.primary_run.execution.log_path.display()
        ));
        if let Some(baseline) = &miri.baseline_run {
            md.push_str(&format!(
                "- **Baseline log:** `{}`\n",
                baseline.execution.log_path.display()
            ));
        }
        md.push('\n');
    }
    append_phase_failures(md, "Miri failures", &miri_failures);
}

fn run_status(run: &MiriRun) -> String {
    if run.execution.success {
        "CLEAN".into()
    } else if run.ub_detected {
        "UB".into()
    } else {
        "FAIL".into()
    }
}

fn miri_scope_note(result: &MiriResult) -> String {
    format!(
        "No result from this phase should be read beyond `{}` scope; clean means no UB was observed on the exercised test paths.",
        result.scope
    )
}
