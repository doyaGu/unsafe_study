use crate::domain::{CrateAuditResult, PhaseIssue, PhaseKind};

pub(super) fn append_phase_failures(
    md: &mut String,
    title: &str,
    failures: &[(&CrateAuditResult, &PhaseIssue)],
) {
    if failures.is_empty() {
        return;
    }

    md.push_str(&format!("### {title}\n\n"));
    for (result, issue) in failures {
        md.push_str(&format!(
            "- **{}:** {}\n",
            result.target.display_name(),
            issue.message
        ));
    }
    md.push('\n');
}

pub(crate) fn phase_summary_fallback(result: &CrateAuditResult, phase: PhaseKind) -> String {
    result
        .phase_issue(phase)
        .map(|_| "ERROR".into())
        .unwrap_or_else(|| "SKIP".into())
}
