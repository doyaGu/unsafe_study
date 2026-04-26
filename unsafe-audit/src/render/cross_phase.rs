use crate::analyzer::{UnsafeFinding, UnsafeSummary};
use crate::domain::{CrateAuditResult, PhaseKind};

pub(crate) fn append_cross_phase_linkage(md: &mut String, crates: &[CrateAuditResult]) {
    if crates.is_empty() {
        return;
    }

    md.push_str("## Cross-Phase Linkage\n\n");
    md.push_str("This section reports hotspot summaries from static findings and coarse dynamic linkage only. It does not claim file-level coverage unless a note is explicitly labeled best-effort and log-derived.\n\n");

    for result in crates {
        md.push_str(&format!("### {}\n\n", result.target.display_name()));
        if let Some(patterns) = &result.patterns {
            let hotspots = hotspot_summaries(patterns);
            if hotspots.is_empty() {
                md.push_str("- No static hotspot files were identified from pattern findings.\n");
            } else {
                md.push_str("| Hotspot File | Findings | Top Patterns |\n");
                md.push_str("|--------------|----------|--------------|\n");
                for hotspot in hotspots {
                    md.push_str(&format!(
                        "| {} | {} | {} |\n",
                        hotspot.file,
                        hotspot.finding_count,
                        hotspot.top_patterns.join(", ")
                    ));
                }
            }
        } else {
            match result.phase_issue(PhaseKind::Patterns) {
                Some(issue) => md.push_str(&format!(
                    "- Pattern analysis failed for this crate: {}.\n",
                    issue.message
                )),
                None => {
                    md.push_str(
                        "- Pattern analysis was skipped, so no hotspot summary is available.\n",
                    );
                }
            }
        }

        md.push_str(&format!(
            "- **Miri linkage:** {}\n",
            miri_linkage_note(result)
        ));
        md.push_str(&format!(
            "- **Fuzz linkage:** {}\n",
            fuzz_linkage_note(result)
        ));
        if let Some(best_effort) = best_effort_miri_hotspot_match(result) {
            md.push_str(&format!(
                "- **Best-effort hotspot hint:** UB location text mentions hotspot file `{}`.\n",
                best_effort
            ));
        }
        md.push('\n');
    }
}

#[derive(Debug)]
struct HotspotSummary {
    file: String,
    finding_count: usize,
    top_patterns: Vec<String>,
}

fn hotspot_summaries(summary: &UnsafeSummary) -> Vec<HotspotSummary> {
    let mut per_file: std::collections::BTreeMap<String, Vec<&UnsafeFinding>> =
        std::collections::BTreeMap::new();
    for finding in &summary.findings {
        let file = finding.file.display().to_string();
        per_file.entry(file).or_default().push(finding);
    }

    let mut hotspots = per_file
        .into_iter()
        .map(|(file, findings)| {
            let mut pattern_counts = std::collections::BTreeMap::<String, usize>::new();
            for finding in &findings {
                *pattern_counts
                    .entry(finding.pattern.to_string())
                    .or_insert(0) += 1;
            }
            let mut top_patterns = pattern_counts.into_iter().collect::<Vec<_>>();
            top_patterns.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

            HotspotSummary {
                file,
                finding_count: findings.len(),
                top_patterns: top_patterns
                    .into_iter()
                    .take(3)
                    .map(|(pattern, count)| format!("{pattern} ({count})"))
                    .collect(),
            }
        })
        .collect::<Vec<_>>();

    hotspots.sort_by(|a, b| {
        b.finding_count
            .cmp(&a.finding_count)
            .then_with(|| a.file.cmp(&b.file))
    });
    hotspots.truncate(3);
    hotspots
}

fn miri_linkage_note(result: &CrateAuditResult) -> String {
    match &result.miri {
        Some(miri) => format!(
            "Miri executed at `{}` scope for this crate from `{}`; this is crate-level evidence, not hotspot coverage.",
            miri.scope,
            miri.invocation.working_dir.display()
        ),
        None => match result.phase_issue(PhaseKind::Miri) {
            Some(issue) => format!("Miri failed for this crate: {}.", issue.message),
            None => "Miri was skipped or unavailable for this crate.".into(),
        },
    }
}

fn fuzz_linkage_note(result: &CrateAuditResult) -> String {
    if let Some(issue) = result.phase_issue(PhaseKind::Fuzz) {
        return format!("Fuzz failed for this crate: {}.", issue.message);
    }
    if result.fuzz.is_empty() {
        return "Fuzz was skipped for this crate.".into();
    }

    if result.fuzz.len() == 1 && result.fuzz[0].target_name == "(none)" {
        return format!(
            "No runnable fuzz target executed (`{}` / `{}`).",
            result.fuzz[0].scope, result.fuzz[0].status
        );
    }

    let targets = result
        .fuzz
        .iter()
        .map(|f| {
            let mut label = match f.budget_label.as_deref() {
                Some(budget) => format!("{} [{}]", f.target_name, budget),
                None => f.target_name.clone(),
            };
            if let Some(dir) = &f.harness_dir {
                label.push_str(&format!(" @ {}", dir.display()));
            }
            label
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("Fuzz executed existing harness targets at target granularity: {targets}.")
}

fn best_effort_miri_hotspot_match(result: &CrateAuditResult) -> Option<String> {
    let summary = result.patterns.as_ref()?;
    let location = result.miri.as_ref()?.primary_run.ub_location.as_ref()?;
    for hotspot in hotspot_summaries(summary) {
        let filename = std::path::Path::new(&hotspot.file)
            .file_name()
            .and_then(|name| name.to_str())?;
        if location.contains(filename) {
            return Some(hotspot.file);
        }
    }
    None
}
