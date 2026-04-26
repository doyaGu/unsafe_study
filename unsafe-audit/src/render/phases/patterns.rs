use super::shared::append_phase_failures;
use crate::analyzer::UnsafeFinding;
use crate::domain::{CrateAuditResult, PhaseKind};

pub(crate) fn append_patterns(md: &mut String, crates: &[CrateAuditResult]) {
    let pattern_crates: Vec<_> = crates.iter().filter(|c| c.patterns.is_some()).collect();
    let pattern_failures: Vec<_> = crates
        .iter()
        .filter_map(|c| c.phase_issue(PhaseKind::Patterns).map(|issue| (c, issue)))
        .collect();
    if pattern_crates.is_empty() && pattern_failures.is_empty() {
        return;
    }

    md.push_str("## Phase 4: Pattern Analysis\n\n");
    for result in pattern_crates {
        let patterns = result.patterns.as_ref().unwrap();
        md.push_str(&format!(
            "### {} (risk: {:.1})\n\n",
            result.target.display_name(),
            patterns.risk_score
        ));
        md.push_str(&format!(
            "- Files: {} scanned, {} with findings, {} findings, {} failed to scan\n",
            patterns.files_scanned,
            patterns.files_with_unsafe,
            patterns.total_findings,
            patterns.files_failed_to_scan
        ));
        md.push_str(&format!(
            "- Finding classes: risky operations={}, unsafe blocks={}, declarations={}, extern items={}\n",
            patterns.risky_operation_findings,
            patterns.unsafe_block_findings,
            patterns.unsafe_declaration_findings,
            patterns.extern_item_findings
        ));
        md.push_str(&format!(
            "- Unsafe site universe: {} total (risky operations={}, unsafe blocks={}, declarations={}, extern items={})\n",
            patterns.unsafe_site_universe.site_total,
            patterns.unsafe_site_universe.risky_operation_sites,
            patterns.unsafe_site_universe.unsafe_block_sites,
            patterns.unsafe_site_universe.unsafe_declaration_sites,
            patterns.unsafe_site_universe.extern_item_sites
        ));
        if let Some(coverage) = &result.unsafe_coverage {
            md.push_str(&format!(
                "- Dynamic unsafe coverage: `{}`\n",
                coverage.state
            ));
            if let Some(reached_any) = coverage.reached_by_any {
                md.push_str(&format!(
                    "- Lower-bound reached sites: miri={}, fuzz={}, any={}\n",
                    coverage.reached_by_miri.unwrap_or(0),
                    coverage.reached_by_fuzz.unwrap_or(0),
                    reached_any
                ));
            }
            if let Some(triggered_any) = coverage.triggered_by_any {
                md.push_str(&format!(
                    "- Triggered sites: miri={}, fuzz={}, any={}\n",
                    coverage.triggered_by_miri.unwrap_or(0),
                    coverage.triggered_by_fuzz.unwrap_or(0),
                    triggered_any
                ));
            }
            if coverage.unmapped_triggered_by_miri.unwrap_or(0) > 0
                || coverage.unmapped_triggered_by_fuzz.unwrap_or(0) > 0
            {
                md.push_str(&format!(
                    "- Unmapped triggered locations: miri={}, fuzz={}\n",
                    coverage.unmapped_triggered_by_miri.unwrap_or(0),
                    coverage.unmapped_triggered_by_fuzz.unwrap_or(0)
                ));
            }
        }
        if let Some(artifacts) = &result.coverage_artifacts {
            if let Some(path) = &artifacts.miri_coverage_json {
                md.push_str(&format!("- Miri coverage JSON: `{}`\n", path.display()));
            }
            if let Some(path) = &artifacts.miri_coverage_build_log {
                md.push_str(&format!(
                    "- Miri coverage build log: `{}`\n",
                    path.display()
                ));
            }
            if let Some(path) = &artifacts.miri_coverage_run_log {
                md.push_str(&format!("- Miri coverage run log: `{}`\n", path.display()));
            }
            if let Some(path) = &artifacts.fuzz_coverage_json {
                md.push_str(&format!("- Fuzz coverage JSON: `{}`\n", path.display()));
            }
            if let Some(path) = &artifacts.fuzz_coverage_log_dir {
                md.push_str(&format!("- Fuzz coverage logs: `{}`\n", path.display()));
            }
        }
        md.push_str("- Interpretation: `risk_score` is a prioritization heuristic, not a calibrated comparative metric.\n");
        if !patterns.patterns.is_empty() {
            md.push_str("\n| Pattern | Count |\n|---------|-------|\n");
            for pattern_count in &patterns.patterns {
                md.push_str(&format!(
                    "| {} | {} |\n",
                    pattern_count.pattern, pattern_count.count
                ));
            }
        }
        let kind_counts = finding_kind_counts(&patterns.findings);
        if !kind_counts.is_empty() {
            md.push_str("\n| Finding Kind | Count |\n|--------------|-------|\n");
            for (kind, count) in kind_counts {
                md.push_str(&format!("| {} | {} |\n", kind, count));
            }
        }
        if !patterns.scan_failures.is_empty() {
            md.push_str("\n| Scan Failure | Error |\n|--------------|-------|\n");
            for issue in &patterns.scan_failures {
                md.push_str(&format!("| {} | {} |\n", issue.path.display(), issue.error));
            }
        }
        md.push('\n');
    }
    append_phase_failures(md, "Pattern analysis failures", &pattern_failures);
}

fn finding_kind_counts(findings: &[UnsafeFinding]) -> Vec<(String, usize)> {
    let mut counts = std::collections::BTreeMap::new();
    for finding in findings {
        *counts.entry(finding.kind.to_string()).or_insert(0) += 1;
    }
    counts.into_iter().collect()
}
