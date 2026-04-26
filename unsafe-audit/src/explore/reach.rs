use std::collections::BTreeMap;
use std::path::Path;

use crate::analyzer::{Severity, UnsafeSummary};
use crate::coverage;
use crate::domain::{
    CrateAuditResult, FuzzStatus, UnsafeCoverageState, UnsafeCoverageSummary, UnsafeSiteReach,
};

pub(super) fn seed_reach(result: &CrateAuditResult) -> BTreeMap<String, UnsafeSiteReach> {
    result
        .unsafe_site_reach
        .as_ref()
        .map(|reach| {
            reach
                .iter()
                .map(|site| (site.site_id.clone(), site.clone()))
                .collect()
        })
        .or_else(|| {
            result.patterns.as_ref().map(|patterns| {
                patterns
                    .unsafe_sites
                    .iter()
                    .map(|site| {
                        (
                            site.site_id.clone(),
                            UnsafeSiteReach {
                                site_id: site.site_id.clone(),
                                reached_by_miri: false,
                                reached_by_fuzz: false,
                                triggered_by_miri: false,
                                triggered_by_fuzz: false,
                            },
                        )
                    })
                    .collect()
            })
        })
        .unwrap_or_default()
}

pub(super) fn merge_dynamic_reach(
    combined: &mut BTreeMap<String, UnsafeSiteReach>,
    result: &CrateAuditResult,
    miri: Option<&crate::domain::MiriResult>,
    fuzz: &[crate::domain::FuzzTargetResult],
    miri_coverage_json: Option<&Path>,
    fuzz_coverage_json: Option<&Path>,
) {
    let Some(patterns) = result.patterns.as_ref() else {
        return;
    };
    let (reach, _) = coverage::derive(
        &result.target.dir,
        Some(patterns),
        miri,
        fuzz,
        miri_coverage_json,
        fuzz_coverage_json,
    );
    if let Some(reach) = reach {
        for site in reach {
            combined
                .entry(site.site_id.clone())
                .and_modify(|existing| {
                    existing.reached_by_miri |= site.reached_by_miri;
                    existing.reached_by_fuzz |= site.reached_by_fuzz;
                    existing.triggered_by_miri |= site.triggered_by_miri;
                    existing.triggered_by_fuzz |= site.triggered_by_fuzz;
                })
                .or_insert(site);
        }
    }
}

pub(super) fn apply_combined_reach(
    result: &mut CrateAuditResult,
    combined: BTreeMap<String, UnsafeSiteReach>,
) {
    if combined.is_empty() {
        return;
    }
    let reach = combined.into_values().collect::<Vec<_>>();
    let reached_by_miri = reach.iter().filter(|site| site.reached_by_miri).count();
    let reached_by_fuzz = reach.iter().filter(|site| site.reached_by_fuzz).count();
    let reached_by_any = reach
        .iter()
        .filter(|site| site.reached_by_miri || site.reached_by_fuzz)
        .count();
    let triggered_by_miri = reach.iter().filter(|site| site.triggered_by_miri).count();
    let triggered_by_fuzz = reach.iter().filter(|site| site.triggered_by_fuzz).count();
    let triggered_by_any = reach
        .iter()
        .filter(|site| site.triggered_by_miri || site.triggered_by_fuzz)
        .count();
    let dynamic_phase_present = result.miri.is_some()
        || result.fuzz.iter().any(|target| {
            target.scope == crate::domain::FuzzScope::ExistingHarness
                && target.execution.is_some()
                && !matches!(
                    target.status,
                    FuzzStatus::BuildFailed
                        | FuzzStatus::EnvironmentError
                        | FuzzStatus::NoFuzzDir
                        | FuzzStatus::NoTargets
                )
        });
    let previous_state = result
        .unsafe_coverage
        .as_ref()
        .map(|coverage| coverage.state);
    result.unsafe_coverage = Some(UnsafeCoverageSummary {
        state: previous_state.unwrap_or_else(|| {
            if dynamic_phase_present {
                UnsafeCoverageState::TriggeredEvidenceOnly
            } else {
                UnsafeCoverageState::StaticUniverseOnly
            }
        }),
        total_sites: reach.len(),
        reached_by_miri: Some(reached_by_miri),
        reached_by_fuzz: Some(reached_by_fuzz),
        reached_by_any: Some(reached_by_any),
        triggered_by_miri: Some(triggered_by_miri),
        triggered_by_fuzz: Some(triggered_by_fuzz),
        triggered_by_any: Some(triggered_by_any),
        unmapped_triggered_by_miri: result
            .unsafe_coverage
            .as_ref()
            .and_then(|coverage| coverage.unmapped_triggered_by_miri),
        unmapped_triggered_by_fuzz: result
            .unsafe_coverage
            .as_ref()
            .and_then(|coverage| coverage.unmapped_triggered_by_fuzz),
        unreached: Some(reach.len().saturating_sub(reached_by_any)),
    });
    result.unsafe_site_reach = Some(reach);
}

pub(super) fn reached_count(combined: &BTreeMap<String, UnsafeSiteReach>) -> usize {
    combined
        .values()
        .filter(|site| site.reached_by_miri || site.reached_by_fuzz)
        .count()
}

pub(super) fn rank_sites(patterns: &UnsafeSummary) -> Vec<String> {
    let mut sites = patterns.unsafe_sites.iter().collect::<Vec<_>>();
    sites.sort_by(|a, b| {
        severity_rank(b.severity)
            .cmp(&severity_rank(a.severity))
            .then_with(|| a.file.cmp(&b.file))
            .then(a.line.cmp(&b.line))
    });
    sites.into_iter().map(|site| site.site_id.clone()).collect()
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Info => 0,
    }
}

pub(super) fn unreached_targets(
    ranked_sites: &[String],
    combined: &BTreeMap<String, UnsafeSiteReach>,
) -> Vec<String> {
    ranked_sites
        .iter()
        .filter(|site_id| {
            combined
                .get(*site_id)
                .map(|site| !site.reached_by_miri && !site.reached_by_fuzz)
                .unwrap_or(true)
        })
        .take(5)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_picks_unreached_ranked_sites() {
        let mut combined = BTreeMap::new();
        combined.insert(
            "a".into(),
            UnsafeSiteReach {
                site_id: "a".into(),
                reached_by_miri: true,
                reached_by_fuzz: false,
                triggered_by_miri: false,
                triggered_by_fuzz: false,
            },
        );
        combined.insert(
            "b".into(),
            UnsafeSiteReach {
                site_id: "b".into(),
                reached_by_miri: false,
                reached_by_fuzz: false,
                triggered_by_miri: false,
                triggered_by_fuzz: false,
            },
        );
        assert_eq!(
            unreached_targets(&["a".into(), "b".into(), "c".into()], &combined),
            vec!["b".to_string(), "c".to_string()]
        );
    }

    #[test]
    fn exploration_preserves_dynamic_scope_when_no_site_is_reached() {
        let mut result = CrateAuditResult {
            target: crate::domain::CrateTarget {
                metadata: crate::domain::CrateMetadata {
                    name: "demo".into(),
                    version: "0.1.0".into(),
                },
                dir: std::path::PathBuf::from("."),
            },
            geiger: None,
            miri: Some(crate::domain::MiriResult {
                scope: crate::domain::MiriScope::Targeted,
                invocation: crate::domain::CommandInvocation {
                    working_dir: std::path::PathBuf::from("."),
                    args: vec!["miri".into(), "test".into()],
                },
                verdict: crate::domain::MiriVerdict::Clean,
                triage_summary: None,
                primary_run: crate::domain::MiriRun {
                    flags: String::new(),
                    execution: crate::domain::ExecutionOutcome {
                        success: true,
                        exit_code: Some(0),
                        duration_secs: 0.0,
                        log_path: std::path::PathBuf::from("miri.log"),
                        log_excerpt: None,
                    },
                    tests_run: Some(1),
                    tests_passed: Some(1),
                    tests_failed: Some(0),
                    ub_detected: false,
                    ub_category: None,
                    ub_message: None,
                    ub_location: None,
                },
                baseline_run: None,
            }),
            fuzz: Vec::new(),
            patterns: None,
            unsafe_site_reach: None,
            unsafe_coverage: None,
            coverage_artifacts: None,
            exploration: None,
            phase_issues: Vec::new(),
        };
        let mut combined = BTreeMap::new();
        combined.insert(
            "site".into(),
            UnsafeSiteReach {
                site_id: "site".into(),
                reached_by_miri: false,
                reached_by_fuzz: false,
                triggered_by_miri: false,
                triggered_by_fuzz: false,
            },
        );

        apply_combined_reach(&mut result, combined);

        assert_eq!(
            result.unsafe_coverage.unwrap().state,
            UnsafeCoverageState::TriggeredEvidenceOnly
        );
    }
}
