use std::collections::BTreeMap;
use std::path::Path;

use crate::domain::{UnsafeCoverageState, UnsafeCoverageSummary, UnsafeSiteReach};
use crate::infra::OutputLayout;

use super::{StudyCrate, StudyRunOptions};

pub(super) fn derive_study_dynamic_coverage(
    study_crate: &StudyCrate,
    shared_patterns: Option<&crate::analyzer::UnsafeSummary>,
    result: Option<&crate::domain::CrateAuditResult>,
    explicit_miri_coverage_json: Option<&Path>,
    explicit_fuzz_coverage_json: Option<&Path>,
    output_dir: &Path,
    options: &StudyRunOptions,
) -> Option<(Vec<UnsafeSiteReach>, UnsafeCoverageSummary)> {
    let patterns = shared_patterns?;
    let result = result?;
    let layout = OutputLayout::new(output_dir.to_path_buf());
    let artifact_miri_coverage_json = result
        .coverage_artifacts
        .as_ref()
        .and_then(|artifacts| artifacts.miri_coverage_json.as_deref());
    let artifact_fuzz_coverage_json = result
        .coverage_artifacts
        .as_ref()
        .and_then(|artifacts| artifacts.fuzz_coverage_json.as_deref());
    let auto_miri_coverage_json = options
        .miri_auto_coverage
        .then(|| layout.miri_coverage_json_path(&study_crate.name))
        .filter(|path| path.exists());
    let auto_fuzz_coverage_json = options
        .fuzz_auto_coverage
        .then(|| layout.fuzz_coverage_json_path(&study_crate.name))
        .filter(|path| path.exists());
    let miri_coverage_json = explicit_miri_coverage_json
        .or(artifact_miri_coverage_json)
        .or(auto_miri_coverage_json.as_deref());
    let fuzz_coverage_json = explicit_fuzz_coverage_json
        .or(artifact_fuzz_coverage_json)
        .or(auto_fuzz_coverage_json.as_deref());
    let (reach, coverage) = crate::coverage::derive(
        &study_crate.path,
        Some(patterns),
        result.miri.as_ref(),
        &result.fuzz,
        miri_coverage_json,
        fuzz_coverage_json,
    );
    match (reach, coverage) {
        (Some(reach), Some(coverage)) => Some((reach, coverage)),
        _ => None,
    }
}

pub(super) fn merge_derived_reach(
    combined: &mut BTreeMap<String, UnsafeSiteReach>,
    site_reach: Option<&Vec<UnsafeSiteReach>>,
) {
    let Some(site_reach) = site_reach else {
        return;
    };

    for site in site_reach {
        let entry = combined
            .entry(site.site_id.clone())
            .or_insert_with(|| site.clone());
        entry.reached_by_miri |= site.reached_by_miri;
        entry.reached_by_fuzz |= site.reached_by_fuzz;
        entry.triggered_by_miri |= site.triggered_by_miri;
        entry.triggered_by_fuzz |= site.triggered_by_fuzz;
    }
}

pub(super) fn derived_coverage_state(
    derived: &Option<(Vec<UnsafeSiteReach>, UnsafeCoverageSummary)>,
) -> Option<UnsafeCoverageState> {
    derived.as_ref().map(|(_, coverage)| coverage.state)
}

pub(super) fn combine_coverage_state(
    current: Option<UnsafeCoverageState>,
    next: Option<UnsafeCoverageState>,
) -> Option<UnsafeCoverageState> {
    match (current, next) {
        (Some(UnsafeCoverageState::Computed), _) | (_, Some(UnsafeCoverageState::Computed)) => {
            Some(UnsafeCoverageState::Computed)
        }
        (Some(UnsafeCoverageState::TriggeredEvidenceOnly), _)
        | (_, Some(UnsafeCoverageState::TriggeredEvidenceOnly)) => {
            Some(UnsafeCoverageState::TriggeredEvidenceOnly)
        }
        (Some(UnsafeCoverageState::StaticUniverseOnly), _)
        | (_, Some(UnsafeCoverageState::StaticUniverseOnly)) => {
            Some(UnsafeCoverageState::StaticUniverseOnly)
        }
        (None, None) => None,
    }
}
