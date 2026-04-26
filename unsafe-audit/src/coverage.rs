mod llvm;
mod location;
mod matching;
mod summary;
#[cfg(test)]
mod tests;

use std::path::Path;

use crate::analyzer::UnsafeSummary;
use crate::domain::{
    FuzzStatus, FuzzTargetResult, MiriResult, UnsafeCoverageSummary, UnsafeSiteReach,
};
use llvm::load_executed_ranges;
use location::{fuzz_locations, miri_locations};
use matching::{match_site_index, match_site_index_for_range};
use summary::{dynamic_summary, static_universe_summary, DynamicEvidence};

pub fn derive(
    crate_dir: &Path,
    patterns: Option<&UnsafeSummary>,
    miri: Option<&MiriResult>,
    fuzz: &[FuzzTargetResult],
    miri_coverage_json: Option<&Path>,
    fuzz_coverage_json: Option<&Path>,
) -> (Option<Vec<UnsafeSiteReach>>, Option<UnsafeCoverageSummary>) {
    let patterns = match patterns {
        Some(patterns) => patterns,
        None => return (None, None),
    };

    let mut site_reach = patterns
        .unsafe_sites
        .iter()
        .map(|site| UnsafeSiteReach {
            site_id: site.site_id.clone(),
            reached_by_miri: false,
            reached_by_fuzz: false,
            triggered_by_miri: false,
            triggered_by_fuzz: false,
        })
        .collect::<Vec<_>>();

    let mut evidence = DynamicEvidence {
        dynamic_phase_present: false,
        computed_from_coverage: false,
        miri_total_locations: 0,
        fuzz_total_locations: 0,
    };

    if let Some(path) = miri_coverage_json {
        if let Ok(ranges) = load_executed_ranges(crate_dir, path) {
            evidence.dynamic_phase_present = true;
            evidence.computed_from_coverage = true;
            for range in &ranges {
                if let Some(index) = match_site_index_for_range(crate_dir, patterns, range) {
                    site_reach[index].reached_by_miri = true;
                }
            }
        }
    }

    if let Some(path) = fuzz_coverage_json {
        if let Ok(ranges) = load_executed_ranges(crate_dir, path) {
            evidence.dynamic_phase_present = true;
            evidence.computed_from_coverage = true;
            for range in &ranges {
                if let Some(index) = match_site_index_for_range(crate_dir, patterns, range) {
                    site_reach[index].reached_by_fuzz = true;
                }
            }
        }
    }

    if let Some(miri) = miri {
        evidence.dynamic_phase_present = true;
        let locations = miri_locations(miri);
        evidence.miri_total_locations = locations.len();
        for location in locations {
            if let Some(index) = match_site_index(crate_dir, patterns, &location) {
                site_reach[index].reached_by_miri = true;
                site_reach[index].triggered_by_miri = true;
            }
        }
    }

    if fuzz.iter().any(has_fuzz_execution_evidence) {
        evidence.dynamic_phase_present = true;
    }
    if !fuzz.is_empty() {
        for target in fuzz {
            let locations = fuzz_locations(crate_dir, target);
            evidence.fuzz_total_locations += locations.len();
            for location in locations {
                if let Some(index) = match_site_index(crate_dir, patterns, &location) {
                    site_reach[index].reached_by_fuzz = true;
                    site_reach[index].triggered_by_fuzz = true;
                }
            }
        }
    }

    if !evidence.dynamic_phase_present {
        return (
            None,
            Some(static_universe_summary(
                patterns.unsafe_site_universe.site_total,
            )),
        );
    }

    let summary = dynamic_summary(
        patterns.unsafe_site_universe.site_total,
        &site_reach,
        evidence,
    );
    (Some(site_reach), Some(summary))
}

fn has_fuzz_execution_evidence(target: &FuzzTargetResult) -> bool {
    target.scope == crate::domain::FuzzScope::ExistingHarness
        && target.execution.is_some()
        && !matches!(
            target.status,
            FuzzStatus::BuildFailed
                | FuzzStatus::EnvironmentError
                | FuzzStatus::NoFuzzDir
                | FuzzStatus::NoTargets
        )
}
