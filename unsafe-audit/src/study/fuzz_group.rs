use anyhow::Result;
use std::collections::BTreeMap;
use std::path::Path;

use crate::domain::{UnsafeCoverageState, UnsafeSiteReach};

use super::coverage::{
    combine_coverage_state, derive_study_dynamic_coverage, derived_coverage_state,
    merge_derived_reach,
};
use super::fuzz_plan::planned_fuzz_targets;
use super::options::fuzz_group_options;
use super::runtime::{summaries_len, update_current_segment};
use super::summary::summarize_fuzz_group;
use super::{
    first_crate, run_or_resume, FuzzGroupSummary, StudyCrate, StudyDefaults, StudyFuzzGroup,
    StudyRunOptions,
};

#[allow(clippy::too_many_arguments)]
pub(super) fn run_fuzz_group(
    study_crate: &StudyCrate,
    group: &StudyFuzzGroup,
    options: &StudyRunOptions,
    defaults: &StudyDefaults,
    group_dir: &Path,
    output_root: &Path,
    shared_patterns: Option<&crate::analyzer::UnsafeSummary>,
    combined_reach: &mut BTreeMap<String, UnsafeSiteReach>,
    unsafe_coverage_state: &mut Option<UnsafeCoverageState>,
    unmapped_triggered_any: &mut usize,
    crate_root: &Path,
) -> Result<FuzzGroupSummary> {
    let group_options = fuzz_group_options(study_crate, group, options, group_dir, defaults);
    let target_names = planned_fuzz_targets(study_crate, group)?;

    if target_names.is_empty() {
        update_current_segment(
            output_root,
            study_crate,
            options,
            summaries_len(crate_root),
            format!("fuzz:{}", group.name),
        )?;
        if let Some(report) = run_or_resume(&group_options, options.dry_run, options.resume)? {
            let derived = derive_study_dynamic_coverage(
                study_crate,
                shared_patterns,
                first_crate(&report),
                None,
                group_options.fuzz_coverage_json.as_deref(),
                group_dir,
                options,
            );
            merge_derived_reach(combined_reach, derived.as_ref().map(|item| &item.0));
            *unsafe_coverage_state =
                combine_coverage_state(*unsafe_coverage_state, derived_coverage_state(&derived));
            *unmapped_triggered_any += derived
                .as_ref()
                .and_then(|(_, coverage)| coverage.unmapped_triggered_by_fuzz)
                .unwrap_or(0);
            return summarize_fuzz_group(
                group,
                &[report],
                group_dir,
                group_options.fuzz_auto_coverage,
            );
        }
        return summarize_fuzz_group(group, &[], group_dir, group_options.fuzz_auto_coverage);
    }

    let mut reports = Vec::new();
    for target_name in target_names {
        update_current_segment(
            output_root,
            study_crate,
            options,
            summaries_len(crate_root),
            format!("fuzz:{}/{}", group.name, target_name),
        )?;
        println!("    [target:{}]", target_name);
        let target_dir = group_dir.join(&target_name);
        let mut target_options =
            fuzz_group_options(study_crate, group, options, &target_dir, defaults);
        target_options.fuzz_targets = vec![target_name.clone()];
        if let Some(report) = run_or_resume(&target_options, options.dry_run, options.resume)? {
            let derived = derive_study_dynamic_coverage(
                study_crate,
                shared_patterns,
                first_crate(&report),
                None,
                target_options.fuzz_coverage_json.as_deref(),
                &target_dir,
                options,
            );
            merge_derived_reach(combined_reach, derived.as_ref().map(|item| &item.0));
            *unsafe_coverage_state =
                combine_coverage_state(*unsafe_coverage_state, derived_coverage_state(&derived));
            *unmapped_triggered_any += derived
                .as_ref()
                .and_then(|(_, coverage)| coverage.unmapped_triggered_by_fuzz)
                .unwrap_or(0);
            reports.push(report);
        }
    }

    summarize_fuzz_group(group, &reports, group_dir, group_options.fuzz_auto_coverage)
}
