use anyhow::Result;
use std::collections::BTreeMap;
use std::path::Path;

use crate::domain::{UnsafeCoverageState, UnsafeSiteReach};

use super::coverage::{
    combine_coverage_state, derive_study_dynamic_coverage, derived_coverage_state,
    merge_derived_reach,
};
use super::options::miri_case_options;
use super::runtime::{summaries_len, update_current_segment};
use super::summary::summarize_miri_case;
use super::{
    first_crate, run_or_resume, MiriCaseSummary, StudyCrate, StudyDefaults, StudyMiriCase,
    StudyRunOptions,
};

#[allow(clippy::too_many_arguments)]
pub(super) fn run_miri_case(
    study_crate: &StudyCrate,
    case: &StudyMiriCase,
    options: &StudyRunOptions,
    defaults: &StudyDefaults,
    case_dir: &Path,
    output_root: &Path,
    shared_patterns: Option<&crate::analyzer::UnsafeSummary>,
    combined_reach: &mut BTreeMap<String, UnsafeSiteReach>,
    unsafe_coverage_state: &mut Option<UnsafeCoverageState>,
    unmapped_triggered_any: &mut usize,
    crate_root: &Path,
) -> Result<Option<MiriCaseSummary>> {
    update_current_segment(
        output_root,
        study_crate,
        options,
        summaries_len(crate_root),
        format!("miri:{}", case.name),
    )?;
    let case_options = miri_case_options(study_crate, case, options, case_dir, defaults);
    let Some(report) = run_or_resume(&case_options, options.dry_run, options.resume)? else {
        return Ok(None);
    };

    let derived = derive_study_dynamic_coverage(
        study_crate,
        shared_patterns,
        first_crate(&report),
        case_options.miri_coverage_json.as_deref(),
        None,
        case_dir,
        options,
    );
    merge_derived_reach(combined_reach, derived.as_ref().map(|item| &item.0));
    *unsafe_coverage_state =
        combine_coverage_state(*unsafe_coverage_state, derived_coverage_state(&derived));
    *unmapped_triggered_any += derived
        .as_ref()
        .and_then(|(_, coverage)| coverage.unmapped_triggered_by_miri)
        .unwrap_or(0);

    Ok(Some(summarize_miri_case(
        case,
        &report,
        case_dir,
        case_options.miri_auto_coverage,
    )))
}
