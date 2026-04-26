use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::Path;

use crate::app::PhaseSelection;
use crate::domain::{StudyReport, UnsafeSiteReach};

use super::fuzz_group::run_fuzz_group;
use super::miri_case::run_miri_case;
use super::options::base_audit_options;
use super::runtime::{summaries_len, update_current_segment};
use super::summary::summarize_shared;
use super::{
    first_crate, run_or_resume, CrateStudySummary, StudyCrate, StudyDefaults, StudyRunOptions,
};

pub(super) fn run_study_crate(
    study_crate: &StudyCrate,
    defaults: &StudyDefaults,
    output_root: &Path,
    options: &StudyRunOptions,
) -> Result<CrateStudySummary> {
    let crate_root = output_root.join(&study_crate.name);
    std::fs::create_dir_all(&crate_root)?;

    let shared_report = run_shared_phase(study_crate, defaults, &crate_root, options)?;
    let shared_patterns = shared_report
        .as_ref()
        .and_then(first_crate)
        .and_then(|result| result.patterns.as_ref());

    let mut miri_summaries = Vec::new();
    let mut combined_reach: BTreeMap<String, UnsafeSiteReach> = BTreeMap::new();
    let mut unsafe_coverage_state = shared_report
        .as_ref()
        .and_then(first_crate)
        .and_then(|result| result.unsafe_coverage.as_ref())
        .map(|coverage| coverage.state);
    let mut unmapped_triggered_any = 0usize;
    if options.phases.miri {
        for case in &study_crate.miri_cases {
            println!("  [miri:{}]", case.name);
            let case_dir = crate_root.join("miri").join(&case.name);
            if let Some(summary) = run_miri_case(
                study_crate,
                case,
                options,
                defaults,
                &case_dir,
                output_root,
                shared_patterns,
                &mut combined_reach,
                &mut unsafe_coverage_state,
                &mut unmapped_triggered_any,
                &crate_root,
            )? {
                miri_summaries.push(summary);
            }
        }
    }

    let mut fuzz_summaries = Vec::new();
    if options.phases.fuzz {
        for group in &study_crate.fuzz_groups {
            println!("  [fuzz:{}]", group.name);
            let group_dir = crate_root.join("fuzz").join(&group.name);
            let summary = run_fuzz_group(
                study_crate,
                group,
                options,
                defaults,
                &group_dir,
                output_root,
                shared_patterns,
                &mut combined_reach,
                &mut unsafe_coverage_state,
                &mut unmapped_triggered_any,
                &crate_root,
            )?;
            fuzz_summaries.push(summary);
        }
    }

    let (
        geiger_root_total,
        geiger_dependency_packages,
        geiger_scan_gaps,
        pattern_findings,
        pattern_scan_failures,
        unsafe_site_total,
    ) = summarize_shared(shared_report.as_ref());
    let unsafe_reached_lower_bound_any = if combined_reach.is_empty() {
        None
    } else {
        Some(
            combined_reach
                .values()
                .filter(|site| site.reached_by_miri || site.reached_by_fuzz)
                .count(),
        )
    };
    let unsafe_triggered_any = if combined_reach.is_empty() {
        None
    } else {
        Some(
            combined_reach
                .values()
                .filter(|site| site.triggered_by_miri || site.triggered_by_fuzz)
                .count(),
        )
    };
    let unmapped_triggered_any = if unsafe_coverage_state.is_some() {
        Some(unmapped_triggered_any)
    } else {
        None
    };

    let summary = CrateStudySummary {
        name: study_crate.name.clone(),
        cohort: study_crate.cohort.clone(),
        coverage_tier: study_crate.coverage_tier.clone(),
        artifact_dir: crate_root.display().to_string(),
        geiger_root_total,
        geiger_dependency_packages,
        geiger_scan_gaps,
        pattern_findings,
        pattern_scan_failures,
        unsafe_site_total,
        unsafe_coverage_state: unsafe_coverage_state.map(|state| state.to_string()),
        unsafe_reached_lower_bound_any,
        unsafe_triggered_any,
        unmapped_triggered_any,
        miri_cases: miri_summaries,
        fuzz_groups: fuzz_summaries,
    };

    if !options.dry_run {
        std::fs::write(
            crate_root.join("summary.json"),
            serde_json::to_string_pretty(&summary)?,
        )?;
    }

    Ok(summary)
}

fn run_shared_phase(
    study_crate: &StudyCrate,
    defaults: &StudyDefaults,
    crate_root: &Path,
    options: &StudyRunOptions,
) -> Result<Option<StudyReport>> {
    if !options.phases.geiger && !options.phases.patterns {
        return Ok(None);
    }

    println!("  [shared]");
    update_current_segment(
        crate_root
            .parent()
            .context("crate root must have parent output root")?,
        study_crate,
        options,
        summaries_len(crate_root),
        "shared".to_string(),
    )?;
    let shared_dir = crate_root.join("shared");
    let mut shared_options = base_audit_options(study_crate, options, &shared_dir, defaults);
    shared_options.phases = PhaseSelection::shared_static();
    shared_options.phases.geiger = options.phases.geiger;
    shared_options.phases.patterns = options.phases.patterns;
    run_or_resume(&shared_options, options.dry_run, options.resume)
}
