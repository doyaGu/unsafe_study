use anyhow::{Context, Result};
use std::path::Path;

use crate::domain::StudyReport;

use super::{FuzzGroupSummary, MiriCaseSummary, StudyFuzzGroup, StudyMiriCase};

pub(super) fn summarize_miri_case(
    case: &StudyMiriCase,
    report: &StudyReport,
    artifact_dir: &Path,
    auto_coverage: bool,
) -> MiriCaseSummary {
    let miri = report.crates.first().and_then(|item| item.miri.as_ref());
    MiriCaseSummary {
        name: case.name.clone(),
        scope: miri.map(|item| item.scope.to_string()),
        harness_dir: display_path(case.harness_dir.as_deref()),
        test: case.test.clone(),
        case: case.case.clone(),
        auto_coverage,
        coverage_json: report
            .crates
            .first()
            .and_then(|item| item.coverage_artifacts.as_ref())
            .and_then(|artifacts| artifacts.miri_coverage_json.as_ref())
            .map(|path| path.display().to_string()),
        verdict: miri
            .map(|item| item.verdict.to_string())
            .unwrap_or_else(|| "ERROR".into()),
        tests_run: miri.and_then(|item| item.primary_run.tests_run),
        artifact_dir: artifact_dir.display().to_string(),
    }
}

pub(super) fn summarize_fuzz_group(
    group: &StudyFuzzGroup,
    reports: &[StudyReport],
    artifact_dir: &Path,
    auto_coverage: bool,
) -> Result<FuzzGroupSummary> {
    let crate_results = reports
        .iter()
        .map(|report| report.crates.first().context("missing crate result"))
        .collect::<Result<Vec<_>>>()?;
    let summary = crate_results
        .iter()
        .map(|item| item.fuzz_summary())
        .collect::<Vec<_>>()
        .join("; ");
    let targets = crate_results
        .iter()
        .flat_map(|item| item.fuzz.iter().map(|target| target.target_name.clone()))
        .collect::<Vec<_>>();
    let coverage_jsons = crate_results
        .iter()
        .filter_map(|item| {
            item.coverage_artifacts
                .as_ref()
                .and_then(|artifacts| artifacts.fuzz_coverage_json.as_ref())
                .map(|path| path.display().to_string())
        })
        .collect::<Vec<_>>();
    Ok(FuzzGroupSummary {
        name: group.name.clone(),
        selection: if group.all {
            "all".into()
        } else {
            "selected".into()
        },
        harness_dir: display_path(group.harness_dir.as_deref()),
        budget_label: group.budget_label.clone(),
        auto_coverage,
        coverage_json: if coverage_jsons.len() == 1 {
            coverage_jsons.first().cloned()
        } else {
            None
        },
        summary,
        targets,
        artifact_dir: artifact_dir.display().to_string(),
    })
}

pub(super) fn summarize_shared(
    report: Option<&StudyReport>,
) -> (
    Option<u64>,
    Option<usize>,
    Option<usize>,
    Option<usize>,
    Option<usize>,
    Option<usize>,
) {
    let Some(report) = report else {
        return (None, None, None, None, None, None);
    };
    let Some(result) = report.crates.first() else {
        return (None, None, None, None, None, None);
    };

    let geiger_root_total = result
        .geiger
        .as_ref()
        .and_then(|geiger| geiger.root_package_result())
        .map(total_unsafe);
    let geiger_dependency_packages = result
        .geiger
        .as_ref()
        .map(|geiger| geiger.packages.iter().filter(|pkg| !pkg.is_root).count());
    let geiger_scan_gaps = result
        .geiger
        .as_ref()
        .map(|geiger| geiger.used_but_not_scanned_files.len());
    let pattern_findings = result
        .patterns
        .as_ref()
        .map(|patterns| patterns.total_findings);
    let pattern_scan_failures = result
        .patterns
        .as_ref()
        .map(|patterns| patterns.files_failed_to_scan);
    let unsafe_site_total = result
        .patterns
        .as_ref()
        .map(|patterns| patterns.unsafe_site_universe.site_total);

    (
        geiger_root_total,
        geiger_dependency_packages,
        geiger_scan_gaps,
        pattern_findings,
        pattern_scan_failures,
        unsafe_site_total,
    )
}

fn total_unsafe(package: &crate::domain::GeigerPackageResult) -> u64 {
    package.used.total_unsafe() + package.unused.total_unsafe()
}

fn display_path(path: Option<&Path>) -> Option<String> {
    path.map(|path| path.display().to_string())
}
