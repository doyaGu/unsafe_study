mod coverage;
mod crate_run;
mod fuzz_group;
mod fuzz_plan;
mod manifest;
mod miri_case;
mod options;
mod output;
mod render;
mod resume;
mod runtime;
mod summary;

use anyhow::{bail, Result};
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::app::{OutputFormat, PhaseSelection};
use crate::domain::{StudyReport, REPORT_SCHEMA_VERSION};
use crate_run::run_study_crate;
use manifest::{load_manifest, StudyCrate, StudyDefaults, StudyFuzzGroup, StudyMiriCase};
use output::write_study_outputs;
use resume::run_or_resume;
use runtime::{now_string, write_runtime_state};

pub use runtime::{
    read_study_runtime_state, stop_study_run, StudyRuntimeState, StudyRuntimeStatus,
};

#[derive(Debug, Clone)]
pub struct StudyRunOptions {
    pub manifest_path: PathBuf,
    pub output_root: Option<PathBuf>,
    pub selected_crates: Vec<String>,
    pub resume: bool,
    pub phases: PhaseSelection,
    pub dry_run: bool,
    pub format: OutputFormat,
    pub miri_flags: String,
    pub baseline_miri_flags: String,
    pub fuzz_env: Vec<(String, String)>,
    pub miri_auto_coverage: bool,
    pub miri_coverage_json: Option<PathBuf>,
    pub fuzz_auto_coverage: bool,
    pub fuzz_coverage_json: Option<PathBuf>,
    pub verbose: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct StudyIndex {
    pub manifest: String,
    pub output_root: String,
    pub schema_version: u32,
    pub crates: Vec<CrateStudySummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CrateStudySummary {
    pub name: String,
    pub cohort: String,
    pub coverage_tier: String,
    pub artifact_dir: String,
    pub geiger_root_total: Option<u64>,
    pub geiger_dependency_packages: Option<usize>,
    pub geiger_scan_gaps: Option<usize>,
    pub pattern_findings: Option<usize>,
    pub pattern_scan_failures: Option<usize>,
    pub unsafe_site_total: Option<usize>,
    pub unsafe_coverage_state: Option<String>,
    pub unsafe_reached_lower_bound_any: Option<usize>,
    pub unsafe_triggered_any: Option<usize>,
    pub unmapped_triggered_any: Option<usize>,
    pub miri_cases: Vec<MiriCaseSummary>,
    pub fuzz_groups: Vec<FuzzGroupSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MiriCaseSummary {
    pub name: String,
    pub scope: Option<String>,
    pub harness_dir: Option<String>,
    pub test: Option<String>,
    pub case: Option<String>,
    pub auto_coverage: bool,
    pub coverage_json: Option<String>,
    pub verdict: String,
    pub tests_run: Option<usize>,
    pub artifact_dir: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FuzzGroupSummary {
    pub name: String,
    pub selection: String,
    pub harness_dir: Option<String>,
    pub budget_label: Option<String>,
    pub auto_coverage: bool,
    pub coverage_json: Option<String>,
    pub summary: String,
    pub targets: Vec<String>,
    pub artifact_dir: String,
}

pub fn list_study_crates(manifest_path: &Path) -> Result<Vec<String>> {
    let manifest = load_manifest(manifest_path)?;
    Ok(manifest.crates.into_iter().map(|item| item.name).collect())
}

pub fn study_output_root(
    manifest_path: &Path,
    output_root_override: Option<&Path>,
) -> Result<PathBuf> {
    let manifest = load_manifest(manifest_path)?;
    Ok(output_root_override
        .map(Path::to_path_buf)
        .unwrap_or(manifest.defaults.output_root))
}

pub fn run_study_manifest(options: &StudyRunOptions) -> Result<StudyIndex> {
    let manifest = load_manifest(&options.manifest_path)?;
    let mut crates = manifest.crates;
    if !options.selected_crates.is_empty() {
        let selected = options
            .selected_crates
            .iter()
            .map(|name| name.trim())
            .filter(|name| !name.is_empty())
            .map(ToOwned::to_owned)
            .collect::<BTreeSet<_>>();
        crates.retain(|item| selected.contains(&item.name));
    }
    if crates.is_empty() {
        bail!("No study crates selected");
    }

    let output_root = options
        .output_root
        .clone()
        .unwrap_or_else(|| manifest.defaults.output_root.clone());
    std::fs::create_dir_all(&output_root)?;
    if !options.dry_run {
        write_runtime_state(
            &output_root,
            StudyRuntimeState {
                manifest: options.manifest_path.display().to_string(),
                output_root: output_root.display().to_string(),
                pid: std::process::id(),
                status: StudyRuntimeStatus::Running,
                current_crate: None,
                current_segment: None,
                updated_at: now_string(),
                completed_crates: 0,
            },
        )?;
    }

    let mut summaries = Vec::new();
    for study_crate in crates {
        if !options.dry_run {
            write_runtime_state(
                &output_root,
                StudyRuntimeState {
                    manifest: options.manifest_path.display().to_string(),
                    output_root: output_root.display().to_string(),
                    pid: std::process::id(),
                    status: StudyRuntimeStatus::Running,
                    current_crate: Some(study_crate.name.clone()),
                    current_segment: None,
                    updated_at: now_string(),
                    completed_crates: summaries.len(),
                },
            )?;
        }
        println!("[study] {}", study_crate.name);
        let summary = run_study_crate(&study_crate, &manifest.defaults, &output_root, options)?;
        summaries.push(summary);
        if !options.dry_run {
            let partial_index = StudyIndex {
                manifest: options.manifest_path.display().to_string(),
                output_root: output_root.display().to_string(),
                schema_version: REPORT_SCHEMA_VERSION,
                crates: summaries.clone(),
            };
            write_study_outputs(&output_root, &partial_index)?;
        }
    }

    let index = StudyIndex {
        manifest: options.manifest_path.display().to_string(),
        output_root: output_root.display().to_string(),
        schema_version: REPORT_SCHEMA_VERSION,
        crates: summaries,
    };

    if !options.dry_run {
        write_study_outputs(&output_root, &index)?;
    }
    if !options.dry_run {
        write_runtime_state(
            &output_root,
            StudyRuntimeState {
                manifest: options.manifest_path.display().to_string(),
                output_root: output_root.display().to_string(),
                pid: std::process::id(),
                status: StudyRuntimeStatus::Completed,
                current_crate: None,
                current_segment: None,
                updated_at: now_string(),
                completed_crates: index.crates.len(),
            },
        )?;
    }

    Ok(index)
}

pub(super) fn first_crate(report: &StudyReport) -> Option<&crate::domain::CrateAuditResult> {
    report.crates.first()
}

#[cfg(test)]
mod tests;
