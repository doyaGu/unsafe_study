pub mod analyzer;
pub mod app;
pub mod coverage;
pub mod coverage_backend;
pub mod domain;
mod explore;
mod infra;
mod phases;
mod render;
mod study;

use anyhow::{bail, Result};
use std::fmt::Write as _;

pub use app::{AuditOptions, DiscoveryOptions, ExplorationOptions, OutputFormat, PhaseSelection};
pub use domain::{CrateAuditResult, CrateTarget, StudyReport, REPORT_SCHEMA_VERSION};
pub use explore::{run_exploration, run_exploration_and_write};
pub use infra::OutputLayout;
pub use render::{generate_json as render_json, generate_markdown as render_markdown};
pub use study::{
    list_study_crates, read_study_runtime_state, run_study_manifest, stop_study_run,
    study_output_root, StudyIndex, StudyRunOptions, StudyRuntimeState, StudyRuntimeStatus,
};

use crate::domain::{DynamicCoverageArtifacts, PhaseIssue, PhaseKind};
use crate::infra::TargetDiscovery;

pub fn discover_targets(options: &DiscoveryOptions) -> Result<Vec<CrateTarget>> {
    TargetDiscovery::discover(&options.path, options.batch)
}

pub fn run(options: &AuditOptions) -> Result<StudyReport> {
    let crates = discover_targets(&options.discovery)?;
    if crates.is_empty() {
        bail!("No crates found at {}", options.discovery.path.display());
    }

    let layout = OutputLayout::new(options.output_dir.clone());
    let mut results = Vec::new();
    for target in crates {
        results.push(run_crate_audit(&target, options, &layout));
    }

    Ok(StudyReport {
        schema_version: REPORT_SCHEMA_VERSION,
        timestamp: chrono::Local::now().to_rfc3339(),
        crates: results,
    })
}

pub fn run_and_write(options: &AuditOptions) -> Result<StudyReport> {
    let layout = OutputLayout::new(options.output_dir.clone());
    layout.create_dirs()?;
    let report = run(options)?;
    write_report(options, &report)?;
    Ok(report)
}

pub fn write_report(options: &AuditOptions, report: &StudyReport) -> Result<()> {
    let layout = OutputLayout::new(options.output_dir.clone());
    if options.format.writes_json() {
        std::fs::write(layout.report_json_path(), render_json(report)?)?;
    }
    if options.format.writes_markdown() {
        std::fs::write(layout.report_markdown_path(), render_markdown(report))?;
    }
    Ok(())
}

pub fn planned_command(options: &AuditOptions) -> String {
    let mut command = String::from("unsafe-audit ");
    let _ = write!(
        command,
        "{} --output {} --format {}",
        options.discovery.path.display(),
        options.output_dir.display(),
        output_format_name(&options.format)
    );
    if !options.phases.geiger {
        command.push_str(" --skip-geiger");
    }
    if !options.phases.miri {
        command.push_str(" --skip-miri");
    }
    if !options.phases.fuzz {
        command.push_str(" --skip-fuzz");
    }
    if !options.phases.patterns {
        command.push_str(" --skip-patterns");
    }
    if options.phases.miri {
        let _ = write!(command, " --miri-scope {}", options.miri_scope);
        if let Some(dir) = &options.miri_harness_dir {
            let _ = write!(command, " --miri-harness-dir {}", dir.display());
        }
        if options.miri_auto_coverage {
            command.push_str(" --miri-auto-coverage");
        }
        if let Some(path) = &options.miri_coverage_json {
            let _ = write!(command, " --miri-coverage-json {}", path.display());
        }
        for arg in &options.miri_args {
            let _ = write!(command, " --miri-arg {}", arg);
        }
        if options.miri_triage {
            command.push_str(" --miri-triage");
        }
    }
    if options.phases.fuzz {
        let _ = write!(command, " --fuzz-time {}", options.fuzz_time);
        if let Some(label) = &options.fuzz_budget_label {
            let _ = write!(command, " --fuzz-budget-label {}", label);
        }
        if let Some(dir) = &options.fuzz_harness_dir {
            let _ = write!(command, " --fuzz-harness-dir {}", dir.display());
        }
        if options.fuzz_auto_coverage {
            command.push_str(" --fuzz-auto-coverage");
        }
        if let Some(path) = &options.fuzz_coverage_json {
            let _ = write!(command, " --fuzz-coverage-json {}", path.display());
        }
        for (key, value) in &options.fuzz_env {
            let _ = write!(command, " --fuzz-env {}={}", key, value);
        }
        for target in &options.fuzz_targets {
            let _ = write!(command, " --fuzz-target {}", target);
        }
    }
    command
}

fn run_crate_audit(
    target: &CrateTarget,
    options: &AuditOptions,
    layout: &OutputLayout,
) -> CrateAuditResult {
    let mut result = CrateAuditResult {
        target: target.clone(),
        geiger: None,
        miri: None,
        fuzz: Vec::new(),
        patterns: None,
        unsafe_site_reach: None,
        unsafe_coverage: None,
        coverage_artifacts: None,
        exploration: None,
        phase_issues: Vec::new(),
    };

    if options.phases.geiger {
        match phases::geiger::run(&target.dir, &layout.geiger_log_path(target.display_name())) {
            Ok(geiger) => result.geiger = Some(geiger),
            Err(error) => result
                .phase_issues
                .push(phase_issue(PhaseKind::Geiger, error)),
        }
    }

    if options.phases.miri {
        let strict_log = layout.miri_log_path(target.display_name(), "strict");
        let baseline_log = layout.miri_log_path(target.display_name(), "baseline");
        let miri = if options.miri_triage {
            phases::miri::run_with_triage(
                &target.dir,
                options.miri_scope,
                options.miri_harness_dir.as_deref(),
                &options.miri_args,
                &options.miri_flags,
                &options.baseline_miri_flags,
                &strict_log,
                &baseline_log,
            )
        } else {
            phases::miri::run(
                &target.dir,
                options.miri_scope,
                options.miri_harness_dir.as_deref(),
                &options.miri_args,
                &options.miri_flags,
                &strict_log,
            )
        };
        match miri {
            Ok(miri) => result.miri = Some(miri),
            Err(error) => result
                .phase_issues
                .push(phase_issue(PhaseKind::Miri, error)),
        }
    }

    if options.phases.fuzz {
        match phases::fuzz::run(
            &target.dir,
            options.fuzz_harness_dir.as_deref(),
            options.fuzz_time,
            &options.fuzz_env,
            &options.fuzz_targets,
            options.fuzz_budget_label.as_deref(),
            &layout.fuzz_logs,
        ) {
            Ok(fuzz) => result.fuzz = fuzz,
            Err(error) => result
                .phase_issues
                .push(phase_issue(PhaseKind::Fuzz, error)),
        }
    }

    if options.phases.patterns {
        match analyzer::analyze_crate(&target.dir) {
            Ok(patterns) => result.patterns = Some(patterns),
            Err(error) => result
                .phase_issues
                .push(phase_issue(PhaseKind::Patterns, error)),
        }
    }

    let effective_miri_coverage_json = if options.miri_auto_coverage
        && options.phases.miri
        && result.miri.is_some()
        && options.miri_coverage_json.is_none()
    {
        match auto_export_miri_coverage(target, result.miri.as_ref().unwrap(), layout) {
            Ok(path) => Some(path),
            Err(error) => {
                result.phase_issues.push(PhaseIssue {
                    phase: PhaseKind::Miri,
                    message: format!("automatic Miri coverage export failed: {error}"),
                });
                None
            }
        }
    } else {
        options.miri_coverage_json.clone()
    };
    let effective_fuzz_log_dir = if options.fuzz_auto_coverage && options.phases.fuzz {
        Some(layout.coverage_artifacts.clone())
    } else {
        None
    };

    let effective_fuzz_coverage_json = if options.fuzz_auto_coverage
        && options.phases.fuzz
        && !result.fuzz.is_empty()
        && options.fuzz_coverage_json.is_none()
    {
        match auto_export_fuzz_coverage(target, &result.fuzz, options, layout) {
            Ok(path) => Some(path),
            Err(error) => {
                result.phase_issues.push(PhaseIssue {
                    phase: PhaseKind::Fuzz,
                    message: format!("automatic fuzz coverage export failed: {error}"),
                });
                None
            }
        }
    } else {
        options.fuzz_coverage_json.clone()
    };
    result.coverage_artifacts = Some(DynamicCoverageArtifacts {
        miri_coverage_json: effective_miri_coverage_json.clone(),
        miri_coverage_build_log: (options.miri_auto_coverage && options.phases.miri)
            .then(|| layout.miri_coverage_log_path(target.display_name(), "coverage-build"))
            .filter(|path| path.exists()),
        miri_coverage_run_log: (options.miri_auto_coverage && options.phases.miri)
            .then(|| layout.miri_coverage_log_path(target.display_name(), "coverage-run"))
            .filter(|path| path.exists()),
        fuzz_coverage_json: effective_fuzz_coverage_json.clone(),
        fuzz_coverage_log_dir: effective_fuzz_log_dir.filter(|path| path.exists()),
    });

    let (unsafe_site_reach, unsafe_coverage) = coverage::derive(
        &target.dir,
        result.patterns.as_ref(),
        result.miri.as_ref(),
        &result.fuzz,
        effective_miri_coverage_json.as_deref(),
        effective_fuzz_coverage_json.as_deref(),
    );
    result.unsafe_site_reach = unsafe_site_reach;
    result.unsafe_coverage = unsafe_coverage;

    result
}

fn auto_export_miri_coverage(
    target: &CrateTarget,
    miri: &crate::domain::MiriResult,
    layout: &OutputLayout,
) -> Result<std::path::PathBuf> {
    let output_json = layout.miri_coverage_json_path(target.display_name());
    crate::coverage_backend::auto_export_miri_coverage_json(
        &miri.invocation,
        &output_json,
        &layout.miri_coverage_log_path(target.display_name(), "coverage-build"),
        &layout.miri_coverage_log_path(target.display_name(), "coverage-run"),
    )?;
    Ok(output_json)
}

fn auto_export_fuzz_coverage(
    target: &CrateTarget,
    fuzz_results: &[crate::domain::FuzzTargetResult],
    options: &AuditOptions,
    layout: &OutputLayout,
) -> Result<std::path::PathBuf> {
    let harness_root = fuzz_results
        .iter()
        .find_map(|result| result.harness_dir.clone())
        .unwrap_or_else(|| target.dir.clone());
    let targets = fuzz_results
        .iter()
        .filter(|result| matches!(result.scope, crate::domain::FuzzScope::ExistingHarness))
        .map(|result| result.target_name.clone())
        .collect::<Vec<_>>();
    if targets.is_empty() {
        bail!("no runnable fuzz targets were recorded for coverage replay");
    }

    let output_json = layout.fuzz_coverage_json_path(target.display_name());
    crate::coverage_backend::auto_export_fuzz_coverage_json(
        &harness_root,
        &options.fuzz_env,
        &targets,
        &output_json,
        &layout.coverage_artifacts,
        target.display_name(),
    )?;
    Ok(output_json)
}

fn phase_issue(phase: PhaseKind, error: anyhow::Error) -> PhaseIssue {
    PhaseIssue {
        phase,
        message: error.to_string(),
    }
}

fn output_format_name(format: &OutputFormat) -> &'static str {
    match format {
        OutputFormat::Json => "json",
        OutputFormat::Markdown => "markdown",
        OutputFormat::Both => "both",
    }
}
