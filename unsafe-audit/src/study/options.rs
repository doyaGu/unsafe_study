use std::collections::BTreeMap;
use std::path::Path;

use crate::app::{AuditOptions, DiscoveryOptions, PhaseSelection};

use super::{StudyCrate, StudyDefaults, StudyFuzzGroup, StudyMiriCase, StudyRunOptions};

pub(super) fn miri_case_options(
    study_crate: &StudyCrate,
    case: &StudyMiriCase,
    options: &StudyRunOptions,
    output_dir: &Path,
    defaults: &StudyDefaults,
) -> AuditOptions {
    let mut case_options = base_audit_options(study_crate, options, output_dir, defaults);
    case_options.phases = PhaseSelection::miri_only();
    case_options.miri_triage = case.triage;
    case_options.miri_scope = case.scope;
    case_options.miri_harness_dir = case.harness_dir.clone();
    case_options.miri_args = build_miri_args(case);
    case_options.miri_auto_coverage = case.auto_coverage.unwrap_or(options.miri_auto_coverage);
    case_options
}

pub(super) fn fuzz_group_options(
    study_crate: &StudyCrate,
    group: &StudyFuzzGroup,
    options: &StudyRunOptions,
    output_dir: &Path,
    defaults: &StudyDefaults,
) -> AuditOptions {
    let mut group_options = base_audit_options(study_crate, options, output_dir, defaults);
    group_options.phases = PhaseSelection::fuzz_only();
    group_options.fuzz_time = group.time;
    group_options.fuzz_harness_dir = group.harness_dir.clone();
    group_options.fuzz_targets = if group.all {
        Vec::new()
    } else {
        group.targets.clone()
    };
    group_options.fuzz_budget_label = group.budget_label.clone();
    group_options.fuzz_env = merge_fuzz_env(&defaults.fuzz_env, &group.env, &options.fuzz_env);
    group_options.fuzz_auto_coverage = group.auto_coverage.unwrap_or(options.fuzz_auto_coverage);
    group_options
}

pub(super) fn base_audit_options(
    study_crate: &StudyCrate,
    options: &StudyRunOptions,
    output_dir: &Path,
    defaults: &StudyDefaults,
) -> AuditOptions {
    AuditOptions {
        discovery: DiscoveryOptions {
            path: study_crate.path.clone(),
            batch: false,
        },
        phases: PhaseSelection {
            geiger: false,
            miri: false,
            fuzz: false,
            patterns: false,
        },
        miri_flags: options.miri_flags.clone(),
        baseline_miri_flags: options.baseline_miri_flags.clone(),
        miri_triage: false,
        miri_scope: crate::domain::MiriScope::FullSuite,
        miri_harness_dir: None,
        miri_args: Vec::new(),
        miri_auto_coverage: options.miri_auto_coverage,
        miri_coverage_json: options.miri_coverage_json.clone(),
        fuzz_time: defaults.fuzz_time,
        fuzz_harness_dir: None,
        fuzz_env: options.fuzz_env.clone(),
        fuzz_targets: Vec::new(),
        fuzz_budget_label: None,
        fuzz_auto_coverage: options.fuzz_auto_coverage,
        fuzz_coverage_json: options.fuzz_coverage_json.clone(),
        output_dir: output_dir.to_path_buf(),
        format: options.format.clone(),
        verbose: options.verbose,
    }
}

fn build_miri_args(case: &StudyMiriCase) -> Vec<String> {
    let mut args = vec!["miri".into(), "test".into()];
    if let Some(test) = &case.test {
        args.push("--test".into());
        args.push(test.clone());
    }
    if let Some(case_name) = &case.case {
        args.push(case_name.clone());
        if case.exact {
            args.push("--".into());
            args.push("--exact".into());
        }
    }
    args
}

fn merge_fuzz_env(
    default_env: &[(String, String)],
    group_env: &[(String, String)],
    cli_env: &[(String, String)],
) -> Vec<(String, String)> {
    let mut merged = BTreeMap::new();
    for (key, value) in default_env {
        merged.insert(key.clone(), value.clone());
    }
    for (key, value) in group_env {
        merged.insert(key.clone(), value.clone());
    }
    for (key, value) in cli_env {
        merged.insert(key.clone(), value.clone());
    }
    merged.into_iter().collect()
}
