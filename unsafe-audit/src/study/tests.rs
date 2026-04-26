use super::*;
use crate::app::{AuditOptions, DiscoveryOptions, PhaseSelection};
use crate::infra::OutputLayout;
use crate::study::fuzz_plan::planned_fuzz_targets;
use crate::study::resume::load_existing_report;

#[test]
fn loads_normalized_study_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("study")).unwrap();
    let manifest = root.join("study").join("manifest.toml");
    std::fs::write(
        &manifest,
        r#"[study]
output_root = "study/output"
fuzz_time = 3600
fuzz_env = { ASAN_OPTIONS = "detect_leaks=0" }

[[crate]]
name = "demo"
path = "targets/demo"
cohort = "baseline"
coverage_tier = "tier1"

[[crate.miri_case]]
name = "full"
scope = "full_suite"

[[crate.fuzz_group]]
name = "existing"
all = true
harness_dir = "fuzz_harnesses/demo"
env = { RUST_LOG = "debug" }
"#,
    )
    .unwrap();

    let loaded = load_manifest(&manifest).unwrap();
    assert_eq!(loaded.crates.len(), 1);
    assert_eq!(loaded.crates[0].name, "demo");
    assert_eq!(loaded.crates[0].miri_cases.len(), 1);
    assert_eq!(loaded.crates[0].fuzz_groups.len(), 1);
    assert_eq!(
        loaded.crates[0].fuzz_groups[0]
            .harness_dir
            .as_deref()
            .map(|path| path.display().to_string()),
        Some(root.join("fuzz_harnesses/demo").display().to_string())
    );
    assert_eq!(loaded.defaults.fuzz_time, 3600);
    assert_eq!(
        loaded.defaults.fuzz_env,
        vec![("ASAN_OPTIONS".into(), "detect_leaks=0".into())]
    );
    assert_eq!(
        loaded.crates[0].fuzz_groups[0].env,
        vec![("RUST_LOG".into(), "debug".into())]
    );
}

#[test]
fn loads_existing_segment_report_for_resume() {
    let dir = tempfile::tempdir().unwrap();
    let output_dir = dir.path().join("demo");
    let options = AuditOptions {
        discovery: DiscoveryOptions {
            path: dir.path().to_path_buf(),
            batch: false,
        },
        phases: PhaseSelection::shared_static(),
        miri_flags: String::new(),
        baseline_miri_flags: String::new(),
        miri_triage: false,
        miri_scope: crate::domain::MiriScope::FullSuite,
        miri_harness_dir: None,
        miri_args: Vec::new(),
        miri_auto_coverage: false,
        miri_coverage_json: None,
        fuzz_time: 1,
        fuzz_harness_dir: None,
        fuzz_env: Vec::new(),
        fuzz_targets: Vec::new(),
        fuzz_budget_label: None,
        fuzz_auto_coverage: false,
        fuzz_coverage_json: None,
        output_dir: output_dir.clone(),
        format: OutputFormat::Json,
        verbose: false,
    };
    let report = StudyReport {
        schema_version: REPORT_SCHEMA_VERSION,
        timestamp: "2026-04-21T00:00:00-04:00".into(),
        crates: vec![crate::domain::CrateAuditResult {
            target: crate::domain::CrateTarget {
                metadata: crate::domain::CrateMetadata {
                    name: "demo".into(),
                    version: "0.1.0".into(),
                },
                dir: dir.path().join("targets").join("demo"),
            },
            geiger: None,
            miri: None,
            fuzz: Vec::new(),
            patterns: None,
            unsafe_site_reach: None,
            unsafe_coverage: None,
            coverage_artifacts: None,
            exploration: None,
            phase_issues: Vec::new(),
        }],
    };

    std::fs::create_dir_all(&output_dir).unwrap();
    std::fs::write(
        OutputLayout::new(output_dir.clone()).report_json_path(),
        serde_json::to_string_pretty(&report).unwrap(),
    )
    .unwrap();

    let loaded = load_existing_report(&options).unwrap().unwrap();
    assert_eq!(loaded.schema_version, REPORT_SCHEMA_VERSION);
    assert_eq!(loaded.crates.len(), 1);
    assert_eq!(loaded.crates[0].target.metadata.name, "demo");
}

#[test]
fn planned_fuzz_targets_expand_all_bins_from_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("targets/demo/fuzz")).unwrap();
    std::fs::write(
        root.join("targets/demo/fuzz/Cargo.toml"),
        r#"
[[bin]]
name = "beta"
path = "fuzz_targets/beta.rs"

[[bin]]
name = "alpha"
path = "fuzz_targets/alpha.rs"
"#,
    )
    .unwrap();

    let study_crate = StudyCrate {
        name: "demo".into(),
        path: root.join("targets/demo"),
        cohort: "baseline".into(),
        coverage_tier: "tier1".into(),
        miri_cases: Vec::new(),
        fuzz_groups: Vec::new(),
    };
    let group = StudyFuzzGroup {
        name: "all_targets".into(),
        harness_dir: None,
        auto_coverage: None,
        all: true,
        targets: Vec::new(),
        time: 1,
        budget_label: None,
        env: Vec::new(),
    };

    let targets = planned_fuzz_targets(&study_crate, &group).unwrap();
    assert_eq!(targets, vec!["alpha", "beta"]);
}

#[test]
fn rejects_legacy_dir_field_in_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("study")).unwrap();
    let manifest = root.join("study").join("manifest.toml");
    std::fs::write(
        &manifest,
        r#"[study]
output_root = "study/output"
fuzz_time = 3600

[[crate]]
name = "demo"
path = "targets/demo"
cohort = "baseline"
coverage_tier = "tier1"

[[crate.miri_case]]
name = "full"
scope = "full_suite"
dir = "extensions_harness"
"#,
    )
    .unwrap();

    assert!(load_manifest(&manifest).is_err());
}
