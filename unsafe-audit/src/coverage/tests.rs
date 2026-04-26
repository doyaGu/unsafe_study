use super::*;
use crate::analyzer::{Severity, UnsafePattern, UnsafeSite, UnsafeSiteUniverse, UnsafeSummary};
use crate::domain::{
    CommandInvocation, ExecutionOutcome, MiriResult, MiriRun, MiriScope, MiriVerdict,
    UnsafeCoverageState,
};
use std::fs;
use std::path::{Path, PathBuf};

fn sample_patterns() -> UnsafeSummary {
    UnsafeSummary {
        crate_name: "demo".into(),
        crate_version: "0.1.0".into(),
        total_findings: 1,
        risky_operation_findings: 1,
        unsafe_block_findings: 0,
        unsafe_declaration_findings: 0,
        extern_item_findings: 0,
        files_with_unsafe: 1,
        files_scanned: 1,
        files_failed_to_scan: 0,
        scan_failures: Vec::new(),
        patterns: Vec::new(),
        findings: Vec::new(),
        unsafe_sites: vec![UnsafeSite {
            site_id: "demo:src/lib.rs:10:4:risky_operation:transmute".into(),
            kind: crate::analyzer::FindingKind::RiskyOperation,
            pattern: UnsafePattern::Transmute,
            file: PathBuf::from("/tmp/demo/src/lib.rs"),
            line: 10,
            column: 4,
            end_line: 10,
            end_column: 20,
            snippet: "transmute".into(),
            severity: Severity::High,
            context: "f".into(),
        }],
        unsafe_site_universe: UnsafeSiteUniverse {
            site_total: 1,
            risky_operation_sites: 1,
            unsafe_block_sites: 0,
            unsafe_declaration_sites: 0,
            extern_item_sites: 0,
        },
        risk_score: 1.0,
    }
}

#[test]
fn static_universe_only_when_no_dynamic_phase_ran() {
    let patterns = sample_patterns();
    let (_, summary) = derive(
        Path::new("/tmp/demo"),
        Some(&patterns),
        None,
        &[],
        None,
        None,
    );
    let summary = summary.unwrap();
    assert_eq!(summary.state, UnsafeCoverageState::StaticUniverseOnly);
    assert_eq!(summary.total_sites, 1);
    assert_eq!(summary.triggered_by_any, None);
}

#[test]
fn no_fuzz_target_available_keeps_static_universe_only() {
    let patterns = sample_patterns();
    let fuzz = vec![FuzzTargetResult {
        target_name: "(none)".into(),
        scope: crate::domain::FuzzScope::NoneAvailable,
        status: FuzzStatus::NoFuzzDir,
        harness_dir: None,
        execution: None,
        requested_time_budget_secs: 60,
        budget_label: None,
        environment_overrides: Vec::new(),
        total_runs: None,
        edges_covered: None,
        artifact_path: None,
        reproducer_size_bytes: None,
    }];

    let (_, summary) = derive(
        Path::new("/tmp/demo"),
        Some(&patterns),
        None,
        &fuzz,
        None,
        None,
    );

    assert_eq!(
        summary.unwrap().state,
        UnsafeCoverageState::StaticUniverseOnly
    );
}

#[test]
fn maps_miri_ub_location_to_site() {
    let patterns = sample_patterns();
    let miri = MiriResult {
        scope: MiriScope::Targeted,
        invocation: CommandInvocation {
            working_dir: PathBuf::from("/tmp/demo"),
            args: vec!["miri".into(), "test".into()],
        },
        verdict: MiriVerdict::TruePositiveUb,
        triage_summary: None,
        primary_run: MiriRun {
            flags: String::new(),
            execution: ExecutionOutcome {
                success: false,
                exit_code: Some(1),
                duration_secs: 1.0,
                log_path: PathBuf::from("strict.log"),
                log_excerpt: None,
            },
            tests_run: None,
            tests_passed: None,
            tests_failed: None,
            ub_detected: true,
            ub_category: None,
            ub_message: None,
            ub_location: Some("src/lib.rs:10:8".into()),
        },
        baseline_run: None,
    };

    let (reach, summary) = derive(
        Path::new("/tmp/demo"),
        Some(&patterns),
        Some(&miri),
        &[],
        None,
        None,
    );
    let reach = reach.unwrap();
    let summary = summary.unwrap();

    assert_eq!(summary.state, UnsafeCoverageState::TriggeredEvidenceOnly);
    assert_eq!(summary.reached_by_miri, Some(1));
    assert_eq!(summary.triggered_by_miri, Some(1));
    assert!(reach[0].reached_by_miri);
    assert!(reach[0].triggered_by_miri);
}

#[test]
fn parses_fuzz_panic_location_and_maps_site() {
    let temp = tempfile::tempdir().unwrap();
    let crate_dir = temp.path().join("demo");
    fs::create_dir_all(crate_dir.join("src")).unwrap();
    fs::write(
        temp.path().join("panic.log"),
        format!(
            "thread '<unnamed>' panicked at {}:10:9:\n",
            crate_dir.join("src/lib.rs").display()
        ),
    )
    .unwrap();

    let patterns = UnsafeSummary {
        unsafe_sites: vec![UnsafeSite {
            site_id: "demo:src/lib.rs:10:4:risky_operation:transmute".into(),
            kind: crate::analyzer::FindingKind::RiskyOperation,
            pattern: UnsafePattern::Transmute,
            file: crate_dir.join("src/lib.rs"),
            line: 10,
            column: 4,
            end_line: 10,
            end_column: 20,
            snippet: "transmute".into(),
            severity: Severity::High,
            context: "f".into(),
        }],
        ..sample_patterns()
    };

    let fuzz = vec![FuzzTargetResult {
        target_name: "demo".into(),
        scope: crate::domain::FuzzScope::ExistingHarness,
        status: FuzzStatus::Panic,
        harness_dir: None,
        execution: Some(ExecutionOutcome {
            success: false,
            exit_code: Some(1),
            duration_secs: 1.0,
            log_path: temp.path().join("panic.log"),
            log_excerpt: None,
        }),
        requested_time_budget_secs: 1,
        budget_label: None,
        environment_overrides: Vec::new(),
        total_runs: None,
        edges_covered: None,
        artifact_path: None,
        reproducer_size_bytes: None,
    }];

    let (reach, summary) = derive(&crate_dir, Some(&patterns), None, &fuzz, None, None);
    let reach = reach.unwrap();
    let summary = summary.unwrap();

    assert_eq!(summary.state, UnsafeCoverageState::TriggeredEvidenceOnly);
    assert_eq!(summary.reached_by_fuzz, Some(1));
    assert_eq!(summary.triggered_by_fuzz, Some(1));
    assert!(reach[0].reached_by_fuzz);
    assert!(reach[0].triggered_by_fuzz);
}

#[test]
fn maps_source_coverage_json_to_computed_reach() {
    let temp = tempfile::tempdir().unwrap();
    let crate_dir = temp.path().join("demo");
    fs::create_dir_all(crate_dir.join("src")).unwrap();
    let coverage_json = temp.path().join("coverage.json");
    fs::write(
        &coverage_json,
        format!(
            r#"{{
  "data": [
    {{
      "files": [
        {{
          "filename": "{}",
          "segments": [
            [10, 5, 1, true, true, false],
            [10, 15, 0, true, true, false]
          ]
        }}
      ]
    }}
  ]
}}"#,
            crate_dir.join("src/lib.rs").display()
        ),
    )
    .unwrap();

    let patterns = UnsafeSummary {
        unsafe_sites: vec![UnsafeSite {
            site_id: "demo:src/lib.rs:10:4:risky_operation:transmute".into(),
            kind: crate::analyzer::FindingKind::RiskyOperation,
            pattern: UnsafePattern::Transmute,
            file: crate_dir.join("src/lib.rs"),
            line: 10,
            column: 4,
            end_line: 10,
            end_column: 20,
            snippet: "transmute".into(),
            severity: Severity::High,
            context: "f".into(),
        }],
        ..sample_patterns()
    };

    let (reach, summary) = derive(
        &crate_dir,
        Some(&patterns),
        None,
        &[],
        Some(&coverage_json),
        None,
    );
    let reach = reach.unwrap();
    let summary = summary.unwrap();

    assert_eq!(summary.state, UnsafeCoverageState::Computed);
    assert_eq!(summary.reached_by_miri, Some(1));
    assert_eq!(summary.reached_by_any, Some(1));
    assert_eq!(summary.triggered_by_any, Some(0));
    assert!(reach[0].reached_by_miri);
    assert!(!reach[0].triggered_by_miri);
}
