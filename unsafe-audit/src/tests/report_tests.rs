use super::*;
use crate::config::{CratePlan, RunPlan, RunProfile};
use std::path::PathBuf;
use tempfile::tempdir;

fn test_execution() -> ExecutionConfig {
    ExecutionConfig {
        profile: RunProfile::Smoke,
        jobs: 2,
        fuzz_jobs: 3,
        phases: PhaseSelection {
            scan: true,
            geiger: false,
            miri: true,
            fuzz: true,
        },
        miri_triage: true,
        fuzz_time: Some(30),
        fuzz_env: BTreeMap::from([("ASAN_OPTIONS".into(), "detect_leaks=0".into())]),
    }
}

#[test]
fn markdown_contains_crate_rows() {
    let report = Report {
        schema_version: 1,
        study_name: "s".into(),
        execution: test_execution(),
        crates: vec![CrateReport {
            name: "demo".into(),
            path: "demo".into(),
            cohort: None,
            unsafe_sites: Vec::new(),
            pattern_summary: PatternSummary::default(),
            phases: Vec::new(),
            review_priority: Vec::new(),
        }],
    };
    assert!(render_markdown(&report).contains("| demo | 0 |"));
}

#[test]
fn report_builders_pull_metadata_from_plans() {
    let plan = RunPlan {
        name: "study".into(),
        output_root: PathBuf::from("out"),
        profile: RunProfile::Smoke,
        jobs: 2,
        fuzz_jobs: 3,
        phases: PhaseSelection {
            scan: true,
            geiger: true,
            miri: false,
            fuzz: false,
        },
        formats: vec![OutputFormat::Json],
        dry_run: false,
        miri_triage: true,
        fuzz_time: Some(30),
        fuzz_env: BTreeMap::from([("ASAN_OPTIONS".into(), "detect_leaks=0".into())]),
        crates: Vec::new(),
    };
    let crate_plan = CratePlan {
        name: "demo".into(),
        path: PathBuf::from("targets/demo"),
        cohort: Some("core".into()),
        miri_cases: Vec::new(),
        fuzz_groups: Vec::new(),
    };

    let crate_report = CrateReport::from_plan(
        &crate_plan,
        Vec::new(),
        PatternSummary::default(),
        Vec::new(),
    );
    let report = Report::from_plan(&plan, vec![crate_report]);

    assert_eq!(report.study_name, "study");
    assert_eq!(report.execution.jobs, 2);
    assert_eq!(report.execution.fuzz_jobs, 3);
    assert_eq!(report.crates[0].name, "demo");
    assert_eq!(report.crates[0].path, "targets/demo");
    assert_eq!(report.crates[0].cohort.as_deref(), Some("core"));
}

#[test]
fn review_priority_prefers_high_risk_patterns() {
    let sites = vec![
        UnsafeSite {
            id: "U1".into(),
            file: "b.rs".into(),
            line: 10,
            kind: "operation".into(),
            pattern: Some("unchecked_op".into()),
        },
        UnsafeSite {
            id: "U2".into(),
            file: "a.rs".into(),
            line: 1,
            kind: "operation".into(),
            pattern: Some("transmute".into()),
        },
    ];
    let rows = build_review_priority(&sites, &PatternSummary::default(), &[]);
    assert_eq!(rows[0].site_id, "U2");
}

#[test]
fn review_priority_mentions_dynamic_findings_when_present() {
    let sites = vec![UnsafeSite {
        id: "U1".into(),
        file: "a.rs".into(),
        line: 1,
        kind: "operation".into(),
        pattern: Some("ptr_op".into()),
    }];
    let phases = vec![PhaseReport {
        kind: PhaseKind::Miri,
        name: "case".into(),
        status: PhaseStatus::Finding,
        command: Vec::new(),
        duration_ms: 0,
        log_path: None,
        summary: "ub".into(),
        evidence: PhaseEvidence::Miri {
            verdict: "ub_observed".into(),
            ub_category: Some("provenance".into()),
            excerpt: None,
        },
    }];
    let rows = build_review_priority(&sites, &PatternSummary::default(), &phases);
    assert!(rows[0].reason.contains("dynamic finding"));
}

#[test]
fn write_reports_respects_requested_formats() {
    let dir = tempdir().unwrap();
    let report = Report {
        schema_version: 1,
        study_name: "s".into(),
        execution: test_execution(),
        crates: Vec::new(),
    };
    write_reports(&report, dir.path(), &[OutputFormat::Json]).unwrap();
    assert!(dir.path().join("report.json").exists());
    assert!(!dir.path().join("report.md").exists());
}

#[test]
fn overview_marks_finding_over_error_and_clean() {
    let report = Report {
        schema_version: 1,
        study_name: "s".into(),
        execution: test_execution(),
        crates: vec![CrateReport {
            name: "demo".into(),
            path: "demo".into(),
            cohort: None,
            unsafe_sites: Vec::new(),
            pattern_summary: PatternSummary::default(),
            phases: vec![
                PhaseReport {
                    kind: PhaseKind::Miri,
                    name: "a".into(),
                    status: PhaseStatus::Error,
                    command: Vec::new(),
                    duration_ms: 0,
                    log_path: None,
                    summary: "err".into(),
                    evidence: PhaseEvidence::Scan,
                },
                PhaseReport {
                    kind: PhaseKind::Miri,
                    name: "b".into(),
                    status: PhaseStatus::Finding,
                    command: Vec::new(),
                    duration_ms: 0,
                    log_path: None,
                    summary: "finding".into(),
                    evidence: PhaseEvidence::Scan,
                },
            ],
            review_priority: Vec::new(),
        }],
    };
    assert!(render_markdown(&report).contains("| demo | 0 | - | finding | - |"));
}

#[test]
fn overview_marks_skipped_when_no_phase_ran_cleanly() {
    let report = Report {
        schema_version: 1,
        study_name: "s".into(),
        execution: test_execution(),
        crates: vec![CrateReport {
            name: "demo".into(),
            path: "demo".into(),
            cohort: None,
            unsafe_sites: Vec::new(),
            pattern_summary: PatternSummary::default(),
            phases: vec![PhaseReport {
                kind: PhaseKind::Fuzz,
                name: "fg.parse".into(),
                status: PhaseStatus::Skipped,
                command: Vec::new(),
                duration_ms: 0,
                log_path: None,
                summary: "skipped".into(),
                evidence: PhaseEvidence::Fuzz {
                    target: Some("parse".into()),
                    budget_secs: Some(30),
                    artifact: None,
                    error_kind: None,
                    runs: None,
                    excerpt: None,
                },
            }],
            review_priority: Vec::new(),
        }],
    };
    assert!(render_markdown(&report).contains("| demo | 0 | - | - | skipped |"));
}

#[test]
fn overview_marks_pass_when_fuzz_hits_budget_cleanly() {
    let report = Report {
        schema_version: 1,
        study_name: "s".into(),
        execution: test_execution(),
        crates: vec![CrateReport {
            name: "demo".into(),
            path: "demo".into(),
            cohort: None,
            unsafe_sites: Vec::new(),
            pattern_summary: PatternSummary::default(),
            phases: vec![PhaseReport {
                kind: PhaseKind::Fuzz,
                name: "fg.parse".into(),
                status: PhaseStatus::Pass,
                command: Vec::new(),
                duration_ms: 0,
                log_path: None,
                summary: "target parse, budget 30s, 123 runs, pass (reached budget limit without findings)".into(),
                evidence: PhaseEvidence::Fuzz {
                    target: Some("parse".into()),
                    budget_secs: Some(30),
                    artifact: None,
                    error_kind: None,
                    runs: Some(123),
                    excerpt: None,
                },
            }],
            review_priority: Vec::new(),
        }],
    };
    assert!(render_markdown(&report).contains("| demo | 0 | - | - | pass |"));
}

#[test]
fn overview_prefers_pass_over_clean_for_mixed_fuzz_results() {
    let report = Report {
        schema_version: 1,
        study_name: "s".into(),
        execution: test_execution(),
        crates: vec![CrateReport {
            name: "demo".into(),
            path: "demo".into(),
            cohort: None,
            unsafe_sites: Vec::new(),
            pattern_summary: PatternSummary::default(),
            phases: vec![
                PhaseReport {
                    kind: PhaseKind::Fuzz,
                    name: "fg.fast".into(),
                    status: PhaseStatus::Clean,
                    command: Vec::new(),
                    duration_ms: 0,
                    log_path: None,
                    summary: "target fast, budget 30s, clean".into(),
                    evidence: PhaseEvidence::Fuzz {
                        target: Some("fast".into()),
                        budget_secs: Some(30),
                        artifact: None,
                        error_kind: None,
                        runs: Some(50),
                        excerpt: None,
                    },
                },
                PhaseReport {
                    kind: PhaseKind::Fuzz,
                    name: "fg.deep".into(),
                    status: PhaseStatus::Pass,
                    command: Vec::new(),
                    duration_ms: 0,
                    log_path: None,
                    summary: "target deep, budget 30s, 123 runs, pass (reached budget limit without findings)".into(),
                    evidence: PhaseEvidence::Fuzz {
                        target: Some("deep".into()),
                        budget_secs: Some(30),
                        artifact: None,
                        error_kind: None,
                        runs: Some(123),
                        excerpt: None,
                    },
                },
            ],
            review_priority: Vec::new(),
        }],
    };
    assert!(render_markdown(&report).contains("| demo | 0 | - | - | pass |"));
}

#[test]
fn markdown_includes_execution_metadata() {
    let report = Report {
        schema_version: 1,
        study_name: "study".into(),
        execution: test_execution(),
        crates: Vec::new(),
    };
    let md = render_markdown(&report);
    assert!(md.contains("Study: `study`"));
    assert!(md.contains("- profile: `smoke`"));
    assert!(md.contains("- jobs: `2`"));
    assert!(md.contains("- fuzz_jobs: `3`"));
    assert!(md.contains("- phases: `scan, miri, fuzz`"));
    assert!(md.contains("- fuzz_env: `ASAN_OPTIONS=detect_leaks=0`"));
}

#[test]
fn markdown_shows_fuzz_error_kind_and_artifact_details() {
    let report = Report {
        schema_version: 1,
        study_name: "study".into(),
        execution: test_execution(),
        crates: vec![CrateReport {
            name: "demo".into(),
            path: "demo".into(),
            cohort: None,
            unsafe_sites: Vec::new(),
            pattern_summary: PatternSummary::default(),
            phases: vec![PhaseReport {
                kind: PhaseKind::Fuzz,
                name: "fg.parse".into(),
                status: PhaseStatus::Error,
                command: Vec::new(),
                duration_ms: 31_000,
                log_path: Some("/tmp/fuzz.log".into()),
                summary: "target parse, budget 30s, error".into(),
                evidence: PhaseEvidence::Fuzz {
                    target: Some("parse".into()),
                    budget_secs: Some(30),
                    artifact: Some("/tmp/crash-1".into()),
                    error_kind: Some("environment_error".into()),
                    runs: Some(123),
                    excerpt: None,
                },
            }],
            review_priority: Vec::new(),
        }],
    };
    let md = render_markdown(&report);
    assert!(md.contains("error_kind=environment_error"));
    assert!(md.contains("artifact=/tmp/crash-1"));
    assert!(md.contains("runs=123"));
}

#[test]
fn markdown_uses_lowercase_phase_labels() {
    let report = Report {
        schema_version: 1,
        study_name: "study".into(),
        execution: test_execution(),
        crates: vec![CrateReport {
            name: "demo".into(),
            path: "demo".into(),
            cohort: None,
            unsafe_sites: Vec::new(),
            pattern_summary: PatternSummary::default(),
            phases: vec![PhaseReport {
                kind: PhaseKind::Fuzz,
                name: "fg.parse".into(),
                status: PhaseStatus::Pass,
                command: Vec::new(),
                duration_ms: 31_000,
                log_path: Some("/tmp/fuzz.log".into()),
                summary: "target parse, budget 30s, 123 runs, pass (reached budget limit without findings)".into(),
                evidence: PhaseEvidence::Fuzz {
                    target: Some("parse".into()),
                    budget_secs: Some(30),
                    artifact: None,
                    error_kind: None,
                    runs: Some(123),
                    excerpt: None,
                },
            }],
            review_priority: Vec::new(),
        }],
    };
    let md = render_markdown(&report);
    assert!(md.contains("| fuzz | fg.parse | pass |"));
}