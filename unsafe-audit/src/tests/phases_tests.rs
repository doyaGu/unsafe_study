use super::*;
use crate::config::{CratePlan, FuzzGroupPlan, MiriCasePlan};
use std::sync::Mutex;
use tempfile::tempdir;

struct ScriptedExecutor {
    outputs: Mutex<Vec<CommandOutput>>,
    calls: Mutex<Vec<CommandSpec>>,
}

impl ScriptedExecutor {
    fn new(outputs: Vec<CommandOutput>) -> Self {
        Self {
            outputs: Mutex::new(outputs),
            calls: Mutex::new(Vec::new()),
        }
    }
}

impl CommandExecutor for ScriptedExecutor {
    fn run(&self, spec: &CommandSpec) -> Result<CommandOutput> {
        self.calls.lock().unwrap().push(spec.clone());
        Ok(self.outputs.lock().unwrap().remove(0))
    }
}

fn output(success: bool, text: &str) -> CommandOutput {
    CommandOutput {
        success,
        exit_code: Some(if success { 0 } else { 1 }),
        duration_ms: 10,
        combined_output: text.into(),
    }
}

fn crate_plan(path: PathBuf) -> CratePlan {
    CratePlan {
        name: "demo".into(),
        path,
        cohort: None,
        miri_cases: Vec::new(),
        fuzz_groups: Vec::new(),
    }
}

fn create_built_fuzz_binary(root: &Path, target: &str) {
    let dir = root
        .join("fuzz")
        .join("target")
        .join("host")
        .join("release");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(target), "bin").unwrap();
}

#[test]
fn miri_verdict_separates_strict_only() {
    let strict = CommandOutput {
        success: false,
        exit_code: Some(1),
        duration_ms: 1,
        combined_output: "undefined behavior: stacked borrow".into(),
    };
    let baseline = CommandOutput {
        success: true,
        exit_code: Some(0),
        duration_ms: 1,
        combined_output: "ok".into(),
    };
    assert_eq!(miri_verdict(&strict, Some(&baseline)), "strict_only_ub");
}

#[test]
fn fuzz_crash_is_finding() {
    let output = CommandOutput {
        success: false,
        exit_code: Some(77),
        duration_ms: 1,
        combined_output: "panic occurred".into(),
    };
    assert_eq!(classify_fuzz_status(&output), PhaseStatus::Finding);
}

#[test]
fn fuzz_budget_stop_is_pass_not_clean() {
    let output = CommandOutput {
        success: true,
        exit_code: Some(0),
        duration_ms: 1,
        combined_output: "Done 19313761 runs in 31 second(s)".into(),
    };
    assert_eq!(classify_fuzz_status(&output), PhaseStatus::Pass);
    assert!(fuzz_reached_budget(&output.combined_output));
    assert_eq!(fuzz_error_kind(&output, classify_fuzz_status(&output)), None);
}

#[test]
fn fuzz_lsan_ptrace_failure_is_error_not_finding() {
    let output = CommandOutput {
        success: false,
        exit_code: Some(1),
        duration_ms: 1,
        combined_output:
            "LeakSanitizer has encountered a fatal error. does not work under ptrace".into(),
    };
    assert_eq!(classify_fuzz_status(&output), PhaseStatus::Error);
    assert!(is_lsan_ptrace_error(&output.combined_output));
    assert_eq!(
        fuzz_error_kind(&output, classify_fuzz_status(&output)).as_deref(),
        Some("environment_error")
    );
}

#[test]
fn geiger_writes_log_and_extracts_root_and_dependency_counts() {
    let dir = tempdir().unwrap();
    let geiger_output = format!(
        "{{\"$message_type\":\"artifact\"}}\n\
{{\"packages\":[\
{{\"package\":{{\"id\":{{\"name\":\"demo\",\"source\":{{\"Path\":\"file://{}%230.1.0\"}}}}}},\"unsafety\":{{\"used\":{{\"functions\":{{\"unsafe_\":1}},\"exprs\":{{\"unsafe_\":4}},\"item_impls\":{{\"unsafe_\":0}},\"item_traits\":{{\"unsafe_\":0}},\"methods\":{{\"unsafe_\":2}}}}}}}},\
{{\"package\":{{\"id\":{{\"name\":\"dep\",\"source\":{{\"Registry\":{{\"name\":\"crates.io\"}}}}}}}},\"unsafety\":{{\"used\":{{\"functions\":{{\"unsafe_\":3}},\"exprs\":{{\"unsafe_\":1}},\"item_impls\":{{\"unsafe_\":0}},\"item_traits\":{{\"unsafe_\":0}},\"methods\":{{\"unsafe_\":1}}}}}}}}\
]}}",
        dir.path().display()
    );
    let executor = ScriptedExecutor::new(vec![output(true, &geiger_output)]);
    let phase = run_geiger(&crate_plan(dir.path().into()), dir.path(), &executor).unwrap();
    assert_eq!(phase.status, PhaseStatus::Clean);
    assert!(phase.summary.contains("root unsafe 7, dependency unsafe 5"));
    match phase.evidence {
        PhaseEvidence::Geiger {
            root_unsafe,
            dependency_unsafe,
            ..
        } => {
            assert_eq!(root_unsafe, Some(7));
            assert_eq!(dependency_unsafe, Some(5));
        }
        _ => panic!("expected geiger evidence"),
    }
    assert!(std::path::Path::new(phase.log_path.as_ref().unwrap()).exists());
}

#[test]
fn geiger_tool_panic_becomes_skipped() {
    let dir = tempdir().unwrap();
    let executor = ScriptedExecutor::new(vec![output(
        false,
        "thread 'main' panicked at cargo/core/package.rs:736:9\nassertion failed: self.pending_ids.insert(id)",
    )]);

    let phase = run_geiger(&crate_plan(dir.path().into()), dir.path(), &executor).unwrap();

    assert_eq!(phase.status, PhaseStatus::Skipped);
    assert!(phase.summary.contains("skipped"));
}

#[test]
fn geiger_uses_member_package_when_root_is_virtual_manifest() {
    let dir = tempdir().unwrap();
    std::fs::write(
        dir.path().join("Cargo.toml"),
        "[workspace]\nmembers=['pulldown-cmark']\n",
    )
    .unwrap();
    let member = dir.path().join("pulldown-cmark");
    std::fs::create_dir(&member).unwrap();
    std::fs::write(
        member.join("Cargo.toml"),
        "[package]\nname='pulldown-cmark'\nversion='0.1.0'\n",
    )
    .unwrap();
    let mut plan = crate_plan(dir.path().into());
    plan.name = "pulldown-cmark".into();
    let executor = ScriptedExecutor::new(vec![output(true, "{\"packages\":[]}")]);

    let _ = run_geiger(&plan, dir.path(), &executor).unwrap();

    let calls = executor.calls.lock().unwrap();
    assert_eq!(calls[0].current_dir, member);
}

#[test]
fn miri_case_uses_harness_test_filter_exact_and_triage() {
    let dir = tempdir().unwrap();
    let harness = dir.path().join("harness");
    std::fs::create_dir(&harness).unwrap();
    let mut plan = crate_plan(dir.path().into());
    plan.miri_cases.push(MiriCasePlan {
        name: "targeted".into(),
        scope: "targeted".into(),
        harness_dir: Some(harness.clone()),
        test: Some("api_smoke".into()),
        case: Some("case_name".into()),
        exact: true,
    });
    let executor = ScriptedExecutor::new(vec![
        output(false, "undefined behavior: stacked borrow"),
        output(true, "test result: ok. 1 passed; 0 failed"),
    ]);

    let phases = run_miri_cases(&plan, true, dir.path(), &executor).unwrap();
    assert_eq!(phases[0].status, PhaseStatus::Finding);
    assert!(phases[0].summary.contains("strict_only_ub"));
    assert_eq!(executor.calls.lock().unwrap().len(), 2);
    let calls = executor.calls.lock().unwrap();
    let first = &calls[0];
    assert_eq!(first.current_dir, harness);
    assert_eq!(
        first.args,
        vec![
            "miri",
            "test",
            "--test",
            "api_smoke",
            "case_name",
            "--",
            "--exact"
        ]
    );
}

#[test]
fn clean_miri_case_does_not_report_ub_category() {
    let dir = tempdir().unwrap();
    let mut plan = crate_plan(dir.path().into());
    plan.miri_cases.push(MiriCasePlan {
        name: "targeted".into(),
        scope: "targeted".into(),
        harness_dir: None,
        test: Some("unaligned_public_inputs".into()),
        case: None,
        exact: false,
    });
    let executor = ScriptedExecutor::new(vec![output(
        true,
        "test unaligned_public_inputs ... ok\n\ntest result: ok. 1 passed; 0 failed",
    )]);

    let phases = run_miri_cases(&plan, false, dir.path(), &executor).unwrap();

    match &phases[0].evidence {
        PhaseEvidence::Miri {
            verdict,
            ub_category,
            ..
        } => {
            assert_eq!(verdict, "clean");
            assert_eq!(*ub_category, None);
        }
        _ => panic!("expected miri evidence"),
    }
}

#[test]
fn fuzz_all_discovers_targets_runs_each_and_parses_runs() {
    let dir = tempdir().unwrap();
    create_built_fuzz_binary(dir.path(), "parse");
    create_built_fuzz_binary(dir.path(), "other");
    let mut plan = crate_plan(dir.path().into());
    plan.fuzz_groups.push(FuzzGroupPlan {
        name: "all".into(),
        harness_dir: None,
        all: true,
        targets: Vec::new(),
        time: Some(3),
        budget_label: Some("smoke".into()),
        env: BTreeMap::from([("A".into(), "B".into())]),
    });
    let executor = ScriptedExecutor::new(vec![
        output(true, "warning: ignore\nparse\nother\n"),
        output(true, "built parse"),
        output(true, "built other"),
        output(true, "#1 runs: 123 cov: 4"),
        output(false, "panic occurred"),
    ]);

    let phases = run_fuzz_groups(
        &plan,
        Some(9),
        1,
        &BTreeMap::from([("GLOBAL".into(), "1".into())]),
        dir.path(),
        &executor,
    )
    .unwrap();
    assert_eq!(phases.len(), 2);
    assert_eq!(phases[0].status, PhaseStatus::Clean);
    assert_eq!(phases[1].status, PhaseStatus::Finding);
    assert!(matches!(
        phases[0].evidence,
        PhaseEvidence::Fuzz {
            budget_secs: Some(3),
            runs: Some(123),
            ..
        }
    ));
    let calls = executor.calls.lock().unwrap();
    assert_eq!(calls[1].args, vec!["fuzz", "build", "parse"]);
    assert_eq!(calls[2].args, vec!["fuzz", "build", "other"]);
    assert!(calls[3].args.contains(&"-max_total_time=3".to_string()));
    assert_eq!(calls[3].env.get("GLOBAL").unwrap(), "1");
    assert_eq!(calls[3].env.get("A").unwrap(), "B");
    assert!(matches!(
        phases[0].evidence,
        PhaseEvidence::Fuzz {
            runs: Some(123),
            ..
        }
    ));
}

#[test]
fn parse_fuzz_runs_supports_done_line_format() {
    assert_eq!(
        parse_fuzz_runs("Done 19313761 runs in 31 second(s)"),
        Some(19313761)
    );
}

#[test]
fn fuzz_summary_mentions_environment_error_and_runs() {
    let summary = fuzz_summary(
        "parse",
        30,
        PhaseStatus::Error,
        Some(19313761),
        "LeakSanitizer has encountered a fatal error. does not work under ptrace",
    );
    assert!(summary.contains("environment error"));
    assert!(summary.contains("19313761 runs"));
}

#[test]
fn fuzz_summary_mentions_budget_limited_pass() {
    let summary = fuzz_summary(
        "parse",
        30,
        PhaseStatus::Pass,
        Some(19313761),
        "Done 19313761 runs in 31 second(s)",
    );
    assert!(summary.contains("19313761 runs"));
    assert!(summary.contains("pass"));
    assert!(summary.contains("budget limit"));
}

#[test]
fn artifact_since_ignores_history_when_no_new_artifact_exists() {
    let dir = tempdir().unwrap();
    let artifact_dir = dir.path().join("artifacts");
    std::fs::create_dir_all(&artifact_dir).unwrap();
    let stale = artifact_dir.join("crash-old");
    std::fs::write(&stale, "old").unwrap();

    let before = artifact_snapshot(&artifact_dir);
    assert_eq!(artifact_since(&artifact_dir, &before), None);
}

#[test]
fn artifact_since_returns_new_artifact_from_current_run() {
    let dir = tempdir().unwrap();
    let artifact_dir = dir.path().join("artifacts");
    std::fs::create_dir_all(&artifact_dir).unwrap();
    std::fs::write(artifact_dir.join("crash-old"), "old").unwrap();
    let before = artifact_snapshot(&artifact_dir);

    std::thread::sleep(std::time::Duration::from_millis(5));
    let fresh = artifact_dir.join("crash-new");
    std::fs::write(&fresh, "new").unwrap();

    assert_eq!(artifact_since(&artifact_dir, &before), Some(fresh));
}

#[test]
fn fuzz_tool_failure_is_tagged_as_tool_error() {
    let output = CommandOutput {
        success: false,
        exit_code: Some(1),
        duration_ms: 1,
        combined_output: "failed to execute fuzz target".into(),
    };
    assert_eq!(classify_fuzz_status(&output), PhaseStatus::Error);
    assert_eq!(
        fuzz_error_kind(&output, classify_fuzz_status(&output)).as_deref(),
        Some("tool_error")
    );
}

#[test]
fn fuzz_all_with_failed_list_becomes_skipped() {
    let dir = tempdir().unwrap();
    create_built_fuzz_binary(dir.path(), "parse");
    std::fs::create_dir_all(dir.path().join("fuzz").join("corpus").join("parse")).unwrap();
    let mut plan = crate_plan(dir.path().into());
    plan.fuzz_groups.push(FuzzGroupPlan {
        name: "all".into(),
        harness_dir: None,
        all: true,
        targets: Vec::new(),
        time: None,
        budget_label: None,
        env: BTreeMap::new(),
    });
    let executor = ScriptedExecutor::new(vec![output(false, "cargo fuzz unavailable")]);
    let phases = run_fuzz_groups(&plan, None, 1, &BTreeMap::new(), dir.path(), &executor).unwrap();
    assert_eq!(phases[0].status, PhaseStatus::Skipped);
    assert!(phases[0].summary.contains("no fuzz targets"));
}

#[test]
fn fuzz_build_failure_becomes_error_report_and_other_targets_continue() {
    let dir = tempdir().unwrap();
    create_built_fuzz_binary(dir.path(), "other");
    let mut plan = crate_plan(dir.path().into());
    plan.fuzz_groups.push(FuzzGroupPlan {
        name: "all".into(),
        harness_dir: None,
        all: true,
        targets: Vec::new(),
        time: Some(3),
        budget_label: Some("smoke".into()),
        env: BTreeMap::new(),
    });
    let executor = ScriptedExecutor::new(vec![
        output(true, "parse\nother\n"),
        output(false, "build failed"),
        output(true, "built other"),
        output(true, "#1 runs: 55 cov: 4"),
    ]);

    let phases = run_fuzz_groups(&plan, Some(9), 1, &BTreeMap::new(), dir.path(), &executor).unwrap();

    assert_eq!(phases.len(), 2);
    assert_eq!(phases[0].status, PhaseStatus::Error);
    assert!(phases[0].summary.contains("build error"));
    assert_eq!(phases[1].status, PhaseStatus::Clean);
    let calls = executor.calls.lock().unwrap();
    assert_eq!(calls[1].args, vec!["fuzz", "build", "parse"]);
    assert_eq!(calls[2].args, vec!["fuzz", "build", "other"]);
}

#[test]
fn fuzz_missing_bin_build_becomes_skipped() {
    let dir = tempdir().unwrap();
    create_built_fuzz_binary(dir.path(), "other");
    let mut plan = crate_plan(dir.path().into());
    plan.fuzz_groups.push(FuzzGroupPlan {
        name: "all".into(),
        harness_dir: None,
        all: true,
        targets: Vec::new(),
        time: Some(3),
        budget_label: Some("smoke".into()),
        env: BTreeMap::new(),
    });
    let executor = ScriptedExecutor::new(vec![
        output(true, "parse\nother\n"),
        output(
            false,
            "error: can't find bin `parse` at path `/tmp/demo/fuzz/fuzz_targets/parse.rs`",
        ),
        output(true, "built other"),
        output(true, "#1 runs: 55 cov: 4"),
    ]);

    let phases = run_fuzz_groups(&plan, Some(9), 1, &BTreeMap::new(), dir.path(), &executor).unwrap();

    assert_eq!(phases.len(), 2);
    assert_eq!(phases[0].status, PhaseStatus::Skipped);
    assert!(phases[0].summary.contains("declared source missing"));
    assert_eq!(phases[1].status, PhaseStatus::Clean);
}

#[test]
fn fuzz_run_creates_empty_corpus_dir_when_missing() {
    let repo = tempdir().unwrap();
    let crate_dir = repo.path().join("targets").join("demo");
    std::fs::create_dir_all(crate_dir.join("src")).unwrap();
    std::fs::write(
        crate_dir.join("Cargo.toml"),
        "[package]\nname='demo'\nversion='0.1.0'\n",
    )
    .unwrap();
    std::fs::write(crate_dir.join("src/lib.rs"), "pub fn demo() {}\n").unwrap();
    create_built_fuzz_binary(&crate_dir, "parse");

    let mut plan = crate_plan(crate_dir.clone());
    plan.fuzz_groups.push(FuzzGroupPlan {
        name: "named".into(),
        harness_dir: None,
        all: false,
        targets: vec!["parse".into()],
        time: Some(3),
        budget_label: Some("smoke".into()),
        env: BTreeMap::new(),
    });
    let executor = ScriptedExecutor::new(vec![
        output(true, "parse\n"),
        output(true, "built parse"),
        output(true, "#1 runs: 5 cov: 1"),
    ]);

    let phases = run_fuzz_groups(&plan, Some(9), 1, &BTreeMap::new(), repo.path(), &executor).unwrap();

    assert_eq!(phases.len(), 1);
    assert!(crate_dir.join("fuzz/corpus/parse").is_dir());
}

#[test]
fn fuzz_group_marks_budget_completion_as_pass() {
    let dir = tempdir().unwrap();
    create_built_fuzz_binary(dir.path(), "parse");
    let mut plan = crate_plan(dir.path().into());
    plan.fuzz_groups.push(FuzzGroupPlan {
        name: "named".into(),
        harness_dir: None,
        all: false,
        targets: vec!["parse".into()],
        time: Some(3),
        budget_label: Some("smoke".into()),
        env: BTreeMap::new(),
    });
    let executor = ScriptedExecutor::new(vec![
        output(true, "parse\n"),
        output(true, "built parse"),
        output(true, "Done 123 runs in 3 second(s)"),
    ]);

    let phases = run_fuzz_groups(&plan, Some(9), 1, &BTreeMap::new(), dir.path(), &executor).unwrap();

    assert_eq!(phases.len(), 1);
    assert_eq!(phases[0].status, PhaseStatus::Pass);
    assert!(phases[0].summary.contains("budget limit"));
}

#[test]
fn fuzz_run_copies_seed_corpus_from_fuzz_harnesses_store() {
    let repo = tempdir().unwrap();
    let crate_dir = repo.path().join("targets").join("demo");
    std::fs::create_dir_all(crate_dir.join("src")).unwrap();
    std::fs::write(
        crate_dir.join("Cargo.toml"),
        "[package]\nname='demo'\nversion='0.1.0'\n",
    )
    .unwrap();
    std::fs::write(crate_dir.join("src/lib.rs"), "pub fn demo() {}\n").unwrap();
    create_built_fuzz_binary(&crate_dir, "parse");

    let seed_dir = repo.path().join("fuzz_harnesses/demo/corpus/parse");
    std::fs::create_dir_all(&seed_dir).unwrap();
    std::fs::write(seed_dir.join("seed.bin"), b"seed").unwrap();

    let mut plan = crate_plan(crate_dir.clone());
    plan.fuzz_groups.push(FuzzGroupPlan {
        name: "named".into(),
        harness_dir: None,
        all: false,
        targets: vec!["parse".into()],
        time: Some(3),
        budget_label: Some("smoke".into()),
        env: BTreeMap::new(),
    });
    let executor = ScriptedExecutor::new(vec![
        output(true, "parse\n"),
        output(true, "built parse"),
        output(true, "#1 runs: 5 cov: 1"),
    ]);

    let phases = run_fuzz_groups(&plan, Some(9), 1, &BTreeMap::new(), repo.path(), &executor).unwrap();

    assert_eq!(phases.len(), 1);
    assert_eq!(
        std::fs::read(crate_dir.join("fuzz/corpus/parse/seed.bin")).unwrap(),
        b"seed"
    );
}

#[test]
fn fuzz_explicit_group_with_missing_workspace_becomes_skipped() {
    let dir = tempdir().unwrap();
    let mut plan = crate_plan(dir.path().into());
    plan.fuzz_groups.push(FuzzGroupPlan {
        name: "named".into(),
        harness_dir: None,
        all: false,
        targets: vec!["parse".into()],
        time: Some(30),
        budget_label: Some("smoke".into()),
        env: BTreeMap::new(),
    });
    let executor = ScriptedExecutor::new(vec![output(false, "missing fuzz workspace")]);

    let phases = run_fuzz_groups(&plan, None, 1, &BTreeMap::new(), dir.path(), &executor).unwrap();

    assert_eq!(phases.len(), 1);
    assert_eq!(phases[0].status, PhaseStatus::Skipped);
    assert!(phases[0].summary.contains("no fuzz targets"));
}

#[test]
fn fuzz_explicit_group_with_missing_target_is_skipped() {
    let dir = tempdir().unwrap();
    let mut plan = crate_plan(dir.path().into());
    plan.fuzz_groups.push(FuzzGroupPlan {
        name: "named".into(),
        harness_dir: None,
        all: false,
        targets: vec!["parse".into()],
        time: Some(30),
        budget_label: Some("smoke".into()),
        env: BTreeMap::new(),
    });
    let executor = ScriptedExecutor::new(vec![output(true, "other\n")]);

    let phases = run_fuzz_groups(&plan, None, 1, &BTreeMap::new(), dir.path(), &executor).unwrap();

    assert_eq!(phases.len(), 1);
    assert_eq!(phases[0].status, PhaseStatus::Skipped);
    assert!(phases[0].summary.contains("no fuzz targets"));
    let calls = executor.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].args, vec!["fuzz", "list"]);
}