use super::*;
use crate::config::{FuzzGroupPlan, MiriCasePlan, PhaseSelection, RunOptions};
use crate::runner::{CommandOutput, CommandSpec};
use std::collections::BTreeMap;
use std::sync::Mutex;
use tempfile::tempdir;

struct FakeExecutor {
    calls: Mutex<Vec<String>>,
}

impl CommandExecutor for FakeExecutor {
    fn run(&self, spec: &CommandSpec) -> Result<CommandOutput> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("{} {}", spec.program, spec.args.join(" ")));
        Ok(CommandOutput {
            success: true,
            exit_code: Some(0),
            duration_ms: 1,
            combined_output: "test result: ok. 1 passed; 0 failed\n".into(),
        })
    }
}

#[test]
fn single_crate_plan_can_run_with_fake_commands() {
    let dir = tempdir().unwrap();
    std::fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname='fixture'\nversion='0.1.0'\n",
    )
    .unwrap();
    std::fs::create_dir(dir.path().join("src")).unwrap();
    std::fs::write(dir.path().join("src/lib.rs"), "pub unsafe fn f() {}\n").unwrap();

    let out = tempdir().unwrap();
    let plan = load_plan(
        dir.path(),
        RunOptions {
            output_root: Some(out.path().to_path_buf()),
            phases: PhaseSelection {
                scan: true,
                geiger: true,
                miri: false,
                fuzz: false,
            },
            ..Default::default()
        },
    )
    .unwrap();
    let fake = FakeExecutor {
        calls: Mutex::new(Vec::new()),
    };
    let report = run_plan(&plan, &fake).unwrap();
    assert_eq!(report.crates[0].name, "fixture");
    assert_eq!(report.crates[0].unsafe_sites.len(), 1);
    assert_eq!(fake.calls.lock().unwrap().len(), 1);
}

#[test]
fn run_plan_covers_scan_geiger_miri_fuzz_and_report_write() {
    let dir = tempdir().unwrap();
    std::fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname='fixture'\nversion='0.1.0'\n",
    )
    .unwrap();
    std::fs::create_dir(dir.path().join("src")).unwrap();
    std::fs::write(
        dir.path().join("src/lib.rs"),
        "pub unsafe fn f(p: *const u8) { unsafe { *p }; }\n",
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("fuzz/target/host/release")).unwrap();
    std::fs::write(dir.path().join("fuzz/target/host/release/parse"), "bin").unwrap();
    std::fs::create_dir_all(dir.path().join("fuzz/corpus/parse")).unwrap();
    std::fs::create_dir_all(dir.path().join("fuzz/artifacts/parse")).unwrap();

    let out = tempdir().unwrap();
    let mut plan = load_plan(
        dir.path(),
        RunOptions {
            output_root: Some(out.path().to_path_buf()),
            phases: PhaseSelection::default(),
            miri_triage: true,
            ..Default::default()
        },
    )
    .unwrap();
    plan.crates[0].miri_cases = vec![MiriCasePlan {
        name: "case".into(),
        scope: "targeted".into(),
        harness_dir: None,
        test: Some("api".into()),
        case: Some("one_case".into()),
        exact: true,
    }];
    plan.crates[0].fuzz_groups = vec![FuzzGroupPlan {
        name: "fg".into(),
        harness_dir: None,
        all: false,
        targets: vec!["parse".into()],
        time: Some(1),
        budget_label: Some("smoke".into()),
        env: BTreeMap::new(),
    }];

    struct FullExecutor {
        calls: Mutex<Vec<Vec<String>>>,
    }

    impl CommandExecutor for FullExecutor {
        fn run(&self, spec: &CommandSpec) -> Result<CommandOutput> {
            self.calls.lock().unwrap().push(spec.args.clone());
            let text = match spec.args.as_slice() {
                [a, ..] if a == "geiger" => r#"{"unsafe": 2}"#,
                [a, b, ..] if a == "miri" && b == "test" => {
                    "test result: ok. 1 passed; 0 failed"
                }
                [a, b, ..] if a == "fuzz" && b == "list" => "parse",
                [a, b, ..] if a == "fuzz" && b == "build" => "built",
                [arg0, ..] if arg0.contains("fuzz/target/host/release/parse") => {
                    "#1 runs: 22 cov: 7"
                }
                _ => "",
            };
            Ok(CommandOutput {
                success: true,
                exit_code: Some(0),
                duration_ms: 1,
                combined_output: text.into(),
            })
        }
    }

    let fake = FullExecutor {
        calls: Mutex::new(Vec::new()),
    };
    let report = run_plan(&plan, &fake).unwrap();
    write_report(&report, out.path(), &plan.formats).unwrap();

    assert_eq!(report.crates[0].phases.len(), 3);
    assert!(report.crates[0].pattern_summary.unsafe_fns >= 1);
    assert!(out.path().join("report.json").exists());
    assert!(out.path().join("report.md").exists());
    assert_eq!(fake.calls.lock().unwrap().len(), 5);
}

#[test]
fn run_plan_supports_parallel_crate_execution() {
    let a = tempdir().unwrap();
    std::fs::write(
        a.path().join("Cargo.toml"),
        "[package]\nname='a'\nversion='0.1.0'\n",
    )
    .unwrap();
    std::fs::create_dir(a.path().join("src")).unwrap();
    std::fs::write(a.path().join("src/lib.rs"), "pub unsafe fn a() {}\n").unwrap();

    let b = tempdir().unwrap();
    std::fs::write(
        b.path().join("Cargo.toml"),
        "[package]\nname='b'\nversion='0.1.0'\n",
    )
    .unwrap();
    std::fs::create_dir(b.path().join("src")).unwrap();
    std::fs::write(b.path().join("src/lib.rs"), "pub unsafe fn b() {}\n").unwrap();

    let out = tempdir().unwrap();
    let plan = crate::config::RunPlan {
        name: "study".into(),
        output_root: out.path().to_path_buf(),
        profile: crate::config::RunProfile::Full,
        jobs: 2,
        fuzz_jobs: 1,
        phases: PhaseSelection {
            scan: true,
            geiger: false,
            miri: false,
            fuzz: false,
        },
        formats: vec![crate::OutputFormat::Json],
        dry_run: false,
        miri_triage: false,
        fuzz_time: None,
        fuzz_env: BTreeMap::new(),
        crates: vec![
            crate::config::CratePlan {
                name: "a".into(),
                path: a.path().to_path_buf(),
                cohort: None,
                miri_cases: Vec::new(),
                fuzz_groups: Vec::new(),
            },
            crate::config::CratePlan {
                name: "b".into(),
                path: b.path().to_path_buf(),
                cohort: None,
                miri_cases: Vec::new(),
                fuzz_groups: Vec::new(),
            },
        ],
    };
    let fake = FakeExecutor {
        calls: Mutex::new(Vec::new()),
    };
    let report = run_plan(&plan, &fake).unwrap();
    assert_eq!(report.crates.len(), 2);
}
