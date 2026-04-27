pub mod config;
pub mod fs;
pub mod phases;
pub mod report;
pub mod runner;
pub mod scan;

use anyhow::Result;
use config::{CratePlan, RunOptions, RunPlan};
use report::{CrateReport, Report};
use runner::{CommandExecutor, ProcessExecutor};
use std::path::Path;

pub use config::{load_plan, OutputFormat};
pub use report::{PhaseKind, PhaseStatus};

pub fn run(input: &Path, options: RunOptions) -> Result<Report> {
    let plan = load_plan(input, options)?;
    run_plan(&plan, &ProcessExecutor)
}

pub fn run_plan(plan: &RunPlan, executor: &dyn CommandExecutor) -> Result<Report> {
    fs::create_output_root(&plan.output_root)?;

    let mut crates = Vec::new();
    for crate_plan in &plan.crates {
        crates.push(run_crate(crate_plan, plan, executor)?);
    }

    Ok(Report {
        schema_version: 1,
        study_name: plan.name.clone(),
        crates,
    })
}

pub fn run_and_write(input: &Path, options: RunOptions) -> Result<Report> {
    let plan = load_plan(input, options)?;
    let report = run_plan(&plan, &ProcessExecutor)?;
    report::write_reports(&report, &plan.output_root, &plan.formats)?;
    Ok(report)
}

pub fn write_report(report: &Report, output_root: &Path, formats: &[OutputFormat]) -> Result<()> {
    fs::create_output_root(output_root)?;
    report::write_reports(report, output_root, formats)
}

fn run_crate(
    crate_plan: &CratePlan,
    plan: &RunPlan,
    executor: &dyn CommandExecutor,
) -> Result<CrateReport> {
    let crate_root = fs::crate_output_dir(&plan.output_root, &crate_plan.name);
    std::fs::create_dir_all(&crate_root)?;

    let scan = if plan.phases.scan {
        Some(scan::scan_crate(&crate_plan.path)?)
    } else {
        None
    };

    let mut phases = Vec::new();
    if plan.phases.geiger {
        phases.push(phases::run_geiger(crate_plan, &crate_root, executor)?);
    }
    if plan.phases.miri {
        phases.extend(phases::run_miri_cases(
            crate_plan,
            plan.miri_triage,
            &crate_root,
            executor,
        )?);
    }
    if plan.phases.fuzz {
        phases.extend(phases::run_fuzz_groups(
            crate_plan,
            plan.fuzz_time,
            &plan.fuzz_env,
            &crate_root,
            executor,
        )?);
    }

    let (unsafe_sites, pattern_summary) = scan
        .map(|s| (s.sites, s.summary))
        .unwrap_or_else(|| (Vec::new(), Default::default()));

    let review_priority = report::build_review_priority(&unsafe_sites, &pattern_summary, &phases);

    Ok(CrateReport {
        name: crate_plan.name.clone(),
        path: crate_plan.path.display().to_string(),
        cohort: crate_plan.cohort.clone(),
        unsafe_sites,
        pattern_summary,
        phases,
        review_priority,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FuzzGroupPlan, MiriCasePlan, PhaseSelection, RunOptions};
    use crate::runner::{CommandOutput, CommandSpec};
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use tempfile::tempdir;

    struct FakeExecutor {
        calls: RefCell<Vec<String>>,
    }

    impl CommandExecutor for FakeExecutor {
        fn run(&self, spec: &CommandSpec) -> Result<CommandOutput> {
            self.calls
                .borrow_mut()
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
            calls: RefCell::new(Vec::new()),
        };
        let report = run_plan(&plan, &fake).unwrap();
        assert_eq!(report.crates[0].name, "fixture");
        assert_eq!(report.crates[0].unsafe_sites.len(), 1);
        assert_eq!(fake.calls.borrow().len(), 1);
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
            calls: RefCell<Vec<Vec<String>>>,
        }
        impl CommandExecutor for FullExecutor {
            fn run(&self, spec: &CommandSpec) -> Result<CommandOutput> {
                self.calls.borrow_mut().push(spec.args.clone());
                let text = match spec.args.as_slice() {
                    [a, ..] if a == "geiger" => r#"{"unsafe": 2}"#,
                    [a, b, ..] if a == "miri" && b == "test" => {
                        "test result: ok. 1 passed; 0 failed"
                    }
                    [a, b, ..] if a == "fuzz" && b == "run" => "#1 runs: 22 cov: 7",
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
            calls: RefCell::new(Vec::new()),
        };
        let report = run_plan(&plan, &fake).unwrap();
        write_report(&report, out.path(), &plan.formats).unwrap();

        assert_eq!(report.crates[0].phases.len(), 3);
        assert!(report.crates[0].pattern_summary.unsafe_fns >= 1);
        assert!(out.path().join("report.json").exists());
        assert!(out.path().join("report.md").exists());
        assert_eq!(fake.calls.borrow().len(), 3);
    }
}
