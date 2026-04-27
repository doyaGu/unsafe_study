pub mod config;
pub mod fs;
pub mod phases;
pub mod report;
pub mod runner;
pub mod scan;

use anyhow::Result;
use config::{CratePlan, RunOptions, RunPlan};
use report::{CrateReport, ExecutionConfig, Report};
use runner::{format_duration_ms, CommandExecutor, ProcessExecutor};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub use config::{load_plan, OutputFormat};
pub use report::{PhaseKind, PhaseStatus};

pub fn run(input: &Path, options: RunOptions) -> Result<Report> {
    let plan = load_plan(input, options)?;
    run_plan(&plan, &ProcessExecutor)
}

pub fn run_plan(plan: &RunPlan, executor: &dyn CommandExecutor) -> Result<Report> {
    fs::create_output_root(&plan.output_root)?;

    let jobs = plan.jobs.max(1);
    let total = plan.crates.len();
    if jobs <= 1 || total <= 1 {
        let mut crates = Vec::new();
        for (idx, crate_plan) in plan.crates.iter().enumerate() {
            crates.push(run_crate(crate_plan, plan, executor, idx + 1, total)?);
        }
        return Ok(Report {
            schema_version: 1,
            study_name: plan.name.clone(),
            execution: execution_config(plan),
            crates,
        });
    }

    let next = Arc::new(Mutex::new(0usize));
    let mut initial = Vec::with_capacity(total);
    initial.resize_with(total, || None);
    let results = Arc::new(Mutex::new(initial));
    std::thread::scope(|scope| {
        for _ in 0..jobs.min(total) {
            let next = Arc::clone(&next);
            let results = Arc::clone(&results);
            scope.spawn(move || loop {
                let idx = {
                    let mut guard = next.lock().unwrap();
                    if *guard >= total {
                        return;
                    }
                    let idx = *guard;
                    *guard += 1;
                    idx
                };
                let result = run_crate(&plan.crates[idx], plan, executor, idx + 1, total);
                results.lock().unwrap()[idx] = Some(result);
            });
        }
    });

    let mut crates = Vec::with_capacity(total);
    for result in results.lock().unwrap().iter_mut() {
        crates.push(result.take().unwrap()?);
    }

    Ok(Report {
        schema_version: 1,
        study_name: plan.name.clone(),
        execution: execution_config(plan),
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
    ordinal: usize,
    total: usize,
) -> Result<CrateReport> {
    eprintln!("[{}/{}] crate {}: start", ordinal, total, crate_plan.name);
    let crate_start = Instant::now();
    let crate_root = fs::crate_output_dir(&plan.output_root, &crate_plan.name);
    std::fs::create_dir_all(&crate_root)?;

    let scan = if plan.phases.scan {
        Some(scan::scan_crate(&crate_plan.path)?)
    } else {
        None
    };

    let mut phases = Vec::new();
    if plan.phases.geiger {
        eprintln!(
            "[{}/{}] crate {}: geiger start",
            ordinal, total, crate_plan.name
        );
        let phase = phases::run_geiger(crate_plan, &crate_root, executor)?;
        eprintln!(
            "[{}/{}] crate {}: geiger {} ({})",
            ordinal,
            total,
            crate_plan.name,
            status_label(phase.status),
            format_duration_ms(phase.duration_ms)
        );
        phases.push(phase);
    }
    if plan.phases.miri {
        eprintln!(
            "[{}/{}] crate {}: miri start",
            ordinal, total, crate_plan.name
        );
        phases.extend(phases::run_miri_cases(
            crate_plan,
            plan.miri_triage,
            &crate_root,
            executor,
        )?);
        eprintln!(
            "[{}/{}] crate {}: miri done",
            ordinal, total, crate_plan.name
        );
    }
    if plan.phases.fuzz {
        eprintln!(
            "[{}/{}] crate {}: fuzz start",
            ordinal, total, crate_plan.name
        );
        phases.extend(phases::run_fuzz_groups(
            crate_plan,
            plan.fuzz_time,
            plan.fuzz_jobs,
            &plan.fuzz_env,
            &crate_root,
            executor,
        )?);
        eprintln!(
            "[{}/{}] crate {}: fuzz done",
            ordinal, total, crate_plan.name
        );
    }

    let (unsafe_sites, pattern_summary) = scan
        .map(|s| (s.sites, s.summary))
        .unwrap_or_else(|| (Vec::new(), Default::default()));

    let review_priority = report::build_review_priority(&unsafe_sites, &pattern_summary, &phases);

    eprintln!(
        "[{}/{}] crate {}: done ({} unsafe sites, {} phase records, {})",
        ordinal,
        total,
        crate_plan.name,
        unsafe_sites.len(),
        phases.len(),
        format_duration_ms(crate_start.elapsed().as_millis())
    );

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

fn status_label(status: report::PhaseStatus) -> &'static str {
    match status {
        report::PhaseStatus::Clean => "clean",
        report::PhaseStatus::Finding => "finding",
        report::PhaseStatus::Skipped => "skipped",
        report::PhaseStatus::Error => "error",
    }
}

fn execution_config(plan: &RunPlan) -> ExecutionConfig {
    ExecutionConfig {
        profile: plan.profile,
        jobs: plan.jobs,
        fuzz_jobs: plan.fuzz_jobs,
        phases: plan.phases,
        miri_triage: plan.miri_triage,
        fuzz_time: plan.fuzz_time,
        fuzz_env: plan.fuzz_env.clone(),
    }
}

#[cfg(test)]
mod tests {
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
}
