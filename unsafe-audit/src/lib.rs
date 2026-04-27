pub mod config;
pub mod fs;
pub mod phases;
pub mod report;
pub mod runner;
pub mod scan;

use anyhow::Result;
use config::{CratePlan, RunOptions, RunPlan};
use report::{CrateReport, Report};
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
        return Ok(Report::from_plan(plan, crates));
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

    Ok(Report::from_plan(plan, crates))
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
    let crate_root = fs::create_crate_output_dir(&plan.output_root, &crate_plan.name)?;

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
            phase.status.label(),
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
    eprintln!(
        "[{}/{}] crate {}: done ({} unsafe sites, {} phase records, {})",
        ordinal,
        total,
        crate_plan.name,
        unsafe_sites.len(),
        phases.len(),
        format_duration_ms(crate_start.elapsed().as_millis())
    );

    Ok(CrateReport::from_plan(
        crate_plan,
        unsafe_sites,
        pattern_summary,
        phases,
    ))
}

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;
