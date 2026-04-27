use crate::config::{CratePlan, FuzzGroupPlan, MiriCasePlan};
use crate::fs;
use crate::report::{PhaseEvidence, PhaseKind, PhaseReport, PhaseStatus};
use crate::runner::{excerpt, format_duration_ms, CommandExecutor, CommandOutput, CommandSpec};
use anyhow::Result;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

pub fn run_geiger(
    crate_plan: &CratePlan,
    crate_root: &Path,
    executor: &dyn CommandExecutor,
) -> Result<PhaseReport> {
    let spec = CommandSpec {
        program: "cargo".into(),
        args: vec!["geiger".into(), "--output-format".into(), "Json".into()],
        env: BTreeMap::new(),
        current_dir: crate_plan.path.clone(),
    };
    let output = executor.run(&spec)?;
    let log_path = fs::phase_log_path(crate_root, "geiger", "root");
    fs::write_log(&log_path, &output.combined_output)?;
    let (root_unsafe, dependency_unsafe) = parse_geiger_counts(&output.combined_output);
    Ok(PhaseReport {
        kind: PhaseKind::Geiger,
        name: "root".into(),
        status: if output.success {
            PhaseStatus::Clean
        } else {
            PhaseStatus::Error
        },
        command: command_vec(&spec),
        duration_ms: output.duration_ms,
        log_path: Some(log_path.display().to_string()),
        summary: match (root_unsafe, dependency_unsafe) {
            (Some(root), Some(deps)) => format!("root unsafe {root}, dependency unsafe {deps}"),
            (Some(root), None) => format!("root unsafe {root}"),
            _ if output.success => "geiger completed".into(),
            _ => "geiger failed".into(),
        },
        evidence: PhaseEvidence::Geiger {
            root_unsafe,
            dependency_unsafe,
            excerpt: excerpt(&output.combined_output),
        },
    })
}

pub fn run_miri_cases(
    crate_plan: &CratePlan,
    triage: bool,
    crate_root: &Path,
    executor: &dyn CommandExecutor,
) -> Result<Vec<PhaseReport>> {
    let cases = if crate_plan.miri_cases.is_empty() {
        vec![MiriCasePlan {
            name: "upstream_full".into(),
            scope: "full_suite".into(),
            harness_dir: None,
            test: None,
            case: None,
            exact: false,
        }]
    } else {
        crate_plan.miri_cases.clone()
    };

    let mut reports = Vec::new();
    for case in &cases {
        eprintln!("  miri case {}: start ({})", case.name, case.scope);
        let report = run_miri_case(crate_plan, case, triage, crate_root, executor)?;
        eprintln!(
            "  miri case {}: {} ({})",
            case.name,
            phase_status_label(report.status),
            format_duration_ms(report.duration_ms)
        );
        reports.push(report);
    }
    Ok(reports)
}

fn run_miri_case(
    crate_plan: &CratePlan,
    case: &MiriCasePlan,
    triage: bool,
    crate_root: &Path,
    executor: &dyn CommandExecutor,
) -> Result<PhaseReport> {
    let strict = run_miri_once(crate_plan, case, true, executor)?;
    let mut combined_log = strict.combined_output.clone();
    let strict_has_ub = has_ub(&strict.combined_output);
    let baseline = if triage && strict_has_ub {
        let baseline = run_miri_once(crate_plan, case, false, executor)?;
        combined_log.push_str("\n\n--- baseline ---\n");
        combined_log.push_str(&baseline.combined_output);
        Some(baseline)
    } else {
        None
    };

    let log_path = fs::phase_log_path(crate_root, "miri", &case.name);
    fs::write_log(&log_path, &combined_log)?;
    let verdict = miri_verdict(&strict, baseline.as_ref());
    let status = match verdict.as_str() {
        "clean" => PhaseStatus::Clean,
        "ub_observed" | "strict_only_ub" => PhaseStatus::Finding,
        _ => PhaseStatus::Error,
    };
    let category = classify_ub(&combined_log);

    Ok(PhaseReport {
        kind: PhaseKind::Miri,
        name: case.name.clone(),
        status,
        command: command_vec(&miri_spec(crate_plan, case, true)),
        duration_ms: strict.duration_ms + baseline.as_ref().map(|b| b.duration_ms).unwrap_or(0),
        log_path: Some(log_path.display().to_string()),
        summary: format!("{} scope, verdict {verdict}", case.scope),
        evidence: PhaseEvidence::Miri {
            verdict,
            ub_category: category,
            excerpt: excerpt(&combined_log),
        },
    })
}

fn run_miri_once(
    crate_plan: &CratePlan,
    case: &MiriCasePlan,
    strict: bool,
    executor: &dyn CommandExecutor,
) -> Result<CommandOutput> {
    executor.run(&miri_spec(crate_plan, case, strict))
}

fn miri_spec(crate_plan: &CratePlan, case: &MiriCasePlan, strict: bool) -> CommandSpec {
    let mut args = vec!["miri".into(), "test".into()];
    if let Some(test) = &case.test {
        args.push("--test".into());
        args.push(test.clone());
    }
    if let Some(filter) = &case.case {
        args.push(filter.clone());
    }
    if case.exact {
        args.push("--".into());
        args.push("--exact".into());
    }
    let mut env = BTreeMap::new();
    if strict {
        env.insert(
            "MIRIFLAGS".into(),
            "-Zmiri-symbolic-alignment-check -Zmiri-strict-provenance".into(),
        );
    } else {
        env.insert("MIRIFLAGS".into(), "-Zmiri-strict-provenance".into());
    }
    CommandSpec {
        program: "cargo".into(),
        args,
        env,
        current_dir: case
            .harness_dir
            .clone()
            .unwrap_or_else(|| crate_plan.path.clone()),
    }
}

pub fn run_fuzz_groups(
    crate_plan: &CratePlan,
    default_time: Option<u64>,
    fuzz_jobs: usize,
    default_env: &BTreeMap<String, String>,
    crate_root: &Path,
    executor: &dyn CommandExecutor,
) -> Result<Vec<PhaseReport>> {
    let groups = if crate_plan.fuzz_groups.is_empty() {
        vec![FuzzGroupPlan {
            name: "existing_targets".into(),
            harness_dir: None,
            all: true,
            targets: Vec::new(),
            time: default_time,
            budget_label: Some("default".into()),
            env: BTreeMap::new(),
        }]
    } else {
        crate_plan.fuzz_groups.clone()
    };

    let mut reports = Vec::new();
    for group in &groups {
        eprintln!("  fuzz group {}: start", group.name);
        let targets = if group.all {
            discover_fuzz_targets(crate_plan, group, executor)?
        } else {
            group.targets.clone()
        };
        if targets.is_empty() {
            reports.push(no_targets_report(group));
            continue;
        }
        reports.extend(run_fuzz_targets_parallel(
            crate_plan,
            group,
            &targets,
            default_time,
            fuzz_jobs,
            default_env,
            crate_root,
            executor,
        )?);
        eprintln!(
            "  fuzz group {}: done ({} targets)",
            group.name,
            targets.len()
        );
    }
    Ok(reports)
}

fn discover_fuzz_targets(
    crate_plan: &CratePlan,
    group: &FuzzGroupPlan,
    executor: &dyn CommandExecutor,
) -> Result<Vec<String>> {
    let harness_root = canonical_harness_dir(crate_plan, group)?;
    let spec = CommandSpec {
        program: "cargo".into(),
        args: vec!["fuzz".into(), "list".into()],
        env: BTreeMap::new(),
        current_dir: harness_root,
    };
    let output = executor.run(&spec)?;
    if !output.success {
        return Ok(Vec::new());
    }
    Ok(output
        .combined_output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("warning:"))
        .map(str::to_string)
        .collect())
}

fn run_fuzz_target(
    binary: &Path,
    crate_plan: &CratePlan,
    group: &FuzzGroupPlan,
    target: &str,
    default_time: Option<u64>,
    default_env: &BTreeMap<String, String>,
    crate_root: &Path,
    executor: &dyn CommandExecutor,
) -> Result<PhaseReport> {
    let time = group.time.or(default_time).unwrap_or(60);
    eprintln!("    fuzz target {}: run start (budget {}s)", target, time);
    let mut env = default_env.clone();
    env.extend(group.env.clone());
    let harness_root = canonical_harness_dir(crate_plan, group)?;
    let corpus = harness_root.join("fuzz").join("corpus").join(target);
    let artifact_prefix = harness_root.join("fuzz").join("artifacts").join(target);
    std::fs::create_dir_all(&artifact_prefix)?;
    let artifact_before = artifact_snapshot(&artifact_prefix);
    let spec = CommandSpec {
        program: binary.display().to_string(),
        args: vec![
            format!("-artifact_prefix={}/", artifact_prefix.display()),
            format!("-max_total_time={time}"),
            corpus.display().to_string(),
        ],
        env,
        current_dir: harness_root,
    };
    let output = executor.run(&spec)?;
    let log_name = format!("{}.{}", group.name, target);
    let log_path = fs::phase_log_path(crate_root, "fuzz", &log_name);
    fs::write_log(&log_path, &output.combined_output)?;
    let status = classify_fuzz_status(&output);
    let error_kind = fuzz_error_kind(&output, status);
    let artifact = artifact_since(&artifact_prefix, &artifact_before);
    let runs = parse_fuzz_runs(&output.combined_output);
    eprintln!(
        "    fuzz target {}: {} ({}/{})",
        target,
        phase_status_label(status),
        format_duration_ms(output.duration_ms),
        budget_label(time)
    );
    let summary = fuzz_summary(target, time, status, runs, &output.combined_output);
    Ok(PhaseReport {
        kind: PhaseKind::Fuzz,
        name: log_name,
        status,
        command: command_vec(&spec),
        duration_ms: output.duration_ms,
        log_path: Some(log_path.display().to_string()),
        summary,
        evidence: PhaseEvidence::Fuzz {
            target: Some(target.into()),
            budget_secs: Some(time),
            artifact: artifact.map(|p| p.display().to_string()),
            error_kind,
            runs,
            excerpt: excerpt(&output.combined_output),
        },
    })
}

fn no_targets_report(group: &FuzzGroupPlan) -> PhaseReport {
    PhaseReport {
        kind: PhaseKind::Fuzz,
        name: group.name.clone(),
        status: PhaseStatus::Skipped,
        command: vec!["cargo".into(), "fuzz".into(), "list".into()],
        duration_ms: 0,
        log_path: None,
        summary: "no fuzz targets discovered".into(),
        evidence: PhaseEvidence::Fuzz {
            target: None,
            budget_secs: None,
            artifact: None,
            error_kind: None,
            runs: None,
            excerpt: None,
        },
    }
}

fn run_fuzz_targets_parallel(
    crate_plan: &CratePlan,
    group: &FuzzGroupPlan,
    targets: &[String],
    default_time: Option<u64>,
    fuzz_jobs: usize,
    default_env: &BTreeMap<String, String>,
    crate_root: &Path,
    executor: &dyn CommandExecutor,
) -> Result<Vec<PhaseReport>> {
    let mut initial = Vec::with_capacity(targets.len());
    initial.resize_with(targets.len(), || None);
    let results = Arc::new(Mutex::new(initial));
    let next = Arc::new(Mutex::new(0usize));
    let jobs = fuzz_jobs.max(1).min(targets.len());
    let mut built = Vec::with_capacity(targets.len());
    for target in targets {
        eprintln!(
            "    fuzz target {}: build start (budget {}s)",
            target,
            group.time.or(default_time).unwrap_or(60)
        );
        let binary = build_fuzz_target(crate_plan, group, target, executor)?;
        eprintln!("    fuzz target {}: build done", target);
        built.push(binary);
    }
    let built = Arc::new(built);
    let targets = Arc::new(targets.to_vec());
    std::thread::scope(|scope| {
        for _ in 0..jobs {
            let results = Arc::clone(&results);
            let next = Arc::clone(&next);
            let built = Arc::clone(&built);
            let targets = Arc::clone(&targets);
            scope.spawn(move || loop {
                let idx = {
                    let mut guard = next.lock().unwrap();
                    if *guard >= targets.len() {
                        return;
                    }
                    let idx = *guard;
                    *guard += 1;
                    idx
                };
                let report = run_fuzz_target(
                    &built[idx],
                    crate_plan,
                    group,
                    &targets[idx],
                    default_time,
                    default_env,
                    crate_root,
                    executor,
                );
                results.lock().unwrap()[idx] = Some(report);
            });
        }
    });
    let mut reports = Vec::with_capacity(targets.len());
    for result in results.lock().unwrap().iter_mut() {
        reports.push(result.take().unwrap()?);
    }
    Ok(reports)
}

fn build_fuzz_target(
    crate_plan: &CratePlan,
    group: &FuzzGroupPlan,
    target: &str,
    executor: &dyn CommandExecutor,
) -> Result<PathBuf> {
    let harness_root = canonical_harness_dir(crate_plan, group)?;
    let spec = CommandSpec {
        program: "cargo".into(),
        args: vec!["fuzz".into(), "build".into(), target.into()],
        env: BTreeMap::new(),
        current_dir: harness_root.clone(),
    };
    let output = executor.run(&spec)?;
    if !output.success {
        anyhow::bail!("cargo fuzz build failed for {target}");
    }
    locate_fuzz_binary(&harness_root, target)
}

fn locate_fuzz_binary(harness_root: &Path, target: &str) -> Result<PathBuf> {
    let target_dir = harness_root.join("fuzz").join("target");
    for host_dir in std::fs::read_dir(&target_dir)? {
        let host_dir = host_dir?;
        let candidate = host_dir.path().join("release").join(target);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    anyhow::bail!(
        "unable to locate built fuzz binary for {} under {}",
        target,
        target_dir.display()
    )
}

fn harness_dir(crate_plan: &CratePlan, group: &FuzzGroupPlan) -> PathBuf {
    group
        .harness_dir
        .clone()
        .unwrap_or_else(|| crate_plan.path.clone())
}

fn canonical_harness_dir(crate_plan: &CratePlan, group: &FuzzGroupPlan) -> Result<PathBuf> {
    Ok(harness_dir(crate_plan, group).canonicalize()?)
}

fn command_vec(spec: &CommandSpec) -> Vec<String> {
    let mut command = vec![spec.program.clone()];
    command.extend(spec.args.clone());
    command
}

fn parse_geiger_counts(output: &str) -> (Option<usize>, Option<usize>) {
    let Some(start) = output.find('{') else {
        return (None, None);
    };
    let Ok(json): Result<Value, _> = serde_json::from_str(&output[start..]) else {
        return (None, None);
    };
    let root = find_number_by_key(&json, "unsafe");
    (root, None)
}

fn find_number_by_key(value: &Value, key_hint: &str) -> Option<usize> {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if key.to_ascii_lowercase().contains(key_hint) {
                    if let Some(n) = value.as_u64() {
                        return Some(n as usize);
                    }
                }
                if let Some(found) = find_number_by_key(value, key_hint) {
                    return Some(found);
                }
            }
            None
        }
        Value::Array(values) => values.iter().find_map(|v| find_number_by_key(v, key_hint)),
        _ => None,
    }
}

fn miri_verdict(strict: &CommandOutput, baseline: Option<&CommandOutput>) -> String {
    let strict_ub = has_ub(&strict.combined_output);
    let baseline_ub = baseline.is_some_and(|b| has_ub(&b.combined_output));
    if strict.success && !strict_ub {
        "clean".into()
    } else if strict_ub && baseline.is_none() {
        "ub_observed".into()
    } else if strict_ub && baseline_ub {
        "ub_observed".into()
    } else if strict_ub {
        "strict_only_ub".into()
    } else {
        "failed_no_ub".into()
    }
}

fn has_ub(output: &str) -> bool {
    let lower = output.to_ascii_lowercase();
    lower.contains("undefined behavior")
        || lower.contains("ub:")
        || lower.contains("stacked borrow")
        || lower.contains("out-of-bounds")
        || lower.contains("uninitialized")
}

fn classify_ub(output: &str) -> Option<String> {
    let lower = output.to_ascii_lowercase();
    let category = if lower.contains("provenance") || lower.contains("stacked borrow") {
        "provenance"
    } else if lower.contains("alignment") || lower.contains("unaligned") {
        "alignment"
    } else if lower.contains("out-of-bounds") || lower.contains("bounds") {
        "out_of_bounds"
    } else if lower.contains("uninitialized") {
        "uninitialized"
    } else if has_ub(output) {
        "other_ub"
    } else {
        return None;
    };
    Some(category.into())
}

fn classify_fuzz_status(output: &CommandOutput) -> PhaseStatus {
    if output.success {
        return PhaseStatus::Clean;
    }
    if is_lsan_ptrace_error(&output.combined_output) {
        return PhaseStatus::Error;
    }
    let lower = output.combined_output.to_ascii_lowercase();
    if lower.contains("panic")
        || lower.contains("crash")
        || lower.contains("artifact_prefix")
        || lower.contains("timeout")
        || lower.contains("out-of-memory")
        || lower.contains("oom")
    {
        PhaseStatus::Finding
    } else {
        PhaseStatus::Error
    }
}

fn fuzz_error_kind(output: &CommandOutput, status: PhaseStatus) -> Option<String> {
    match status {
        PhaseStatus::Clean | PhaseStatus::Skipped => None,
        PhaseStatus::Finding => Some("finding".into()),
        PhaseStatus::Error if is_lsan_ptrace_error(&output.combined_output) => {
            Some("environment_error".into())
        }
        PhaseStatus::Error => Some("tool_error".into()),
    }
}

fn fuzz_summary(
    target: &str,
    time: u64,
    status: PhaseStatus,
    runs: Option<u64>,
    output: &str,
) -> String {
    let status_text = match status {
        PhaseStatus::Clean => "clean",
        PhaseStatus::Finding => "finding",
        PhaseStatus::Skipped => "skipped",
        PhaseStatus::Error if is_lsan_ptrace_error(output) => {
            "environment error: LeakSanitizer unsupported under ptrace"
        }
        PhaseStatus::Error => "error",
    };
    match runs {
        Some(runs) => format!("target {target}, budget {time}s, {runs} runs, {status_text}"),
        None => format!("target {target}, budget {time}s, {status_text}"),
    }
}

fn phase_status_label(status: PhaseStatus) -> &'static str {
    match status {
        PhaseStatus::Clean => "clean",
        PhaseStatus::Finding => "finding",
        PhaseStatus::Skipped => "skipped",
        PhaseStatus::Error => "error",
    }
}

fn budget_label(time: u64) -> String {
    format!("{time}s")
}

fn is_lsan_ptrace_error(output: &str) -> bool {
    let lower = output.to_ascii_lowercase();
    lower.contains("leaksanitizer has encountered a fatal error")
        && lower.contains("does not work under ptrace")
}

fn parse_fuzz_runs(output: &str) -> Option<u64> {
    let mut tokens = output.split(|c: char| !c.is_ascii_alphanumeric() && c != ':');
    while let Some(token) = tokens.next() {
        if let Some(value) = token.strip_prefix("runs:").filter(|v| !v.is_empty()) {
            if let Ok(n) = value.parse() {
                return Some(n);
            }
        }
        if token == "runs:" {
            if let Some(next) = tokens.next().and_then(|n| n.parse().ok()) {
                return Some(next);
            }
        }
    }
    for line in output.lines() {
        if let Some(rest) = line.strip_prefix("Done ") {
            if let Some(value) = rest.split_whitespace().next().and_then(|n| n.parse().ok()) {
                return Some(value);
            }
        }
    }
    None
}

fn artifact_snapshot(dir: &Path) -> BTreeMap<PathBuf, SystemTime> {
    let mut snapshot = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return snapshot;
    };
    for entry in entries.flatten() {
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        snapshot.insert(entry.path(), modified);
    }
    snapshot
}

fn artifact_since(dir: &Path, before: &BTreeMap<PathBuf, SystemTime>) -> Option<PathBuf> {
    let mut newest = None;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return None;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        let changed = before
            .get(&path)
            .is_none_or(|previous| modified > *previous);
        if !changed {
            continue;
        }
        if newest
            .as_ref()
            .is_none_or(|(current, _): &(SystemTime, PathBuf)| modified > *current)
        {
            newest = Some((modified, path));
        }
    }
    newest.map(|(_, path)| path)
}

#[cfg(test)]
mod tests {
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
    fn geiger_writes_log_and_extracts_unsafe_count() {
        let dir = tempdir().unwrap();
        let executor = ScriptedExecutor::new(vec![output(true, r#"prefix {"unsafe": 7}"#)]);
        let phase = run_geiger(&crate_plan(dir.path().into()), dir.path(), &executor).unwrap();
        assert_eq!(phase.status, PhaseStatus::Clean);
        assert!(phase.summary.contains("root unsafe 7"));
        assert!(std::path::Path::new(phase.log_path.as_ref().unwrap()).exists());
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
        let phases =
            run_fuzz_groups(&plan, None, 1, &BTreeMap::new(), dir.path(), &executor).unwrap();
        assert_eq!(phases[0].status, PhaseStatus::Skipped);
        assert!(phases[0].summary.contains("no fuzz targets"));
    }
}
