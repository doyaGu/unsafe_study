use crate::config::{CratePlan, FuzzGroupPlan, MiriCasePlan};
use crate::fs;
use crate::report::{PhaseEvidence, PhaseKind, PhaseReport, PhaseStatus};
use crate::runner::{excerpt, CommandExecutor, CommandOutput, CommandSpec};
use anyhow::Result;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

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
        reports.push(run_miri_case(
            crate_plan, case, triage, crate_root, executor,
        )?);
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
        let targets = if group.all {
            discover_fuzz_targets(crate_plan, group, executor)?
        } else {
            group.targets.clone()
        };
        if targets.is_empty() {
            reports.push(no_targets_report(group));
            continue;
        }
        for target in targets {
            reports.push(run_fuzz_target(
                crate_plan,
                group,
                &target,
                default_time,
                default_env,
                crate_root,
                executor,
            )?);
        }
    }
    Ok(reports)
}

fn discover_fuzz_targets(
    crate_plan: &CratePlan,
    group: &FuzzGroupPlan,
    executor: &dyn CommandExecutor,
) -> Result<Vec<String>> {
    let spec = CommandSpec {
        program: "cargo".into(),
        args: vec!["fuzz".into(), "list".into()],
        env: BTreeMap::new(),
        current_dir: harness_dir(crate_plan, group),
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
    crate_plan: &CratePlan,
    group: &FuzzGroupPlan,
    target: &str,
    default_time: Option<u64>,
    default_env: &BTreeMap<String, String>,
    crate_root: &Path,
    executor: &dyn CommandExecutor,
) -> Result<PhaseReport> {
    let time = group.time.or(default_time).unwrap_or(60);
    let mut env = default_env.clone();
    env.extend(group.env.clone());
    let spec = CommandSpec {
        program: "cargo".into(),
        args: vec![
            "fuzz".into(),
            "run".into(),
            target.into(),
            "--".into(),
            format!("-max_total_time={time}"),
        ],
        env,
        current_dir: harness_dir(crate_plan, group),
    };
    let output = executor.run(&spec)?;
    let log_name = format!("{}.{}", group.name, target);
    let log_path = fs::phase_log_path(crate_root, "fuzz", &log_name);
    fs::write_log(&log_path, &output.combined_output)?;
    let status = classify_fuzz_status(&output);
    let artifact = newest_artifact(&spec.current_dir, target);
    let runs = parse_fuzz_runs(&output.combined_output);
    Ok(PhaseReport {
        kind: PhaseKind::Fuzz,
        name: log_name,
        status,
        command: command_vec(&spec),
        duration_ms: output.duration_ms,
        log_path: Some(log_path.display().to_string()),
        summary: format!("target {target}, budget {time}s"),
        evidence: PhaseEvidence::Fuzz {
            target: Some(target.into()),
            artifact: artifact.map(|p| p.display().to_string()),
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
            artifact: None,
            runs: None,
            excerpt: None,
        },
    }
}

fn harness_dir(crate_plan: &CratePlan, group: &FuzzGroupPlan) -> PathBuf {
    group
        .harness_dir
        .clone()
        .unwrap_or_else(|| crate_plan.path.clone())
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
    None
}

fn newest_artifact(harness_root: &Path, target: &str) -> Option<PathBuf> {
    let dir = harness_root.join("fuzz").join("artifacts").join(target);
    let mut newest = None;
    for entry in std::fs::read_dir(dir).ok()? {
        let entry = entry.ok()?;
        let modified = entry.metadata().ok()?.modified().ok()?;
        if newest
            .as_ref()
            .is_none_or(|(current, _): &(std::time::SystemTime, PathBuf)| modified > *current)
        {
            newest = Some((modified, entry.path()));
        }
    }
    newest.map(|(_, path)| path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CratePlan, FuzzGroupPlan, MiriCasePlan};
    use std::cell::RefCell;
    use tempfile::tempdir;

    struct ScriptedExecutor {
        outputs: RefCell<Vec<CommandOutput>>,
        calls: RefCell<Vec<CommandSpec>>,
    }

    impl ScriptedExecutor {
        fn new(outputs: Vec<CommandOutput>) -> Self {
            Self {
                outputs: RefCell::new(outputs),
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl CommandExecutor for ScriptedExecutor {
        fn run(&self, spec: &CommandSpec) -> Result<CommandOutput> {
            self.calls.borrow_mut().push(spec.clone());
            Ok(self.outputs.borrow_mut().remove(0))
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
        assert_eq!(executor.calls.borrow().len(), 2);
        let first = &executor.calls.borrow()[0];
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
            output(true, "#1 runs: 123 cov: 4"),
            output(false, "panic occurred"),
        ]);

        let phases = run_fuzz_groups(
            &plan,
            Some(9),
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
                runs: Some(123),
                ..
            }
        ));
        assert!(executor.calls.borrow()[1]
            .args
            .contains(&"-max_total_time=3".to_string()));
        assert_eq!(executor.calls.borrow()[1].env.get("GLOBAL").unwrap(), "1");
        assert_eq!(executor.calls.borrow()[1].env.get("A").unwrap(), "B");
    }

    #[test]
    fn fuzz_all_with_failed_list_becomes_skipped() {
        let dir = tempdir().unwrap();
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
        let phases = run_fuzz_groups(&plan, None, &BTreeMap::new(), dir.path(), &executor).unwrap();
        assert_eq!(phases[0].status, PhaseStatus::Skipped);
        assert!(phases[0].summary.contains("no fuzz targets"));
    }
}
