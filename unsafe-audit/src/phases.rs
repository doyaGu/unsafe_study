use crate::config::{CratePlan, FuzzGroupPlan, MiriCasePlan};
use crate::fs;
use crate::report::{PhaseEvidence, PhaseKind, PhaseReport, PhaseStatus};
use crate::runner::{excerpt, format_duration_ms, CommandExecutor, CommandOutput, CommandSpec};
use anyhow::Result;
use serde::Deserialize;
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
        current_dir: geiger_working_dir(crate_plan),
    };
    let output = executor.run(&spec)?;
    let log_path = phase_log_path(crate_root, "geiger", "root");
    fs::write_log(&log_path, &output.combined_output)?;
    let (root_unsafe, dependency_unsafe) = parse_geiger_counts(&output.combined_output, crate_plan);
    let status = if output.success {
        PhaseStatus::Clean
    } else if is_geiger_tool_failure(&output.combined_output) {
        PhaseStatus::Skipped
    } else {
        PhaseStatus::Error
    };
    Ok(PhaseReport {
        kind: PhaseKind::Geiger,
        name: "root".into(),
        status,
        command: command_vec(&spec),
        duration_ms: output.duration_ms,
        log_path: Some(log_path.display().to_string()),
        summary: match (root_unsafe, dependency_unsafe) {
            (Some(root), Some(deps)) => format!("root unsafe {root}, dependency unsafe {deps}"),
            (Some(root), None) => format!("root unsafe {root}"),
            _ if status == PhaseStatus::Skipped => "geiger tool failure, skipped".into(),
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

#[derive(Deserialize)]
struct CargoManifestProbe {
    package: Option<CargoManifestPackage>,
    workspace: Option<toml::Value>,
}

#[derive(Deserialize)]
struct CargoManifestPackage {
    name: String,
}

fn geiger_working_dir(crate_plan: &CratePlan) -> PathBuf {
    let manifest = crate_plan.path.join("Cargo.toml");
    let Ok(contents) = std::fs::read_to_string(&manifest) else {
        return crate_plan.path.clone();
    };
    let Ok(parsed) = toml::from_str::<CargoManifestProbe>(&contents) else {
        return crate_plan.path.clone();
    };
    if parsed.package.is_some() || parsed.workspace.is_none() {
        return crate_plan.path.clone();
    }
    find_workspace_member_dir(&crate_plan.path, &crate_plan.name)
        .unwrap_or_else(|| crate_plan.path.clone())
}

fn find_workspace_member_dir(root: &Path, crate_name: &str) -> Option<PathBuf> {
    let entries = std::fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let manifest = entry.path().join("Cargo.toml");
        let Some(package_name) = manifest_package_name(&manifest) else {
            continue;
        };
        if package_names_match(&package_name, crate_name) {
            return Some(entry.path());
        }
    }
    None
}

fn manifest_package_name(manifest: &Path) -> Option<String> {
    let contents = std::fs::read_to_string(manifest).ok()?;
    let parsed = toml::from_str::<CargoManifestProbe>(&contents).ok()?;
    parsed.package.map(|package| package.name)
}

fn package_names_match(actual: &str, expected: &str) -> bool {
    normalize_package_name(actual) == normalize_package_name(expected)
}

fn normalize_package_name(name: &str) -> String {
    name.replace('_', "-")
}

fn is_geiger_tool_failure(output: &str) -> bool {
    output.contains("thread 'main'")
        && output.contains("assertion failed: self.pending_ids.insert(id)")
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

    let log_path = phase_log_path(crate_root, "miri", &case.name);
    fs::write_log(&log_path, &combined_log)?;
    let verdict = miri_verdict(&strict, baseline.as_ref());
    let status = match verdict.as_str() {
        "clean" => PhaseStatus::Clean,
        "ub_observed" | "strict_only_ub" => PhaseStatus::Finding,
        _ => PhaseStatus::Error,
    };
    let category = if matches!(status, PhaseStatus::Finding) {
        classify_ub(&combined_log)
    } else {
        None
    };

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
        let discovered = discover_fuzz_targets(crate_plan, group, executor)?;
        let (targets, skipped) = if group.all {
            (discovered.targets.clone(), Vec::new())
        } else {
            select_fuzz_targets(group, &discovered, crate_root)?
        };
        if targets.is_empty() {
            reports.push(no_targets_report(group, &discovered, crate_root)?);
            continue;
        }
        reports.extend(skipped);
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

struct FuzzDiscovery {
    targets: Vec<String>,
    command: Vec<String>,
    summary: String,
    detail: String,
}

#[derive(Debug, Clone)]
struct FuzzBuildFailure {
    command: Vec<String>,
    detail: String,
}

fn discover_fuzz_targets(
    crate_plan: &CratePlan,
    group: &FuzzGroupPlan,
    executor: &dyn CommandExecutor,
) -> Result<FuzzDiscovery> {
    let default_command = vec!["cargo".into(), "fuzz".into(), "list".into()];
    let harness_root = match canonical_harness_dir(crate_plan, group) {
        Ok(path) => path,
        Err(err) => {
            return Ok(FuzzDiscovery {
                targets: Vec::new(),
                command: default_command,
                summary: "fuzz workspace missing or harness dir unresolved".into(),
                detail: format!(
                    "unable to resolve harness directory for fuzz group {}: {}",
                    group.name, err
                ),
            });
        }
    };
    let spec = CommandSpec {
        program: "cargo".into(),
        args: vec!["fuzz".into(), "list".into()],
        env: BTreeMap::new(),
        current_dir: harness_root,
    };
    let command = command_vec(&spec);
    let output = match executor.run(&spec) {
        Ok(output) => output,
        Err(err) => {
            return Ok(FuzzDiscovery {
                targets: Vec::new(),
                command,
                summary: "cargo fuzz list failed".into(),
                detail: format!("failed to run cargo fuzz list: {err}"),
            });
        }
    };
    if !output.success {
        return Ok(FuzzDiscovery {
            targets: Vec::new(),
            command,
            summary: "cargo fuzz list failed".into(),
            detail: output.combined_output,
        });
    }
    let targets: Vec<String> = output
        .combined_output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("warning:"))
        .map(str::to_string)
        .collect();
    let summary = if targets.is_empty() {
        "no fuzz targets discovered".into()
    } else {
        format!("discovered {} fuzz targets", targets.len())
    };
    Ok(FuzzDiscovery {
        targets,
        command,
        summary,
        detail: output.combined_output,
    })
}

fn select_fuzz_targets(
    group: &FuzzGroupPlan,
    discovery: &FuzzDiscovery,
    crate_root: &Path,
) -> Result<(Vec<String>, Vec<PhaseReport>)> {
    let discovered = &discovery.targets;
    let discovered: std::collections::BTreeSet<_> = discovered.iter().map(String::as_str).collect();
    let mut available = Vec::new();
    let mut skipped = Vec::new();

    for target in &group.targets {
        if discovered.contains(target.as_str()) {
            available.push(target.clone());
        } else {
            skipped.push(missing_fuzz_target_report(
                group, target, discovery, crate_root,
            )?);
        }
    }

    Ok((available, skipped))
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
    let corpus = ensure_fuzz_corpus_dir(crate_plan, target, &harness_root)?;
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
    let log_path = phase_log_path(crate_root, "fuzz", &log_name);
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

fn ensure_fuzz_corpus_dir(
    crate_plan: &CratePlan,
    target: &str,
    harness_root: &Path,
) -> Result<PathBuf> {
    let corpus = harness_root.join("fuzz").join("corpus").join(target);
    std::fs::create_dir_all(&corpus)?;
    if !dir_is_empty(&corpus)? {
        return Ok(corpus);
    }
    if let Some(seed_dir) = canonical_seed_corpus_dir(crate_plan, target) {
        if seed_dir.is_dir() {
            copy_dir_contents(&seed_dir, &corpus)?;
        }
    }
    Ok(corpus)
}

fn canonical_seed_corpus_dir(crate_plan: &CratePlan, target: &str) -> Option<PathBuf> {
    let repo_root = repo_root_from_crate_path(&crate_plan.path)?;
    Some(
        repo_root
            .join("fuzz_harnesses")
            .join(&crate_plan.name)
            .join("corpus")
            .join(target),
    )
}

fn repo_root_from_crate_path(crate_path: &Path) -> Option<PathBuf> {
    let crate_path = crate_path.canonicalize().ok()?;
    for ancestor in crate_path.ancestors() {
        if ancestor.join("study").is_dir() && ancestor.join("unsafe-audit").is_dir() {
            return Some(ancestor.to_path_buf());
        }
    }
    let parent = crate_path.parent()?;
    if parent.file_name().and_then(|name| name.to_str()) == Some("targets") {
        return parent.parent().map(Path::to_path_buf);
    }
    None
}

fn dir_is_empty(dir: &Path) -> Result<bool> {
    Ok(std::fs::read_dir(dir)?.next().transpose()?.is_none())
}

fn copy_dir_contents(src: &Path, dst: &Path) -> Result<()> {
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            std::fs::create_dir_all(&dst_path)?;
            copy_dir_contents(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

fn no_targets_report(
    group: &FuzzGroupPlan,
    discovery: &FuzzDiscovery,
    crate_root: &Path,
) -> Result<PhaseReport> {
    let root_cause = if discovery.targets.is_empty() {
        discovery.summary.clone()
    } else {
        "configured fuzz targets not present in local workspace".into()
    };
    let summary = format!("no fuzz targets available: {root_cause}");
    let log_name = group.name.clone();
    let mut log = format!("command: {}\n", discovery.command.join(" "));
    if !group.all && !group.targets.is_empty() {
        log.push_str(&format!(
            "configured targets: {}\n",
            group.targets.join(", ")
        ));
    }
    if !discovery.targets.is_empty() {
        log.push_str(&format!(
            "discovered targets: {}\n",
            discovery.targets.join(", ")
        ));
    }
    if !discovery.detail.trim().is_empty() {
        log.push('\n');
        log.push_str(discovery.detail.trim());
        log.push('\n');
    }
    let log_path = write_phase_note(crate_root, "fuzz", &log_name, &log)?;
    Ok(PhaseReport {
        kind: PhaseKind::Fuzz,
        name: group.name.clone(),
        status: PhaseStatus::Skipped,
        command: discovery.command.clone(),
        duration_ms: 0,
        log_path: Some(log_path),
        summary,
        evidence: PhaseEvidence::Fuzz {
            target: None,
            budget_secs: None,
            artifact: None,
            error_kind: None,
            runs: None,
            excerpt: excerpt(&log),
        },
    })
}

fn missing_fuzz_target_report(
    group: &FuzzGroupPlan,
    target: &str,
    discovery: &FuzzDiscovery,
    crate_root: &Path,
) -> Result<PhaseReport> {
    let name = format!("{}.{}", group.name, target);
    let mut log = format!(
        "command: {}\nconfigured target: {}\n",
        discovery.command.join(" "),
        target
    );
    if !discovery.targets.is_empty() {
        log.push_str(&format!(
            "discovered targets: {}\n",
            discovery.targets.join(", ")
        ));
    }
    if !discovery.detail.trim().is_empty() {
        log.push('\n');
        log.push_str(discovery.detail.trim());
        log.push('\n');
    }
    let log_path = write_phase_note(crate_root, "fuzz", &name, &log)?;
    Ok(PhaseReport {
        kind: PhaseKind::Fuzz,
        name,
        status: PhaseStatus::Skipped,
        command: vec!["cargo".into(), "fuzz".into(), "build".into(), target.into()],
        duration_ms: 0,
        log_path: Some(log_path),
        summary: format!("configured fuzz target {target} not present in local workspace"),
        evidence: PhaseEvidence::Fuzz {
            target: Some(target.into()),
            budget_secs: group.time,
            artifact: None,
            error_kind: None,
            runs: None,
            excerpt: excerpt(&log),
        },
    })
}

fn write_phase_note(crate_root: &Path, phase: &str, name: &str, content: &str) -> Result<String> {
    let log_path = phase_log_path(crate_root, phase, name);
    fs::write_log(&log_path, content)?;
    Ok(log_path.display().to_string())
}

fn phase_log_path(crate_root: &Path, phase: &str, name: &str) -> PathBuf {
    crate_root.join("logs").join(format!(
        "{}.{}.log",
        fs::sanitize(phase),
        fs::sanitize(name)
    ))
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
    let mut reports = Vec::new();
    let mut runnable_targets = Vec::new();
    let mut built = Vec::new();
    for target in targets {
        eprintln!(
            "    fuzz target {}: build start (budget {}s)",
            target,
            group.time.or(default_time).unwrap_or(60)
        );
        match build_fuzz_target(crate_plan, group, target, executor) {
            Ok(binary) => {
                eprintln!("    fuzz target {}: build done", target);
                runnable_targets.push(target.clone());
                built.push(binary);
            }
            Err(err) => {
                eprintln!("    fuzz target {}: build error ({})", target, err.detail);
                reports.push(if let Some(path) = missing_fuzz_bin_path(&err.detail) {
                    missing_fuzz_bin_report(group, target, default_time, crate_root, &err, &path)?
                } else {
                    fuzz_build_error_report(group, target, default_time, crate_root, &err)?
                });
            }
        }
    }
    if runnable_targets.is_empty() {
        return Ok(reports);
    }

    let mut initial = Vec::with_capacity(runnable_targets.len());
    initial.resize_with(runnable_targets.len(), || None);
    let results = Arc::new(Mutex::new(initial));
    let next = Arc::new(Mutex::new(0usize));
    let jobs = fuzz_jobs.max(1).min(runnable_targets.len());
    let built = Arc::new(built);
    let targets = Arc::new(runnable_targets);
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
    for result in results.lock().unwrap().iter_mut() {
        reports.push(result.take().unwrap()?);
    }
    Ok(reports)
}

fn fuzz_build_error_report(
    group: &FuzzGroupPlan,
    target: &str,
    default_time: Option<u64>,
    crate_root: &Path,
    err: &FuzzBuildFailure,
) -> Result<PhaseReport> {
    let time = group.time.or(default_time).unwrap_or(60);
    let name = format!("{}.{}", group.name, target);
    let detail = if err.detail.trim().is_empty() {
        format!("cargo fuzz build failed for {target}")
    } else {
        err.detail.clone()
    };
    let log_path = write_phase_note(crate_root, "fuzz", &name, &detail)?;
    Ok(PhaseReport {
        kind: PhaseKind::Fuzz,
        name,
        status: PhaseStatus::Error,
        command: err.command.clone(),
        duration_ms: 0,
        log_path: Some(log_path),
        summary: format!("target {target}, budget {time}s, build error"),
        evidence: PhaseEvidence::Fuzz {
            target: Some(target.into()),
            budget_secs: Some(time),
            artifact: None,
            error_kind: Some("tool_error".into()),
            runs: None,
            excerpt: excerpt(&detail),
        },
    })
}

fn missing_fuzz_bin_report(
    group: &FuzzGroupPlan,
    target: &str,
    default_time: Option<u64>,
    crate_root: &Path,
    err: &FuzzBuildFailure,
    path: &str,
) -> Result<PhaseReport> {
    let time = group.time.or(default_time).unwrap_or(60);
    let name = format!("{}.{}", group.name, target);
    let detail = if err.detail.trim().is_empty() {
        format!("declared fuzz target source is missing for {target}")
    } else {
        err.detail.clone()
    };
    let log_path = write_phase_note(crate_root, "fuzz", &name, &detail)?;
    Ok(PhaseReport {
        kind: PhaseKind::Fuzz,
        name,
        status: PhaseStatus::Skipped,
        command: err.command.clone(),
        duration_ms: 0,
        log_path: Some(log_path),
        summary: format!("target {target}, budget {time}s, declared source missing at {path}"),
        evidence: PhaseEvidence::Fuzz {
            target: Some(target.into()),
            budget_secs: Some(time),
            artifact: None,
            error_kind: None,
            runs: None,
            excerpt: excerpt(&detail),
        },
    })
}

fn missing_fuzz_bin_path(detail: &str) -> Option<String> {
    let prefix = "error: can't find bin `";
    let rest = detail.split_once(prefix)?.1;
    let (_, after_name) = rest.split_once('`')?;
    let path_prefix = " at path `";
    let path = after_name.split_once(path_prefix)?.1.split_once('`')?.0;
    Some(path.to_string())
}

fn build_fuzz_target(
    crate_plan: &CratePlan,
    group: &FuzzGroupPlan,
    target: &str,
    executor: &dyn CommandExecutor,
) -> std::result::Result<PathBuf, FuzzBuildFailure> {
    let harness_root =
        canonical_harness_dir(crate_plan, group).map_err(|err| FuzzBuildFailure {
            command: vec!["cargo".into(), "fuzz".into(), "build".into(), target.into()],
            detail: format!("unable to resolve harness directory for {target}: {err}"),
        })?;
    let spec = CommandSpec {
        program: "cargo".into(),
        args: vec!["fuzz".into(), "build".into(), target.into()],
        env: BTreeMap::new(),
        current_dir: harness_root.clone(),
    };
    let command = command_vec(&spec);
    let output = executor.run(&spec).map_err(|err| FuzzBuildFailure {
        command: command.clone(),
        detail: format!("failed to run cargo fuzz build for {target}: {err}"),
    })?;
    if !output.success {
        return Err(FuzzBuildFailure {
            command,
            detail: output.combined_output,
        });
    }
    locate_fuzz_binary(&harness_root, target).map_err(|err| FuzzBuildFailure {
        command,
        detail: format!("{}\n\n{}", output.combined_output.trim(), err)
            .trim()
            .to_string(),
    })
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

#[derive(Debug, Deserialize)]
struct GeigerReport {
    packages: Vec<GeigerPackage>,
}

#[derive(Debug, Deserialize)]
struct GeigerPackage {
    package: GeigerPackageMeta,
    unsafety: GeigerUnsafety,
}

#[derive(Debug, Deserialize)]
struct GeigerPackageMeta {
    id: GeigerPackageId,
}

#[derive(Debug, Deserialize)]
struct GeigerPackageId {
    name: String,
    source: Option<GeigerPackageSource>,
}

#[derive(Debug, Deserialize)]
struct GeigerPackageSource {
    #[serde(rename = "Path")]
    path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GeigerUnsafety {
    used: GeigerCounts,
}

#[derive(Debug, Deserialize)]
struct GeigerCounts {
    functions: GeigerUnsafeCount,
    exprs: GeigerUnsafeCount,
    item_impls: GeigerUnsafeCount,
    item_traits: GeigerUnsafeCount,
    methods: GeigerUnsafeCount,
}

#[derive(Debug, Deserialize)]
struct GeigerUnsafeCount {
    #[serde(rename = "unsafe_")]
    unsafe_count: usize,
}

fn parse_geiger_counts(output: &str, crate_plan: &CratePlan) -> (Option<usize>, Option<usize>) {
    let Some(report) = output.lines().rev().find_map(parse_geiger_report_line) else {
        return (None, None);
    };

    let Some(root_index) = report
        .packages
        .iter()
        .position(|package| is_root_geiger_package(package, crate_plan))
        .or_else(|| {
            report
                .packages
                .iter()
                .position(|package| package.package.id.name == crate_plan.name)
        })
    else {
        return (None, None);
    };

    let root_unsafe = geiger_used_unsafe_total(&report.packages[root_index]);
    let dependency_unsafe = report
        .packages
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != root_index)
        .map(|(_, package)| geiger_used_unsafe_total(package))
        .sum();

    (Some(root_unsafe), Some(dependency_unsafe))
}

fn parse_geiger_report_line(line: &str) -> Option<GeigerReport> {
    let candidate = line.trim();
    if !candidate.starts_with('{') || !candidate.contains("\"packages\"") {
        return None;
    }
    serde_json::from_str(candidate).ok()
}

fn is_root_geiger_package(package: &GeigerPackage, crate_plan: &CratePlan) -> bool {
    if package.package.id.name != crate_plan.name {
        return false;
    }

    let Some(source_path) = package
        .package
        .id
        .source
        .as_ref()
        .and_then(|source| source.path.as_deref())
    else {
        return true;
    };

    let Some(decoded_path) = decode_geiger_file_path(source_path) else {
        return false;
    };
    let Ok(root_path) = crate_plan.path.canonicalize() else {
        return decoded_path == crate_plan.path;
    };
    decoded_path == root_path
}

fn decode_geiger_file_path(source_path: &str) -> Option<PathBuf> {
    let encoded = source_path.strip_prefix("file://")?;
    let mut decoded = String::with_capacity(encoded.len());
    let bytes = encoded.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok()?;
            let value = u8::from_str_radix(hex, 16).ok()?;
            decoded.push(char::from(value));
            index += 3;
        } else {
            decoded.push(char::from(bytes[index]));
            index += 1;
        }
    }

    let path_only = decoded.split('#').next().unwrap_or(&decoded);
    Some(PathBuf::from(path_only))
}

fn geiger_used_unsafe_total(package: &GeigerPackage) -> usize {
    let used = &package.unsafety.used;
    used.functions.unsafe_count
        + used.exprs.unsafe_count
        + used.item_impls.unsafe_count
        + used.item_traits.unsafe_count
        + used.methods.unsafe_count
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
        return if fuzz_reached_budget(&output.combined_output) {
            PhaseStatus::Pass
        } else {
            PhaseStatus::Clean
        };
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
        PhaseStatus::Clean | PhaseStatus::Pass | PhaseStatus::Skipped => None,
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
        PhaseStatus::Pass => "pass (reached budget limit without findings)",
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
    status.label()
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

fn fuzz_reached_budget(output: &str) -> bool {
    output.lines().any(|line| {
        let line = line.trim();
        line.strip_prefix("Done ")
            .is_some_and(|rest| rest.contains(" runs in ") && rest.contains(" second(s)"))
    })
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
#[path = "tests/phases_tests.rs"]
mod tests;
