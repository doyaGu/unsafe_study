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
    let log_path = fs::phase_log_path(crate_root, "geiger", "root");
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

    let log_path = fs::phase_log_path(crate_root, "miri", &case.name);
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
    let log_path = fs::phase_log_path(crate_root, phase, name);
    fs::write_log(&log_path, content)?;
    Ok(log_path.display().to_string())
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
    match status {
        PhaseStatus::Clean => "clean",
        PhaseStatus::Pass => "pass",
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
            PhaseEvidence::Miri { verdict, ub_category, .. } => {
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
        let phases =
            run_fuzz_groups(&plan, None, 1, &BTreeMap::new(), dir.path(), &executor).unwrap();
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

        let phases =
            run_fuzz_groups(&plan, Some(9), 1, &BTreeMap::new(), dir.path(), &executor).unwrap();

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

        let phases =
            run_fuzz_groups(&plan, Some(9), 1, &BTreeMap::new(), dir.path(), &executor).unwrap();

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

        let phases =
            run_fuzz_groups(&plan, Some(9), 1, &BTreeMap::new(), repo.path(), &executor).unwrap();

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

        let phases =
            run_fuzz_groups(&plan, Some(9), 1, &BTreeMap::new(), dir.path(), &executor).unwrap();

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

        let phases =
            run_fuzz_groups(&plan, Some(9), 1, &BTreeMap::new(), repo.path(), &executor).unwrap();

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

        let phases =
            run_fuzz_groups(&plan, None, 1, &BTreeMap::new(), dir.path(), &executor).unwrap();

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

        let phases =
            run_fuzz_groups(&plan, None, 1, &BTreeMap::new(), dir.path(), &executor).unwrap();

        assert_eq!(phases.len(), 1);
        assert_eq!(phases[0].status, PhaseStatus::Skipped);
        assert!(phases[0].summary.contains("no fuzz targets"));
        let calls = executor.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].args, vec!["fuzz", "list"]);
    }
}
