use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    Json,
    Markdown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunProfile {
    Smoke,
    Baseline,
    Full,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunPlan {
    pub name: String,
    pub output_root: PathBuf,
    pub profile: RunProfile,
    pub jobs: usize,
    pub fuzz_jobs: usize,
    pub phases: PhaseSelection,
    pub formats: Vec<OutputFormat>,
    pub dry_run: bool,
    pub miri_triage: bool,
    pub fuzz_time: Option<u64>,
    pub fuzz_env: BTreeMap<String, String>,
    pub crates: Vec<CratePlan>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PhaseSelection {
    pub scan: bool,
    pub geiger: bool,
    pub miri: bool,
    pub fuzz: bool,
}

impl Default for PhaseSelection {
    fn default() -> Self {
        Self {
            scan: true,
            geiger: true,
            miri: true,
            fuzz: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub output_root: Option<PathBuf>,
    pub crates: Vec<String>,
    pub dry_run: bool,
    pub profile: RunProfile,
    pub jobs: usize,
    pub fuzz_jobs: usize,
    pub phases: PhaseSelection,
    pub miri_triage: bool,
    pub fuzz_time: Option<u64>,
    pub fuzz_env: BTreeMap<String, String>,
    pub formats: Vec<OutputFormat>,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            output_root: None,
            crates: Vec::new(),
            dry_run: false,
            profile: RunProfile::Full,
            jobs: 1,
            fuzz_jobs: 1,
            phases: PhaseSelection::default(),
            miri_triage: false,
            fuzz_time: None,
            fuzz_env: BTreeMap::new(),
            formats: vec![OutputFormat::Json, OutputFormat::Markdown],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CratePlan {
    pub name: String,
    pub path: PathBuf,
    pub cohort: Option<String>,
    pub miri_cases: Vec<MiriCasePlan>,
    pub fuzz_groups: Vec<FuzzGroupPlan>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiriCasePlan {
    pub name: String,
    pub scope: String,
    pub harness_dir: Option<PathBuf>,
    pub test: Option<String>,
    pub case: Option<String>,
    pub exact: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzGroupPlan {
    pub name: String,
    pub harness_dir: Option<PathBuf>,
    pub all: bool,
    pub targets: Vec<String>,
    pub time: Option<u64>,
    pub budget_label: Option<String>,
    pub env: BTreeMap<String, String>,
}

pub fn load_plan(input: &Path, options: RunOptions) -> Result<RunPlan> {
    if input.is_file() {
        load_manifest_plan(input, options)
    } else {
        load_single_crate_plan(input, options)
    }
}

fn load_single_crate_plan(input: &Path, options: RunOptions) -> Result<RunPlan> {
    let cargo_toml = input.join("Cargo.toml");
    if !cargo_toml.exists() {
        anyhow::bail!("crate input must contain Cargo.toml: {}", input.display());
    }

    let name = crate_name(input)?;
    Ok(RunPlan {
        name: name.clone(),
        output_root: options
            .output_root
            .unwrap_or_else(|| PathBuf::from("unsafe-audit-out")),
        profile: options.profile,
        jobs: normalize_jobs(options.jobs),
        fuzz_jobs: normalize_jobs(options.fuzz_jobs),
        phases: options.phases,
        formats: normalized_formats(options.formats),
        dry_run: options.dry_run,
        miri_triage: options.miri_triage,
        fuzz_time: apply_profile_time(options.profile, options.fuzz_time),
        fuzz_env: options.fuzz_env,
        crates: vec![CratePlan {
            name,
            path: input.to_path_buf(),
            cohort: None,
            miri_cases: vec![MiriCasePlan {
                name: "upstream_full".into(),
                scope: "full_suite".into(),
                harness_dir: None,
                test: None,
                case: None,
                exact: false,
            }],
            fuzz_groups: vec![FuzzGroupPlan {
                name: "existing_targets".into(),
                harness_dir: None,
                all: true,
                targets: Vec::new(),
                time: apply_profile_time(options.profile, options.fuzz_time),
                budget_label: Some("single_crate".into()),
                env: default_single_crate_fuzz_env(),
            }],
        }],
    })
}

fn load_manifest_plan(path: &Path, options: RunOptions) -> Result<RunPlan> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading study manifest {}", path.display()))?;
    let manifest: ManifestToml = toml::from_str(&content)
        .with_context(|| format!("parsing study manifest {}", path.display()))?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    let cwd = std::env::current_dir()?;
    let manifest_root = if base.file_name().is_some_and(|name| name == "study") {
        base.parent().unwrap_or(base)
    } else {
        cwd.as_path()
    };
    let study = manifest.study.unwrap_or_default();
    let output_root = options
        .output_root
        .or(study
            .output_root
            .map(|p| resolve_from_root_or_manifest(base, manifest_root, p)))
        .unwrap_or_else(|| PathBuf::from("study-output"));
    let fuzz_time = apply_profile_time(options.profile, options.fuzz_time.or(study.fuzz_time));

    let selected: Option<std::collections::BTreeSet<_>> = if options.crates.is_empty() {
        None
    } else {
        Some(options.crates.iter().cloned().collect())
    };

    let mut crates = Vec::new();
    for item in manifest.crates {
        if selected
            .as_ref()
            .is_some_and(|names| !names.contains(&item.name))
        {
            continue;
        }
        let crate_path = resolve_from_root_or_manifest(base, manifest_root, item.path.clone());
        let miri_cases = manifest_miri_cases(&item, base, manifest_root);
        let fuzz_groups = manifest_fuzz_groups(
            &item,
            &study.fuzz_env,
            &options.fuzz_env,
            fuzz_time,
            options.profile,
            manifest_root,
            base,
        );
        crates.push(CratePlan {
            name: item.name,
            path: crate_path,
            cohort: item.cohort,
            miri_cases,
            fuzz_groups,
        });
    }

    if crates.is_empty() {
        anyhow::bail!("study manifest selected no crates");
    }

    Ok(RunPlan {
        name: study.name.unwrap_or_else(|| "unsafe-study".into()),
        output_root,
        profile: options.profile,
        jobs: normalize_jobs(options.jobs),
        fuzz_jobs: normalize_jobs(options.fuzz_jobs),
        phases: options.phases,
        formats: normalized_formats(options.formats),
        dry_run: options.dry_run,
        miri_triage: options.miri_triage,
        fuzz_time,
        fuzz_env: options.fuzz_env,
        crates,
    })
}

fn manifest_miri_cases(
    item: &ManifestCrate,
    base: &Path,
    manifest_root: &Path,
) -> Vec<MiriCasePlan> {
    let mapped: Vec<_> = item
        .miri_case
        .iter()
        .map(|case| MiriCasePlan {
            name: case.name.clone(),
            scope: case.scope.clone().unwrap_or_else(|| "unspecified".into()),
            harness_dir: case
                .harness_dir
                .clone()
                .map(|p| resolve_from_root_or_manifest(base, manifest_root, p)),
            test: case.test.clone(),
            case: case.case.clone(),
            exact: case.exact.unwrap_or(false),
        })
        .collect();

    let (builtin, harness): (Vec<_>, Vec<_>) = mapped
        .into_iter()
        .partition(|case| case.harness_dir.is_none());

    let mut ordered = Vec::new();
    if builtin.is_empty() && !harness.is_empty() {
        ordered.push(default_manifest_miri_case());
    }
    ordered.extend(builtin);
    ordered.extend(harness);
    ordered
}

fn default_manifest_miri_case() -> MiriCasePlan {
    MiriCasePlan {
        name: "upstream_full".into(),
        scope: "full_suite".into(),
        harness_dir: None,
        test: None,
        case: None,
        exact: false,
    }
}

fn manifest_fuzz_groups(
    item: &ManifestCrate,
    study_fuzz_env: &BTreeMap<String, String>,
    cli_fuzz_env: &BTreeMap<String, String>,
    fuzz_time: Option<u64>,
    profile: RunProfile,
    manifest_root: &Path,
    base: &Path,
) -> Vec<FuzzGroupPlan> {
    let mapped: Vec<_> = item
        .fuzz_group
        .iter()
        .map(|group| {
            manifest_fuzz_group_plan(
                group,
                study_fuzz_env,
                cli_fuzz_env,
                fuzz_time,
                profile,
                base,
                manifest_root,
            )
        })
        .collect();

    let (builtin, harness): (Vec<_>, Vec<_>) = mapped
        .into_iter()
        .partition(|group| group.harness_dir.is_none());

    let auto_harness = if harness.is_empty() {
        find_fuzz_harness_dir(manifest_root, &item.name).map(|dir| FuzzGroupPlan {
            name: "harness_targets".into(),
            harness_dir: Some(dir),
            all: true,
            targets: Vec::new(),
            time: apply_profile_time(profile, fuzz_time),
            budget_label: Some("harness".into()),
            env: merged_fuzz_env(study_fuzz_env, BTreeMap::new(), cli_fuzz_env),
        })
    } else {
        None
    };

    let mut ordered = Vec::new();
    if builtin.is_empty() && (auto_harness.is_some() || !harness.is_empty()) {
        ordered.push(default_manifest_fuzz_group(
            study_fuzz_env,
            cli_fuzz_env,
            apply_profile_time(profile, fuzz_time),
        ));
    }
    ordered.extend(builtin);
    ordered.extend(harness);
    if let Some(group) = auto_harness {
        ordered.push(group);
    }
    ordered
}

fn manifest_fuzz_group_plan(
    group: &ManifestFuzzGroup,
    study_fuzz_env: &BTreeMap<String, String>,
    cli_fuzz_env: &BTreeMap<String, String>,
    fuzz_time: Option<u64>,
    profile: RunProfile,
    base: &Path,
    manifest_root: &Path,
) -> FuzzGroupPlan {
    FuzzGroupPlan {
        name: group.name.clone(),
        harness_dir: group
            .harness_dir
            .clone()
            .map(|p| resolve_from_root_or_manifest(base, manifest_root, p)),
        all: group.all.unwrap_or(false),
        targets: group.targets.clone(),
        time: apply_profile_time(profile, group.time.or(fuzz_time)),
        budget_label: group.budget_label.clone(),
        env: merged_fuzz_env(study_fuzz_env, group.env.clone(), cli_fuzz_env),
    }
}

fn default_manifest_fuzz_group(
    study_fuzz_env: &BTreeMap<String, String>,
    cli_fuzz_env: &BTreeMap<String, String>,
    fuzz_time: Option<u64>,
) -> FuzzGroupPlan {
    FuzzGroupPlan {
        name: "existing_targets".into(),
        harness_dir: None,
        all: true,
        targets: Vec::new(),
        time: fuzz_time,
        budget_label: Some("default".into()),
        env: merged_fuzz_env(study_fuzz_env, BTreeMap::new(), cli_fuzz_env),
    }
}

fn merged_fuzz_env(
    study_fuzz_env: &BTreeMap<String, String>,
    group_env: BTreeMap<String, String>,
    cli_fuzz_env: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut env = study_fuzz_env.clone();
    env.extend(group_env);
    env.extend(cli_fuzz_env.clone());
    env
}

fn find_fuzz_harness_dir(manifest_root: &Path, crate_name: &str) -> Option<PathBuf> {
    for root in fuzz_harness_roots(manifest_root) {
        let harness_root = root.join("fuzz_harnesses");
        let Ok(entries) = std::fs::read_dir(&harness_root) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_dir() {
                continue;
            }
            let dir_name = entry.file_name();
            let dir_name = dir_name.to_string_lossy();
            if normalize_package_name(&dir_name) != normalize_package_name(crate_name) {
                continue;
            }
            let manifest = entry.path().join("Cargo.toml");
            if manifest.is_file() {
                return Some(entry.path());
            }
        }
    }
    None
}

fn fuzz_harness_roots(manifest_root: &Path) -> Vec<PathBuf> {
    let mut roots = vec![manifest_root.to_path_buf()];
    if let Some(parent) = manifest_root.parent() {
        if parent != manifest_root {
            roots.push(parent.to_path_buf());
        }
    }
    roots
}

fn normalize_package_name(name: &str) -> String {
    name.replace('_', "-")
}

fn normalized_formats(formats: Vec<OutputFormat>) -> Vec<OutputFormat> {
    if formats.is_empty() {
        vec![OutputFormat::Json, OutputFormat::Markdown]
    } else {
        formats
    }
}

fn normalize_jobs(jobs: usize) -> usize {
    jobs.max(1)
}

fn default_single_crate_fuzz_env() -> BTreeMap<String, String> {
    BTreeMap::from([("ASAN_OPTIONS".into(), "detect_leaks=0".into())])
}

fn apply_profile_time(profile: RunProfile, time: Option<u64>) -> Option<u64> {
    let capped = match profile {
        RunProfile::Smoke => Some(30),
        RunProfile::Baseline => Some(300),
        RunProfile::Full => None,
    };
    match (time, capped) {
        (_, None) => time,
        (Some(time), Some(cap)) => Some(time.min(cap)),
        (None, Some(cap)) => Some(cap),
    }
}

fn resolve(base: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

fn resolve_from_root_or_manifest(base: &Path, root: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        return path;
    }
    let root_path = root.join(&path);
    if root_path.exists()
        || path.starts_with("study/")
        || path.starts_with("targets/")
        || path.starts_with("miri_harnesses")
    {
        root_path
    } else {
        resolve(base, path)
    }
}

fn crate_name(path: &Path) -> Result<String> {
    #[derive(Deserialize)]
    struct CargoToml {
        package: Option<Package>,
    }
    #[derive(Deserialize)]
    struct Package {
        name: Option<String>,
    }
    let content = std::fs::read_to_string(path.join("Cargo.toml"))
        .with_context(|| format!("reading {}", path.join("Cargo.toml").display()))?;
    let cargo: CargoToml = toml::from_str(&content)?;
    Ok(cargo
        .package
        .and_then(|p| p.name)
        .or_else(|| path.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "crate".into()))
}

#[derive(Debug, Default, Deserialize)]
struct ManifestStudy {
    name: Option<String>,
    output_root: Option<PathBuf>,
    fuzz_time: Option<u64>,
    #[serde(default)]
    fuzz_env: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct ManifestToml {
    study: Option<ManifestStudy>,
    #[serde(rename = "crate", default)]
    crates: Vec<ManifestCrate>,
}

#[derive(Debug, Deserialize)]
struct ManifestCrate {
    name: String,
    path: PathBuf,
    cohort: Option<String>,
    #[serde(default)]
    miri_case: Vec<ManifestMiriCase>,
    #[serde(default)]
    fuzz_group: Vec<ManifestFuzzGroup>,
}

#[derive(Debug, Deserialize)]
struct ManifestMiriCase {
    name: String,
    scope: Option<String>,
    harness_dir: Option<PathBuf>,
    test: Option<String>,
    case: Option<String>,
    exact: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct ManifestFuzzGroup {
    name: String,
    harness_dir: Option<PathBuf>,
    all: Option<bool>,
    #[serde(default)]
    targets: Vec<String>,
    time: Option<u64>,
    budget_label: Option<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
}

#[cfg(test)]
#[path = "tests/config_tests.rs"]
mod tests;
