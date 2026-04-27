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
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn single_crate_defaults_to_one_miri_case_and_one_fuzz_group() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname='demo'\nversion='0.1.0'\n",
        )
        .unwrap();

        let plan = load_plan(dir.path(), RunOptions::default()).unwrap();
        assert_eq!(plan.crates[0].name, "demo");
        assert_eq!(plan.crates[0].miri_cases[0].name, "upstream_full");
        assert!(plan.crates[0].fuzz_groups[0].all);
        assert_eq!(plan.jobs, 1);
        assert_eq!(plan.fuzz_jobs, 1);
        assert_eq!(
            plan.crates[0].fuzz_groups[0]
                .env
                .get("ASAN_OPTIONS")
                .unwrap(),
            "detect_leaks=0"
        );
    }

    #[test]
    fn manifest_selection_filters_crates() {
        let dir = tempdir().unwrap();
        let manifest = dir.path().join("study.toml");
        std::fs::write(
            &manifest,
            "[study]\nname='s'\n[[crate]]\nname='a'\npath='a'\n[[crate]]\nname='b'\npath='b'\n",
        )
        .unwrap();

        let plan = load_plan(
            &manifest,
            RunOptions {
                crates: vec!["b".into()],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(plan.crates.len(), 1);
        assert_eq!(plan.crates[0].name, "b");
    }

    #[test]
    fn smoke_profile_caps_fuzz_time() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname='demo'\nversion='0.1.0'\n",
        )
        .unwrap();
        let plan = load_plan(
            dir.path(),
            RunOptions {
                profile: RunProfile::Smoke,
                fuzz_time: Some(600),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(plan.fuzz_time, Some(30));
        assert_eq!(plan.crates[0].fuzz_groups[0].time, Some(30));
    }

    #[test]
    fn baseline_profile_caps_manifest_group_times() {
        let dir = tempdir().unwrap();
        let manifest = dir.path().join("study.toml");
        std::fs::write(
            &manifest,
            "[study]\nfuzz_time=3600\n[[crate]]\nname='a'\npath='a'\n[[crate.fuzz_group]]\nname='g'\ntargets=['x']\ntime=900\n",
        )
        .unwrap();
        let plan = load_plan(
            &manifest,
            RunOptions {
                profile: RunProfile::Baseline,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(plan.fuzz_time, Some(300));
        assert_eq!(plan.crates[0].fuzz_groups[0].time, Some(300));
    }

    #[test]
    fn manifest_merges_fuzz_env_with_cli_precedence() {
        let dir = tempdir().unwrap();
        let manifest = dir.path().join("study.toml");
        std::fs::write(
            &manifest,
            r#"
[study]
fuzz_time = 30
fuzz_env = { A = "study", B = "study" }

[[crate]]
name = "demo"
path = "demo"

[[crate.fuzz_group]]
name = "fg"
targets = ["parse"]
time = 5
env = { B = "group", C = "group" }
"#,
        )
        .unwrap();

        let plan = load_plan(
            &manifest,
            RunOptions {
                fuzz_env: BTreeMap::from([("C".into(), "cli".into()), ("D".into(), "cli".into())]),
                ..Default::default()
            },
        )
        .unwrap();
        let group = &plan.crates[0].fuzz_groups[0];
        assert_eq!(group.time, Some(5));
        assert_eq!(group.env.get("A").unwrap(), "study");
        assert_eq!(group.env.get("B").unwrap(), "group");
        assert_eq!(group.env.get("C").unwrap(), "cli");
        assert_eq!(group.env.get("D").unwrap(), "cli");
    }

    #[test]
    fn manifest_prepends_builtin_miri_before_harness_cases() {
        let dir = tempdir().unwrap();
        let manifest = dir.path().join("study.toml");
        std::fs::create_dir_all(dir.path().join("demo")).unwrap();
        std::fs::create_dir_all(dir.path().join("harness")).unwrap();
        std::fs::write(
            &manifest,
            "[[crate]]\nname='demo'\npath='demo'\n[[crate.miri_case]]\nname='targeted'\nharness_dir='harness'\ntest='demo'\ncase='case_name'\nexact=true\n",
        )
        .unwrap();

        let plan = load_plan(&manifest, RunOptions::default()).unwrap();
        let cases = &plan.crates[0].miri_cases;

        assert_eq!(cases.len(), 2);
        assert_eq!(cases[0].name, "upstream_full");
        assert!(cases[0].harness_dir.is_none());
        assert_eq!(cases[1].name, "targeted");
        assert!(cases[1].harness_dir.is_some());
    }

    #[test]
    fn manifest_appends_detected_fuzz_harness_after_builtin_groups() {
        let dir = tempdir().unwrap();
        let study_dir = dir.path().join("study");
        std::fs::create_dir_all(&study_dir).unwrap();
        let manifest = study_dir.join("study.toml");
        std::fs::create_dir_all(dir.path().join("fuzz_harnesses/demo")).unwrap();
        std::fs::write(
            dir.path().join("fuzz_harnesses/demo/Cargo.toml"),
            "[package]\nname='demo-fuzz'\nversion='0.1.0'\n",
        )
        .unwrap();
        std::fs::write(
            &manifest,
            "[[crate]]\nname='demo'\npath='demo'\n[[crate.fuzz_group]]\nname='builtin'\nall=true\n",
        )
        .unwrap();

        let plan = load_plan(&manifest, RunOptions::default()).unwrap();
        let groups = &plan.crates[0].fuzz_groups;

        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].name, "builtin");
        assert!(groups[0].harness_dir.is_none());
        assert_eq!(groups[1].name, "harness_targets");
        assert_eq!(
            groups[1].harness_dir.as_ref().unwrap(),
            &dir.path().join("fuzz_harnesses/demo")
        );
    }

    #[test]
    fn manifest_injects_builtin_fuzz_group_before_harness_only_groups() {
        let dir = tempdir().unwrap();
        let manifest = dir.path().join("study.toml");
        std::fs::create_dir_all(dir.path().join("fuzz_harnesses/demo")).unwrap();
        std::fs::write(
            dir.path().join("fuzz_harnesses/demo/Cargo.toml"),
            "[package]\nname='demo-fuzz'\nversion='0.1.0'\n",
        )
        .unwrap();
        std::fs::write(
            &manifest,
            "[[crate]]\nname='demo'\npath='demo'\n[[crate.fuzz_group]]\nname='manual_harness'\nharness_dir='fuzz_harnesses/demo'\nall=true\n",
        )
        .unwrap();

        let plan = load_plan(&manifest, RunOptions::default()).unwrap();
        let groups = &plan.crates[0].fuzz_groups;

        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].name, "existing_targets");
        assert!(groups[0].harness_dir.is_none());
        assert_eq!(groups[1].name, "manual_harness");
        assert!(groups[1].harness_dir.is_some());
    }

    #[test]
    fn empty_format_list_restores_default_outputs() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname='demo'\nversion='0.1.0'\n",
        )
        .unwrap();
        let plan = load_plan(
            dir.path(),
            RunOptions {
                formats: Vec::new(),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            plan.formats,
            vec![OutputFormat::Json, OutputFormat::Markdown]
        );
    }

    #[test]
    fn selecting_missing_manifest_crate_is_an_error() {
        let dir = tempdir().unwrap();
        let manifest = dir.path().join("study.toml");
        std::fs::write(&manifest, "[[crate]]\nname='a'\npath='a'\n").unwrap();
        let err = load_plan(
            &manifest,
            RunOptions {
                crates: vec!["missing".into()],
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("selected no crates"));
    }
}
