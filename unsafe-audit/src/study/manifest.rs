use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
struct StudyManifestFile {
    study: StudyDefaultsToml,
    #[serde(rename = "crate")]
    crates: Vec<CrateToml>,
}

#[derive(Debug, Deserialize)]
struct StudyDefaultsToml {
    output_root: String,
    fuzz_time: u64,
    #[serde(default)]
    fuzz_env: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct CrateToml {
    name: String,
    path: String,
    cohort: String,
    coverage_tier: String,
    #[serde(default, rename = "miri_case")]
    miri_cases: Vec<MiriCaseToml>,
    #[serde(default, rename = "fuzz_group")]
    fuzz_groups: Vec<FuzzGroupToml>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MiriCaseToml {
    name: String,
    scope: String,
    harness_dir: Option<String>,
    test: Option<String>,
    case: Option<String>,
    auto_coverage: Option<bool>,
    #[serde(default)]
    exact: bool,
    #[serde(default)]
    triage: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FuzzGroupToml {
    name: String,
    harness_dir: Option<String>,
    auto_coverage: Option<bool>,
    #[serde(default)]
    all: bool,
    #[serde(default)]
    targets: Vec<String>,
    time: Option<u64>,
    budget_label: Option<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
}

pub(super) struct LoadedStudyManifest {
    pub(super) defaults: StudyDefaults,
    pub(super) crates: Vec<StudyCrate>,
}

pub(super) struct StudyDefaults {
    pub(super) output_root: PathBuf,
    pub(super) fuzz_time: u64,
    pub(super) fuzz_env: Vec<(String, String)>,
}

pub(super) struct StudyCrate {
    pub(super) name: String,
    pub(super) path: PathBuf,
    pub(super) cohort: String,
    pub(super) coverage_tier: String,
    pub(super) miri_cases: Vec<StudyMiriCase>,
    pub(super) fuzz_groups: Vec<StudyFuzzGroup>,
}

pub(super) struct StudyMiriCase {
    pub(super) name: String,
    pub(super) scope: crate::domain::MiriScope,
    pub(super) harness_dir: Option<PathBuf>,
    pub(super) test: Option<String>,
    pub(super) case: Option<String>,
    pub(super) auto_coverage: Option<bool>,
    pub(super) exact: bool,
    pub(super) triage: bool,
}

pub(super) struct StudyFuzzGroup {
    pub(super) name: String,
    pub(super) harness_dir: Option<PathBuf>,
    pub(super) auto_coverage: Option<bool>,
    pub(super) all: bool,
    pub(super) targets: Vec<String>,
    pub(super) time: u64,
    pub(super) budget_label: Option<String>,
    pub(super) env: Vec<(String, String)>,
}

pub(super) fn load_manifest(manifest_path: &Path) -> Result<LoadedStudyManifest> {
    let content = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("reading study manifest {}", manifest_path.display()))?;
    let parsed: StudyManifestFile = toml::from_str(&content)
        .with_context(|| format!("parsing study manifest {}", manifest_path.display()))?;

    let manifest_dir = manifest_path
        .parent()
        .context("study manifest must have a parent directory")?;
    let workspace_root = manifest_dir.parent().unwrap_or(manifest_dir);

    let defaults = StudyDefaults {
        output_root: resolve_path(workspace_root, Path::new(&parsed.study.output_root)),
        fuzz_time: parsed.study.fuzz_time,
        fuzz_env: pairs_from_map(parsed.study.fuzz_env),
    };

    let crates = parsed
        .crates
        .into_iter()
        .map(|item| load_study_crate(item, workspace_root, defaults.fuzz_time))
        .collect::<Result<Vec<_>>>()?;

    Ok(LoadedStudyManifest { defaults, crates })
}

fn load_study_crate(
    item: CrateToml,
    workspace_root: &Path,
    default_fuzz_time: u64,
) -> Result<StudyCrate> {
    Ok(StudyCrate {
        name: item.name,
        path: resolve_path(workspace_root, Path::new(&item.path)),
        cohort: item.cohort,
        coverage_tier: item.coverage_tier,
        miri_cases: item
            .miri_cases
            .into_iter()
            .map(|case| load_miri_case(case, workspace_root))
            .collect::<Result<Vec<_>>>()?,
        fuzz_groups: item
            .fuzz_groups
            .into_iter()
            .map(|group| load_fuzz_group(group, workspace_root, default_fuzz_time))
            .collect::<Result<Vec<_>>>()?,
    })
}

fn load_miri_case(case: MiriCaseToml, workspace_root: &Path) -> Result<StudyMiriCase> {
    Ok(StudyMiriCase {
        name: case.name,
        scope: parse_miri_scope(&case.scope)?,
        harness_dir: case
            .harness_dir
            .as_deref()
            .map(|dir| resolve_path(workspace_root, Path::new(dir))),
        test: case.test,
        case: case.case,
        auto_coverage: case.auto_coverage,
        exact: case.exact,
        triage: case.triage,
    })
}

fn load_fuzz_group(
    group: FuzzGroupToml,
    workspace_root: &Path,
    default_fuzz_time: u64,
) -> Result<StudyFuzzGroup> {
    if group.all && !group.targets.is_empty() {
        bail!(
            "fuzz_group `{}` cannot set both `all = true` and explicit `targets`",
            group.name
        );
    }
    Ok(StudyFuzzGroup {
        name: group.name,
        harness_dir: group
            .harness_dir
            .as_deref()
            .map(|dir| resolve_path(workspace_root, Path::new(dir))),
        auto_coverage: group.auto_coverage,
        all: group.all,
        targets: group.targets,
        time: group.time.unwrap_or(default_fuzz_time),
        budget_label: group.budget_label,
        env: pairs_from_map(group.env),
    })
}

fn pairs_from_map(map: BTreeMap<String, String>) -> Vec<(String, String)> {
    map.into_iter().collect()
}

fn resolve_path(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

fn parse_miri_scope(value: &str) -> Result<crate::domain::MiriScope> {
    match value {
        "full_suite" => Ok(crate::domain::MiriScope::FullSuite),
        "targeted" => Ok(crate::domain::MiriScope::Targeted),
        "targeted_smoke" => Ok(crate::domain::MiriScope::TargetedSmoke),
        "custom" => Ok(crate::domain::MiriScope::Custom),
        other => bail!("unsupported miri scope `{other}` in study manifest"),
    }
}
