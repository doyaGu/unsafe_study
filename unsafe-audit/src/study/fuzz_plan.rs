use anyhow::{Context, Result};
use serde::Deserialize;

use super::{StudyCrate, StudyFuzzGroup};

#[derive(Debug, Deserialize)]
struct FuzzCargoToml {
    #[serde(default)]
    bin: Vec<FuzzBinToml>,
}

#[derive(Debug, Deserialize)]
struct FuzzBinToml {
    name: String,
}

pub(super) fn planned_fuzz_targets(
    study_crate: &StudyCrate,
    group: &StudyFuzzGroup,
) -> Result<Vec<String>> {
    if !group.all {
        return Ok(group.targets.clone());
    }

    let harness_root = group.harness_dir.as_deref().unwrap_or(&study_crate.path);
    let manifest_path = harness_root.join("fuzz").join("Cargo.toml");
    if !manifest_path.exists() {
        return Ok(Vec::new());
    }

    let content = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("reading fuzz manifest {}", manifest_path.display()))?;
    let parsed: FuzzCargoToml = toml::from_str(&content)
        .with_context(|| format!("parsing fuzz manifest {}", manifest_path.display()))?;
    let mut names = parsed
        .bin
        .into_iter()
        .map(|bin| bin.name)
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    Ok(names)
}
