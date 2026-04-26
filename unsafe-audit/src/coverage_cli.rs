use anyhow::{bail, Result};
use std::path::PathBuf;

use unsafe_audit::coverage_backend::export_json_from_profraw;

pub(crate) fn prepare_coverage_json(
    label: &str,
    coverage_json: Option<&PathBuf>,
    profraw_dir: Option<&PathBuf>,
    coverage_objects: &[PathBuf],
) -> Result<Option<PathBuf>> {
    match (coverage_json, profraw_dir, coverage_objects.is_empty()) {
        (None, None, true) => Ok(None),
        (Some(path), None, true) => Ok(Some(path.clone())),
        (None, Some(_), _) => bail!(
            "--{label}-profraw-dir requires --{label}-coverage-json so the exported coverage can be written somewhere"
        ),
        (None, None, false) => bail!(
            "--{label}-coverage-object requires both --{label}-profraw-dir and --{label}-coverage-json"
        ),
        (Some(_), None, false) => {
            bail!("--{label}-coverage-object requires --{label}-profraw-dir")
        }
        (Some(_), Some(_), true) => {
            bail!("--{label}-profraw-dir requires at least one --{label}-coverage-object")
        }
        (Some(path), Some(dir), false) => {
            if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)?;
            }
            export_json_from_profraw(dir, coverage_objects, path)?;
            Ok(Some(path.clone()))
        }
    }
}
