use anyhow::Result;
use std::path::Path;

use super::render::render_study_markdown;
use super::StudyIndex;

pub(super) fn write_study_outputs(output_root: &Path, index: &StudyIndex) -> Result<()> {
    std::fs::write(
        output_root.join("study_index.json"),
        serde_json::to_string_pretty(index)?,
    )?;
    std::fs::write(
        output_root.join("study_summary.json"),
        serde_json::to_string_pretty(&index.crates)?,
    )?;
    std::fs::write(
        output_root.join("study_summary.md"),
        render_study_markdown(index),
    )?;
    Ok(())
}
