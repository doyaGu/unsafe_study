use anyhow::Result;
use std::path::{Path, PathBuf};

pub fn create_output_root(root: &Path) -> Result<()> {
    std::fs::create_dir_all(root)?;
    Ok(())
}

pub fn crate_output_dir(root: &Path, crate_name: &str) -> PathBuf {
    root.join("crates").join(sanitize(crate_name))
}

pub fn phase_log_path(crate_root: &Path, phase: &str, name: &str) -> PathBuf {
    crate_root
        .join("logs")
        .join(format!("{}.{}.log", sanitize(phase), sanitize(name)))
}

pub fn report_json_path(root: &Path) -> PathBuf {
    root.join("report.json")
}

pub fn report_markdown_path(root: &Path) -> PathBuf {
    root.join("report.md")
}

pub fn write_log(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, content)?;
    Ok(())
}

pub fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_keeps_paths_file_safe() {
        assert_eq!(sanitize("a/b:c"), "a_b_c");
    }
}
