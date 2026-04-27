use anyhow::Result;
use std::path::{Path, PathBuf};

pub fn create_output_root(root: &Path) -> Result<()> {
    std::fs::create_dir_all(root)?;
    Ok(())
}

pub fn crate_output_dir(root: &Path, crate_name: &str) -> PathBuf {
    root.join("crates").join(sanitize(crate_name))
}

pub fn create_crate_output_dir(root: &Path, crate_name: &str) -> Result<PathBuf> {
    let path = crate_output_dir(root, crate_name);
    std::fs::create_dir_all(&path)?;
    Ok(path)
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
#[path = "tests/fs_tests.rs"]
mod tests;
