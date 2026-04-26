use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use crate::domain::{CrateMetadata, CrateTarget, ExecutionOutcome};

#[derive(Debug, Clone)]
pub struct OutputLayout {
    pub root: PathBuf,
    pub geiger_logs: PathBuf,
    pub miri_logs: PathBuf,
    pub fuzz_logs: PathBuf,
    pub coverage_artifacts: PathBuf,
}

impl OutputLayout {
    pub fn new(root: PathBuf) -> Self {
        Self {
            geiger_logs: root.join("geiger_logs"),
            miri_logs: root.join("miri_logs"),
            fuzz_logs: root.join("fuzz_logs"),
            coverage_artifacts: root.join("coverage"),
            root,
        }
    }

    pub fn create_dirs(&self) -> Result<()> {
        std::fs::create_dir_all(&self.root)?;
        std::fs::create_dir_all(&self.geiger_logs)?;
        std::fs::create_dir_all(&self.miri_logs)?;
        std::fs::create_dir_all(&self.fuzz_logs)?;
        std::fs::create_dir_all(&self.coverage_artifacts)?;
        Ok(())
    }

    pub fn report_json_path(&self) -> PathBuf {
        self.root.join("report.json")
    }

    pub fn report_markdown_path(&self) -> PathBuf {
        self.root.join("report.md")
    }

    pub fn geiger_log_path(&self, crate_name: &str) -> PathBuf {
        self.geiger_logs.join(format!("{crate_name}.log"))
    }

    pub fn miri_log_path(&self, crate_name: &str, suffix: &str) -> PathBuf {
        self.miri_logs.join(format!("{crate_name}.{suffix}.log"))
    }

    pub fn fuzz_log_path(&self, target_name: &str) -> PathBuf {
        self.fuzz_logs.join(format!("{target_name}.log"))
    }

    pub fn miri_coverage_json_path(&self, crate_name: &str) -> PathBuf {
        self.coverage_artifacts
            .join(format!("{crate_name}.miri.json"))
    }

    pub fn miri_coverage_log_path(&self, crate_name: &str, suffix: &str) -> PathBuf {
        self.coverage_artifacts
            .join(format!("{crate_name}.miri.{suffix}.log"))
    }

    pub fn fuzz_coverage_json_path(&self, crate_name: &str) -> PathBuf {
        self.coverage_artifacts
            .join(format!("{crate_name}.fuzz.json"))
    }

    pub fn fuzz_coverage_log_path(
        &self,
        crate_name: &str,
        target_name: &str,
        suffix: &str,
    ) -> PathBuf {
        self.coverage_artifacts
            .join(format!("{crate_name}.fuzz.{target_name}.{suffix}.log"))
    }
}

pub struct ManifestReader;

#[derive(Debug, Deserialize)]
struct CargoToml {
    package: Option<PackageSection>,
}

#[derive(Debug, Deserialize)]
struct PackageSection {
    name: Option<String>,
    version: Option<String>,
}

impl ManifestReader {
    pub fn read(crate_dir: &Path) -> Result<CrateMetadata> {
        let cargo_toml = crate_dir.join("Cargo.toml");
        let content = std::fs::read_to_string(&cargo_toml)
            .with_context(|| format!("reading manifest {}", cargo_toml.display()))?;
        let parsed: CargoToml = toml::from_str(&content)
            .with_context(|| format!("parsing manifest {}", cargo_toml.display()))?;
        let fallback_name = crate_dir
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".into());
        Ok(CrateMetadata {
            name: parsed
                .package
                .as_ref()
                .and_then(|pkg| pkg.name.clone())
                .unwrap_or(fallback_name),
            version: parsed
                .package
                .and_then(|pkg| pkg.version)
                .unwrap_or_else(|| "0.0.0".into()),
        })
    }
}

pub struct TargetDiscovery;

impl TargetDiscovery {
    pub fn discover(path: &Path, batch: bool) -> Result<Vec<CrateTarget>> {
        if path.join("Cargo.toml").exists() && !batch {
            return Ok(vec![CrateTarget {
                metadata: ManifestReader::read(path)?,
                dir: path.to_path_buf(),
            }]);
        }

        let mut crates = Vec::new();
        for entry in std::fs::read_dir(path)? {
            let sub = entry?.path();
            if sub.join("Cargo.toml").exists() {
                crates.push(CrateTarget {
                    metadata: ManifestReader::read(&sub)?,
                    dir: sub,
                });
            }
        }
        crates.sort_by(|a, b| a.metadata.name.cmp(&b.metadata.name));
        Ok(crates)
    }
}

#[derive(Debug, Clone)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub current_dir: PathBuf,
    pub log_path: PathBuf,
}

pub struct CommandRunner;

impl CommandRunner {
    pub fn run(spec: &CommandSpec) -> Result<(ExecutionOutcome, String)> {
        let start = Instant::now();
        let mut cmd = Command::new(&spec.program);
        cmd.args(&spec.args).current_dir(&spec.current_dir);
        for (key, value) in &spec.env {
            cmd.env(key, value);
        }
        let output = cmd
            .output()
            .with_context(|| format!("running {} {}", spec.program, spec.args.join(" ")))?;

        let duration_secs = start.elapsed().as_secs_f64();
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        std::fs::write(&spec.log_path, &combined)?;

        Ok((
            ExecutionOutcome {
                success: output.status.success(),
                exit_code: output.status.code(),
                duration_secs,
                log_path: spec.log_path.clone(),
                log_excerpt: excerpt(&combined),
            },
            combined,
        ))
    }
}

pub fn excerpt(combined: &str) -> Option<String> {
    if combined.len() > 500 {
        Some(format!("...{}", &combined[combined.len() - 500..]))
    } else if !combined.is_empty() {
        Some(combined.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_layout_builds_expected_paths() {
        let layout = OutputLayout::new(PathBuf::from("/tmp/report"));
        assert_eq!(
            layout.report_json_path(),
            PathBuf::from("/tmp/report/report.json")
        );
        assert_eq!(
            layout.geiger_log_path("crate"),
            PathBuf::from("/tmp/report/geiger_logs/crate.log")
        );
        assert_eq!(
            layout.miri_log_path("crate", "strict"),
            PathBuf::from("/tmp/report/miri_logs/crate.strict.log")
        );
    }
}
