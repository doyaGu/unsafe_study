use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use super::{study_output_root, StudyCrate, StudyRunOptions};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StudyRuntimeState {
    pub manifest: String,
    pub output_root: String,
    pub pid: u32,
    pub status: StudyRuntimeStatus,
    pub current_crate: Option<String>,
    pub current_segment: Option<String>,
    pub updated_at: String,
    pub completed_crates: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StudyRuntimeStatus {
    Running,
    Completed,
    Stopping,
}

pub fn read_study_runtime_state(
    manifest_path: &Path,
    output_root_override: Option<&Path>,
) -> Result<Option<StudyRuntimeState>> {
    let output_root = study_output_root(manifest_path, output_root_override)?;
    let state_path = runtime_state_path(&output_root);
    if !state_path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&state_path)
        .with_context(|| format!("reading {}", state_path.display()))?;
    let state = serde_json::from_str(&content)
        .with_context(|| format!("parsing {}", state_path.display()))?;
    Ok(Some(state))
}

pub fn stop_study_run(manifest_path: &Path, output_root_override: Option<&Path>) -> Result<bool> {
    let output_root = study_output_root(manifest_path, output_root_override)?;
    let pid_path = output_root.join("study.pid");
    if !pid_path.exists() {
        return Ok(false);
    }
    let pid_text = std::fs::read_to_string(&pid_path)
        .with_context(|| format!("reading {}", pid_path.display()))?;
    let pid: i32 = pid_text
        .trim()
        .parse()
        .with_context(|| format!("parsing pid from {}", pid_path.display()))?;

    #[cfg(unix)]
    {
        if !pid_is_alive(pid) {
            return Ok(false);
        }
        write_runtime_state(
            &output_root,
            StudyRuntimeState {
                manifest: manifest_path.display().to_string(),
                output_root: output_root.display().to_string(),
                pid: pid as u32,
                status: StudyRuntimeStatus::Stopping,
                current_crate: None,
                current_segment: None,
                updated_at: now_string(),
                completed_crates: count_completed_crates(&output_root),
            },
        )?;
        let result = unsafe { libc::kill(pid, libc::SIGTERM) };
        if result == -1 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ESRCH) {
                return Ok(false);
            }
            return Err(err.into());
        }
        return Ok(true);
    }

    #[cfg(not(unix))]
    {
        let _ = output_root;
        let _ = pid;
        anyhow::bail!("study stop is only supported on unix");
    }
}

fn runtime_state_path(output_root: &Path) -> PathBuf {
    output_root.join("study.runtime.json")
}

pub(super) fn write_runtime_state(output_root: &Path, state: StudyRuntimeState) -> Result<()> {
    std::fs::write(
        runtime_state_path(output_root),
        serde_json::to_string_pretty(&state)?,
    )?;
    std::fs::write(output_root.join("study.pid"), format!("{}\n", state.pid))?;
    Ok(())
}

pub(super) fn now_string() -> String {
    chrono::Local::now().to_rfc3339()
}

pub(super) fn count_completed_crates(output_root: &Path) -> usize {
    std::fs::read_dir(output_root)
        .ok()
        .into_iter()
        .flat_map(|items| items.filter_map(|item| item.ok()))
        .map(|item| item.path())
        .filter(|path| path.join("summary.json").exists())
        .count()
}

pub(super) fn update_current_segment(
    output_root: &Path,
    study_crate: &StudyCrate,
    options: &StudyRunOptions,
    completed_crates: usize,
    segment: String,
) -> Result<()> {
    if options.dry_run {
        return Ok(());
    }
    write_runtime_state(
        output_root,
        StudyRuntimeState {
            manifest: options.manifest_path.display().to_string(),
            output_root: output_root.display().to_string(),
            pid: std::process::id(),
            status: StudyRuntimeStatus::Running,
            current_crate: Some(study_crate.name.clone()),
            current_segment: Some(segment),
            updated_at: now_string(),
            completed_crates,
        },
    )
}

pub(super) fn summaries_len(crate_root: &Path) -> usize {
    crate_root.parent().map(count_completed_crates).unwrap_or(0)
}

#[cfg(unix)]
fn pid_is_alive(pid: i32) -> bool {
    let result = unsafe { libc::kill(pid, 0) };
    if result == 0 {
        true
    } else {
        let err = std::io::Error::last_os_error();
        err.raw_os_error() == Some(libc::EPERM)
    }
}
