use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub current_dir: PathBuf,
}

impl CommandSpec {
    pub fn display(&self) -> String {
        let mut parts = Vec::with_capacity(1 + self.args.len());
        parts.push(self.program.clone());
        parts.extend(self.args.clone());
        parts.join(" ")
    }
}

#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub duration_ms: u128,
    pub combined_output: String,
}

pub trait CommandExecutor: Send + Sync {
    fn run(&self, spec: &CommandSpec) -> Result<CommandOutput>;
}

pub struct ProcessExecutor;

impl CommandExecutor for ProcessExecutor {
    fn run(&self, spec: &CommandSpec) -> Result<CommandOutput> {
        let start = Instant::now();
        let mut command = Command::new(&spec.program);
        command.args(&spec.args).current_dir(&spec.current_dir);
        for (key, value) in &spec.env {
            command.env(key, value);
        }
        let output = command
            .output()
            .with_context(|| format!("running {}", spec.display()))?;
        let combined_output = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(CommandOutput {
            success: output.status.success(),
            exit_code: output.status.code(),
            duration_ms: start.elapsed().as_millis(),
            combined_output,
        })
    }
}

pub fn excerpt(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else if trimmed.len() <= 700 {
        Some(trimmed.to_string())
    } else {
        let tail: String = trimmed
            .chars()
            .rev()
            .take(700)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        Some(format!("...{tail}"))
    }
}

pub fn format_duration_ms(duration_ms: u128) -> String {
    if duration_ms < 1_000 {
        format!("{duration_ms}ms")
    } else if duration_ms < 60_000 {
        format!("{:.1}s", duration_ms as f64 / 1_000.0)
    } else {
        let total_secs = duration_ms / 1_000;
        let minutes = total_secs / 60;
        let seconds = total_secs % 60;
        format!("{minutes}m{seconds:02}s")
    }
}

#[cfg(test)]
#[path = "tests/runner_tests.rs"]
mod tests;
