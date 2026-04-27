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

pub trait CommandExecutor {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_display_joins_program_and_args() {
        let spec = CommandSpec {
            program: "cargo".into(),
            args: vec!["test".into(), "--all".into()],
            env: BTreeMap::new(),
            current_dir: PathBuf::from("."),
        };
        assert_eq!(spec.display(), "cargo test --all");
    }

    #[test]
    fn excerpt_truncates_on_char_boundaries() {
        let text = format!("{}{}", "a".repeat(800), "─".repeat(10));
        let shortened = excerpt(&text).unwrap();
        assert!(shortened.starts_with("..."));
        assert!(shortened.ends_with('─'));
    }
}
