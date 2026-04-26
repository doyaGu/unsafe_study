use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrateMetadata {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrateTarget {
    pub metadata: CrateMetadata,
    pub dir: PathBuf,
}

impl CrateTarget {
    pub fn display_name(&self) -> &str {
        &self.metadata.name
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandInvocation {
    pub working_dir: PathBuf,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionOutcome {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub duration_secs: f64,
    pub log_path: PathBuf,
    pub log_excerpt: Option<String>,
}
