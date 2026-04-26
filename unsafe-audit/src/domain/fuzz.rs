use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::ExecutionOutcome;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FuzzStatus {
    Clean,
    Panic,
    Oom,
    Timeout,
    BuildFailed,
    EnvironmentError,
    NoFuzzDir,
    NoTargets,
    Error,
}

impl std::fmt::Display for FuzzStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FuzzStatus::Clean => write!(f, "CLEAN"),
            FuzzStatus::Panic => write!(f, "PANIC"),
            FuzzStatus::Oom => write!(f, "OOM"),
            FuzzStatus::Timeout => write!(f, "TIMEOUT"),
            FuzzStatus::BuildFailed => write!(f, "BUILD FAIL"),
            FuzzStatus::EnvironmentError => write!(f, "ENVIRONMENT ERROR"),
            FuzzStatus::NoFuzzDir => write!(f, "NO FUZZ DIR"),
            FuzzStatus::NoTargets => write!(f, "NO TARGETS"),
            FuzzStatus::Error => write!(f, "ERROR"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FuzzScope {
    ExistingHarness,
    DiscoveryOnly,
    NoneAvailable,
}

impl Default for FuzzScope {
    fn default() -> Self {
        Self::ExistingHarness
    }
}

impl std::fmt::Display for FuzzScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FuzzScope::ExistingHarness => write!(f, "existing_harness"),
            FuzzScope::DiscoveryOnly => write!(f, "discovery_only"),
            FuzzScope::NoneAvailable => write!(f, "none_available"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzTargetResult {
    pub target_name: String,
    pub scope: FuzzScope,
    pub status: FuzzStatus,
    pub harness_dir: Option<PathBuf>,
    pub execution: Option<ExecutionOutcome>,
    pub requested_time_budget_secs: u64,
    pub budget_label: Option<String>,
    pub environment_overrides: Vec<String>,
    pub total_runs: Option<u64>,
    pub edges_covered: Option<u64>,
    pub artifact_path: Option<PathBuf>,
    pub reproducer_size_bytes: Option<u64>,
}
