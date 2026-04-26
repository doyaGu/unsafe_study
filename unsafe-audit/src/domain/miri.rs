use serde::{Deserialize, Serialize};

use super::{CommandInvocation, ExecutionOutcome};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MiriScope {
    FullSuite,
    Targeted,
    TargetedSmoke,
    Custom,
}

impl Default for MiriScope {
    fn default() -> Self {
        Self::FullSuite
    }
}

impl std::fmt::Display for MiriScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MiriScope::FullSuite => write!(f, "full_suite"),
            MiriScope::Targeted => write!(f, "targeted"),
            MiriScope::TargetedSmoke => write!(f, "targeted_smoke"),
            MiriScope::Custom => write!(f, "custom"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MiriVerdict {
    Clean,
    TruePositiveUb,
    StrictOnlySuspectedFalsePositive,
    FailedNoUb,
    Inconclusive,
}

impl std::fmt::Display for MiriVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MiriVerdict::Clean => write!(f, "CLEAN"),
            MiriVerdict::TruePositiveUb => write!(f, "TRUE POSITIVE UB"),
            MiriVerdict::StrictOnlySuspectedFalsePositive => {
                write!(f, "STRICT-ONLY SUSPECTED FP")
            }
            MiriVerdict::FailedNoUb => write!(f, "FAILED NO UB"),
            MiriVerdict::Inconclusive => write!(f, "INCONCLUSIVE"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MiriUbCategory {
    Alignment,
    Provenance,
    OutOfBounds,
    Uninitialized,
    Other,
}

impl std::fmt::Display for MiriUbCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MiriUbCategory::Alignment => write!(f, "alignment"),
            MiriUbCategory::Provenance => write!(f, "provenance"),
            MiriUbCategory::OutOfBounds => write!(f, "out_of_bounds"),
            MiriUbCategory::Uninitialized => write!(f, "uninitialized"),
            MiriUbCategory::Other => write!(f, "other"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiriRun {
    pub flags: String,
    pub execution: ExecutionOutcome,
    pub tests_run: Option<usize>,
    pub tests_passed: Option<usize>,
    pub tests_failed: Option<usize>,
    pub ub_detected: bool,
    pub ub_category: Option<MiriUbCategory>,
    pub ub_message: Option<String>,
    pub ub_location: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiriResult {
    pub scope: MiriScope,
    pub invocation: CommandInvocation,
    pub verdict: MiriVerdict,
    pub triage_summary: Option<String>,
    pub primary_run: MiriRun,
    pub baseline_run: Option<MiriRun>,
}

impl MiriResult {
    pub fn duration_secs(&self) -> f64 {
        self.primary_run.execution.duration_secs
            + self
                .baseline_run
                .as_ref()
                .map(|run| run.execution.duration_secs)
                .unwrap_or(0.0)
    }
}
