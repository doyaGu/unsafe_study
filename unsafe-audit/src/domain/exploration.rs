use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::{CommandInvocation, FuzzStatus, MiriVerdict};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplorationSummary {
    pub mode: String,
    pub max_rounds: usize,
    pub max_time_secs: Option<u64>,
    pub no_new_coverage_limit: usize,
    pub rounds: Vec<ExplorationRound>,
    pub isolated_miri_cases: Vec<ExplorationMiriCase>,
    pub fuzz_runs: Vec<ExplorationFuzzRun>,
    pub harness_candidates: Vec<HarnessCandidate>,
    pub scheduler_decisions: Vec<SchedulerDecision>,
    pub issues: Vec<ExplorationIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplorationRound {
    pub round: usize,
    pub planned_action: String,
    pub reason: String,
    pub reached_before: usize,
    pub reached_after: usize,
    pub new_reach: usize,
    pub stop_after_round: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplorationMiriCase {
    pub name: String,
    pub invocation: CommandInvocation,
    pub verdict: Option<MiriVerdict>,
    pub ub_detected: Option<bool>,
    pub coverage_json: Option<PathBuf>,
    pub log_path: Option<PathBuf>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplorationFuzzRun {
    pub target_name: String,
    pub status: FuzzStatus,
    pub budget_secs: u64,
    pub coverage_json: Option<PathBuf>,
    pub log_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessCandidate {
    pub id: String,
    pub kind: HarnessCandidateKind,
    pub target_api: Option<String>,
    pub target_site_ids: Vec<String>,
    pub patch_text: String,
    pub rationale: String,
    pub suggested_command: String,
    pub validation_status: HarnessValidationStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HarnessCandidateKind {
    MiriTest,
    FuzzTarget,
}

impl std::fmt::Display for HarnessCandidateKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HarnessCandidateKind::MiriTest => write!(f, "miri_test"),
            HarnessCandidateKind::FuzzTarget => write!(f, "fuzz_target"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HarnessValidationStatus {
    GeneratedDraft,
    ProviderError,
    Disabled,
}

impl std::fmt::Display for HarnessValidationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HarnessValidationStatus::GeneratedDraft => write!(f, "generated_draft"),
            HarnessValidationStatus::ProviderError => write!(f, "provider_error"),
            HarnessValidationStatus::Disabled => write!(f, "disabled"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerDecision {
    pub round: usize,
    pub action: String,
    pub reason: String,
    pub target_site_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplorationIssue {
    pub stage: String,
    pub message: String,
}
