use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnsafeCoverageState {
    StaticUniverseOnly,
    TriggeredEvidenceOnly,
    Computed,
}

impl std::fmt::Display for UnsafeCoverageState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnsafeCoverageState::StaticUniverseOnly => write!(f, "static_universe_only"),
            UnsafeCoverageState::TriggeredEvidenceOnly => write!(f, "triggered_evidence_only"),
            UnsafeCoverageState::Computed => write!(f, "computed"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsafeSiteReach {
    pub site_id: String,
    pub reached_by_miri: bool,
    pub reached_by_fuzz: bool,
    pub triggered_by_miri: bool,
    pub triggered_by_fuzz: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsafeCoverageSummary {
    pub state: UnsafeCoverageState,
    pub total_sites: usize,
    pub reached_by_miri: Option<usize>,
    pub reached_by_fuzz: Option<usize>,
    pub reached_by_any: Option<usize>,
    pub triggered_by_miri: Option<usize>,
    pub triggered_by_fuzz: Option<usize>,
    pub triggered_by_any: Option<usize>,
    pub unmapped_triggered_by_miri: Option<usize>,
    pub unmapped_triggered_by_fuzz: Option<usize>,
    pub unreached: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicCoverageArtifacts {
    pub miri_coverage_json: Option<PathBuf>,
    pub miri_coverage_build_log: Option<PathBuf>,
    pub miri_coverage_run_log: Option<PathBuf>,
    pub fuzz_coverage_json: Option<PathBuf>,
    pub fuzz_coverage_log_dir: Option<PathBuf>,
}
