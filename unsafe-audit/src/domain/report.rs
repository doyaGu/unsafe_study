use serde::{Deserialize, Serialize};

use super::{
    CrateTarget, DynamicCoverageArtifacts, ExplorationSummary, FuzzTargetResult, GeigerResult,
    MiriResult, UnsafeCoverageSummary, UnsafeSiteReach,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrateAuditResult {
    pub target: CrateTarget,
    pub geiger: Option<GeigerResult>,
    pub miri: Option<MiriResult>,
    pub fuzz: Vec<FuzzTargetResult>,
    pub patterns: Option<crate::analyzer::UnsafeSummary>,
    pub unsafe_site_reach: Option<Vec<UnsafeSiteReach>>,
    pub unsafe_coverage: Option<UnsafeCoverageSummary>,
    pub coverage_artifacts: Option<DynamicCoverageArtifacts>,
    pub exploration: Option<ExplorationSummary>,
    pub phase_issues: Vec<PhaseIssue>,
}

impl CrateAuditResult {
    pub fn fuzz_summary(&self) -> String {
        if self.phase_issue(PhaseKind::Fuzz).is_some() {
            return "ERROR".into();
        }
        if self.fuzz.is_empty() {
            return "SKIPPED".into();
        }
        self.fuzz
            .iter()
            .map(|f| format!("{}: {}", f.target_name, f.status))
            .collect::<Vec<_>>()
            .join("; ")
    }

    pub fn phase_issue(&self, phase: PhaseKind) -> Option<&PhaseIssue> {
        self.phase_issues.iter().find(|issue| issue.phase == phase)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PhaseKind {
    Geiger,
    Miri,
    Fuzz,
    Patterns,
}

impl std::fmt::Display for PhaseKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PhaseKind::Geiger => write!(f, "geiger"),
            PhaseKind::Miri => write!(f, "miri"),
            PhaseKind::Fuzz => write!(f, "fuzz"),
            PhaseKind::Patterns => write!(f, "patterns"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseIssue {
    pub phase: PhaseKind,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StudyReport {
    pub schema_version: u32,
    pub timestamp: String,
    pub crates: Vec<CrateAuditResult>,
}
