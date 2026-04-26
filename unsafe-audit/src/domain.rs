mod common;
mod coverage;
mod exploration;
mod fuzz;
mod geiger;
mod miri;
mod report;

pub const REPORT_SCHEMA_VERSION: u32 = 6;

pub use common::{CommandInvocation, CrateMetadata, CrateTarget, ExecutionOutcome};
pub use coverage::{
    DynamicCoverageArtifacts, UnsafeCoverageState, UnsafeCoverageSummary, UnsafeSiteReach,
};
pub use exploration::{
    ExplorationFuzzRun, ExplorationIssue, ExplorationMiriCase, ExplorationRound,
    ExplorationSummary, HarnessCandidate, HarnessCandidateKind, HarnessValidationStatus,
    SchedulerDecision,
};
pub use fuzz::{FuzzScope, FuzzStatus, FuzzTargetResult};
pub use geiger::{CountPair, GeigerMetrics, GeigerMode, GeigerPackageResult, GeigerResult};
pub use miri::{MiriResult, MiriRun, MiriScope, MiriUbCategory, MiriVerdict};
pub use report::{CrateAuditResult, PhaseIssue, PhaseKind, StudyReport};
