use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// =========================================================================
// Shared data types
// =========================================================================

/// A single crate being audited.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrateTarget {
    pub name: String,
    pub dir: PathBuf,
}

// ---- Phase 1: Geiger ----

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeigerMetrics {
    pub functions: CountPair,
    pub exprs: CountPair,
    pub item_impls: CountPair,
    pub item_traits: CountPair,
    pub methods: CountPair,
}

impl GeigerMetrics {
    pub fn total_unsafe(&self) -> u64 {
        self.functions.unsafe_
            + self.exprs.unsafe_
            + self.item_impls.unsafe_
            + self.item_traits.unsafe_
            + self.methods.unsafe_
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CountPair {
    pub safe: u64,
    #[serde(rename = "unsafe_")]
    pub unsafe_: u64,
}

// ---- Phase 2: Miri ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiriResult {
    pub verdict: MiriVerdict,
    pub passed: bool,
    pub tests_run: Option<usize>,
    pub tests_passed: Option<usize>,
    pub tests_failed: Option<usize>,
    pub ub_detected: bool,
    pub ub_message: Option<String>,
    pub ub_location: Option<String>,
    pub log_path: PathBuf,
    pub duration_secs: f64,
    pub strict: MiriRun,
    pub baseline: Option<MiriRun>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiriRun {
    pub flags: String,
    pub passed: bool,
    pub tests_run: Option<usize>,
    pub tests_passed: Option<usize>,
    pub tests_failed: Option<usize>,
    pub ub_detected: bool,
    pub ub_message: Option<String>,
    pub ub_location: Option<String>,
    pub log_path: PathBuf,
    pub duration_secs: f64,
}

// ---- Phase 3: Fuzz ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FuzzStatus {
    Clean,
    Panic,
    Oom,
    Timeout,
    BuildFailed,
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
            FuzzStatus::NoFuzzDir => write!(f, "NO FUZZ DIR"),
            FuzzStatus::NoTargets => write!(f, "NO TARGETS"),
            FuzzStatus::Error => write!(f, "ERROR"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzTargetResult {
    pub target_name: String,
    pub status: FuzzStatus,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub total_runs: Option<u64>,
    pub edges_covered: Option<u64>,
    pub duration_secs: u64,
    pub artifact_path: Option<PathBuf>,
    pub reproducer_size_bytes: Option<u64>,
    pub log_excerpt: Option<String>,
}

// ---- Per-crate result ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrateAuditResult {
    pub target: CrateTarget,
    pub geiger: Option<GeigerResult>,
    pub miri: Option<MiriResult>,
    pub fuzz: Vec<FuzzTargetResult>,
    pub pattern_analysis: Option<crate::analyzer::UnsafeSummary>,
}

impl CrateAuditResult {
    pub fn fuzz_summary(&self) -> String {
        if self.fuzz.is_empty() {
            return "SKIPPED".into();
        }
        self.fuzz
            .iter()
            .map(|f| format!("{}: {}", f.target_name, f.status))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

// ---- Phase 1 result ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeigerResult {
    pub crate_name: String,
    pub crate_version: String,
    pub used: GeigerMetrics,
    pub unused: GeigerMetrics,
    pub forbids_unsafe: bool,
    pub files_scanned: u64,
}

// ---- Full report ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StudyReport {
    pub timestamp: String,
    pub crates: Vec<CrateAuditResult>,
}
