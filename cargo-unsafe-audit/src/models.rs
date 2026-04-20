use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// =========================================================================
// Shared data types for the entire pipeline
// =========================================================================

/// Which depth of analysis a crate gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrateTier {
    /// Full Miri directly on crate tests (httparse, serde_json, bstr)
    Tier1,
    /// Miri via extensions_harness with targeted test functions
    Tier2,
}

/// A single crate being audited.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrateTarget {
    pub name: String,
    pub dir: PathBuf,
    pub tier: CrateTier,
}

// ---- Phase 1: Geiger ----

#[derive(Debug, Clone, Serialize, Deserialize)]
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

    pub fn total_safe(&self) -> u64 {
        self.functions.safe
            + self.exprs.safe
            + self.item_impls.safe
            + self.item_traits.safe
            + self.methods.safe
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CountPair {
    pub safe: u64,
    /// Named `unsafe_` because `unsafe` is a Rust keyword,
    /// matching cargo-geiger's JSON field name.
    #[serde(rename = "unsafe_")]
    pub unsafe_: u64,
}

impl CountPair {
    pub fn zero() -> Self {
        Self { safe: 0, unsafe_: 0 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeigerResult {
    pub crate_name: String,
    pub crate_version: String,
    /// Unsafe code actually used by the build (reachable from entry points).
    pub used: GeigerMetrics,
    /// Unsafe code present but not reachable.
    pub unused: GeigerMetrics,
    pub forbids_unsafe: bool,
}

// ---- Phase 2: Miri ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MiriMode {
    /// `cargo miri test` run directly in the crate directory.
    Direct,
    /// `cargo miri test --test <file> <name> --exact` run via extensions_harness.
    Harness {
        test_file: String,
        test_name: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiriResult {
    pub mode: MiriMode,
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
    pub total_runs: Option<u64>,
    pub edges_covered: Option<u64>,
    pub duration_secs: u64,
    pub artifact_path: Option<PathBuf>,
    pub reproducer_size_bytes: Option<u64>,
    pub log_excerpt: Option<String>,
}

// ---- Per-crate result (combines all phases) ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrateAuditResult {
    pub target: CrateTarget,
    pub geiger: Option<GeigerResult>,
    pub miri: Option<MiriResult>,
    pub fuzz: Vec<FuzzTargetResult>,
    pub pattern_analysis: Option<crate::analyzer::UnsafeSummary>,
}

impl CrateAuditResult {
    /// Human-readable fuzz summary.
    pub fn fuzz_summary(&self) -> String {
        if self.fuzz.is_empty() {
            return "SKIPPED".into();
        }
        let mut parts = Vec::new();
        for f in &self.fuzz {
            parts.push(format!("{}: {}", f.target_name, f.status));
        }
        parts.join("; ")
    }
}

// ---- Full study report ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StudyReport {
    pub timestamp: String,
    pub crates: Vec<CrateAuditResult>,
}
