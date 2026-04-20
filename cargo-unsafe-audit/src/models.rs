use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// =========================================================================
// Shared types for the entire tool
// =========================================================================

/// A fuzzable public API discovered in the target crate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzTarget {
    /// Function or method name (e.g. "parse", "Request::parse")
    pub name: String,
    /// Fully qualified path (e.g. "httparse::Request::parse")
    pub full_path: String,
    /// The kind of input the function accepts
    pub input_kind: InputKind,
    /// Is this a method (has &self / &mut self)?
    pub is_method: bool,
    /// Return type as string, if we can determine it
    pub return_type: Option<String>,
    /// Source file and line
    pub file: PathBuf,
    pub line: usize,
    /// Priority for fuzzing (higher = more interesting)
    pub priority: u8,
}

/// What kind of input does the fuzzable API accept?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InputKind {
    /// `&[u8]` or `Vec<u8>` -- raw bytes, most direct fuzz target
    Bytes,
    /// `&str` or `String` -- UTF-8 text, fuzz bytes then validate
    Str,
    /// `impl Read` -- can wrap a `&[u8]` in a Cursor
    Read,
    /// Some other type that may implement Arbitrary
    Other,
}

impl std::fmt::Display for InputKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InputKind::Bytes => write!(f, "&[u8]"),
            InputKind::Str => write!(f, "&str"),
            InputKind::Read => write!(f, "impl Read"),
            InputKind::Other => write!(f, "other"),
        }
    }
}

/// Result of running the full audit pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub crate_name: String,
    pub crate_version: String,
    pub crate_dir: PathBuf,
    pub timestamp: String,
    pub static_analysis: crate::analyzer::UnsafeSummary,
    pub miri_result: Option<MiriResult>,
    pub fuzz_results: Vec<FuzzResult>,
}

/// Result of the two-pass Miri triage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiriResult {
    pub pass1: MiriPassResult,
    pub pass2: Option<MiriPassResult>,
    pub classification: MiriClassification,
    pub log_excerpt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiriPassResult {
    pub passed: bool,
    pub tests_run: Option<usize>,
    pub tests_passed: Option<usize>,
    pub tests_failed: Option<usize>,
    pub ub_message: Option<String>,
    pub ub_location: Option<String>,
    pub duration_secs: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MiriClassification {
    Clean,
    TruePositive,
    SuspectedFalsePositive,
    ConfirmedFalsePositive,
    Error,
}

/// Result of fuzzing a single target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResult {
    pub target_name: String,
    pub harness_file: PathBuf,
    pub duration_secs: u64,
    pub total_runs: Option<u64>,
    pub edges_covered: Option<u64>,
    pub crashes: u64,
    pub findings: Vec<FuzzFinding>,
    pub status: FuzzStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FuzzStatus {
    Clean,
    CrashFound,
    BuildFailed,
    Timeout,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzFinding {
    pub finding_type: FindingType,
    pub reproducer_path: Option<PathBuf>,
    pub reproducer_size: Option<u64>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingType {
    MemorySafety,
    Panic,
    Oom,
    Timeout,
}
