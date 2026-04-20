use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

// =========================================================================
// Shared data types for the entire pipeline
// =========================================================================

/// Per-crate configuration, loaded from unsafe-audit.toml or auto-discovered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrateTarget {
    pub name: String,
    pub dir: PathBuf,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CountPair {
    pub safe: u64,
    #[serde(rename = "unsafe_")]
    pub unsafe_: u64,
}

// ---- Phase 2: Miri ----

/// Describes how Miri should be invoked for a specific crate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MiriMode {
    /// `cargo miri test` run directly in the crate's own directory.
    Direct,
    /// `cargo miri test --test <file> [test_name] -- [--exact]`
    /// run in an external harness workspace.
    ExternalTest {
        /// Directory containing the harness Cargo.toml.
        harness_dir: PathBuf,
        /// Integration test file name (without .rs).
        test_file: String,
        /// Specific test function name. If None, run all tests in the file.
        test_name: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeigerResult {
    pub crate_name: String,
    pub crate_version: String,
    pub used: GeigerMetrics,
    pub unused: GeigerMetrics,
    pub forbids_unsafe: bool,
}

// ---- Full study report ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StudyReport {
    pub timestamp: String,
    pub crates: Vec<CrateAuditResult>,
}

// =========================================================================
// Configuration file: unsafe-audit.toml
// =========================================================================

/// Top-level configuration file. All fields optional.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct AuditConfig {
    /// Miri configuration.
    #[serde(default)]
    pub miri: MiriConfig,

    /// Fuzz configuration.
    #[serde(default)]
    pub fuzz: FuzzConfig,

    /// Per-crate overrides. Key = crate name.
    #[serde(default)]
    pub crate_overrides: HashMap<String, CrateOverride>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct MiriConfig {
    /// Extra flags passed via MIRIFLAGS.
    pub extra_flags: String,

    /// Path to an external harness workspace.
    /// If set, the tool scans its tests/ directory to discover test→crate mappings.
    pub harness_dir: Option<PathBuf>,

    /// Explicit crate→test mappings. Takes priority over auto-discovery.
    /// Each entry: { test_file = "...", test_name = "..." (optional) }
    #[serde(default)]
    pub harness_map: HashMap<String, HarnessMapping>,
}

impl Default for MiriConfig {
    fn default() -> Self {
        Self {
            extra_flags: "-Zmiri-symbolic-alignment-check -Zmiri-strict-provenance".into(),
            harness_dir: None,
            harness_map: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct HarnessMapping {
    /// Integration test file name (without .rs) in the harness workspace.
    pub test_file: String,
    /// Specific test function. If omitted, all tests in the file are run.
    pub test_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FuzzConfig {
    /// Seconds to run each fuzz target (default 60).
    pub time_per_target: u64,
    /// Extra environment variables (KEY=VALUE pairs).
    pub env: Vec<String>,
}

impl Default for FuzzConfig {
    fn default() -> Self {
        Self {
            time_per_target: 60,
            env: vec![
                "CARGO_NET_OFFLINE=true".into(),
                "ASAN_OPTIONS=detect_odr_violation=0:detect_leaks=0".into(),
            ],
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct CrateOverride {
    /// Override Miri mode for this specific crate.
    pub miri_harness: Option<HarnessMapping>,
}

impl AuditConfig {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }

    /// Try to find a config file: first at `dir/unsafe-audit.toml`,
    /// then walk up parent directories.
    pub fn discover(dir: &std::path::Path) -> Option<std::path::PathBuf> {
        let mut current = dir.to_path_buf();
        loop {
            let candidate = current.join("unsafe-audit.toml");
            if candidate.is_file() {
                return Some(candidate);
            }
            current = current.parent()?.to_path_buf();
        }
    }
}
