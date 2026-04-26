use std::path::PathBuf;

use crate::domain::MiriScope;

#[derive(Debug, Clone)]
pub struct PhaseSelection {
    pub geiger: bool,
    pub miri: bool,
    pub fuzz: bool,
    pub patterns: bool,
}

impl PhaseSelection {
    pub fn from_skip_flags(
        skip_geiger: bool,
        skip_miri: bool,
        skip_fuzz: bool,
        skip_patterns: bool,
    ) -> Self {
        Self {
            geiger: !skip_geiger,
            miri: !skip_miri,
            fuzz: !skip_fuzz,
            patterns: !skip_patterns,
        }
    }

    pub fn shared_static() -> Self {
        Self {
            geiger: true,
            miri: false,
            fuzz: false,
            patterns: true,
        }
    }

    pub fn miri_only() -> Self {
        Self {
            geiger: false,
            miri: true,
            fuzz: false,
            patterns: false,
        }
    }

    pub fn fuzz_only() -> Self {
        Self {
            geiger: false,
            miri: false,
            fuzz: true,
            patterns: false,
        }
    }
}

#[derive(Debug, Clone)]
pub enum OutputFormat {
    Json,
    Markdown,
    Both,
}

impl OutputFormat {
    pub fn writes_json(&self) -> bool {
        matches!(self, Self::Json | Self::Both)
    }

    pub fn writes_markdown(&self) -> bool {
        matches!(self, Self::Markdown | Self::Both)
    }
}

#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    pub path: PathBuf,
    pub batch: bool,
}

#[derive(Debug, Clone)]
pub struct AuditOptions {
    pub discovery: DiscoveryOptions,
    pub phases: PhaseSelection,
    pub miri_flags: String,
    pub baseline_miri_flags: String,
    pub miri_triage: bool,
    pub miri_scope: MiriScope,
    pub miri_harness_dir: Option<PathBuf>,
    pub miri_args: Vec<String>,
    pub miri_auto_coverage: bool,
    pub miri_coverage_json: Option<PathBuf>,
    pub fuzz_time: u64,
    pub fuzz_harness_dir: Option<PathBuf>,
    pub fuzz_env: Vec<(String, String)>,
    pub fuzz_targets: Vec<String>,
    pub fuzz_budget_label: Option<String>,
    pub fuzz_auto_coverage: bool,
    pub fuzz_coverage_json: Option<PathBuf>,
    pub output_dir: PathBuf,
    pub format: OutputFormat,
    pub verbose: bool,
}

#[derive(Debug, Clone)]
pub struct ExplorationOptions {
    pub max_rounds: usize,
    pub max_time_secs: Option<u64>,
    pub no_new_coverage_limit: usize,
    pub generate_harnesses: bool,
    pub llm_provider_cmd: Option<String>,
}

impl Default for ExplorationOptions {
    fn default() -> Self {
        Self {
            max_rounds: 3,
            max_time_secs: None,
            no_new_coverage_limit: 2,
            generate_harnesses: false,
            llm_provider_cmd: None,
        }
    }
}
