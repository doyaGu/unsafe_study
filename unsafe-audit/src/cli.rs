use anyhow::{bail, Result};
use clap::ValueEnum;
use std::path::PathBuf;

use unsafe_audit::domain::MiriScope;
use unsafe_audit::OutputFormat;

pub(crate) const STRICT_MIRI_FLAGS: &str =
    "-Zmiri-symbolic-alignment-check -Zmiri-strict-provenance";
pub(crate) const BASELINE_MIRI_FLAGS: &str = "-Zmiri-strict-provenance";

#[derive(Copy, Clone, Debug, ValueEnum)]
pub(crate) enum CliMiriScope {
    FullSuite,
    Targeted,
    TargetedSmoke,
    Custom,
}

impl From<CliMiriScope> for MiriScope {
    fn from(value: CliMiriScope) -> Self {
        match value {
            CliMiriScope::FullSuite => MiriScope::FullSuite,
            CliMiriScope::Targeted => MiriScope::Targeted,
            CliMiriScope::TargetedSmoke => MiriScope::TargetedSmoke,
            CliMiriScope::Custom => MiriScope::Custom,
        }
    }
}

#[derive(clap::Parser, Debug)]
#[command(
    name = "unsafe-audit",
    bin_name = "unsafe-audit",
    about = "Collect multi-phase evidence about unsafe code: Geiger + Miri + Fuzz + Pattern Analysis",
    version
)]
pub(crate) struct Cli {
    #[arg(value_name = "PATH", default_value = ".")]
    pub(crate) path: PathBuf,
    #[arg(long = "crates", value_name = "NAME1,NAME2")]
    pub(crate) crates: Option<String>,
    #[arg(long = "detach")]
    pub(crate) detach: bool,
    #[arg(long = "status")]
    pub(crate) status: bool,
    #[arg(long = "stop")]
    pub(crate) stop: bool,
    #[arg(long = "no-resume")]
    pub(crate) no_resume: bool,
    #[arg(long)]
    pub(crate) classic: bool,
    #[arg(long = "max-rounds", default_value = "3")]
    pub(crate) max_rounds: usize,
    #[arg(long = "max-time-secs")]
    pub(crate) max_time_secs: Option<u64>,
    #[arg(long = "no-new-coverage-limit", default_value = "2")]
    pub(crate) no_new_coverage_limit: usize,
    #[arg(long = "generate-harnesses")]
    pub(crate) generate_harnesses: bool,
    #[arg(long = "llm-provider-cmd")]
    pub(crate) llm_provider_cmd: Option<String>,
    #[arg(long)]
    pub(crate) batch: bool,
    #[arg(long)]
    pub(crate) skip_geiger: bool,
    #[arg(long)]
    pub(crate) skip_miri: bool,
    #[arg(long)]
    pub(crate) skip_fuzz: bool,
    #[arg(long)]
    pub(crate) skip_patterns: bool,
    #[arg(long, default_value = STRICT_MIRI_FLAGS)]
    pub(crate) miri_flags: String,
    #[arg(long, default_value = BASELINE_MIRI_FLAGS)]
    pub(crate) baseline_miri_flags: String,
    #[arg(long)]
    pub(crate) miri_triage: bool,
    #[arg(long, value_enum, default_value_t = CliMiriScope::FullSuite)]
    pub(crate) miri_scope: CliMiriScope,
    #[arg(long = "miri-harness-dir")]
    pub(crate) miri_harness_dir: Option<PathBuf>,
    #[arg(long = "miri-arg", value_name = "ARG")]
    pub(crate) miri_args: Vec<String>,
    #[arg(long = "miri-auto-coverage")]
    pub(crate) miri_auto_coverage: bool,
    #[arg(long = "miri-coverage-json", value_name = "PATH")]
    pub(crate) miri_coverage_json: Option<PathBuf>,
    #[arg(long = "miri-profraw-dir", value_name = "PATH")]
    pub(crate) miri_profraw_dir: Option<PathBuf>,
    #[arg(long = "miri-coverage-object", value_name = "PATH")]
    pub(crate) miri_coverage_objects: Vec<PathBuf>,
    #[arg(long, default_value = "60")]
    pub(crate) fuzz_time: u64,
    #[arg(long = "fuzz-harness-dir")]
    pub(crate) fuzz_harness_dir: Option<PathBuf>,
    #[arg(long = "fuzz-env", value_name = "KEY=VALUE")]
    pub(crate) fuzz_env: Vec<String>,
    #[arg(long = "fuzz-target", value_name = "TARGET")]
    pub(crate) fuzz_targets: Vec<String>,
    #[arg(long)]
    pub(crate) fuzz_budget_label: Option<String>,
    #[arg(long = "fuzz-auto-coverage")]
    pub(crate) fuzz_auto_coverage: bool,
    #[arg(long = "fuzz-coverage-json", value_name = "PATH")]
    pub(crate) fuzz_coverage_json: Option<PathBuf>,
    #[arg(long = "fuzz-profraw-dir", value_name = "PATH")]
    pub(crate) fuzz_profraw_dir: Option<PathBuf>,
    #[arg(long = "fuzz-coverage-object", value_name = "PATH")]
    pub(crate) fuzz_coverage_objects: Vec<PathBuf>,
    #[arg(long)]
    pub(crate) output: Option<PathBuf>,
    #[arg(long, default_value = "both")]
    pub(crate) format: String,
    #[arg(long)]
    pub(crate) list: bool,
    #[arg(long)]
    pub(crate) dry_run: bool,
    #[arg(short, long)]
    pub(crate) verbose: bool,
}

pub(crate) fn parse_env_pairs(values: &[String]) -> Vec<(String, String)> {
    values
        .iter()
        .filter_map(|s| {
            s.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect()
}

pub(crate) fn parse_format(value: &str) -> Result<OutputFormat> {
    match value {
        "json" => Ok(OutputFormat::Json),
        "markdown" => Ok(OutputFormat::Markdown),
        "both" => Ok(OutputFormat::Both),
        other => bail!("unsupported format `{other}`"),
    }
}
