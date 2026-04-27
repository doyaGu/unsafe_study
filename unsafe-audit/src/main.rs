use anyhow::Result;
use clap::{Parser, ValueEnum};
use std::path::PathBuf;
use unsafe_audit::config::{PhaseSelection, RunOptions};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Collect research evidence for Rust unsafe usage"
)]
struct Cli {
    /// Crate directory or study manifest TOML.
    input: PathBuf,

    /// Output directory.
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Comma-separated crate names when input is a study manifest.
    #[arg(long, value_delimiter = ',')]
    crates: Vec<String>,

    /// Print normalized plan without running external tools.
    #[arg(long)]
    dry_run: bool,

    #[arg(long)]
    skip_scan: bool,

    #[arg(long)]
    skip_geiger: bool,

    #[arg(long)]
    skip_miri: bool,

    #[arg(long)]
    skip_fuzz: bool,

    /// Run strict Miri first, then a baseline pass when strict reports UB.
    #[arg(long)]
    miri_triage: bool,

    /// Default fuzz time budget in seconds.
    #[arg(long)]
    fuzz_time: Option<u64>,

    /// Environment override for fuzz runs, as KEY=VALUE.
    #[arg(long)]
    fuzz_env: Vec<String>,

    /// Report format. May be repeated.
    #[arg(long, value_enum, default_values_t = [FormatArg::Json, FormatArg::Markdown])]
    format: Vec<FormatArg>,
}

#[derive(Debug, Clone, ValueEnum)]
enum FormatArg {
    Json,
    Markdown,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let options = RunOptions {
        output_root: cli.output,
        crates: cli.crates,
        dry_run: cli.dry_run,
        phases: PhaseSelection {
            scan: !cli.skip_scan,
            geiger: !cli.skip_geiger,
            miri: !cli.skip_miri,
            fuzz: !cli.skip_fuzz,
        },
        miri_triage: cli.miri_triage,
        fuzz_time: cli.fuzz_time,
        fuzz_env: parse_env(cli.fuzz_env)?,
        formats: cli
            .format
            .into_iter()
            .map(|f| match f {
                FormatArg::Json => unsafe_audit::OutputFormat::Json,
                FormatArg::Markdown => unsafe_audit::OutputFormat::Markdown,
            })
            .collect(),
    };

    if options.dry_run {
        let plan = unsafe_audit::load_plan(&cli.input, options)?;
        println!("{}", serde_json::to_string_pretty(&plan)?);
        return Ok(());
    }

    let report = unsafe_audit::run_and_write(&cli.input, options)?;
    println!(
        "wrote report for {} crate(s), schema v{}",
        report.crates.len(),
        report.schema_version
    );
    Ok(())
}

fn parse_env(values: Vec<String>) -> Result<std::collections::BTreeMap<String, String>> {
    let mut env = std::collections::BTreeMap::new();
    for value in values {
        let Some((key, val)) = value.split_once('=') else {
            anyhow::bail!("--fuzz-env must use KEY=VALUE, got {value}");
        };
        env.insert(key.to_string(), val.to_string());
    }
    Ok(env)
}
