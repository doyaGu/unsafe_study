use anyhow::{bail, Result};
use colored::*;
use std::path::PathBuf;

use crate::cli::{parse_env_pairs, parse_format, Cli};
use crate::console::{phase, print_crate_summary};
use unsafe_audit::{
    discover_targets, run_and_write, run_exploration_and_write, AuditOptions, DiscoveryOptions,
    ExplorationOptions, OutputLayout, PhaseSelection,
};

pub(crate) fn run_audit_mode(
    cli: &Cli,
    input_path: PathBuf,
    miri_coverage_json: Option<PathBuf>,
    fuzz_coverage_json: Option<PathBuf>,
) -> Result<()> {
    if cli.detach {
        bail!("--detach is only supported when PATH is a study manifest file");
    }

    let discovery = DiscoveryOptions {
        path: input_path,
        batch: cli.batch,
    };
    let crates = discover_targets(&discovery)?;
    if crates.is_empty() {
        bail!("No crates found at {}", discovery.path.display());
    }

    println!();
    println!(
        "  {} {} crate(s)",
        "unsafe-audit:".bold().cyan(),
        crates.len().to_string().green(),
    );
    for target in &crates {
        println!("    {} {}", "·".dimmed(), target.display_name().bold());
    }
    println!();

    if cli.list {
        return Ok(());
    }

    let format = parse_format(&cli.format)?;
    let phases = PhaseSelection::from_skip_flags(
        cli.skip_geiger,
        cli.skip_miri,
        cli.skip_fuzz,
        cli.skip_patterns,
    );
    let options = AuditOptions {
        discovery,
        phases,
        miri_flags: cli.miri_flags.clone(),
        baseline_miri_flags: cli.baseline_miri_flags.clone(),
        miri_triage: cli.miri_triage,
        miri_scope: cli.miri_scope.into(),
        miri_harness_dir: cli.miri_harness_dir.clone(),
        miri_args: cli.miri_args.clone(),
        miri_auto_coverage: cli.miri_auto_coverage,
        miri_coverage_json,
        fuzz_time: cli.fuzz_time,
        fuzz_harness_dir: cli.fuzz_harness_dir.clone(),
        fuzz_env: parse_env_pairs(&cli.fuzz_env),
        fuzz_targets: cli.fuzz_targets.clone(),
        fuzz_budget_label: cli.fuzz_budget_label.clone(),
        fuzz_auto_coverage: cli.fuzz_auto_coverage,
        fuzz_coverage_json,
        output_dir: cli.output.clone().unwrap_or_else(|| {
            std::env::current_dir()
                .unwrap()
                .join(&cli.path)
                .join("unsafe-audit-report")
        }),
        format,
        verbose: cli.verbose,
    };

    let report = if cli.classic {
        run_and_write(&options)?
    } else {
        run_exploration_and_write(
            &options,
            &ExplorationOptions {
                max_rounds: cli.max_rounds,
                max_time_secs: cli.max_time_secs,
                no_new_coverage_limit: cli.no_new_coverage_limit,
                generate_harnesses: cli.generate_harnesses,
                llm_provider_cmd: cli.llm_provider_cmd.clone(),
            },
        )?
    };
    for result in &report.crates {
        print_crate_summary(result, options.verbose);
    }

    let layout = OutputLayout::new(options.output_dir.clone());
    phase("Report");
    if options.format.writes_json() {
        let path = layout.report_json_path();
        println!("  {} {}", "·".green(), path.display());
    }
    if options.format.writes_markdown() {
        let path = layout.report_markdown_path();
        println!("  {} {}", "·".green(), path.display());
    }

    println!();
    println!(
        "  {} ({})",
        "Done.".bold().green(),
        format!("{} crates", report.crates.len()).dimmed(),
    );
    Ok(())
}
