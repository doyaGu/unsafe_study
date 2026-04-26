mod audit_cli;
mod cli;
mod console;
mod coverage_cli;
#[cfg(test)]
mod main_tests;
mod study_cli;

use anyhow::{bail, Result};
use clap::Parser;
use colored::*;
use std::ffi::OsString;

use audit_cli::run_audit_mode;
use cli::Cli;
use coverage_cli::prepare_coverage_json;
use study_cli::{detach_study_run, detached_child_args, print_study_status, run_study_mode};
use unsafe_audit::stop_study_run;

fn main() -> Result<()> {
    let raw_args: Vec<OsString> = std::env::args_os().collect();
    let args: Vec<String> = std::env::args().collect();
    let cli = if args.len() > 1 && args[1] == "unsafe-audit" {
        Cli::parse_from(args.iter().skip(1))
    } else {
        Cli::parse()
    };
    let input_path = std::env::current_dir()?.join(&cli.path);
    if cli.status || cli.stop {
        if !input_path.is_file() {
            bail!("--status/--stop are only supported when PATH is a study manifest file");
        }
        if cli.status && cli.stop {
            bail!("--status and --stop cannot be used together");
        }
        if cli.stop {
            let stopped = stop_study_run(&input_path, cli.output.as_deref())?;
            if stopped {
                println!(
                    "  {} {}",
                    "Stop signal sent.".bold().green(),
                    input_path.display()
                );
            } else {
                println!(
                    "  {} {}",
                    "No live study process found.".bold().yellow(),
                    input_path.display()
                );
            }
            return Ok(());
        }
        return print_study_status(&input_path, cli.output.as_deref());
    }
    if input_path.is_file() && cli.detach {
        return detach_study_run(&raw_args, &cli, &input_path);
    }
    let miri_coverage_json = prepare_coverage_json(
        "miri",
        cli.miri_coverage_json.as_ref(),
        cli.miri_profraw_dir.as_ref(),
        &cli.miri_coverage_objects,
    )?;
    let fuzz_coverage_json = prepare_coverage_json(
        "fuzz",
        cli.fuzz_coverage_json.as_ref(),
        cli.fuzz_profraw_dir.as_ref(),
        &cli.fuzz_coverage_objects,
    )?;

    if input_path.is_file() {
        return run_study_mode(&cli, &input_path, miri_coverage_json, fuzz_coverage_json);
    }
    run_audit_mode(&cli, input_path, miri_coverage_json, fuzz_coverage_json)
}
