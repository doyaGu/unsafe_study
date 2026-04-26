use anyhow::Result;
use colored::*;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use crate::cli::{parse_env_pairs, parse_format, Cli};
use unsafe_audit::{
    list_study_crates, read_study_runtime_state, run_study_manifest, study_output_root,
    PhaseSelection, StudyRunOptions,
};

pub(crate) fn run_study_mode(
    cli: &Cli,
    manifest: &PathBuf,
    miri_coverage_json: Option<PathBuf>,
    fuzz_coverage_json: Option<PathBuf>,
) -> Result<()> {
    if cli.list {
        for name in list_study_crates(manifest)? {
            println!("{name}");
        }
        return Ok(());
    }

    let format = parse_format(&cli.format)?;
    let phases = PhaseSelection::from_skip_flags(
        cli.skip_geiger,
        cli.skip_miri,
        cli.skip_fuzz,
        cli.skip_patterns,
    );
    let selected_crates = cli
        .crates
        .as_deref()
        .map(|value| {
            value
                .split(',')
                .map(|item| item.trim().to_string())
                .filter(|item| !item.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let index = run_study_manifest(&StudyRunOptions {
        manifest_path: manifest.clone(),
        output_root: cli.output.clone(),
        selected_crates,
        resume: !cli.no_resume,
        phases,
        dry_run: cli.dry_run,
        format,
        miri_flags: cli.miri_flags.clone(),
        baseline_miri_flags: cli.baseline_miri_flags.clone(),
        fuzz_env: parse_env_pairs(&cli.fuzz_env),
        miri_auto_coverage: cli.miri_auto_coverage,
        miri_coverage_json,
        fuzz_auto_coverage: cli.fuzz_auto_coverage,
        fuzz_coverage_json,
        verbose: cli.verbose,
    })?;

    if cli.dry_run {
        println!();
        println!(
            "  {} ({})",
            "Dry run complete.".bold().green(),
            format!("{} crates", index.crates.len()).dimmed(),
        );
        return Ok(());
    }

    println!();
    println!(
        "  {} {}",
        "·".green(),
        format!("{}/study_index.json", index.output_root).dimmed()
    );
    println!(
        "  {} {}",
        "·".green(),
        format!("{}/study_summary.md", index.output_root).dimmed()
    );
    println!();
    println!(
        "  {} ({})",
        "Done.".bold().green(),
        format!("{} crates", index.crates.len()).dimmed(),
    );
    Ok(())
}

pub(crate) fn print_study_status(manifest: &PathBuf, output_override: Option<&Path>) -> Result<()> {
    let output_root = study_output_root(manifest, output_override)?;
    println!();
    println!("  {} {}", "Study".bold().cyan(), manifest.display());
    println!("  {} {}", "·".green(), output_root.display());

    if let Some(state) = read_study_runtime_state(manifest, output_override)? {
        println!(
            "  {} status={}",
            "·".green(),
            format!("{:?}", state.status).to_lowercase()
        );
        println!("  {} pid={}", "·".green(), state.pid);
        println!("  {} updated={}", "·".green(), state.updated_at);
        if let Some(name) = state.current_crate {
            println!("  {} crate={}", "·".green(), name);
        }
        if let Some(segment) = state.current_segment {
            println!("  {} segment={}", "·".green(), segment);
        }
        println!(
            "  {} completed_crates={}",
            "·".green(),
            state.completed_crates
        );
    } else {
        println!("  {} no study runtime state", "·".yellow());
    }

    let pid_path = output_root.join("study.pid");
    let stdout_path = output_root.join("study.stdout.log");
    let stderr_path = output_root.join("study.stderr.log");
    println!("  {} {}", "·".green(), pid_path.display());
    println!("  {} {}", "·".green(), stdout_path.display());
    println!("  {} {}", "·".green(), stderr_path.display());
    println!();
    Ok(())
}

pub(crate) fn detach_study_run(raw_args: &[OsString], cli: &Cli, manifest: &PathBuf) -> Result<()> {
    let output_root = study_output_root(manifest, cli.output.as_deref())?;
    std::fs::create_dir_all(&output_root)?;

    let stdout_path = output_root.join("study.stdout.log");
    let stderr_path = output_root.join("study.stderr.log");
    let pid_path = output_root.join("study.pid");
    let command_path = output_root.join("study.command.txt");

    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&stdout_path)?;
    let stderr = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&stderr_path)?;
    let stdin = OpenOptions::new().read(true).open("/dev/null")?;

    let child_args = detached_child_args(raw_args);
    let command_line = child_args
        .iter()
        .skip(1)
        .map(|item| item.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join(" ");

    let mut command = std::process::Command::new(&child_args[0]);
    command
        .args(child_args.iter().skip(1))
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    let child = command.spawn()?;
    std::fs::write(&pid_path, format!("{}\n", child.id()))?;
    let mut command_file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&command_path)?;
    writeln!(command_file, "{}", command_line)?;

    println!();
    println!("  {} {}", "Detached.".bold().green(), manifest.display());
    println!("  {} pid={}", "·".green(), child.id().to_string().yellow());
    println!("  {} {}", "·".green(), pid_path.display());
    println!("  {} {}", "·".green(), stdout_path.display());
    println!("  {} {}", "·".green(), stderr_path.display());
    println!();
    Ok(())
}

pub(crate) fn detached_child_args(raw_args: &[OsString]) -> Vec<OsString> {
    raw_args
        .iter()
        .enumerate()
        .filter_map(|(index, arg)| {
            if index > 0 && arg == "--detach" {
                None
            } else {
                Some(arg.clone())
            }
        })
        .collect()
}
