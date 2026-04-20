//! cargo-unsafe-audit: Audit a Rust crate for unsafe code.
//!
//! Phases:
//!   1. Geiger    — unsafe hotspot mining
//!   2. Miri      — UB detection
//!   3. Fuzz      — crash/panic discovery
//!   4. Patterns  — syn AST classification (unique value-add)
//!   5. Report    — Markdown + JSON
//!
//! Usage:
//!   unsafe-audit <crate-dir>                     # audit one crate
//!   unsafe-audit <dir> --batch                   # audit all subdirs with Cargo.toml
//!   unsafe-audit <crate-dir> --skip-miri         # skip a phase

mod analyzer;
mod fuzz;
mod geiger;
mod miri;
mod models;
mod report_gen;

use anyhow::{bail, Result};
use clap::Parser;
use colored::*;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "cargo-unsafe-audit",
    bin_name = "cargo-unsafe-audit",
    about = "Audit a Rust crate for unsafe code: Geiger + Miri + Fuzz + Pattern Analysis",
    version
)]
struct Cli {
    /// Path to a crate directory, or a directory of crates (with --batch).
    #[arg(value_name = "PATH", default_value = ".")]
    path: PathBuf,

    /// Treat PATH as a directory containing multiple crate subdirectories.
    #[arg(long)]
    batch: bool,

    /// Skip Phase 1 (Geiger).
    #[arg(long)]
    skip_geiger: bool,

    /// Skip Phase 2 (Miri).
    #[arg(long)]
    skip_miri: bool,

    /// Skip Phase 3 (Fuzz).
    #[arg(long)]
    skip_fuzz: bool,

    /// Skip Phase 4 (Pattern analysis).
    #[arg(long)]
    skip_patterns: bool,

    /// Extra flags for MIRIFLAGS.
    #[arg(long, default_value = "-Zmiri-symbolic-alignment-check -Zmiri-strict-provenance")]
    miri_flags: String,

    /// Fuzz duration per target in seconds.
    #[arg(long, default_value = "60")]
    fuzz_time: u64,

    /// Extra env var for fuzz (KEY=VALUE, can repeat).
    #[arg(long = "fuzz-env", value_name = "KEY=VALUE")]
    fuzz_env: Vec<String>,

    /// Output directory for reports and logs.
    #[arg(long)]
    output: Option<PathBuf>,

    /// Output format: json, markdown, both.
    #[arg(long, default_value = "both")]
    format: String,

    /// List discovered crates without running.
    #[arg(long)]
    list: bool,

    /// Verbose output.
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cli = if args.len() > 1 && args[1] == "unsafe-audit" {
        Cli::parse_from(args.iter().skip(1))
    } else {
        Cli::parse()
    };

    let path = std::env::current_dir()?.join(&cli.path);

    // Parse fuzz env pairs
    let fuzz_env: Vec<(String, String)> = cli
        .fuzz_env
        .iter()
        .filter_map(|s| s.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
        .collect();

    // Discover crates
    let crates = discover_crates(&path, cli.batch)?;
    if crates.is_empty() {
        bail!("No crates found at {}", path.display());
    }

    println!();
    println!(
        "  {} {} crate(s)",
        "unsafe-audit:".bold().cyan(),
        crates.len().to_string().green(),
    );
    for c in &crates {
        println!("    {} {}", "·".dimmed(), c.name.bold());
    }
    println!();

    if cli.list {
        return Ok(());
    }

    // Output directory
    let output_dir = cli.output.clone().unwrap_or_else(|| path.join("unsafe-audit-report"));
    let miri_log_dir = output_dir.join("miri_logs");
    let fuzz_log_dir = output_dir.join("fuzz_logs");
    std::fs::create_dir_all(&output_dir)?;
    std::fs::create_dir_all(&miri_log_dir)?;
    std::fs::create_dir_all(&fuzz_log_dir)?;

    let mut results = Vec::new();

    for target in &crates {
        println!("{}", format!("━━ {} ━━", target.name).bold().cyan());
        results.push(audit_crate(target, &cli, &fuzz_env, &miri_log_dir, &fuzz_log_dir));
        println!();
    }

    // Report
    phase("Report");
    let report = models::StudyReport {
        timestamp: chrono::Local::now().to_rfc3339(),
        crates: results,
    };

    if cli.format == "json" || cli.format == "both" {
        let p = output_dir.join("report.json");
        std::fs::write(&p, report_gen::generate_json(&report)?)?;
        println!("  {} {}", "·".green(), p.display());
    }
    if cli.format == "markdown" || cli.format == "both" {
        let p = output_dir.join("report.md");
        std::fs::write(&p, report_gen::generate_markdown(&report))?;
        println!("  {} {}", "·".green(), p.display());
    }

    println!();
    println!(
        "  {} ({})",
        "Done.".bold().green(),
        format!("{} crates", report.crates.len()).dimmed(),
    );
    Ok(())
}

// =========================================================================
// Discovery
// =========================================================================

fn discover_crates(path: &Path, batch: bool) -> Result<Vec<models::CrateTarget>> {
    if path.join("Cargo.toml").exists() && !batch {
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or("unknown".into());
        return Ok(vec![models::CrateTarget { name, dir: path.to_path_buf() }]);
    }

    let mut crates = Vec::new();
    for entry in std::fs::read_dir(path)? {
        let sub = entry?.path();
        if sub.join("Cargo.toml").exists() {
            let name = sub.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or("unknown".into());
            crates.push(models::CrateTarget { name, dir: sub });
        }
    }
    crates.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(crates)
}

// =========================================================================
// Per-crate audit
// =========================================================================

fn audit_crate(
    target: &models::CrateTarget,
    cli: &Cli,
    fuzz_env: &[(String, String)],
    miri_log_dir: &Path,
    fuzz_log_dir: &Path,
) -> models::CrateAuditResult {
    let mut result = models::CrateAuditResult {
        target: target.clone(),
        geiger: None,
        miri: None,
        fuzz: vec![],
        pattern_analysis: None,
    };

    // Phase 1
    if !cli.skip_geiger {
        phase("Phase 1: Geiger");
        match geiger::run_geiger(&target.dir) {
            Ok(g) => {
                println!(
                    "  {} {} unsafe exprs ({} unused), forbids={}",
                    "·".green(),
                    g.used.exprs.unsafe_.to_string().yellow(),
                    g.unused.exprs.unsafe_.to_string().dimmed(),
                    g.forbids_unsafe,
                );
                result.geiger = Some(g);
            }
            Err(e) => println!("  {} {}", "✗".red(), e.to_string().dimmed()),
        }
    }

    // Phase 2
    if !cli.skip_miri {
        phase("Phase 2: Miri");
        let log_path = miri_log_dir.join(format!("{}.log", target.name));
        match miri::run_miri(&target.dir, &cli.miri_flags, &log_path) {
            Ok(m) => {
                let status = if m.passed { "CLEAN".green() } else if m.ub_detected { "UB DETECTED".red().bold() } else { "FAILED".red() };
                println!("  {} {} ({:.1}s)", "·".green(), status, m.duration_secs);
                if m.ub_detected {
                    if let Some(msg) = &m.ub_message {
                        println!("    {} {}", "↳".yellow(), msg.red());
                    }
                }
                result.miri = Some(m);
            }
            Err(e) => println!("  {} {}", "✗".red(), e.to_string().dimmed()),
        }
    }

    // Phase 3
    if !cli.skip_fuzz {
        phase(&format!("Phase 3: Fuzz ({}s/target)", cli.fuzz_time));
        match fuzz::run_fuzz(&target.dir, cli.fuzz_time, fuzz_env, fuzz_log_dir) {
            Ok(fuzz_results) => {
                for f in &fuzz_results {
                    let s = match f.status {
                        models::FuzzStatus::Clean => "CLEAN".green(),
                        models::FuzzStatus::Panic => "PANIC".red().bold(),
                        models::FuzzStatus::Oom => "OOM".red().bold(),
                        models::FuzzStatus::Timeout => "TIMEOUT".yellow(),
                        models::FuzzStatus::BuildFailed => "BUILD FAIL".red(),
                        models::FuzzStatus::NoFuzzDir | models::FuzzStatus::NoTargets => format!("{}", f.status).dimmed(),
                        models::FuzzStatus::Error => "ERROR".red(),
                    };
                    println!(
                        "  {} {} — {} {}",
                        "·".green(),
                        f.target_name.bold(),
                        s,
                        f.total_runs.map(|n| format!("({} runs)", n)).unwrap_or_default().dimmed(),
                    );
                    if let Some(p) = &f.artifact_path {
                        println!("    {} {} ({}B)", "↳".yellow(), p.display(), f.reproducer_size_bytes.unwrap_or(0));
                    }
                }
                result.fuzz = fuzz_results;
            }
            Err(e) => println!("  {} {}", "✗".red(), e.to_string().dimmed()),
        }
    }

    // Phase 4
    if !cli.skip_patterns {
        phase("Phase 4: Patterns");
        match analyzer::analyze_crate(&target.dir) {
            Ok(summary) => {
                let (score, rating) = (summary.risk_score, if summary.risk_score < 20.0 { "LOW".green() } else if summary.risk_score < 50.0 { "MEDIUM".yellow() } else { "HIGH".red() });
                println!(
                    "  {} {} unsafe exprs, {} files, risk={:.1} ({})",
                    "·".green(),
                    summary.total_unsafe_exprs.to_string().yellow(),
                    summary.files_with_unsafe.to_string().dimmed(),
                    score,
                    rating,
                );
                if cli.verbose && !summary.patterns.is_empty() {
                    for pc in &summary.patterns {
                        println!("    {} {} ({})", "·".dimmed(), format!("{:?}", pc.pattern), pc.count.to_string().yellow());
                    }
                }
                result.pattern_analysis = Some(summary);
            }
            Err(e) => println!("  {} {}", "✗".red(), e.to_string().dimmed()),
        }
    }

    result
}

fn phase(name: &str) {
    println!("  {} {}", format!("[{}]", "Phase".dimmed()).dimmed(), name.bold());
}
