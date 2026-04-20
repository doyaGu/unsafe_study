//! cargo-unsafe-audit: Audit Rust crates for unsafe code.
//!
//! Faithfully wraps the three-phase study pipeline:
//!   Phase 1: Geiger (hotspot mining)
//!   Phase 2: Miri  (UB detection)
//!   Phase 3: Fuzz  (crash/panic discovery)
//!   Phase 4: Pattern analysis (optional, syn-based)
//!   Phase 5: Report generation

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

// =========================================================================
// CLI
// =========================================================================

#[derive(Parser, Debug)]
#[command(
    name = "cargo-unsafe-audit",
    bin_name = "cargo-unsafe-audit",
    about = "Audit Rust crates for unsafe code: Geiger + Miri + Fuzz + Pattern Analysis",
    version,
)]
struct Cli {
    /// Path to a single crate directory, or a targets/ directory containing multiple crates.
    #[arg(value_name = "PATH")]
    path: Option<PathBuf>,

    /// Study mode: audit all crates found in the targets/ directory.
    #[arg(long)]
    study: bool,

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

    /// Fuzz duration per target in seconds (default: 60).
    #[arg(long, default_value = "60")]
    fuzz_time: u64,

    /// Output directory for reports.
    #[arg(long)]
    output: Option<PathBuf>,

    /// Output format: json, markdown, or both.
    #[arg(long, default_value = "both")]
    format: String,

    /// List discovered crates without running anything.
    #[arg(long)]
    list: bool,

    /// Verbose output.
    #[arg(short, long)]
    verbose: bool,
}

// =========================================================================
// Main
// =========================================================================

fn main() -> Result<()> {
    // Handle both `cargo unsafe-audit` and `unsafe-audit` invocation.
    let args: Vec<String> = std::env::args().collect();
    let cli = if args.len() > 1 && args[1] == "unsafe-audit" {
        Cli::parse_from(args.iter().skip(1))
    } else {
        Cli::parse()
    };

    let path = cli.path.clone().unwrap_or_else(|| PathBuf::from("."));
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };

    // Discover crates
    let crates = discover_crates(&path, cli.study)?;
    if crates.is_empty() {
        bail!("No crates found at {}", path.display());
    }

    println!();
    println!(
        "  {} {} crate(s) discovered",
        "unsafe-audit:".bold().cyan(),
        crates.len().to_string().green(),
    );
    for c in &crates {
        let tier_str = match c.tier {
            models::CrateTier::Tier1 => "T1".dimmed(),
            models::CrateTier::Tier2 => "T2".yellow(),
        };
        println!("    {} {} [{}]", "•".dimmed(), c.name.bold(), tier_str);
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

    let mut results: Vec<models::CrateAuditResult> = Vec::new();

    for target in &crates {
        println!("{}", format!("━━━ {} ━━━", target.name).bold().cyan());
        let result = audit_crate(target, &cli, &miri_log_dir, &fuzz_log_dir);
        results.push(result);
        println!();
    }

    // Phase 5: Report
    print_phase("Report");
    let report = models::StudyReport {
        timestamp: chrono::Local::now().to_rfc3339(),
        crates: results,
    };

    if cli.format == "json" || cli.format == "both" {
        let json_path = output_dir.join("report.json");
        let json = report_gen::generate_json(&report)?;
        std::fs::write(&json_path, &json)?;
        println!("  {} {}", "•".green(), json_path.display());
    }
    if cli.format == "markdown" || cli.format == "both" {
        let md_path = output_dir.join("report.md");
        let md = report_gen::generate_markdown(&report);
        std::fs::write(&md_path, &md)?;
        println!("  {} {}", "•".green(), md_path.display());
    }

    println!();
    println!("  {} {}", "Done.".bold().green(), format!("({} crates)", report.crates.len()).dimmed());
    Ok(())
}

// =========================================================================
// Crate discovery
// =========================================================================

fn discover_crates(path: &Path, study_mode: bool) -> Result<Vec<models::CrateTarget>> {
    // If path points to a directory with Cargo.toml -> single crate
    if path.join("Cargo.toml").exists() && !study_mode {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".into());
        let tier = determine_tier(&name);
        return Ok(vec![models::CrateTarget {
            name,
            dir: path.to_path_buf(),
            tier,
        }]);
    }

    // Otherwise treat as targets/ directory
    let mut crates = Vec::new();
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let sub = entry.path();
        if sub.join("Cargo.toml").exists() {
            let name = sub
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".into());
            let tier = determine_tier(&name);
            crates.push(models::CrateTarget {
                name,
                dir: sub,
                tier,
            });
        }
    }
    crates.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(crates)
}

fn determine_tier(name: &str) -> models::CrateTier {
    if miri::harness_for(name).is_some() {
        models::CrateTier::Tier2
    } else {
        models::CrateTier::Tier1
    }
}

// =========================================================================
// Per-crate audit
// =========================================================================

fn audit_crate(
    target: &models::CrateTarget,
    cli: &Cli,
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

    // Phase 1: Geiger
    if !cli.skip_geiger {
        print_phase("Phase 1: Geiger");
        match geiger::run_geiger(&target.dir) {
            Ok(g) => {
                let unsafe_exprs = g.used.exprs.unsafe_;
                let deps_unsafe = g.unused.exprs.unsafe_;
                println!(
                    "  {} used={} unsafe exprs, deps_unused={}, forbids={}",
                    "•".green(),
                    unsafe_exprs.to_string().yellow(),
                    deps_unsafe.to_string().dimmed(),
                    g.forbids_unsafe,
                );
                result.geiger = Some(g);
            }
            Err(e) => {
                println!("  {} Geiger: {}", "✗".red(), e.to_string().dimmed());
            }
        }
    }

    // Phase 2: Miri
    if !cli.skip_miri {
        print_phase("Phase 2: Miri");
        match miri::run_miri(&target.name, &target.dir, miri_log_dir) {
            Ok(m) => {
                let status = if m.passed {
                    "CLEAN".green()
                } else if m.ub_detected {
                    "UB DETECTED".red().bold()
                } else {
                    "FAILED".red()
                };
                let mode_str = match &m.mode {
                    models::MiriMode::Direct => "direct".dimmed(),
                    models::MiriMode::Harness { test_file, .. } => format!("harness({})", test_file).yellow(),
                };
                println!(
                    "  {} {} [{}] {:.1}s",
                    "•".green(),
                    status,
                    mode_str,
                    m.duration_secs,
                );
                if m.ub_detected {
                    if let Some(msg) = &m.ub_message {
                        println!("    {} {}", "↳".yellow(), msg.red());
                    }
                }
                result.miri = Some(m);
            }
            Err(e) => {
                println!("  {} Miri: {}", "✗".red(), e.to_string().dimmed());
            }
        }
    }

    // Phase 3: Fuzz
    if !cli.skip_fuzz {
        print_phase(&format!("Phase 3: Fuzz ({}s/target)", cli.fuzz_time));
        match fuzz::run_fuzz(&target.name, &target.dir, cli.fuzz_time, fuzz_log_dir) {
            Ok(fuzz_results) => {
                for f in &fuzz_results {
                    let status_colored = match f.status {
                        models::FuzzStatus::Clean => "CLEAN".green(),
                        models::FuzzStatus::Panic => "PANIC".red().bold(),
                        models::FuzzStatus::Oom => "OOM".red().bold(),
                        models::FuzzStatus::Timeout => "TIMEOUT".yellow(),
                        models::FuzzStatus::BuildFailed => "BUILD FAIL".red(),
                        models::FuzzStatus::NoFuzzDir => "NO FUZZ DIR".dimmed(),
                        models::FuzzStatus::NoTargets => "NO TARGETS".dimmed(),
                        models::FuzzStatus::Error => "ERROR".red(),
                    };
                    println!(
                        "  {} {} -- {} {}",
                        "•".green(),
                        f.target_name.bold(),
                        status_colored,
                        f.total_runs
                            .map(|n| format!("({} runs)", n))
                            .unwrap_or_default()
                            .dimmed(),
                    );
                    if f.artifact_path.is_some() {
                        println!(
                            "    {} reproducer: {} ({} bytes)",
                            "↳".yellow(),
                            f.artifact_path.as_ref().unwrap().display(),
                            f.reproducer_size_bytes.unwrap_or(0),
                        );
                    }
                }
                result.fuzz = fuzz_results;
            }
            Err(e) => {
                println!("  {} Fuzz: {}", "✗".red(), e.to_string().dimmed());
            }
        }
    }

    // Phase 4: Pattern analysis (optional)
    if !cli.skip_patterns {
        print_phase("Phase 4: Pattern Analysis");
        match analyzer::analyze_crate(&target.dir) {
            Ok(summary) => {
                let score = summary.risk_score;
                let rating = if score < 20.0 {
                    "LOW".green()
                } else if score < 50.0 {
                    "MEDIUM".yellow()
                } else {
                    "HIGH".red()
                };
                println!(
                    "  {} {} unsafe exprs across {} files, risk={:.1} ({})",
                    "•".green(),
                    summary.total_unsafe_exprs.to_string().yellow(),
                    summary.files_with_unsafe.to_string().dimmed(),
                    score,
                    rating,
                );
                if !summary.patterns.is_empty() && cli.verbose {
                    for pc in &summary.patterns {
                        println!(
                            "    {} {} ({})",
                            "•".dimmed(),
                            format!("{:?}", pc.pattern),
                            pc.count.to_string().yellow(),
                        );
                    }
                }
                result.pattern_analysis = Some(summary);
            }
            Err(e) => {
                println!("  {} Pattern analysis: {}", "✗".red(), e.to_string().dimmed());
            }
        }
    }

    result
}

// =========================================================================
// Helpers
// =========================================================================

fn print_phase(name: &str) {
    println!(
        "  {} {}",
        format!("[{}]", "Phase".dimmed()).dimmed(),
        name.bold(),
    );
}
