//! cargo-unsafe-audit: Audit Rust crates for unsafe code patterns, Miri UB, and fuzz robustness.
//!
//! Usage:
//!   cargo unsafe-audit <crate-path> [options]
//!   unsafe-audit <crate-path> [options]

mod analyzer;
mod api_discovery;
mod corpus_gen;
mod fuzz_runner;
mod harness_gen;
mod miri_runner;
mod models;
mod report_gen;

use anyhow::{bail, Context, Result};
use clap::Parser;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};
use std::time::Instant;

// =========================================================================
// CLI
// =========================================================================

#[derive(Parser, Debug)]
#[command(
    name = "cargo-unsafe-audit",
    bin_name = "cargo-unsafe-audit",
    about = "Audit Rust crates for unsafe code patterns, Miri UB, and fuzz robustness",
    version,
)]
struct Cli {
    /// Path to the crate to audit (directory containing Cargo.toml)
    #[arg(value_name = "CRATE_PATH")]
    crate_path: Option<PathBuf>,

    /// Run only static analysis (no Miri, no fuzz)
    #[arg(long)]
    static_only: bool,

    /// Skip static analysis
    #[arg(long)]
    skip_static: bool,

    /// Skip Miri testing
    #[arg(long)]
    skip_miri: bool,

    /// Skip fuzzing
    #[arg(long)]
    skip_fuzz: bool,

    /// Fuzz duration per target in seconds (default: 60)
    #[arg(long, default_value = "60")]
    fuzz_time: u64,

    /// Maximum number of fuzz targets to generate
    #[arg(long, default_value = "5")]
    max_targets: usize,

    /// Miri test filter (e.g. specific test name)
    #[arg(long)]
    miri_filter: Option<String>,

    /// Output directory for reports (default: <crate>/unsafe-audit-report/)
    #[arg(long)]
    output: Option<PathBuf>,

    /// Output format: json, markdown, or both
    #[arg(long, default_value = "both")]
    format: String,

    /// Don't actually run fuzzing, just generate harnesses
    #[arg(long)]
    dry_run: bool,

    /// Show discovered APIs without running anything
    #[arg(long)]
    list_targets: bool,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

// =========================================================================
// Main
// =========================================================================

fn main() -> Result<()> {
    // Handle both `cargo unsafe-audit` and `unsafe-audit` invocation
    let args = std::env::args().collect::<Vec<_>>();
    let cli = if args.len() > 1 && args[1] == "unsafe-audit" {
        Cli::parse_from(args.iter().skip(1))
    } else {
        Cli::parse()
    };

    let crate_path = cli.crate_path.unwrap_or_else(|| PathBuf::from("."));
    let crate_dir = if crate_path.is_absolute() {
        crate_path
    } else {
        std::env::current_dir()?.join(crate_path)
    };

    if !crate_dir.join("Cargo.toml").exists() {
        bail!(
            "No Cargo.toml found at {}. Specify a valid crate directory.",
            crate_dir.display()
        );
    }

    let (crate_name, crate_version) = read_crate_info(&crate_dir)?;

    println!();
    println!(
        "{}",
        format!("  {} {} v{}", "unsafe-audit:".bold().cyan(), crate_name, crate_version)
            .bold()
    );
    println!(
        "  {}",
        format!("Path: {}", crate_dir.display()).dimmed()
    );
    println!();

    // Phase 0: API discovery
    if !cli.skip_fuzz || cli.list_targets {
        print_phase("API Discovery");
        let targets = api_discovery::discover_apis(&crate_dir, &crate_name)
            .context("discovering fuzzable APIs")?;

        if targets.is_empty() {
            println!("  No fuzzable APIs found.");
        } else {
            println!(
                "  Found {} fuzzable API(s):",
                targets.len().to_string().green()
            );
            for t in targets.iter().take(cli.max_targets) {
                println!(
                    "    {} {} ({}, priority {})",
                    "•".green(),
                    t.full_path.bold(),
                    t.input_kind.to_string().dimmed(),
                    t.priority.to_string().yellow(),
                );
            }
            if targets.len() > cli.max_targets {
                println!(
                    "    {} {} more (use --max-targets to increase)",
                    "...".dimmed(),
                    (targets.len() - cli.max_targets).to_string().dimmed()
                );
            }
        }
        println!();

        if cli.list_targets {
            return Ok(());
        }
    }

    let mut report = models::AuditReport {
        crate_name: crate_name.clone(),
        crate_version: crate_version.clone(),
        crate_dir: crate_dir.clone(),
        timestamp: chrono::Local::now().to_rfc3339(),
        static_analysis: analyzer::UnsafeSummary {
            crate_name: crate_name.clone(),
            crate_version: crate_version.clone(),
            total_unsafe_exprs: 0,
            total_unsafe_fns: 0,
            total_unsafe_impls: 0,
            files_with_unsafe: 0,
            files_scanned: 0,
            patterns: vec![],
            findings: vec![],
            risk_score: 0.0,
        },
        miri_result: None,
        fuzz_results: vec![],
    };

    // Phase 1: Static analysis
    if !cli.skip_static {
        print_phase("Static Analysis");
        match analyzer::analyze_crate(&crate_dir) {
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
                    "  Files: {} | Unsafe files: {} | Unsafe exprs: {} | Score: {:.1} ({})",
                    summary.files_scanned.to_string().dimmed(),
                    summary.files_with_unsafe.to_string().yellow(),
                    summary.total_unsafe_exprs.to_string().yellow(),
                    score,
                    rating,
                );
                if !summary.patterns.is_empty() {
                    println!("  Patterns:");
                    for pc in &summary.patterns {
                        println!(
                            "    {} {} ({} occurrences)",
                            "•".dimmed(),
                            format!("{:?}", pc.pattern).bold(),
                            pc.count.to_string().yellow(),
                        );
                    }
                }
                report.static_analysis = summary;
            }
            Err(e) => {
                println!("  {} Static analysis failed: {}", "✗".red(), e);
            }
        }
        println!();
    }

    // Phase 2: Miri
    if !cli.skip_miri && !cli.static_only {
        print_phase("Miri Triage");
        match miri_runner::run_miri_triage(&crate_dir, cli.miri_filter.as_deref(), false) {
            Ok(result) => {
                let classification_str = format!("{:?}", result.classification);
                let colored_class = match result.classification {
                    models::MiriClassification::Clean => classification_str.green(),
                    models::MiriClassification::TruePositive => classification_str.red(),
                    models::MiriClassification::SuspectedFalsePositive => classification_str.yellow(),
                    models::MiriClassification::ConfirmedFalsePositive => "ConfirmedFalsePositive".yellow(),
                    models::MiriClassification::Error => classification_str.red(),
                };
                println!(
                    "  Pass 1: {} ({:.1}s)",
                    if result.pass1.passed { "CLEAN".green() } else { "UB".red() },
                    result.pass1.duration_secs,
                );
                if let Some(pass2) = &result.pass2 {
                    println!(
                        "  Pass 2: {} ({:.1}s)",
                        if pass2.passed { "CLEAN".green() } else { "UB".red() },
                        pass2.duration_secs,
                    );
                }
                println!("  Classification: {}", colored_class.bold());
                report.miri_result = Some(result);
            }
            Err(e) => {
                println!("  {} Miri failed: {}", "✗".red(), e);
            }
        }
        println!();
    }

    // Phase 3: Fuzzing
    if !cli.skip_fuzz && !cli.static_only {
        print_phase("Fuzz Harness Generation");

        let targets = api_discovery::discover_apis(&crate_dir, &crate_name)
            .context("re-discovering APIs for fuzz")?;
        let targets_to_use: Vec<_> = targets.into_iter().take(cli.max_targets).collect();

        if targets_to_use.is_empty() {
            println!("  No fuzzable targets found. Skipping fuzz phase.");
        } else {
            let fuzz_dir = harness_gen::generate_fuzz_workspace(
                &crate_dir,
                &crate_name,
                &targets_to_use,
                None,
            )
            .context("generating fuzz workspace")?;

            println!(
                "  Generated {} harness(es) in {}",
                targets_to_use.len().to_string().green(),
                fuzz_dir.display(),
            );
            for t in &targets_to_use {
                let name = t.full_path.replace("::", "_").replace(|c: char| !c.is_alphanumeric() && c != '_', "").to_lowercase();
                println!("    {} {} -> fuzz_targets/{}.rs", "•".green(), t.full_path, name);
            }
            println!();

            // Generate seed corpus
            print_phase("Seed Corpus");
            let mut corpus_dirs = std::collections::HashMap::new();
            for t in &targets_to_use {
                let name = t.full_path.replace("::", "_").replace(|c: char| !c.is_alphanumeric() && c != '_', "").to_lowercase();
                let corpus_dir = fuzz_dir.join("corpus").join(&name);
                match corpus_gen::generate_seed_corpus(&corpus_dir, t.input_kind, &t.name) {
                    Ok(files) => {
                        println!(
                            "  {} {} -- {} seed(s)",
                            "•".green(),
                            name,
                            files.len().to_string().yellow(),
                        );
                        corpus_dirs.insert(name, corpus_dir);
                    }
                    Err(e) => println!("  {} Failed to generate corpus for {}: {}", "✗".red(), name, e),
                }
            }
            println!();

            if cli.dry_run {
                println!(
                    "  {} Dry run -- harnesses generated but not executed.",
                    "ℹ️".blue()
                );
                println!("  Run manually: cd {} && cargo fuzz run <target>", crate_dir.display());
            } else {
                print_phase(&format!("Fuzzing ({}s per target)", cli.fuzz_time));
                let harness_names: Vec<String> = targets_to_use
                    .iter()
                    .map(|t| {
                        t.full_path
                            .replace("::", "_")
                            .replace(|c: char| !c.is_alphanumeric() && c != '_', "")
                            .to_lowercase()
                    })
                    .collect();

                match fuzz_runner::run_all_fuzz(
                    &crate_dir,
                    &harness_names,
                    cli.fuzz_time,
                    &corpus_dirs,
                ) {
                    Ok(results) => {
                        for fr in &results {
                            let status_colored = match fr.status {
                                models::FuzzStatus::Clean => "CLEAN".green(),
                                models::FuzzStatus::CrashFound => "CRASH".red().bold(),
                                models::FuzzStatus::BuildFailed => "BUILD FAIL".red(),
                                models::FuzzStatus::Timeout => "TIMEOUT".yellow(),
                                models::FuzzStatus::Error => "ERROR".red(),
                            };
                            println!(
                                "  {} {} -- runs={} edges={} [{}]",
                                "•".green(),
                                fr.target_name.bold(),
                                fr.total_runs
                                    .map(|n| n.to_string())
                                    .unwrap_or_else(|| "-".into())
                                    .dimmed(),
                                fr.edges_covered
                                    .map(|n| n.to_string())
                                    .unwrap_or_else(|| "-".into())
                                    .dimmed(),
                                status_colored,
                            );
                            for f in &fr.findings {
                                println!(
                                    "    {} {:?}: {}",
                                    "↳".yellow(),
                                    f.finding_type,
                                    f.message.red(),
                                );
                            }
                        }
                        report.fuzz_results = results;
                    }
                    Err(e) => {
                        println!("  {} Fuzzing failed: {}", "✗".red(), e);
                    }
                }
            }
            println!();
        }
    }

    // Generate reports
    print_phase("Report");
    let output_dir = cli.output.unwrap_or_else(|| crate_dir.join("unsafe-audit-report"));
    std::fs::create_dir_all(&output_dir)?;

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

    // Final summary
    let overall = if report.fuzz_results.iter().any(|f| f.status == models::FuzzStatus::CrashFound) {
        "CRASHES FOUND".red().bold()
    } else if let Some(ref miri) = report.miri_result {
        if miri.classification == models::MiriClassification::TruePositive {
            "UB DETECTED".red().bold()
        } else {
            "CLEAN".green().bold()
        }
    } else {
        "COMPLETE".cyan().bold()
    };
    println!("  Overall: {}", overall);

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_crate_info(dir: &Path) -> Result<(String, String)> {
    let cargo_toml = std::fs::read_to_string(dir.join("Cargo.toml"))
        .context("reading Cargo.toml")?;
    let name = cargo_toml
        .lines()
        .find(|l| l.trim().starts_with("name"))
        .and_then(|l| l.split('=').nth(1))
        .map(|v| v.trim().trim_matches('"').to_string())
        .unwrap_or_else(|| dir.file_name().unwrap().to_string_lossy().to_string());
    let version = cargo_toml
        .lines()
        .find(|l| l.trim().starts_with("version"))
        .and_then(|l| l.split('=').nth(1))
        .map(|v| v.trim().trim_matches('"').to_string())
        .unwrap_or_else(|| "0.0.0".to_string());
    Ok((name, version))
}

fn print_phase(name: &str) {
    println!(
        "{} {}",
        format!("[{}]", "Phase".dimmed()).dimmed(),
        name.bold()
    );
}
