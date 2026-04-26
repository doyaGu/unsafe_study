use colored::*;

use unsafe_audit::domain::{CrateAuditResult, MiriVerdict, PhaseKind};

pub(crate) fn print_crate_summary(result: &CrateAuditResult, verbose: bool) {
    println!(
        "{}",
        format!("━━ {} ━━", result.target.display_name())
            .bold()
            .cyan()
    );

    if let Some(geiger) = &result.geiger {
        phase("Phase 1: Geiger");
        if let Some(root) = geiger.root_package_result() {
            println!(
                "  {} root={} total={} used_exprs={} deps={}",
                "·".green(),
                root.name.bold(),
                root.total_unsafe().to_string().yellow(),
                root.used.exprs.unsafe_.to_string().yellow(),
                geiger
                    .packages
                    .iter()
                    .filter(|pkg| !pkg.is_root)
                    .count()
                    .to_string()
                    .dimmed(),
            );
        } else {
            println!(
                "  {} dependency-aware geiger packages={}",
                "·".green(),
                geiger.packages.len().to_string().yellow()
            );
        }
        if verbose {
            println!(
                "    {} mode={} log={}",
                "↳".dimmed(),
                geiger.mode,
                geiger.execution.log_path.display()
            );
            if !geiger.used_but_not_scanned_files.is_empty() {
                println!(
                    "    {} {} file(s) used but not scanned",
                    "↳".yellow(),
                    geiger.used_but_not_scanned_files.len()
                );
            }
        }
    } else if let Some(issue) = result.phase_issue(PhaseKind::Geiger) {
        phase("Phase 1: Geiger");
        println!("  {} {}", "✗".red(), issue.message.dimmed());
    }

    if let Some(miri) = &result.miri {
        phase("Phase 2: Miri");
        let status = match miri.verdict {
            MiriVerdict::Clean => "CLEAN".green(),
            MiriVerdict::TruePositiveUb => "TRUE UB".red().bold(),
            MiriVerdict::StrictOnlySuspectedFalsePositive => "STRICT-ONLY FP?".yellow().bold(),
            MiriVerdict::FailedNoUb => "FAILED".red(),
            MiriVerdict::Inconclusive => "INCONCLUSIVE".yellow(),
        };
        println!(
            "  {} {} scope={} ({:.1}s)",
            "·".green(),
            status,
            miri.scope.to_string().cyan(),
            miri.duration_secs()
        );
        if let Some(msg) = &miri.primary_run.ub_message {
            println!("    {} {}", "↳".yellow(), msg.red());
        }
        if verbose {
            println!(
                "    {} cargo {} @ {}",
                "↳".dimmed(),
                miri.invocation.args.join(" "),
                miri.invocation.working_dir.display()
            );
        }
    } else if let Some(issue) = result.phase_issue(PhaseKind::Miri) {
        phase("Phase 2: Miri");
        println!("  {} {}", "✗".red(), issue.message.dimmed());
    }

    if !result.fuzz.is_empty() {
        phase("Phase 3: Fuzz");
        for fuzz in &result.fuzz {
            let status = match fuzz.status {
                unsafe_audit::domain::FuzzStatus::Clean => "CLEAN".green(),
                unsafe_audit::domain::FuzzStatus::Panic => "PANIC".red().bold(),
                unsafe_audit::domain::FuzzStatus::Oom => "OOM".red().bold(),
                unsafe_audit::domain::FuzzStatus::Timeout => "TIMEOUT".yellow(),
                unsafe_audit::domain::FuzzStatus::BuildFailed => "BUILD FAIL".red(),
                unsafe_audit::domain::FuzzStatus::EnvironmentError => {
                    "ENVIRONMENT ERROR".yellow().bold()
                }
                unsafe_audit::domain::FuzzStatus::NoFuzzDir
                | unsafe_audit::domain::FuzzStatus::NoTargets => {
                    format!("{}", fuzz.status).dimmed()
                }
                unsafe_audit::domain::FuzzStatus::Error => "ERROR".red(),
            };
            println!(
                "  {} {} — {} {} {}",
                "·".green(),
                fuzz.target_name.bold(),
                status,
                fuzz.total_runs
                    .map(|n| format!("({n} runs)"))
                    .unwrap_or_default()
                    .dimmed(),
                fuzz.budget_label
                    .as_deref()
                    .map(|label| format!("[{label}]"))
                    .unwrap_or_default()
                    .dimmed(),
            );
            if let Some(path) = &fuzz.artifact_path {
                println!(
                    "    {} {} ({}B)",
                    "↳".yellow(),
                    path.display(),
                    fuzz.reproducer_size_bytes.unwrap_or(0)
                );
            } else if verbose {
                if let Some(execution) = &fuzz.execution {
                    println!("    {} {}", "↳".dimmed(), execution.log_path.display());
                }
            }
        }
    } else if let Some(issue) = result.phase_issue(PhaseKind::Fuzz) {
        phase("Phase 3: Fuzz");
        println!("  {} {}", "✗".red(), issue.message.dimmed());
    }

    if let Some(patterns) = &result.patterns {
        phase("Phase 4: Patterns");
        let rating = if patterns.risk_score < 20.0 {
            "LOW".green()
        } else if patterns.risk_score < 50.0 {
            "MEDIUM".yellow()
        } else {
            "HIGH".red()
        };
        println!(
            "  {} {} findings, {} files, risk={:.1} ({})",
            "·".green(),
            patterns.total_findings.to_string().yellow(),
            patterns.files_with_unsafe.to_string().dimmed(),
            patterns.risk_score,
            rating,
        );
        if patterns.files_failed_to_scan > 0 {
            println!(
                "    {} {} file(s) failed to scan",
                "↳".yellow(),
                patterns.files_failed_to_scan
            );
        }
        if verbose {
            println!(
                "    {} risky={} unsafe_blocks={} declarations={} externs={}",
                "↳".dimmed(),
                patterns.risky_operation_findings,
                patterns.unsafe_block_findings,
                patterns.unsafe_declaration_findings,
                patterns.extern_item_findings
            );
            for pattern in &patterns.patterns {
                println!(
                    "    {} {} ({})",
                    "·".dimmed(),
                    pattern.pattern,
                    pattern.count.to_string().yellow()
                );
            }
        }
        if let Some(coverage) = &result.unsafe_coverage {
            println!(
                "    {} unsafe={} dynamic={}",
                "↳".dimmed(),
                coverage.total_sites.to_string().yellow(),
                coverage.state.to_string().dimmed(),
            );
            if let Some(reached_any) = coverage.reached_by_any {
                println!(
                    "    {} reach≥{} triggered={} unmapped={}",
                    "↳".dimmed(),
                    reached_any.to_string().yellow(),
                    coverage.triggered_by_any.unwrap_or(0).to_string().yellow(),
                    (coverage.unmapped_triggered_by_miri.unwrap_or(0)
                        + coverage.unmapped_triggered_by_fuzz.unwrap_or(0))
                    .to_string()
                    .yellow(),
                );
            } else if coverage.unmapped_triggered_by_miri.unwrap_or(0)
                + coverage.unmapped_triggered_by_fuzz.unwrap_or(0)
                > 0
            {
                println!(
                    "    {} unmapped trigger locations={}",
                    "↳".dimmed(),
                    (coverage.unmapped_triggered_by_miri.unwrap_or(0)
                        + coverage.unmapped_triggered_by_fuzz.unwrap_or(0))
                    .to_string()
                    .yellow(),
                );
            }
        }
    } else if let Some(issue) = result.phase_issue(PhaseKind::Patterns) {
        phase("Phase 4: Patterns");
        println!("  {} {}", "✗".red(), issue.message.dimmed());
    }

    if let Some(exploration) = &result.exploration {
        phase("Exploration");
        println!(
            "  {} rounds={} miri_cases={} fuzz_runs={} harness_candidates={}",
            "·".green(),
            exploration.rounds.len().to_string().yellow(),
            exploration.isolated_miri_cases.len().to_string().yellow(),
            exploration.fuzz_runs.len().to_string().yellow(),
            exploration.harness_candidates.len().to_string().yellow(),
        );
        if verbose {
            for round in &exploration.rounds {
                println!(
                    "    {} round={} action={} new_reach={}",
                    "↳".dimmed(),
                    round.round,
                    round.planned_action,
                    round.new_reach
                );
            }
        }
    }

    println!();
}

pub(crate) fn phase(name: &str) {
    println!(
        "  {} {}",
        format!("[{}]", "Phase".dimmed()).dimmed(),
        name.bold()
    );
}
