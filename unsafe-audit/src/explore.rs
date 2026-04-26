mod harness;
mod miri;
mod reach;

use anyhow::Result;
use std::time::Instant;

use crate::app::{AuditOptions, ExplorationOptions, PhaseSelection};
use crate::domain::{
    CrateAuditResult, ExplorationIssue, ExplorationMiriCase, ExplorationRound, ExplorationSummary,
    PhaseKind, SchedulerDecision, StudyReport, REPORT_SCHEMA_VERSION,
};
use crate::infra::OutputLayout;
use crate::{discover_targets, phases, write_report};
use harness::{disabled_candidate, generate_harness_candidates};
use miri::{discover_miri_cases, isolated_miri_args, run_isolated_miri_case};
use reach::{
    apply_combined_reach, merge_dynamic_reach, rank_sites, reached_count, seed_reach,
    unreached_targets,
};

pub fn run_exploration(
    options: &AuditOptions,
    exploration: &ExplorationOptions,
) -> Result<StudyReport> {
    let targets = discover_targets(&options.discovery)?;
    let layout = OutputLayout::new(options.output_dir.clone());
    layout.create_dirs()?;

    let mut static_options = options.clone();
    static_options.phases = PhaseSelection {
        geiger: options.phases.geiger,
        patterns: options.phases.patterns,
        miri: false,
        fuzz: false,
    };

    let mut results = Vec::new();
    for target in targets {
        let mut result = super::run_crate_audit(&target, &static_options, &layout);
        attach_exploration(&mut result, options, exploration, &layout)?;
        results.push(result);
    }

    Ok(StudyReport {
        schema_version: REPORT_SCHEMA_VERSION,
        timestamp: chrono::Local::now().to_rfc3339(),
        crates: results,
    })
}

pub fn run_exploration_and_write(
    options: &AuditOptions,
    exploration: &ExplorationOptions,
) -> Result<StudyReport> {
    let report = run_exploration(options, exploration)?;
    write_report(options, &report)?;
    Ok(report)
}

fn attach_exploration(
    result: &mut CrateAuditResult,
    options: &AuditOptions,
    exploration: &ExplorationOptions,
    layout: &OutputLayout,
) -> Result<()> {
    let started = Instant::now();
    let ranked_sites = result.patterns.as_ref().map(rank_sites).unwrap_or_default();
    let mut combined_reach = seed_reach(result);
    let mut rounds = Vec::new();
    let mut decisions = Vec::new();
    let mut isolated_miri_cases = Vec::new();
    let mut fuzz_runs = Vec::new();
    let mut harness_candidates = Vec::new();
    let mut issues = Vec::new();
    let mut no_new_coverage_rounds = 0usize;
    let miri_cases = if options.phases.miri {
        discover_miri_cases(result, layout).unwrap_or_else(|error| {
            issues.push(ExplorationIssue {
                stage: "miri_discovery".into(),
                message: error.to_string(),
            });
            Vec::new()
        })
    } else {
        Vec::new()
    };
    let mut miri_index = 0usize;
    let mut fuzz_done = false;

    for round in 1..=exploration.max_rounds {
        if let Some(max_secs) = exploration.max_time_secs {
            if started.elapsed().as_secs() >= max_secs {
                break;
            }
        }

        let before = reached_count(&combined_reach);
        let target_site_ids = unreached_targets(&ranked_sites, &combined_reach);
        let (action, reason) = if options.phases.miri && miri_index < miri_cases.len() {
            (
                format!("miri:{}", miri_cases[miri_index]),
                "Run the next isolated Miri test case so one UB does not stop the remaining cases."
                    .to_string(),
            )
        } else if options.phases.fuzz && !fuzz_done {
            (
                "fuzz:existing_targets".to_string(),
                "Run existing fuzz targets after isolated Miri cases have been exhausted.".into(),
            )
        } else if exploration.generate_harnesses {
            (
                "llm:harness_candidates".to_string(),
                "Ask the configured provider for auditable harness patch drafts targeting unreached hotspots."
                    .into(),
            )
        } else {
            (
                "stop:no_action".to_string(),
                "No enabled dynamic action remains.".into(),
            )
        };

        decisions.push(SchedulerDecision {
            round,
            action: action.clone(),
            reason: reason.clone(),
            target_site_ids: target_site_ids.clone(),
        });

        if let Some(case_name) = action.strip_prefix("miri:") {
            let case = run_isolated_miri_case(
                result,
                options,
                layout,
                case_name,
                isolated_miri_cases.len(),
            );
            if let Some(miri) = case.as_ref().ok().and_then(|(_, miri)| miri.as_ref()) {
                merge_dynamic_reach(
                    &mut combined_reach,
                    result,
                    Some(miri),
                    &[],
                    options.miri_coverage_json.as_deref(),
                    None,
                );
                if result.miri.is_none() {
                    result.miri = Some(miri.clone());
                }
            }
            match case {
                Ok((summary, _)) => isolated_miri_cases.push(summary),
                Err(error) => {
                    isolated_miri_cases.push(ExplorationMiriCase {
                        name: case_name.to_string(),
                        invocation: crate::domain::CommandInvocation {
                            working_dir: options
                                .miri_harness_dir
                                .clone()
                                .unwrap_or_else(|| result.target.dir.clone()),
                            args: isolated_miri_args(case_name),
                        },
                        verdict: None,
                        ub_detected: None,
                        coverage_json: None,
                        log_path: None,
                        error: Some(error.to_string()),
                    });
                }
            }
            miri_index += 1;
        } else if action == "fuzz:existing_targets" {
            match phases::fuzz::run(
                &result.target.dir,
                options.fuzz_harness_dir.as_deref(),
                options.fuzz_time,
                &options.fuzz_env,
                &options.fuzz_targets,
                options.fuzz_budget_label.as_deref(),
                &layout.fuzz_logs,
            ) {
                Ok(fuzz) => {
                    merge_dynamic_reach(
                        &mut combined_reach,
                        result,
                        None,
                        &fuzz,
                        None,
                        options.fuzz_coverage_json.as_deref(),
                    );
                    fuzz_runs.extend(fuzz.iter().map(|run| {
                        crate::domain::ExplorationFuzzRun {
                            target_name: run.target_name.clone(),
                            status: run.status,
                            budget_secs: run.requested_time_budget_secs,
                            coverage_json: options.fuzz_coverage_json.clone(),
                            log_path: run
                                .execution
                                .as_ref()
                                .map(|execution| execution.log_path.clone()),
                        }
                    }));
                    result.fuzz = fuzz;
                }
                Err(error) => result.phase_issues.push(crate::domain::PhaseIssue {
                    phase: PhaseKind::Fuzz,
                    message: error.to_string(),
                }),
            }
            fuzz_done = true;
        } else if action == "llm:harness_candidates" {
            match generate_harness_candidates(result, exploration, &ranked_sites, &combined_reach) {
                Ok(mut candidates) => harness_candidates.append(&mut candidates),
                Err(error) => issues.push(ExplorationIssue {
                    stage: "llm_generation".into(),
                    message: error.to_string(),
                }),
            }
        }

        let after = reached_count(&combined_reach);
        let new_reach = after.saturating_sub(before);
        if new_reach == 0 {
            no_new_coverage_rounds += 1;
        } else {
            no_new_coverage_rounds = 0;
        }
        let stop_after_round = action.starts_with("stop:")
            || no_new_coverage_rounds >= exploration.no_new_coverage_limit;
        rounds.push(ExplorationRound {
            round,
            planned_action: action,
            reason,
            reached_before: before,
            reached_after: after,
            new_reach,
            stop_after_round,
        });
        if stop_after_round {
            break;
        }
    }

    apply_combined_reach(result, combined_reach);
    if exploration.generate_harnesses
        && harness_candidates.is_empty()
        && exploration.llm_provider_cmd.is_none()
    {
        harness_candidates.push(disabled_candidate(result, &ranked_sites));
    }

    result.exploration = Some(ExplorationSummary {
        mode: "coverage_priority".into(),
        max_rounds: exploration.max_rounds,
        max_time_secs: exploration.max_time_secs,
        no_new_coverage_limit: exploration.no_new_coverage_limit,
        rounds,
        isolated_miri_cases,
        fuzz_runs,
        harness_candidates,
        scheduler_decisions: decisions,
        issues,
    });
    Ok(())
}
