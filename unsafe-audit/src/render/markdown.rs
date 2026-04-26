use super::cross_phase::append_cross_phase_linkage;
use super::exploration::append_exploration;
use super::phases::{
    append_fuzz, append_geiger, append_miri, append_patterns, phase_summary_fallback,
};
use crate::domain::*;

pub fn generate_markdown(report: &StudyReport) -> String {
    let mut md = String::new();
    md.push_str("# Unsafe Audit Report\n\n");
    md.push_str(&format!("- Schema: {}\n", report.schema_version));
    md.push_str(&format!("- Generated: {}\n", report.timestamp));
    md.push_str(&format!("- Crates: {}\n\n", report.crates.len()));

    append_interpretation_guide(&mut md);
    append_summary(&mut md, report);
    append_geiger(&mut md, &report.crates);
    append_miri(&mut md, &report.crates);
    append_fuzz(&mut md, &report.crates);
    append_exploration(&mut md, &report.crates);
    append_patterns(&mut md, &report.crates);
    append_cross_phase_linkage(&mut md, &report.crates);
    md
}

fn append_interpretation_guide(md: &mut String) {
    md.push_str("## Interpretation Guide\n\n");
    md.push_str(
        "- Geiger is dependency-aware in this schema: root-package counts and dependency-package counts are both preserved.\n",
    );
    md.push_str(
        "- Miri results apply only to the recorded invocation scope and working directory.\n",
    );
    md.push_str("- Fuzz results apply only to the recorded targets and time budget.\n");
    md.push_str(
        "- Pattern findings are heuristic structural classifications for audit prioritization, not proof of exploitability.\n\n",
    );
    md.push_str("- `unsafe_site_universe` reports the root-crate static unsafe-site inventory.\n");
    md.push_str(
        "- `unsafe_coverage = static_universe_only` means no site-level dynamic reach is available; this includes skipped phases and requested dynamic phases with no executable target.\n",
    );
    md.push_str(
        "- `unsafe_coverage = triggered_evidence_only` means dynamic execution ran, but only site-level trigger mapping is populated from Miri UB locations and fuzz panic logs; clean-path reach is still unknown.\n",
    );
    md.push_str(
        "- `unsafe_coverage = computed` means source coverage JSON was supplied and executed source ranges were mapped onto root-crate unsafe sites.\n\n",
    );
}

fn append_summary(md: &mut String, report: &StudyReport) {
    md.push_str("## Summary\n\n");
    md.push_str("| Crate | Geiger | Miri | Fuzz |\n");
    md.push_str("|-------|--------|------|------|\n");
    for result in &report.crates {
        let geiger = result
            .geiger
            .as_ref()
            .map(geiger_summary)
            .unwrap_or_else(|| phase_summary_fallback(result, PhaseKind::Geiger));
        let miri = result
            .miri
            .as_ref()
            .map(|m| {
                if m.primary_run.ub_detected {
                    format!(
                        "{}: {}",
                        m.verdict,
                        m.primary_run
                            .ub_message
                            .as_deref()
                            .unwrap_or("?")
                            .chars()
                            .take(60)
                            .collect::<String>()
                    )
                } else {
                    m.verdict.to_string()
                }
            })
            .unwrap_or_else(|| phase_summary_fallback(result, PhaseKind::Miri));
        md.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            result.target.display_name(),
            geiger,
            miri,
            result.fuzz_summary()
        ));
    }
    md.push('\n');
}

fn geiger_summary(geiger: &GeigerResult) -> String {
    match geiger.root_package_result() {
        Some(root) => format!(
            "root {} total, {} deps",
            root.total_unsafe(),
            geiger.packages.iter().filter(|pkg| !pkg.is_root).count()
        ),
        None => format!("{} packages", geiger.packages.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{
        FileScanIssue, FindingKind, PatternCount, Severity, UnsafeFinding, UnsafePattern,
        UnsafeSite, UnsafeSiteUniverse, UnsafeSummary,
    };
    use std::path::PathBuf;

    #[test]
    fn markdown_includes_reliability_fields() {
        let strict = MiriRun {
            flags: "-Zmiri-symbolic-alignment-check -Zmiri-strict-provenance".into(),
            execution: ExecutionOutcome {
                success: false,
                exit_code: Some(1),
                duration_secs: 1.0,
                log_path: PathBuf::from("strict.log"),
                log_excerpt: Some("strict".into()),
            },
            tests_run: Some(1),
            tests_passed: Some(0),
            tests_failed: Some(1),
            ub_detected: true,
            ub_category: Some(MiriUbCategory::OutOfBounds),
            ub_message: Some("Undefined Behavior".into()),
            ub_location: Some("src/lib.rs:1:1".into()),
        };
        let baseline = MiriRun {
            flags: "-Zmiri-strict-provenance".into(),
            execution: ExecutionOutcome {
                success: true,
                exit_code: Some(0),
                duration_secs: 1.0,
                log_path: PathBuf::from("baseline.log"),
                log_excerpt: None,
            },
            tests_run: Some(1),
            tests_passed: Some(1),
            tests_failed: Some(0),
            ub_detected: false,
            ub_category: None,
            ub_message: None,
            ub_location: None,
        };
        let report = StudyReport {
            schema_version: REPORT_SCHEMA_VERSION,
            timestamp: "now".into(),
            crates: vec![CrateAuditResult {
                target: CrateTarget {
                    metadata: CrateMetadata {
                        name: "crate".into(),
                        version: "1.0.0".into(),
                    },
                    dir: PathBuf::from("."),
                },
                geiger: Some(GeigerResult {
                    mode: GeigerMode::DependencyAware,
                    root_package: "crate".into(),
                    invocation: CommandInvocation {
                        working_dir: PathBuf::from("."),
                        args: vec!["geiger".into(), "--output-format".into(), "Json".into()],
                    },
                    execution: ExecutionOutcome {
                        success: true,
                        exit_code: Some(0),
                        duration_secs: 1.0,
                        log_path: PathBuf::from("geiger.log"),
                        log_excerpt: None,
                    },
                    packages: vec![
                        GeigerPackageResult {
                            name: "crate".into(),
                            version: "1.0.0".into(),
                            source: None,
                            is_root: true,
                            used: GeigerMetrics {
                                exprs: CountPair { safe: 0, unsafe_: 2 },
                                ..GeigerMetrics::default()
                            },
                            unused: GeigerMetrics::default(),
                            forbids_unsafe: false,
                        },
                        GeigerPackageResult {
                            name: "dep".into(),
                            version: "0.2.0".into(),
                            source: Some("registry".into()),
                            is_root: false,
                            used: GeigerMetrics {
                                functions: CountPair { safe: 0, unsafe_: 1 },
                                ..GeigerMetrics::default()
                            },
                            unused: GeigerMetrics::default(),
                            forbids_unsafe: false,
                        },
                    ],
                    packages_without_metrics: vec!["missing_dep".into()],
                    used_but_not_scanned_files: vec![PathBuf::from("build.rs")],
                }),
                miri: Some(MiriResult {
                    scope: MiriScope::TargetedSmoke,
                    invocation: CommandInvocation {
                        working_dir: PathBuf::from("extensions_harness"),
                        args: vec![
                            "miri".into(),
                            "test".into(),
                            "--test".into(),
                            "api_smoke".into(),
                        ],
                    },
                    verdict: MiriVerdict::StrictOnlySuspectedFalsePositive,
                    triage_summary: Some(
                        "Strict Miri reported UB, but the baseline rerun completed without a UB signal."
                            .into(),
                    ),
                    primary_run: strict,
                    baseline_run: Some(baseline),
                }),
                fuzz: vec![FuzzTargetResult {
                    target_name: "target".into(),
                    scope: FuzzScope::ExistingHarness,
                    status: FuzzStatus::Error,
                    harness_dir: Some(PathBuf::from("fuzz_harnesses/demo")),
                    execution: Some(ExecutionOutcome {
                        success: false,
                        exit_code: Some(77),
                        duration_secs: 2.0,
                        log_path: PathBuf::from("fuzz.log"),
                        log_excerpt: Some("boom".into()),
                    }),
                    requested_time_budget_secs: 60,
                    budget_label: Some("baseline".into()),
                    environment_overrides: vec!["ASAN_OPTIONS=detect_leaks=0".into()],
                    total_runs: Some(10),
                    edges_covered: Some(4),
                    artifact_path: None,
                    reproducer_size_bytes: None,
                }],
                patterns: Some(UnsafeSummary {
                    crate_name: "crate".into(),
                    crate_version: "1.0.0".into(),
                    total_findings: 1,
                    risky_operation_findings: 0,
                    unsafe_block_findings: 0,
                    unsafe_declaration_findings: 1,
                    extern_item_findings: 0,
                    files_with_unsafe: 1,
                    files_scanned: 1,
                    files_failed_to_scan: 1,
                    scan_failures: vec![FileScanIssue {
                        path: PathBuf::from("src/broken.rs"),
                        error: "parse error".into(),
                    }],
                    patterns: vec![PatternCount {
                        pattern: UnsafePattern::OtherUnsafe,
                        count: 1,
                    }],
                    findings: vec![UnsafeFinding {
                        site_id: "crate:src/lib.rs:1:1:unsafe_fn_decl:other_unsafe".into(),
                        kind: FindingKind::UnsafeFnDecl,
                        pattern: UnsafePattern::OtherUnsafe,
                        file: PathBuf::from("src/lib.rs"),
                        line: 1,
                        column: 1,
                        end_line: 1,
                        end_column: 18,
                        snippet: "unsafe fn f() {}".into(),
                        severity: Severity::Info,
                        context: "f".into(),
                    }],
                    unsafe_sites: vec![UnsafeSite {
                        site_id: "crate:src/lib.rs:1:1:unsafe_fn_decl:other_unsafe".into(),
                        kind: FindingKind::UnsafeFnDecl,
                        pattern: UnsafePattern::OtherUnsafe,
                        file: PathBuf::from("src/lib.rs"),
                        line: 1,
                        column: 1,
                        end_line: 1,
                        end_column: 18,
                        snippet: "unsafe fn f() {}".into(),
                        severity: Severity::Info,
                        context: "f".into(),
                    }],
                    unsafe_site_universe: UnsafeSiteUniverse {
                        site_total: 1,
                        risky_operation_sites: 0,
                        unsafe_block_sites: 0,
                        unsafe_declaration_sites: 1,
                        extern_item_sites: 0,
                    },
                    risk_score: 1.0,
                }),
                unsafe_site_reach: None,
                unsafe_coverage: Some(UnsafeCoverageSummary {
                    state: UnsafeCoverageState::StaticUniverseOnly,
                    total_sites: 1,
                    reached_by_miri: None,
                    reached_by_fuzz: None,
                    reached_by_any: None,
                    triggered_by_miri: None,
                    triggered_by_fuzz: None,
                    triggered_by_any: None,
                    unmapped_triggered_by_miri: None,
                    unmapped_triggered_by_fuzz: None,
                    unreached: None,
                }),
                coverage_artifacts: None,
                exploration: None,
                phase_issues: Vec::new(),
            }],
        };

        let md = generate_markdown(&report);
        assert!(md.contains("dependency-aware"));
        assert!(md.contains("| crate | root 2 total, 1 deps |"));
        assert!(md.contains("| crate | targeted_smoke | STRICT-ONLY SUSPECTED FP | out_of_bounds | UB | CLEAN | 1 | YES | 2.0s |"));
        assert!(md.contains(
            "- **Invocation:** `cargo miri test --test api_smoke` in `extensions_harness`"
        ));
        assert!(md
            .contains("| target | existing_harness | ERROR | 77 | 60s | baseline | 10 | 4 | 2s |"));
        assert!(md.contains("`baseline` budget label"));
        assert!(md.contains("- **target harness dir:** `fuzz_harnesses/demo`"));
        assert!(md.contains("1 failed to scan"));
        assert!(md.contains("| src/broken.rs | parse error |"));
        assert!(md.contains("Unsafe site universe: 1 total"));
        assert!(md.contains("Dynamic unsafe coverage: `static_universe_only`"));
        assert!(md.contains("- **Miri linkage:** Miri executed at `targeted_smoke` scope"));
        assert!(md.contains(
            "- **Fuzz linkage:** Fuzz executed existing harness targets at target granularity: target [baseline] @ fuzz_harnesses/demo."
        ));
        assert!(md.contains("UB location text mentions hotspot file `src/lib.rs`."));
    }

    #[test]
    fn markdown_distinguishes_phase_failures_from_skips() {
        let report = StudyReport {
            schema_version: REPORT_SCHEMA_VERSION,
            timestamp: "now".into(),
            crates: vec![CrateAuditResult {
                target: CrateTarget {
                    metadata: CrateMetadata {
                        name: "broken".into(),
                        version: "0.1.0".into(),
                    },
                    dir: PathBuf::from("."),
                },
                geiger: None,
                miri: None,
                fuzz: Vec::new(),
                patterns: None,
                unsafe_site_reach: None,
                unsafe_coverage: None,
                coverage_artifacts: None,
                exploration: None,
                phase_issues: vec![
                    PhaseIssue {
                        phase: PhaseKind::Geiger,
                        message: "geiger exploded".into(),
                    },
                    PhaseIssue {
                        phase: PhaseKind::Fuzz,
                        message: "cargo fuzz missing".into(),
                    },
                ],
            }],
        };

        let md = generate_markdown(&report);
        assert!(md.contains("| broken | ERROR | SKIP | ERROR |"));
        assert!(md.contains("### Geiger failures"));
        assert!(md.contains("geiger exploded"));
        assert!(md.contains("Fuzz failed for this crate: cargo fuzz missing."));
        assert!(md.contains("Pattern analysis was skipped"));
    }
}
