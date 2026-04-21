use crate::models::*;

// =========================================================================
// Report Generator — Markdown + JSON
// =========================================================================

pub fn generate_markdown(report: &StudyReport) -> String {
    let mut md = String::new();

    md.push_str("# Unsafe Audit Report\n\n");
    md.push_str(&format!("- Generated: {}\n", report.timestamp));
    md.push_str(&format!("- Crates: {}\n", report.crates.len()));
    md.push_str("\n");

    // Summary table
    md.push_str("## Summary\n\n");
    md.push_str("| Crate | Geiger (unsafe exprs) | Miri | Fuzz |\n");
    md.push_str("|-------|----------------------|------|------|\n");

    for r in &report.crates {
        let g = r
            .geiger
            .as_ref()
            .map(|g| {
                if g.forbids_unsafe {
                    "forbids_unsafe".into()
                } else {
                    format!(
                        "{} used, {} unused",
                        g.used.exprs.unsafe_, g.unused.exprs.unsafe_
                    )
                }
            })
            .unwrap_or_else(|| "SKIP".into());

        let m = r
            .miri
            .as_ref()
            .map(|m| {
                if m.ub_detected {
                    format!(
                        "{}: {}",
                        m.verdict,
                        m.ub_message
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
            .unwrap_or_else(|| "SKIP".into());

        md.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            r.target.name,
            g,
            m,
            r.fuzz_summary()
        ));
    }
    md.push_str("\n");

    // Geiger detail
    let geiger_crates: Vec<_> = report
        .crates
        .iter()
        .filter(|c| c.geiger.is_some())
        .collect();
    if !geiger_crates.is_empty() {
        md.push_str("## Phase 1: Geiger\n\n");
        md.push_str("| Crate | fn/expr/impl/trait/method | Total | Forbids |\n");
        md.push_str("|-------|--------------------------|-------|---------|\n");
        for r in &geiger_crates {
            let g = r.geiger.as_ref().unwrap();
            md.push_str(&format!(
                "| {} | {}/{}/{}/{}/{} | {} | {} |\n",
                g.crate_name,
                g.used.functions.unsafe_,
                g.used.exprs.unsafe_,
                g.used.item_impls.unsafe_,
                g.used.item_traits.unsafe_,
                g.used.methods.unsafe_,
                g.used.total_unsafe(),
                g.forbids_unsafe,
            ));
        }
        md.push_str("\n");
    }

    // Miri detail
    let miri_crates: Vec<_> = report.crates.iter().filter(|c| c.miri.is_some()).collect();
    if !miri_crates.is_empty() {
        md.push_str("## Phase 2: Miri\n\n");
        md.push_str("| Crate | Verdict | Strict | Baseline | Tests | UB | Duration |\n");
        md.push_str("|-------|---------|--------|----------|-------|----|----------|\n");
        for r in &miri_crates {
            let m = r.miri.as_ref().unwrap();
            let strict_str = run_status(&m.strict);
            let baseline_str = m
                .baseline
                .as_ref()
                .map(run_status)
                .unwrap_or_else(|| "-".into());
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {:.1}s |\n",
                r.target.name,
                m.verdict,
                strict_str,
                baseline_str,
                m.tests_run.map(|n| n.to_string()).unwrap_or("-".into()),
                if m.ub_detected { "YES" } else { "no" },
                m.duration_secs,
            ));
        }
        md.push_str("\n");
        for r in &miri_crates {
            let m = r.miri.as_ref().unwrap();
            if m.ub_detected {
                md.push_str(&format!("### {} UB Detail\n\n", r.target.name));
                if let Some(msg) = &m.ub_message {
                    md.push_str(&format!("- **Message:** {}\n", msg));
                }
                if let Some(loc) = &m.ub_location {
                    md.push_str(&format!("- **Location:** `{}`\n", loc));
                }
                md.push_str(&format!(
                    "- **Strict log:** `{}`\n",
                    m.strict.log_path.display()
                ));
                if let Some(baseline) = &m.baseline {
                    md.push_str(&format!(
                        "- **Baseline log:** `{}`\n",
                        baseline.log_path.display()
                    ));
                }
                md.push_str("\n");
            }
        }
    }

    // Fuzz detail
    let fuzz_crates: Vec<_> = report
        .crates
        .iter()
        .filter(|c| !c.fuzz.is_empty())
        .collect();
    if !fuzz_crates.is_empty() {
        md.push_str("## Phase 3: Fuzz\n\n");
        for r in &fuzz_crates {
            md.push_str(&format!("### {}\n\n", r.target.name));
            if r.fuzz.len() == 1 && r.fuzz[0].target_name == "(none)" {
                md.push_str(&format!("{}\n\n", r.fuzz[0].status));
                continue;
            }
            md.push_str("| Target | Status | Success | Exit | Runs | Edges | Duration |\n");
            md.push_str("|--------|--------|---------|------|------|-------|----------|\n");
            for f in &r.fuzz {
                md.push_str(&format!(
                    "| {} | {} | {} | {} | {} | {} | {}s |\n",
                    f.target_name,
                    f.status,
                    f.success,
                    f.exit_code
                        .map(|code| code.to_string())
                        .unwrap_or_else(|| "-".into()),
                    f.total_runs.map(|n| n.to_string()).unwrap_or("-".into()),
                    f.edges_covered
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "-".into()),
                    f.duration_secs,
                ));
            }
            for f in &r.fuzz {
                if let Some(p) = &f.artifact_path {
                    md.push_str(&format!(
                        "- **{}**: reproducer `{}` ({} bytes)\n",
                        f.target_name,
                        p.display(),
                        f.reproducer_size_bytes.unwrap_or(0),
                    ));
                }
                if f.status == FuzzStatus::Error {
                    if let Some(excerpt) = &f.log_excerpt {
                        md.push_str(&format!("- **{} error:** `{}`\n", f.target_name, excerpt));
                    }
                }
            }
            md.push_str("\n");
        }
    }

    // Pattern analysis
    let pattern_crates: Vec<_> = report
        .crates
        .iter()
        .filter(|c| c.pattern_analysis.is_some())
        .collect();
    if !pattern_crates.is_empty() {
        md.push_str("## Phase 4: Pattern Analysis\n\n");
        for r in &pattern_crates {
            let pa = r.pattern_analysis.as_ref().unwrap();
            md.push_str(&format!(
                "### {} (risk: {:.1})\n\n",
                r.target.name, pa.risk_score
            ));
            md.push_str(&format!(
                "- Files: {} scanned, {} with findings, {} findings\n",
                pa.files_scanned, pa.files_with_unsafe, pa.total_unsafe_exprs,
            ));
            md.push_str(&format!(
                "- Declarations: {} unsafe fn/method, {} unsafe impl\n",
                pa.total_unsafe_fns, pa.total_unsafe_impls,
            ));
            if !pa.patterns.is_empty() {
                md.push_str("\n| Pattern | Count |\n|---------|-------|\n");
                for pc in &pa.patterns {
                    md.push_str(&format!("| {} | {} |\n", pc.pattern, pc.count));
                }
            }
            let kind_counts = finding_kind_counts(&pa.findings);
            if !kind_counts.is_empty() {
                md.push_str("\n| Finding Kind | Count |\n|--------------|-------|\n");
                for (kind, count) in kind_counts {
                    md.push_str(&format!("| {} | {} |\n", kind, count));
                }
            }
            md.push_str("\n");
        }
    }

    md
}

pub fn generate_json(report: &StudyReport) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

fn run_status(run: &MiriRun) -> String {
    if run.passed {
        "CLEAN".into()
    } else if run.ub_detected {
        "UB".into()
    } else {
        "FAIL".into()
    }
}

fn finding_kind_counts(findings: &[crate::analyzer::UnsafeFinding]) -> Vec<(String, usize)> {
    let mut counts = std::collections::BTreeMap::new();
    for finding in findings {
        *counts.entry(finding.kind.to_string()).or_insert(0) += 1;
    }
    counts.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{
        FindingKind, PatternCount, Severity, UnsafeFinding, UnsafePattern, UnsafeSummary,
    };
    use std::path::PathBuf;

    #[test]
    fn markdown_includes_reliability_fields() {
        let strict = MiriRun {
            flags: "-Zmiri-symbolic-alignment-check -Zmiri-strict-provenance".into(),
            passed: false,
            tests_run: Some(1),
            tests_passed: Some(0),
            tests_failed: Some(1),
            ub_detected: true,
            ub_message: Some("Undefined Behavior".into()),
            ub_location: Some("src/lib.rs:1:1".into()),
            log_path: PathBuf::from("strict.log"),
            duration_secs: 1.0,
        };
        let baseline = MiriRun {
            flags: "-Zmiri-strict-provenance".into(),
            passed: true,
            tests_run: Some(1),
            tests_passed: Some(1),
            tests_failed: Some(0),
            ub_detected: false,
            ub_message: None,
            ub_location: None,
            log_path: PathBuf::from("baseline.log"),
            duration_secs: 1.0,
        };
        let report = StudyReport {
            timestamp: "now".into(),
            crates: vec![CrateAuditResult {
                target: CrateTarget {
                    name: "crate".into(),
                    dir: PathBuf::from("."),
                },
                geiger: None,
                miri: Some(MiriResult {
                    verdict: MiriVerdict::StrictOnlySuspectedFalsePositive,
                    passed: strict.passed,
                    tests_run: strict.tests_run,
                    tests_passed: strict.tests_passed,
                    tests_failed: strict.tests_failed,
                    ub_detected: strict.ub_detected,
                    ub_message: strict.ub_message.clone(),
                    ub_location: strict.ub_location.clone(),
                    log_path: strict.log_path.clone(),
                    duration_secs: strict.duration_secs,
                    strict,
                    baseline: Some(baseline),
                }),
                fuzz: vec![FuzzTargetResult {
                    target_name: "target".into(),
                    status: FuzzStatus::Error,
                    success: false,
                    exit_code: Some(77),
                    total_runs: Some(10),
                    edges_covered: Some(4),
                    duration_secs: 2,
                    artifact_path: None,
                    reproducer_size_bytes: None,
                    log_excerpt: Some("boom".into()),
                }],
                pattern_analysis: Some(UnsafeSummary {
                    crate_name: "crate".into(),
                    crate_version: "1.0.0".into(),
                    total_unsafe_exprs: 1,
                    total_unsafe_fns: 1,
                    total_unsafe_impls: 1,
                    files_with_unsafe: 1,
                    files_scanned: 1,
                    patterns: vec![PatternCount {
                        pattern: UnsafePattern::OtherUnsafe,
                        count: 1,
                    }],
                    findings: vec![UnsafeFinding {
                        kind: FindingKind::UnsafeFnDecl,
                        pattern: UnsafePattern::OtherUnsafe,
                        file: PathBuf::from("src/lib.rs"),
                        line: 1,
                        column: 1,
                        snippet: "unsafe fn f() {}".into(),
                        severity: Severity::Info,
                        context: "f".into(),
                    }],
                    risk_score: 1.0,
                }),
            }],
        };

        let md = generate_markdown(&report);

        assert!(md.contains("STRICT-ONLY SUSPECTED FP"));
        assert!(md.contains("| target | ERROR | false | 77 | 10 | 4 | 2s |"));
        assert!(md.contains("1 unsafe fn/method, 1 unsafe impl"));
        assert!(md.contains("| unsafe_fn_decl | 1 |"));
    }
}
