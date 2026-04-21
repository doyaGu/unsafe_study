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
    append_interpretation_guide(&mut md);

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
        md.push_str("| Crate | Scope | Verdict | Category | Strict | Baseline | Tests | UB | Duration |\n");
        md.push_str("|-------|-------|---------|----------|--------|----------|-------|----|----------|\n");
        for r in &miri_crates {
            let m = r.miri.as_ref().unwrap();
            let strict_str = run_status(&m.strict);
            let baseline_str = m
                .baseline
                .as_ref()
                .map(run_status)
                .unwrap_or_else(|| "-".into());
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {:.1}s |\n",
                r.target.name,
                m.scope,
                m.verdict,
                m.ub_category
                    .map(|category| category.to_string())
                    .unwrap_or_else(|| "-".into()),
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
            md.push_str(&format!("### {} Scope\n\n", r.target.name));
            md.push_str(&format!("- **Scope:** `{}`\n", m.scope));
            md.push_str(&format!("- **Interpretation:** {}\n\n", miri_scope_note(m)));
            if let Some(summary) = &m.triage_summary {
                md.push_str(&format!("### {} Triage Summary\n\n", r.target.name));
                md.push_str(&format!("- {}\n\n", summary));
            }
            if m.ub_detected {
                md.push_str(&format!("### {} UB Detail\n\n", r.target.name));
                if let Some(category) = m.ub_category {
                    md.push_str(&format!("- **Category:** `{}`\n", category));
                }
                if let Some(msg) = &m.ub_message {
                    md.push_str(&format!("- **Message:** {}\n", msg));
                }
                if let Some(loc) = &m.ub_location {
                    md.push_str(&format!("- **Location:** `{}`\n", loc));
                }
                md.push_str(&format!(
                    "- **Strict category:** `{}`\n",
                    m.strict
                        .ub_category
                        .map(|category| category.to_string())
                        .unwrap_or_else(|| "-".into())
                ));
                md.push_str(&format!(
                    "- **Strict log:** `{}`\n",
                    m.strict.log_path.display()
                ));
                if let Some(baseline) = &m.baseline {
                    md.push_str(&format!(
                        "- **Baseline category:** `{}`\n",
                        baseline
                            .ub_category
                            .map(|category| category.to_string())
                            .unwrap_or_else(|| "-".into())
                    ));
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
                md.push_str(&format!(
                    "- **Scope:** `{}`\n- **Interpretation:** {}\n- **Status meaning:** {}\n\n",
                    r.fuzz[0].scope,
                    fuzz_scope_note(&r.fuzz[0]),
                    fuzz_status_note(&r.fuzz[0])
                ));
                continue;
            }
            md.push_str("| Target | Scope | Status | Success | Exit | Budget | Runs | Edges | Duration |\n");
            md.push_str("|--------|-------|--------|---------|------|--------|------|-------|----------|\n");
            for f in &r.fuzz {
                md.push_str(&format!(
                    "| {} | {} | {} | {} | {} | {}s | {} | {} | {}s |\n",
                    f.target_name,
                    f.scope,
                    f.status,
                    f.success,
                    f.exit_code
                        .map(|code| code.to_string())
                        .unwrap_or_else(|| "-".into()),
                    f.requested_time_budget_secs,
                    f.total_runs.map(|n| n.to_string()).unwrap_or("-".into()),
                    f.edges_covered
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "-".into()),
                    f.duration_secs,
                ));
            }
            for f in &r.fuzz {
                md.push_str(&format!("- **{} scope:** `{}`\n", f.target_name, f.scope));
                md.push_str(&format!(
                    "- **{} interpretation:** {}\n",
                    f.target_name,
                    fuzz_scope_note(f)
                ));
                md.push_str(&format!(
                    "- **{} status meaning:** {}\n",
                    f.target_name,
                    fuzz_status_note(f)
                ));
                if let Some(p) = &f.artifact_path {
                    md.push_str(&format!(
                        "- **{}**: reproducer `{}` ({} bytes)\n",
                        f.target_name,
                        p.display(),
                        f.reproducer_size_bytes.unwrap_or(0),
                    ));
                }
                if matches!(
                    f.status,
                    FuzzStatus::BuildFailed
                        | FuzzStatus::Panic
                        | FuzzStatus::Oom
                        | FuzzStatus::Timeout
                        | FuzzStatus::Error
                ) {
                    if let Some(excerpt) = &f.log_excerpt {
                        md.push_str(&format!("- **{} excerpt:** `{}`\n", f.target_name, excerpt));
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
                pa.files_scanned, pa.files_with_unsafe, pa.total_findings,
            ));
            md.push_str(&format!(
                "- Declarations: {} unsafe fn/method, {} unsafe impl\n",
                pa.total_unsafe_fns, pa.total_unsafe_impls,
            ));
            md.push_str(
                "- Interpretation: finding counts are heuristic audit artifacts; `total_unsafe_exprs` remains a legacy compatibility field in JSON.\n",
            );
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

    append_cross_phase_linkage(&mut md, &report.crates);

    md
}

pub fn generate_json(report: &StudyReport) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

fn append_interpretation_guide(md: &mut String) {
    md.push_str("## Interpretation Guide\n\n");
    md.push_str("- Geiger counts are a syntactic proxy for local `unsafe` surface area.\n");
    md.push_str("- Miri results apply only to the paths exercised by the recorded test scope.\n");
    md.push_str("- Fuzz results apply only to the recorded harness scope and time budget.\n");
    md.push_str("- Pattern findings are heuristic structural classifications for audit prioritization.\n\n");
}

fn append_cross_phase_linkage(md: &mut String, crates: &[CrateAuditResult]) {
    if crates.is_empty() {
        return;
    }

    md.push_str("## Cross-Phase Linkage\n\n");
    md.push_str(
        "This section reports hotspot summaries from static findings and coarse dynamic linkage only. \
It does not claim file-level coverage unless a note is explicitly labeled best-effort and log-derived.\n\n",
    );

    for result in crates {
        md.push_str(&format!("### {}\n\n", result.target.name));

        if let Some(patterns) = &result.pattern_analysis {
            let hotspots = hotspot_summaries(patterns);
            if hotspots.is_empty() {
                md.push_str("- No static hotspot files were identified from pattern findings.\n");
            } else {
                md.push_str("| Hotspot File | Findings | Top Patterns |\n");
                md.push_str("|--------------|----------|--------------|\n");
                for hotspot in hotspots {
                    md.push_str(&format!(
                        "| {} | {} | {} |\n",
                        hotspot.file,
                        hotspot.finding_count,
                        hotspot.top_patterns.join(", ")
                    ));
                }
            }
        } else {
            md.push_str("- Pattern analysis was skipped, so no hotspot summary is available.\n");
        }

        md.push_str(&format!("- **Miri linkage:** {}\n", miri_linkage_note(result)));
        md.push_str(&format!("- **Fuzz linkage:** {}\n", fuzz_linkage_note(result)));

        if let Some(best_effort) = best_effort_miri_hotspot_match(result) {
            md.push_str(&format!(
                "- **Best-effort hotspot hint:** UB location text mentions hotspot file `{}`.\n",
                best_effort
            ));
        }
        md.push_str("\n");
    }
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

fn miri_scope_note(result: &MiriResult) -> String {
    format!(
        "No result from this phase should be read beyond `{}` scope; clean means no UB was observed on the exercised test paths.",
        result.scope
    )
}

fn fuzz_scope_note(result: &FuzzTargetResult) -> String {
    match result.scope {
        FuzzScope::ExistingHarness => format!(
            "This result is limited to the existing fuzz harness and a {}s budget.",
            result.requested_time_budget_secs
        ),
        FuzzScope::DiscoveryOnly => {
            "Only fuzz target discovery was attempted; no target execution coverage is implied."
                .into()
        }
        FuzzScope::NoneAvailable => {
            "No fuzz harness was available, so this phase provides no execution evidence.".into()
        }
    }
}

fn fuzz_status_note(result: &FuzzTargetResult) -> &'static str {
    match result.status {
        FuzzStatus::Clean => "No visible failure was observed under the recorded harness and budget.",
        FuzzStatus::Panic => "The harness observed a panic or crash-like termination under fuzz input.",
        FuzzStatus::Oom => "The run exhausted memory under the current fuzz setup.",
        FuzzStatus::Timeout => "The run hit a timeout-like condition under the current fuzz setup.",
        FuzzStatus::BuildFailed => "The fuzz target did not build, so this phase produced no execution evidence for that target.",
        FuzzStatus::NoFuzzDir => "The crate does not contain a local fuzz directory, so no fuzz target was available to run.",
        FuzzStatus::NoTargets => "A fuzz directory exists, but no runnable fuzz target was discovered.",
        FuzzStatus::Error => "The fuzz command failed without a cleaner classification; inspect the excerpt and log for details.",
    }
}

#[derive(Debug)]
struct HotspotSummary {
    file: String,
    finding_count: usize,
    top_patterns: Vec<String>,
}

fn hotspot_summaries(summary: &crate::analyzer::UnsafeSummary) -> Vec<HotspotSummary> {
    let mut per_file: std::collections::BTreeMap<String, Vec<&crate::analyzer::UnsafeFinding>> =
        std::collections::BTreeMap::new();
    for finding in &summary.findings {
        let file = finding.file.display().to_string();
        per_file.entry(file).or_default().push(finding);
    }

    let mut hotspots = per_file
        .into_iter()
        .map(|(file, findings)| {
            let mut pattern_counts = std::collections::BTreeMap::<String, usize>::new();
            for finding in &findings {
                *pattern_counts
                    .entry(finding.pattern.to_string())
                    .or_insert(0) += 1;
            }
            let mut top_patterns = pattern_counts.into_iter().collect::<Vec<_>>();
            top_patterns.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

            HotspotSummary {
                file,
                finding_count: findings.len(),
                top_patterns: top_patterns
                    .into_iter()
                    .take(3)
                    .map(|(pattern, count)| format!("{pattern} ({count})"))
                    .collect(),
            }
        })
        .collect::<Vec<_>>();

    hotspots.sort_by(|a, b| {
        b.finding_count
            .cmp(&a.finding_count)
            .then_with(|| a.file.cmp(&b.file))
    });
    hotspots.truncate(3);
    hotspots
}

fn miri_linkage_note(result: &CrateAuditResult) -> String {
    match &result.miri {
        Some(miri) => format!(
            "Miri executed at `{}` scope for this crate; this is crate-level evidence, not hotspot coverage.",
            miri.scope
        ),
        None => "Miri was skipped or unavailable for this crate.".into(),
    }
}

fn fuzz_linkage_note(result: &CrateAuditResult) -> String {
    if result.fuzz.is_empty() {
        return "Fuzz was skipped for this crate.".into();
    }

    if result.fuzz.len() == 1 && result.fuzz[0].target_name == "(none)" {
        return format!(
            "No runnable fuzz target executed (`{}` / `{}`).",
            result.fuzz[0].scope, result.fuzz[0].status
        );
    }

    let targets = result
        .fuzz
        .iter()
        .map(|f| f.target_name.clone())
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "Fuzz executed existing harness targets at target granularity: {}.",
        targets
    )
}

fn best_effort_miri_hotspot_match(result: &CrateAuditResult) -> Option<String> {
    let summary = result.pattern_analysis.as_ref()?;
    let location = result.miri.as_ref()?.ub_location.as_ref()?;
    for hotspot in hotspot_summaries(summary) {
        let filename = std::path::Path::new(&hotspot.file)
            .file_name()
            .and_then(|name| name.to_str())?;
        if location.contains(filename) {
            return Some(hotspot.file);
        }
    }
    None
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
            ub_category: Some(MiriUbCategory::OutOfBounds),
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
            ub_category: None,
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
                    scope: MiriScope::FullSuite,
                    verdict: MiriVerdict::StrictOnlySuspectedFalsePositive,
                    triage_summary: Some(
                        "Strict Miri reported UB, but the baseline rerun completed without a UB signal."
                            .into(),
                    ),
                    passed: strict.passed,
                    tests_run: strict.tests_run,
                    tests_passed: strict.tests_passed,
                    tests_failed: strict.tests_failed,
                    ub_detected: strict.ub_detected,
                    ub_category: Some(MiriUbCategory::OutOfBounds),
                    ub_message: strict.ub_message.clone(),
                    ub_location: strict.ub_location.clone(),
                    log_path: strict.log_path.clone(),
                    duration_secs: strict.duration_secs,
                    strict,
                    baseline: Some(baseline),
                }),
                fuzz: vec![FuzzTargetResult {
                    target_name: "target".into(),
                    scope: FuzzScope::ExistingHarness,
                    status: FuzzStatus::Error,
                    success: false,
                    exit_code: Some(77),
                    requested_time_budget_secs: 60,
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
                    total_findings: 1,
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

        assert!(md.contains("## Interpretation Guide"));
        assert!(md.contains("| crate | full_suite | STRICT-ONLY SUSPECTED FP | out_of_bounds |"));
        assert!(md.contains(
            "No result from this phase should be read beyond `full_suite` scope"
        ));
        assert!(md.contains("Strict Miri reported UB, but the baseline rerun completed without a UB signal."));
        assert!(md.contains("- **Category:** `out_of_bounds`"));
        assert!(md.contains("STRICT-ONLY SUSPECTED FP"));
        assert!(md.contains(
            "| target | existing_harness | ERROR | false | 77 | 60s | 10 | 4 | 2s |"
        ));
        assert!(md.contains("The fuzz command failed without a cleaner classification"));
        assert!(md.contains("- **target excerpt:** `boom`"));
        assert!(md.contains("1 unsafe fn/method, 1 unsafe impl"));
        assert!(md.contains("| unsafe_fn_decl | 1 |"));
        assert!(md.contains("## Cross-Phase Linkage"));
        assert!(md.contains("| Hotspot File | Findings | Top Patterns |"));
        assert!(md.contains("- **Miri linkage:** Miri executed at `full_suite` scope"));
        assert!(md.contains("- **Fuzz linkage:** Fuzz executed existing harness targets at target granularity: target."));
        assert!(md.contains("UB location text mentions hotspot file `src/lib.rs`."));
    }
}
