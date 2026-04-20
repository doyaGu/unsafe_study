use crate::models::*;

// =========================================================================
// Report Generator -- Markdown + JSON
// =========================================================================

/// Generate a Markdown report from the study results.
pub fn generate_markdown(report: &StudyReport) -> String {
    let mut md = String::new();

    md.push_str("# Unsafe Study Report\n\n");
    md.push_str(&format!("- Generated: {}\n", report.timestamp));
    md.push_str(&format!("- Crates: {}\n", report.crates.len()));
    md.push_str("\n");

    // Summary table
    md.push_str("## Summary\n\n");
    md.push_str("| Crate | Tier | Geiger (used unsafe exprs) | Miri | Fuzz |\n");
    md.push_str("|-------|------|---------------------------|------|------|\n");

    for result in &report.crates {
        let tier_str = match result.target.tier {
            CrateTier::Tier1 => "1",
            CrateTier::Tier2 => "2",
        };
        let geiger_str = result.geiger
            .as_ref()
            .map(|g| {
                if g.forbids_unsafe {
                    "forbids_unsafe".to_string()
                } else {
                    format!("{} used, {} unused",
                        g.used.exprs.unsafe_,
                        g.unused.exprs.unsafe_)
                }
            })
            .unwrap_or_else(|| "SKIP".into());

        let miri_str = result.miri
            .as_ref()
            .map(|m| {
                if m.passed {
                    "CLEAN".to_string()
                } else if m.ub_detected {
                    format!("UB: {}", m.ub_message.as_deref().unwrap_or("?").chars().take(60).collect::<String>())
                } else {
                    "FAILED".to_string()
                }
            })
            .unwrap_or_else(|| "SKIP".into());

        let fuzz_str = result.fuzz_summary();

        md.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            result.target.name, tier_str, geiger_str, miri_str, fuzz_str,
        ));
    }
    md.push_str("\n");

    // Phase 1: Geiger detail
    let geiger_crates: Vec<_> = report.crates.iter().filter(|c| c.geiger.is_some()).collect();
    if !geiger_crates.is_empty() {
        md.push_str("## Phase 1: Geiger Hotspot Mining\n\n");
        md.push_str("| Crate | Used (fn/expr/impl/trait/method) | Unsafe total | Forbids unsafe |\n");
        md.push_str("|-------|-----------------------------------|-------------|----------------|\n");
        for result in &geiger_crates {
            let g = result.geiger.as_ref().unwrap();
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

    // Phase 2: Miri detail
    let miri_crates: Vec<_> = report.crates.iter().filter(|c| c.miri.is_some()).collect();
    if !miri_crates.is_empty() {
        md.push_str("## Phase 2: Miri UB Detection\n\n");
        md.push_str("MIRIFLAGS: `-Zmiri-symbolic-alignment-check -Zmiri-strict-provenance`\n\n");
        md.push_str("| Crate | Mode | Result | Tests | UB | Duration |\n");
        md.push_str("|-------|------|--------|-------|----|----------|\n");
        for result in &miri_crates {
            let m = result.miri.as_ref().unwrap();
            let mode_str = match &m.mode {
                MiriMode::Direct => "direct".to_string(),
                MiriMode::Harness { test_file, .. } => format!("harness ({})", test_file),
            };
            let result_str = if m.passed { "CLEAN" } else if m.ub_detected { "UB" } else { "FAIL" };
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {:.1}s |\n",
                result.target.name,
                mode_str,
                result_str,
                m.tests_run.map(|n| n.to_string()).unwrap_or("-".into()),
                if m.ub_detected { "YES" } else { "no" },
                m.duration_secs,
            ));
        }
        md.push_str("\n");

        // UB details
        for result in &miri_crates {
            let m = result.miri.as_ref().unwrap();
            if m.ub_detected {
                md.push_str(&format!("### {} -- UB Detail\n\n", result.target.name));
                if let Some(msg) = &m.ub_message {
                    md.push_str(&format!("**Message:** {}\n", msg));
                }
                if let Some(loc) = &m.ub_location {
                    md.push_str(&format!("**Location:** `{}`\n", loc));
                }
                md.push_str(&format!("**Log:** `{}`\n\n", m.log_path.display()));
            }
        }
    }

    // Phase 3: Fuzz detail
    let fuzz_crates: Vec<_> = report.crates.iter().filter(|c| !c.fuzz.is_empty()).collect();
    if !fuzz_crates.is_empty() {
        md.push_str("## Phase 3: Fuzzing\n\n");
        for result in &fuzz_crates {
            md.push_str(&format!("### {}\n\n", result.target.name));
            if result.fuzz.len() == 1 && result.fuzz[0].target_name == "(none)" {
                md.push_str(&format!("{}\n\n", result.fuzz[0].status));
                continue;
            }
            md.push_str("| Target | Status | Runs | Duration |\n");
            md.push_str("|--------|--------|------|----------|\n");
            for f in &result.fuzz {
                md.push_str(&format!(
                    "| {} | {} | {} | {}s |\n",
                    f.target_name,
                    f.status,
                    f.total_runs.map(|n| n.to_string()).unwrap_or("-".into()),
                    f.duration_secs,
                ));
            }
            // Artifact details
            for f in &result.fuzz {
                if f.artifact_path.is_some() {
                    md.push_str(&format!(
                        "- **{}**: reproducer at `{}` ({} bytes)\n",
                        f.target_name,
                        f.artifact_path.as_ref().unwrap().display(),
                        f.reproducer_size_bytes.unwrap_or(0),
                    ));
                }
            }
            md.push_str("\n");
        }
    }

    // Phase 4: Pattern analysis (optional)
    let pattern_crates: Vec<_> = report.crates.iter().filter(|c| c.pattern_analysis.is_some()).collect();
    if !pattern_crates.is_empty() {
        md.push_str("## Phase 4: Unsafe Pattern Classification\n\n");
        for result in &pattern_crates {
            let pa = result.pattern_analysis.as_ref().unwrap();
            md.push_str(&format!("### {} -- Risk Score: {:.1}\n\n", result.target.name, pa.risk_score));
            md.push_str(&format!(
                "- Files scanned: {} | Files with unsafe: {} | Unsafe expressions: {}\n",
                pa.files_scanned, pa.files_with_unsafe, pa.total_unsafe_exprs,
            ));
            if !pa.patterns.is_empty() {
                md.push_str("\n| Pattern | Count |\n|---------|-------|\n");
                for pc in &pa.patterns {
                    md.push_str(&format!("| {} | {} |\n", pc.pattern, pc.count));
                }
            }
            md.push_str("\n");
        }
    }

    md
}

/// Generate a JSON report.
pub fn generate_json(report: &StudyReport) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}
