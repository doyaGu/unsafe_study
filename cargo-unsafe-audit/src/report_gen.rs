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
        let g = r.geiger.as_ref().map(|g| {
            if g.forbids_unsafe {
                "forbids_unsafe".into()
            } else {
                format!("{} used, {} unused", g.used.exprs.unsafe_, g.unused.exprs.unsafe_)
            }
        }).unwrap_or_else(|| "SKIP".into());

        let m = r.miri.as_ref().map(|m| {
            if m.passed {
                "CLEAN".into()
            } else if m.ub_detected {
                format!("UB: {}", m.ub_message.as_deref().unwrap_or("?").chars().take(60).collect::<String>())
            } else {
                "FAILED".into()
            }
        }).unwrap_or_else(|| "SKIP".into());

        md.push_str(&format!("| {} | {} | {} | {} |\n", r.target.name, g, m, r.fuzz_summary()));
    }
    md.push_str("\n");

    // Geiger detail
    let geiger_crates: Vec<_> = report.crates.iter().filter(|c| c.geiger.is_some()).collect();
    if !geiger_crates.is_empty() {
        md.push_str("## Phase 1: Geiger\n\n");
        md.push_str("| Crate | fn/expr/impl/trait/method | Total | Forbids |\n");
        md.push_str("|-------|--------------------------|-------|---------|\n");
        for r in &geiger_crates {
            let g = r.geiger.as_ref().unwrap();
            md.push_str(&format!(
                "| {} | {}/{}/{}/{}/{} | {} | {} |\n",
                g.crate_name,
                g.used.functions.unsafe_, g.used.exprs.unsafe_,
                g.used.item_impls.unsafe_, g.used.item_traits.unsafe_,
                g.used.methods.unsafe_,
                g.used.total_unsafe(), g.forbids_unsafe,
            ));
        }
        md.push_str("\n");
    }

    // Miri detail
    let miri_crates: Vec<_> = report.crates.iter().filter(|c| c.miri.is_some()).collect();
    if !miri_crates.is_empty() {
        md.push_str("## Phase 2: Miri\n\n");
        md.push_str("| Crate | Result | Tests | UB | Duration |\n");
        md.push_str("|-------|--------|-------|----|----------|\n");
        for r in &miri_crates {
            let m = r.miri.as_ref().unwrap();
            let result_str = if m.passed { "CLEAN" } else if m.ub_detected { "UB" } else { "FAIL" };
            md.push_str(&format!(
                "| {} | {} | {} | {} | {:.1}s |\n",
                r.target.name, result_str,
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
                md.push_str(&format!("- **Log:** `{}`\n\n", m.log_path.display()));
            }
        }
    }

    // Fuzz detail
    let fuzz_crates: Vec<_> = report.crates.iter().filter(|c| !c.fuzz.is_empty()).collect();
    if !fuzz_crates.is_empty() {
        md.push_str("## Phase 3: Fuzz\n\n");
        for r in &fuzz_crates {
            md.push_str(&format!("### {}\n\n", r.target.name));
            if r.fuzz.len() == 1 && r.fuzz[0].target_name == "(none)" {
                md.push_str(&format!("{}\n\n", r.fuzz[0].status));
                continue;
            }
            md.push_str("| Target | Status | Runs | Duration |\n");
            md.push_str("|--------|--------|------|----------|\n");
            for f in &r.fuzz {
                md.push_str(&format!(
                    "| {} | {} | {} | {}s |\n",
                    f.target_name, f.status,
                    f.total_runs.map(|n| n.to_string()).unwrap_or("-".into()),
                    f.duration_secs,
                ));
            }
            for f in &r.fuzz {
                if let Some(p) = &f.artifact_path {
                    md.push_str(&format!(
                        "- **{}**: reproducer `{}` ({} bytes)\n",
                        f.target_name, p.display(), f.reproducer_size_bytes.unwrap_or(0),
                    ));
                }
            }
            md.push_str("\n");
        }
    }

    // Pattern analysis
    let pattern_crates: Vec<_> = report.crates.iter().filter(|c| c.pattern_analysis.is_some()).collect();
    if !pattern_crates.is_empty() {
        md.push_str("## Phase 4: Pattern Analysis\n\n");
        for r in &pattern_crates {
            let pa = r.pattern_analysis.as_ref().unwrap();
            md.push_str(&format!("### {} (risk: {:.1})\n\n", r.target.name, pa.risk_score));
            md.push_str(&format!(
                "- Files: {} scanned, {} with unsafe, {} unsafe exprs\n",
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

pub fn generate_json(report: &StudyReport) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}
