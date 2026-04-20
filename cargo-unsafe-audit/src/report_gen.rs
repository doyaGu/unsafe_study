use std::path::Path;

use crate::models::*;
use crate::analyzer::{UnsafeSummary, Severity};

// =========================================================================
// Report Generator -- JSON + Markdown
// =========================================================================

/// Generate a Markdown report.
pub fn generate_markdown(report: &AuditReport) -> String {
    let mut md = String::new();

    // Header
    md.push_str(&format!(
        "# unsafe-audit report: {} v{}\n\n",
        report.crate_name, report.crate_version
    ));
    md.push_str(&format!("- Generated: {}\n", report.timestamp));
    md.push_str(&format!("- Path: `{}`\n\n", report.crate_dir.display()));

    // Risk score
    let score = report.static_analysis.risk_score;
    let rating = if score < 20.0 {
        "LOW"
    } else if score < 50.0 {
        "MEDIUM"
    } else {
        "HIGH"
    };
    md.push_str(&format!("## Risk Score: {:.1}/100 ({})\n\n", score, rating));

    // Static analysis summary
    md.push_str("## Static Analysis\n\n");
    md.push_str(&format!(
        "| Metric | Value |\n|--------|-------|\n| Files scanned | {} |\n| Files with unsafe | {} |\n| Total unsafe expressions | {} |\n| Risk score | {:.1} |\n\n",
        report.static_analysis.files_scanned,
        report.static_analysis.files_with_unsafe,
        report.static_analysis.total_unsafe_exprs,
        report.static_analysis.risk_score,
    ));

    if !report.static_analysis.patterns.is_empty() {
        md.push_str("### Pattern Breakdown\n\n");
        md.push_str("| Pattern | Count | Severity |\n|---------|-------|----------|\n");
        for pc in &report.static_analysis.patterns {
            let sev = severity_emoji(&pattern_default_severity(pc.pattern));
            md.push_str(&format!("| {} | {} | {} |\n", pc.pattern, pc.count, sev));
        }
        md.push('\n');
    }

    // Top findings
    if !report.static_analysis.findings.is_empty() {
        md.push_str("### Top Findings (by severity)\n\n");
        let mut sorted = report.static_analysis.findings.clone();
        sorted.sort_by(|a, b| {
            let sa = severity_order(a.severity);
            let sb = severity_order(b.severity);
            sb.cmp(&sa)
        });
        for f in sorted.iter().take(15) {
            md.push_str(&format!(
                "- **{}** `{}:{}` -- {} [{}]\n",
                f.pattern,
                f.file.display(),
                f.line,
                &f.snippet[..f.snippet.len().min(80)],
                f.context,
            ));
        }
        md.push('\n');
    }

    // Miri results
    if let Some(miri) = &report.miri_result {
        md.push_str("## Miri Triage\n\n");
        md.push_str(&format!(
            "| Pass | Result | Tests | Duration |\n|------|--------|-------|----------|\n"
        ));
        md.push_str(&format!(
            "| Pass 1 (strict) | {} | {} | {:.1}s |\n",
            if miri.pass1.passed { "CLEAN" } else { "UB" },
            format_tests(&miri.pass1),
            miri.pass1.duration_secs,
        ));
        if let Some(pass2) = &miri.pass2 {
            md.push_str(&format!(
                "| Pass 2 (baseline) | {} | {} | {:.1}s |\n",
                if pass2.passed { "CLEAN" } else { "UB" },
                format_tests(pass2),
                pass2.duration_secs,
            ));
        }
        md.push_str(&format!(
            "\n**Classification: {:?}**\n\n",
            miri.classification
        ));
        if !miri.log_excerpt.is_empty() {
            md.push_str(&format!("```\n{}\n```\n\n", miri.log_excerpt));
        }
    }

    // Fuzz results
    if !report.fuzz_results.is_empty() {
        md.push_str("## Fuzzing\n\n");
        md.push_str("| Target | Runs | Edges | Duration | Status |\n|--------|------|-------|----------|--------|\n");
        for fr in &report.fuzz_results {
            let status_str = match fr.status {
                FuzzStatus::Clean => "CLEAN",
                FuzzStatus::CrashFound => "CRASH",
                FuzzStatus::BuildFailed => "BUILD FAIL",
                FuzzStatus::Timeout => "TIMEOUT",
                FuzzStatus::Error => "ERROR",
            };
            md.push_str(&format!(
                "| {} | {} | {} | {}s | {} |\n",
                fr.target_name,
                fr.total_runs.map(|n| n.to_string()).unwrap_or("-".into()),
                fr.edges_covered.map(|n| n.to_string()).unwrap_or("-".into()),
                fr.duration_secs,
                status_str,
            ));
        }
        md.push('\n');

        let findings: Vec<_> = report.fuzz_results.iter()
            .flat_map(|fr| fr.findings.iter().map(|f| (fr.target_name.clone(), f)))
            .collect();

        if !findings.is_empty() {
            md.push_str("### Findings\n\n");
            for (target, finding) in &findings {
                md.push_str(&format!(
                    "- **[{}] {:?}**: {}", target, finding.finding_type, finding.message));
                if let Some(path) = &finding.reproducer_path {
                    md.push_str(&format!(" (reproducer: `{}`)", path.display()));
                }
                md.push('\n');
            }
            md.push('\n');
        }
    }

    md
}

/// Generate a JSON report.
pub fn generate_json(report: &AuditReport) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn severity_emoji(sev: &Severity) -> &'static str {
    match sev {
        Severity::High => "🔴 High",
        Severity::Medium => "🟡 Medium",
        Severity::Low => "🟢 Low",
        Severity::Info => "ℹ️ Info",
    }
}

fn severity_order(sev: Severity) -> u8 {
    match sev {
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Info => 0,
    }
}

fn pattern_default_severity(p: crate::analyzer::UnsafePattern) -> Severity {
    use crate::analyzer::UnsafePattern::*;
    match p {
        Transmute | UninitMemory | UnreachableUnchecked | InlineAsm => Severity::High,
        PtrDereference | PtrReadWrite | UncheckedConversion | UncheckedIndex
        | SimdIntrinsic | UnionAccess | ExternBlock => Severity::Medium,
        AddrOf => Severity::Low,
        OtherUnsafe => Severity::Info,
    }
}

fn format_tests(pass: &MiriPassResult) -> String {
    match (pass.tests_run, pass.tests_passed) {
        (Some(run), Some(passed)) => format!("{}/{}", passed, run),
        _ => "-".into(),
    }
}
