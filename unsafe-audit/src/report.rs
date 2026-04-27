use crate::config::{OutputFormat, PhaseSelection, RunProfile};
use crate::fs;
use crate::runner::excerpt;
use crate::scan::{PatternSummary, UnsafeSite};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PhaseKind {
    Scan,
    Geiger,
    Miri,
    Fuzz,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PhaseStatus {
    Clean,
    Finding,
    Skipped,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub study_name: String,
    pub execution: ExecutionConfig,
    pub crates: Vec<CrateReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionConfig {
    pub profile: RunProfile,
    pub jobs: usize,
    pub fuzz_jobs: usize,
    pub phases: PhaseSelection,
    pub miri_triage: bool,
    pub fuzz_time: Option<u64>,
    pub fuzz_env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrateReport {
    pub name: String,
    pub path: String,
    pub cohort: Option<String>,
    pub unsafe_sites: Vec<UnsafeSite>,
    pub pattern_summary: PatternSummary,
    pub phases: Vec<PhaseReport>,
    pub review_priority: Vec<ReviewRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseReport {
    pub kind: PhaseKind,
    pub name: String,
    pub status: PhaseStatus,
    pub command: Vec<String>,
    pub duration_ms: u128,
    pub log_path: Option<String>,
    pub summary: String,
    pub evidence: PhaseEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PhaseEvidence {
    Geiger {
        root_unsafe: Option<usize>,
        dependency_unsafe: Option<usize>,
        excerpt: Option<String>,
    },
    Miri {
        verdict: String,
        ub_category: Option<String>,
        excerpt: Option<String>,
    },
    Fuzz {
        target: Option<String>,
        budget_secs: Option<u64>,
        artifact: Option<String>,
        error_kind: Option<String>,
        runs: Option<u64>,
        excerpt: Option<String>,
    },
    Scan,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewRow {
    pub site_id: String,
    pub file: String,
    pub line: usize,
    pub reason: String,
}

pub fn write_reports(report: &Report, output_root: &Path, formats: &[OutputFormat]) -> Result<()> {
    for format in formats {
        match format {
            OutputFormat::Json => {
                std::fs::write(
                    fs::report_json_path(output_root),
                    serde_json::to_string_pretty(report)?,
                )?;
            }
            OutputFormat::Markdown => {
                std::fs::write(
                    fs::report_markdown_path(output_root),
                    render_markdown(report),
                )?;
            }
        }
    }
    Ok(())
}

pub fn build_review_priority(
    sites: &[UnsafeSite],
    _summary: &PatternSummary,
    phases: &[PhaseReport],
) -> Vec<ReviewRow> {
    let dynamic_findings = phases
        .iter()
        .any(|p| matches!(p.status, PhaseStatus::Finding | PhaseStatus::Error));
    let mut rows: Vec<_> = sites
        .iter()
        .map(|site| ReviewRow {
            site_id: site.id.clone(),
            file: site.file.clone(),
            line: site.line,
            reason: if dynamic_findings && site.pattern.is_some() {
                format!(
                    "{} with dynamic finding in crate scope",
                    site.pattern.clone().unwrap_or_else(|| site.kind.clone())
                )
            } else {
                site.pattern.clone().unwrap_or_else(|| site.kind.clone())
            },
        })
        .collect();
    rows.sort_by_key(|row| {
        let score = if row.reason.contains("transmute") {
            0
        } else if row.reason.contains("ptr") {
            1
        } else if row.reason.contains("unchecked") {
            2
        } else {
            3
        };
        (score, row.file.clone(), row.line)
    });
    rows.truncate(10);
    rows
}

pub fn render_markdown(report: &Report) -> String {
    let mut md = String::new();
    md.push_str(&format!(
        "# unsafe-audit report\n\nSchema version: `{}`\n\nStudy: `{}`\n\n",
        report.schema_version, report.study_name
    ));
    md.push_str("## Execution\n\n");
    md.push_str(&format!(
        "- profile: `{}`\n- jobs: `{}`\n- fuzz_jobs: `{}`\n- phases: `{}`\n- miri_triage: `{}`\n- default_fuzz_time: `{}`\n",
        profile_label(report.execution.profile),
        report.execution.jobs,
        report.execution.fuzz_jobs,
        phase_selection_label(report.execution.phases),
        report.execution.miri_triage,
        report
            .execution
            .fuzz_time
            .map(|secs| format!("{secs}s"))
            .unwrap_or_else(|| "-".into())
    ));
    if report.execution.fuzz_env.is_empty() {
        md.push_str("- fuzz_env: `-`\n\n");
    } else {
        let env = report
            .execution
            .fuzz_env
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(", ");
        md.push_str(&format!("- fuzz_env: `{env}`\n\n"));
    }
    md.push_str("## Study overview\n\n");
    md.push_str("| crate | unsafe sites | geiger | miri | fuzz |\n");
    md.push_str("| --- | ---: | --- | --- | --- |\n");
    for krate in &report.crates {
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            krate.name,
            krate.unsafe_sites.len(),
            phase_cell(&krate.phases, PhaseKind::Geiger),
            phase_cell(&krate.phases, PhaseKind::Miri),
            phase_cell(&krate.phases, PhaseKind::Fuzz)
        ));
    }

    for krate in &report.crates {
        md.push_str(&format!("\n## Crate `{}`\n\n", krate.name));
        md.push_str(&format!("Path: `{}`\n\n", krate.path));
        md.push_str("### Unsafe inventory\n\n");
        md.push_str(&format!(
            "- sites: {}\n- unsafe blocks: {}\n- unsafe fns: {}\n- unsafe impls: {}\n- extern blocks: {}\n- pointer operations: {}\n- transmutes: {}\n- unchecked operations: {}\n\n",
            krate.unsafe_sites.len(),
            krate.pattern_summary.unsafe_blocks,
            krate.pattern_summary.unsafe_fns,
            krate.pattern_summary.unsafe_impls,
            krate.pattern_summary.extern_blocks,
            krate.pattern_summary.ptr_ops,
            krate.pattern_summary.transmutes,
            krate.pattern_summary.unchecked_ops
        ));

        md.push_str("### Dynamic evidence\n\n");
        md.push_str("| phase | name | status | summary | detail | log |\n");
        md.push_str("| --- | --- | --- | --- | --- | --- |\n");
        for phase in &krate.phases {
            md.push_str(&format!(
                "| {:?} | {} | {:?} | {} | {} | {} |\n",
                phase.kind,
                phase.name,
                phase.status,
                format!(
                    "{} ({} ms)",
                    phase.summary.replace('|', "\\|"),
                    phase.duration_ms
                ),
                phase_detail(phase),
                phase.log_path.as_deref().unwrap_or("-")
            ));
        }

        if !krate.review_priority.is_empty() {
            md.push_str("\n### Review priority\n\n");
            for row in &krate.review_priority {
                md.push_str(&format!(
                    "- `{}`:{} `{}` - {}\n",
                    row.file, row.line, row.site_id, row.reason
                ));
            }
            md.push('\n');
        }
    }
    md
}

fn phase_detail(phase: &PhaseReport) -> String {
    match &phase.evidence {
        PhaseEvidence::Geiger {
            root_unsafe,
            dependency_unsafe,
            ..
        } => {
            let mut details = Vec::new();
            if let Some(root) = root_unsafe {
                details.push(format!("root_unsafe={root}"));
            }
            if let Some(deps) = dependency_unsafe {
                details.push(format!("dependency_unsafe={deps}"));
            }
            if details.is_empty() {
                "-".into()
            } else {
                details.join("; ")
            }
        }
        PhaseEvidence::Miri {
            verdict,
            ub_category,
            ..
        } => {
            let mut details = vec![format!("verdict={verdict}")];
            if let Some(category) = ub_category {
                details.push(format!("ub_category={category}"));
            }
            details.join("; ")
        }
        PhaseEvidence::Fuzz {
            target,
            budget_secs,
            artifact,
            error_kind,
            runs,
            ..
        } => {
            let mut details = Vec::new();
            if let Some(target) = target {
                details.push(format!("target={target}"));
            }
            if let Some(budget_secs) = budget_secs {
                details.push(format!("budget={budget_secs}s"));
            }
            if let Some(runs) = runs {
                details.push(format!("runs={runs}"));
            }
            if let Some(error_kind) = error_kind {
                details.push(format!("error_kind={error_kind}"));
            }
            if let Some(artifact) = artifact {
                details.push(format!("artifact={artifact}"));
            }
            if details.is_empty() {
                "-".into()
            } else {
                details.join("; ")
            }
        }
        PhaseEvidence::Scan => "-".into(),
    }
}

fn profile_label(profile: RunProfile) -> &'static str {
    match profile {
        RunProfile::Smoke => "smoke",
        RunProfile::Baseline => "baseline",
        RunProfile::Full => "full",
    }
}

fn phase_selection_label(phases: PhaseSelection) -> String {
    let mut enabled = Vec::new();
    if phases.scan {
        enabled.push("scan");
    }
    if phases.geiger {
        enabled.push("geiger");
    }
    if phases.miri {
        enabled.push("miri");
    }
    if phases.fuzz {
        enabled.push("fuzz");
    }
    if enabled.is_empty() {
        "-".into()
    } else {
        enabled.join(", ")
    }
}

fn phase_cell(phases: &[PhaseReport], kind: PhaseKind) -> String {
    let relevant: Vec<_> = phases.iter().filter(|p| p.kind == kind).collect();
    if relevant.is_empty() {
        return "-".into();
    }
    if relevant
        .iter()
        .any(|p| matches!(p.status, PhaseStatus::Finding))
    {
        "finding".into()
    } else if relevant
        .iter()
        .any(|p| matches!(p.status, PhaseStatus::Error))
    {
        "error".into()
    } else {
        "clean".into()
    }
}

pub fn command_failure_report(
    kind: PhaseKind,
    name: String,
    command: Vec<String>,
    duration_ms: u128,
    log_path: Option<String>,
    output: &str,
) -> PhaseReport {
    PhaseReport {
        kind,
        name,
        status: PhaseStatus::Error,
        command,
        duration_ms,
        log_path,
        summary: "command failed".into(),
        evidence: PhaseEvidence::Geiger {
            root_unsafe: None,
            dependency_unsafe: None,
            excerpt: excerpt(output),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RunProfile;
    use tempfile::tempdir;

    fn test_execution() -> ExecutionConfig {
        ExecutionConfig {
            profile: RunProfile::Smoke,
            jobs: 2,
            fuzz_jobs: 3,
            phases: PhaseSelection {
                scan: true,
                geiger: false,
                miri: true,
                fuzz: true,
            },
            miri_triage: true,
            fuzz_time: Some(30),
            fuzz_env: BTreeMap::from([("ASAN_OPTIONS".into(), "detect_leaks=0".into())]),
        }
    }

    #[test]
    fn markdown_contains_crate_rows() {
        let report = Report {
            schema_version: 1,
            study_name: "s".into(),
            execution: test_execution(),
            crates: vec![CrateReport {
                name: "demo".into(),
                path: "demo".into(),
                cohort: None,
                unsafe_sites: Vec::new(),
                pattern_summary: PatternSummary::default(),
                phases: Vec::new(),
                review_priority: Vec::new(),
            }],
        };
        assert!(render_markdown(&report).contains("| demo | 0 |"));
    }

    #[test]
    fn review_priority_prefers_high_risk_patterns() {
        let sites = vec![
            UnsafeSite {
                id: "U1".into(),
                file: "b.rs".into(),
                line: 10,
                kind: "operation".into(),
                pattern: Some("unchecked_op".into()),
            },
            UnsafeSite {
                id: "U2".into(),
                file: "a.rs".into(),
                line: 1,
                kind: "operation".into(),
                pattern: Some("transmute".into()),
            },
        ];
        let rows = build_review_priority(&sites, &PatternSummary::default(), &[]);
        assert_eq!(rows[0].site_id, "U2");
    }

    #[test]
    fn review_priority_mentions_dynamic_findings_when_present() {
        let sites = vec![UnsafeSite {
            id: "U1".into(),
            file: "a.rs".into(),
            line: 1,
            kind: "operation".into(),
            pattern: Some("ptr_op".into()),
        }];
        let phases = vec![PhaseReport {
            kind: PhaseKind::Miri,
            name: "case".into(),
            status: PhaseStatus::Finding,
            command: Vec::new(),
            duration_ms: 0,
            log_path: None,
            summary: "ub".into(),
            evidence: PhaseEvidence::Miri {
                verdict: "ub_observed".into(),
                ub_category: Some("provenance".into()),
                excerpt: None,
            },
        }];
        let rows = build_review_priority(&sites, &PatternSummary::default(), &phases);
        assert!(rows[0].reason.contains("dynamic finding"));
    }

    #[test]
    fn write_reports_respects_requested_formats() {
        let dir = tempdir().unwrap();
        let report = Report {
            schema_version: 1,
            study_name: "s".into(),
            execution: test_execution(),
            crates: Vec::new(),
        };
        write_reports(&report, dir.path(), &[OutputFormat::Json]).unwrap();
        assert!(dir.path().join("report.json").exists());
        assert!(!dir.path().join("report.md").exists());
    }

    #[test]
    fn overview_marks_finding_over_error_and_clean() {
        let report = Report {
            schema_version: 1,
            study_name: "s".into(),
            execution: test_execution(),
            crates: vec![CrateReport {
                name: "demo".into(),
                path: "demo".into(),
                cohort: None,
                unsafe_sites: Vec::new(),
                pattern_summary: PatternSummary::default(),
                phases: vec![
                    PhaseReport {
                        kind: PhaseKind::Miri,
                        name: "a".into(),
                        status: PhaseStatus::Error,
                        command: Vec::new(),
                        duration_ms: 0,
                        log_path: None,
                        summary: "err".into(),
                        evidence: PhaseEvidence::Scan,
                    },
                    PhaseReport {
                        kind: PhaseKind::Miri,
                        name: "b".into(),
                        status: PhaseStatus::Finding,
                        command: Vec::new(),
                        duration_ms: 0,
                        log_path: None,
                        summary: "finding".into(),
                        evidence: PhaseEvidence::Scan,
                    },
                ],
                review_priority: Vec::new(),
            }],
        };
        assert!(render_markdown(&report).contains("| demo | 0 | - | finding | - |"));
    }

    #[test]
    fn markdown_includes_execution_metadata() {
        let report = Report {
            schema_version: 1,
            study_name: "study".into(),
            execution: test_execution(),
            crates: Vec::new(),
        };
        let md = render_markdown(&report);
        assert!(md.contains("Study: `study`"));
        assert!(md.contains("- profile: `smoke`"));
        assert!(md.contains("- jobs: `2`"));
        assert!(md.contains("- fuzz_jobs: `3`"));
        assert!(md.contains("- phases: `scan, miri, fuzz`"));
        assert!(md.contains("- fuzz_env: `ASAN_OPTIONS=detect_leaks=0`"));
    }

    #[test]
    fn markdown_shows_fuzz_error_kind_and_artifact_details() {
        let report = Report {
            schema_version: 1,
            study_name: "study".into(),
            execution: test_execution(),
            crates: vec![CrateReport {
                name: "demo".into(),
                path: "demo".into(),
                cohort: None,
                unsafe_sites: Vec::new(),
                pattern_summary: PatternSummary::default(),
                phases: vec![PhaseReport {
                    kind: PhaseKind::Fuzz,
                    name: "fg.parse".into(),
                    status: PhaseStatus::Error,
                    command: Vec::new(),
                    duration_ms: 31_000,
                    log_path: Some("/tmp/fuzz.log".into()),
                    summary: "target parse, budget 30s, error".into(),
                    evidence: PhaseEvidence::Fuzz {
                        target: Some("parse".into()),
                        budget_secs: Some(30),
                        artifact: Some("/tmp/crash-1".into()),
                        error_kind: Some("environment_error".into()),
                        runs: Some(123),
                        excerpt: None,
                    },
                }],
                review_priority: Vec::new(),
            }],
        };
        let md = render_markdown(&report);
        assert!(md.contains("error_kind=environment_error"));
        assert!(md.contains("artifact=/tmp/crash-1"));
        assert!(md.contains("runs=123"));
    }
}
