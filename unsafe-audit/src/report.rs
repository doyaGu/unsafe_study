use crate::config::{CratePlan, OutputFormat, PhaseSelection, RunPlan, RunProfile};
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

impl PhaseKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Scan => "scan",
            Self::Geiger => "geiger",
            Self::Miri => "miri",
            Self::Fuzz => "fuzz",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PhaseStatus {
    Clean,
    Pass,
    Finding,
    Skipped,
    Error,
}

impl PhaseStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Pass => "pass",
            Self::Finding => "finding",
            Self::Skipped => "skipped",
            Self::Error => "error",
        }
    }
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

impl ExecutionConfig {
    pub fn from_plan(plan: &RunPlan) -> Self {
        Self {
            profile: plan.profile,
            jobs: plan.jobs,
            fuzz_jobs: plan.fuzz_jobs,
            phases: plan.phases,
            miri_triage: plan.miri_triage,
            fuzz_time: plan.fuzz_time,
            fuzz_env: plan.fuzz_env.clone(),
        }
    }
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

impl CrateReport {
    pub fn from_plan(
        crate_plan: &CratePlan,
        unsafe_sites: Vec<UnsafeSite>,
        pattern_summary: PatternSummary,
        phases: Vec<PhaseReport>,
    ) -> Self {
        let review_priority = build_review_priority(&unsafe_sites, &pattern_summary, &phases);

        Self {
            name: crate_plan.name.clone(),
            path: crate_plan.path.display().to_string(),
            cohort: crate_plan.cohort.clone(),
            unsafe_sites,
            pattern_summary,
            phases,
            review_priority,
        }
    }
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

impl Report {
    pub fn from_plan(plan: &RunPlan, crates: Vec<CrateReport>) -> Self {
        Self {
            schema_version: 1,
            study_name: plan.name.clone(),
            execution: ExecutionConfig::from_plan(plan),
            crates,
        }
    }
}

pub fn write_reports(report: &Report, output_root: &Path, formats: &[OutputFormat]) -> Result<()> {
    for format in formats {
        match format {
            OutputFormat::Json => {
                std::fs::write(report_json_path(output_root), serde_json::to_string_pretty(report)?)?;
            }
            OutputFormat::Markdown => {
                std::fs::write(report_markdown_path(output_root), render_markdown(report))?;
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
        report.execution.profile.label(),
        report.execution.jobs,
        report.execution.fuzz_jobs,
        report.execution.phases.label(),
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
                "| {} | {} | {} | {} | {} | {} |\n",
                phase.kind.label(),
                phase.name,
                phase.status.label(),
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

fn report_json_path(root: &Path) -> std::path::PathBuf {
    root.join("report.json")
}

fn report_markdown_path(root: &Path) -> std::path::PathBuf {
    root.join("report.md")
}

fn phase_cell(phases: &[PhaseReport], kind: PhaseKind) -> &'static str {
    let mut saw = false;
    let mut best = PhaseStatus::Skipped;
    for phase in phases.iter().filter(|phase| phase.kind == kind) {
        saw = true;
        best = match (best, phase.status) {
            (_, PhaseStatus::Finding) => PhaseStatus::Finding,
            (PhaseStatus::Finding, _) => PhaseStatus::Finding,
            (_, PhaseStatus::Error) => PhaseStatus::Error,
            (PhaseStatus::Error, _) => PhaseStatus::Error,
            (_, PhaseStatus::Pass) => PhaseStatus::Pass,
            (PhaseStatus::Pass, _) => PhaseStatus::Pass,
            (_, PhaseStatus::Clean) => PhaseStatus::Clean,
            (PhaseStatus::Clean, _) => PhaseStatus::Clean,
            _ => PhaseStatus::Skipped,
        };
    }

    if saw {
        best.label()
    } else {
        "-"
    }
}

fn phase_detail(phase: &PhaseReport) -> String {
    let mut fields = Vec::new();

    match &phase.evidence {
        PhaseEvidence::Geiger {
            root_unsafe,
            dependency_unsafe,
            excerpt: excerpt_text,
        } => {
            if let Some(root_unsafe) = root_unsafe {
                fields.push(format!("root_unsafe={root_unsafe}"));
            }
            if let Some(dependency_unsafe) = dependency_unsafe {
                fields.push(format!("dependency_unsafe={dependency_unsafe}"));
            }
            if let Some(preview) = detail_excerpt(excerpt_text.as_deref()) {
                fields.push(format!("excerpt={preview}"));
            }
        }
        PhaseEvidence::Miri {
            verdict,
            ub_category,
            excerpt: excerpt_text,
        } => {
            fields.push(format!("verdict={verdict}"));
            if let Some(ub_category) = ub_category {
                fields.push(format!("ub_category={ub_category}"));
            }
            if let Some(preview) = detail_excerpt(excerpt_text.as_deref()) {
                fields.push(format!("excerpt={preview}"));
            }
        }
        PhaseEvidence::Fuzz {
            target,
            budget_secs,
            artifact,
            error_kind,
            runs,
            excerpt: excerpt_text,
        } => {
            if let Some(target) = target {
                fields.push(format!("target={target}"));
            }
            if let Some(budget_secs) = budget_secs {
                fields.push(format!("budget={budget_secs}s"));
            }
            if let Some(error_kind) = error_kind {
                fields.push(format!("error_kind={error_kind}"));
            }
            if let Some(artifact) = artifact {
                fields.push(format!("artifact={artifact}"));
            }
            if let Some(runs) = runs {
                fields.push(format!("runs={runs}"));
            }
            if let Some(preview) = detail_excerpt(excerpt_text.as_deref()) {
                fields.push(format!("excerpt={preview}"));
            }
        }
        PhaseEvidence::Scan => {}
    }

    if fields.is_empty() {
        "-".into()
    } else {
        fields.join("; ")
    }
}

fn detail_excerpt(text: Option<&str>) -> Option<String> {
    excerpt(text.unwrap_or_default()).map(|snippet| sanitize_markdown_cell(&snippet))
}

fn sanitize_markdown_cell(text: &str) -> String {
    text.replace('|', "\\|").replace('\n', " ")
}

#[cfg(test)]
#[path = "tests/report_tests.rs"]
mod tests;
