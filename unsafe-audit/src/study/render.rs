use super::{CrateStudySummary, FuzzGroupSummary, MiriCaseSummary, StudyIndex};

pub(super) fn render_study_markdown(index: &StudyIndex) -> String {
    let mut md = String::new();
    md.push_str(&study_markdown_header(index));
    md.push_str(study_markdown_table_header());
    for item in &index.crates {
        md.push_str(&study_markdown_row(item));
    }
    md.push('\n');
    md
}

fn study_markdown_header(index: &StudyIndex) -> String {
    format!(
        "# Study Summary\n\n- Manifest: `{}`\n- Output root: `{}`\n- Schema: `{}`\n\n",
        index.manifest, index.output_root, index.schema_version
    )
}

fn study_markdown_table_header() -> &'static str {
    "| Crate | Cohort | Tier | Geiger Root | Unsafe Sites | Unsafe Dynamic | Miri Cases | Fuzz Groups | Pattern Findings | Scan Failures |\n\
|-------|--------|------|-------------|--------------|----------------|------------|-------------|------------------|---------------|\n"
}

fn study_markdown_row(item: &CrateStudySummary) -> String {
    format!(
        "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
        item.name,
        item.cohort,
        item.coverage_tier,
        display_count(item.geiger_root_total),
        display_count(item.unsafe_site_total),
        summarize_unsafe_dynamic(item),
        summarize_miri_cases(&item.miri_cases),
        summarize_fuzz_groups(&item.fuzz_groups),
        display_count(item.pattern_findings),
        display_count(item.pattern_scan_failures),
    )
}

fn summarize_unsafe_dynamic(item: &CrateStudySummary) -> String {
    match &item.unsafe_coverage_state {
        None => "SKIPPED".into(),
        Some(state) => {
            let mut parts = vec![state.clone()];
            if let Some(reached) = item.unsafe_reached_lower_bound_any {
                parts.push(format!("reach≥{reached}"));
            }
            if let Some(triggered) = item.unsafe_triggered_any {
                parts.push(format!("triggered={triggered}"));
            }
            if let Some(unmapped) = item.unmapped_triggered_any {
                if unmapped > 0 {
                    parts.push(format!("unmapped={unmapped}"));
                }
            }
            parts.join(" ")
        }
    }
}

fn summarize_miri_cases(cases: &[MiriCaseSummary]) -> String {
    if cases.is_empty() {
        return "SKIPPED".into();
    }
    cases
        .iter()
        .map(|item| format!("{}: {}", item.name, item.verdict))
        .collect::<Vec<_>>()
        .join("; ")
}

fn summarize_fuzz_groups(groups: &[FuzzGroupSummary]) -> String {
    if groups.is_empty() {
        return "SKIPPED".into();
    }
    groups
        .iter()
        .map(|item| match &item.harness_dir {
            Some(dir) => format!(
                "{} [{} @ {}]: {}",
                item.name, item.selection, dir, item.summary
            ),
            None => format!("{} [{}]: {}", item.name, item.selection, item.summary),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn display_count<T: ToString>(value: Option<T>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".into())
}
