use crate::domain::StudyReport;

pub fn generate_json(report: &StudyReport) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}
