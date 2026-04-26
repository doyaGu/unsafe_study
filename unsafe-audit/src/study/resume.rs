use anyhow::Result;

use crate::app::AuditOptions;
use crate::domain::{StudyReport, REPORT_SCHEMA_VERSION};
use crate::infra::OutputLayout;
use crate::{planned_command, run_and_write, write_report};

pub(super) fn run_or_resume(
    options: &AuditOptions,
    dry_run: bool,
    resume: bool,
) -> Result<Option<StudyReport>> {
    if dry_run {
        println!("    {}", planned_command(options));
        Ok(None)
    } else if resume {
        if let Some(report) = load_existing_report(options)? {
            println!("    [resume] {}", options.output_dir.display());
            write_report(options, &report)?;
            Ok(Some(report))
        } else {
            Ok(Some(run_and_write(options)?))
        }
    } else {
        Ok(Some(run_and_write(options)?))
    }
}

pub(super) fn load_existing_report(options: &AuditOptions) -> Result<Option<StudyReport>> {
    let layout = OutputLayout::new(options.output_dir.clone());
    let report_path = layout.report_json_path();
    if !report_path.exists() {
        return Ok(None);
    }

    let content = match std::fs::read_to_string(&report_path) {
        Ok(content) => content,
        Err(error) => {
            println!(
                "    [resume-skip] {} (read failed: {error})",
                report_path.display()
            );
            return Ok(None);
        }
    };
    let report: StudyReport = match serde_json::from_str(&content) {
        Ok(report) => report,
        Err(error) => {
            println!(
                "    [resume-skip] {} (parse failed: {error})",
                report_path.display()
            );
            return Ok(None);
        }
    };
    if report.schema_version != REPORT_SCHEMA_VERSION {
        println!(
            "    [resume-skip] {} (schema {} != current {})",
            report_path.display(),
            report.schema_version,
            REPORT_SCHEMA_VERSION,
        );
        return Ok(None);
    }
    if report.crates.len() != 1 {
        println!(
            "    [resume-skip] {} (expected exactly 1 crate report)",
            report_path.display()
        );
        return Ok(None);
    }

    Ok(Some(report))
}
