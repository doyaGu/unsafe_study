use anyhow::Result;
use std::collections::BTreeMap;

use crate::app::AuditOptions;
use crate::domain::{CrateAuditResult, ExplorationMiriCase};
use crate::infra::{CommandRunner, CommandSpec, OutputLayout};
use crate::phases;

pub(super) fn discover_miri_cases(
    result: &CrateAuditResult,
    layout: &OutputLayout,
) -> Result<Vec<String>> {
    let log_path = layout
        .miri_logs
        .join(format!("{}.test-list.log", result.target.display_name()));
    let (_, combined) = CommandRunner::run(&CommandSpec {
        program: "cargo".into(),
        args: vec!["test".into(), "--".into(), "--list".into()],
        env: BTreeMap::new(),
        current_dir: result.target.dir.clone(),
        log_path,
    })?;
    Ok(parse_test_list(&combined))
}

fn parse_test_list(output: &str) -> Vec<String> {
    let mut tests = output
        .lines()
        .filter_map(|line| {
            line.split_once(": test")
                .map(|(name, _)| name.trim().to_string())
        })
        .filter(|name| !name.is_empty())
        .collect::<Vec<_>>();
    tests.sort();
    tests.dedup();
    tests
}

pub(super) fn run_isolated_miri_case(
    result: &CrateAuditResult,
    options: &AuditOptions,
    layout: &OutputLayout,
    case_name: &str,
    index: usize,
) -> Result<(ExplorationMiriCase, Option<crate::domain::MiriResult>)> {
    let log_path = layout.miri_log_path(
        result.target.display_name(),
        &format!("case-{index}-strict"),
    );
    let args = isolated_miri_args(case_name);
    let miri = phases::miri::run(
        &result.target.dir,
        crate::domain::MiriScope::Targeted,
        options.miri_harness_dir.as_deref(),
        &args,
        &options.miri_flags,
        &log_path,
    )?;
    Ok((
        ExplorationMiriCase {
            name: case_name.to_string(),
            invocation: miri.invocation.clone(),
            verdict: Some(miri.verdict),
            ub_detected: Some(miri.primary_run.ub_detected),
            coverage_json: options.miri_coverage_json.clone(),
            log_path: Some(miri.primary_run.execution.log_path.clone()),
            error: None,
        },
        Some(miri),
    ))
}

pub(super) fn isolated_miri_args(case_name: &str) -> Vec<String> {
    vec![
        "miri".into(),
        "test".into(),
        case_name.into(),
        "--".into(),
        "--exact".into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cargo_test_list() {
        let output = "tests::a: test\nignored_case: test\nhelper: benchmark\n";
        assert_eq!(
            parse_test_list(output),
            vec!["ignored_case".to_string(), "tests::a".to_string()]
        );
    }
}
