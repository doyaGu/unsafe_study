use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

use crate::domain::CommandInvocation;
use crate::infra::{CommandRunner, CommandSpec};

use super::llvm::{collect_profraw_files, coverage_env, export_json_from_profraw};

pub fn auto_export_miri_coverage_json(
    invocation: &CommandInvocation,
    output_json: &Path,
    build_log: &Path,
    run_log: &Path,
) -> Result<()> {
    let tempdir = tempfile::tempdir().context("creating temp dir for Miri coverage capture")?;
    let profraw_dir = tempdir.path().join("profraw");
    std::fs::create_dir_all(&profraw_dir)?;

    let build_args = miri_coverage_build_args(&invocation.args)?;
    let run_args = miri_coverage_run_args(&invocation.args)?;
    let coverage_env = coverage_env(&profraw_dir);

    let (build_execution, build_output) = CommandRunner::run(&CommandSpec {
        program: "cargo".into(),
        args: build_args,
        env: coverage_env.clone(),
        current_dir: invocation.working_dir.clone(),
        log_path: build_log.to_path_buf(),
    })?;
    if !build_execution.success {
        bail!(
            "coverage build failed for `{}`; see {}",
            invocation.args.join(" "),
            build_log.display()
        );
    }

    let objects = coverage_objects_from_cargo_output(&build_output);
    if objects.is_empty() {
        bail!(
            "no coverage-capable test objects were discovered for `{}`",
            invocation.args.join(" ")
        );
    }

    let (run_execution, _) = CommandRunner::run(&CommandSpec {
        program: "cargo".into(),
        args: run_args,
        env: coverage_env,
        current_dir: invocation.working_dir.clone(),
        log_path: run_log.to_path_buf(),
    })?;
    if !run_execution.success && collect_profraw_files(&profraw_dir)?.is_empty() {
        bail!(
            "coverage run failed before producing profiling data; see {}",
            run_log.display()
        );
    }

    export_json_from_profraw(&profraw_dir, &objects, output_json)
}

fn miri_coverage_build_args(args: &[String]) -> Result<Vec<String>> {
    let (mut cargo_args, _) = normalize_miri_args(args)?;
    cargo_args.push("--no-run".into());
    cargo_args.push("--message-format=json".into());
    Ok(cargo_args)
}

fn miri_coverage_run_args(args: &[String]) -> Result<Vec<String>> {
    let (cargo_args, test_args) = normalize_miri_args(args)?;
    if test_args.is_empty() {
        Ok(cargo_args)
    } else {
        let mut run_args = cargo_args;
        run_args.push("--".into());
        run_args.extend(test_args);
        Ok(run_args)
    }
}

fn normalize_miri_args(args: &[String]) -> Result<(Vec<String>, Vec<String>)> {
    if args.is_empty() {
        return Ok((vec!["test".into()], Vec::new()));
    }

    let mut cargo_args = Vec::new();
    let mut test_args = Vec::new();
    let mut in_test_args = false;
    for arg in args {
        if in_test_args {
            test_args.push(arg.clone());
            continue;
        }
        if arg == "--" {
            in_test_args = true;
            continue;
        }
        cargo_args.push(arg.clone());
    }

    match cargo_args.first().map(String::as_str) {
        Some("miri") => {
            cargo_args.remove(0);
            if cargo_args.is_empty() {
                cargo_args.push("test".into());
            }
        }
        Some("test") => {}
        Some(other) => bail!(
            "automatic Miri coverage only supports `cargo miri ...` style invocations, got `cargo {other}`"
        ),
        None => cargo_args.push("test".into()),
    }

    Ok((cargo_args, test_args))
}

fn coverage_objects_from_cargo_output(output: &str) -> Vec<PathBuf> {
    output
        .lines()
        .filter_map(|line| serde_json::from_str::<CargoMessage>(line).ok())
        .filter_map(|message| match message {
            CargoMessage::CompilerArtifact { executable } => executable,
            CargoMessage::Other => None,
        })
        .collect()
}

#[derive(Debug, Deserialize)]
#[serde(tag = "reason", rename_all = "kebab-case")]
enum CargoMessage {
    CompilerArtifact {
        executable: Option<PathBuf>,
    },
    #[serde(other)]
    Other,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_miri_args_to_coverage_test_args() {
        let args = vec![
            "miri".into(),
            "test".into(),
            "--test".into(),
            "api_smoke".into(),
            "case_name".into(),
            "--".into(),
            "--exact".into(),
        ];
        assert_eq!(
            miri_coverage_build_args(&args).unwrap(),
            vec![
                "test",
                "--test",
                "api_smoke",
                "case_name",
                "--no-run",
                "--message-format=json",
            ]
        );
        assert_eq!(
            miri_coverage_run_args(&args).unwrap(),
            vec!["test", "--test", "api_smoke", "case_name", "--", "--exact",]
        );
    }

    #[test]
    fn extracts_executables_from_cargo_json() {
        let output = r#"{"reason":"compiler-artifact","executable":"/tmp/test-bin"}
{"reason":"build-script-executed"}"#;
        assert_eq!(
            coverage_objects_from_cargo_output(output),
            vec![PathBuf::from("/tmp/test-bin")]
        );
    }
}
