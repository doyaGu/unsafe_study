use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::infra::{CommandRunner, CommandSpec};

use super::llvm::{coverage_env, export_json_from_profraw};

const MAX_FUZZ_COVERAGE_REPLAY_INPUTS: usize = 256;

pub fn auto_export_fuzz_coverage_json(
    harness_root: &Path,
    env_pairs: &[(String, String)],
    targets: &[String],
    output_json: &Path,
    log_dir: &Path,
    crate_name: &str,
) -> Result<()> {
    let tempdir = tempfile::tempdir().context("creating temp dir for fuzz coverage capture")?;
    let profraw_dir = tempdir.path().join("profraw");
    std::fs::create_dir_all(&profraw_dir)?;

    let coverage_env = fuzz_coverage_env(&profraw_dir, env_pairs);
    let mut objects = Vec::new();
    let mut replay_inputs_seen = 0usize;

    for target in targets {
        let build_log = log_dir.join(format!("{crate_name}.fuzz.{target}.coverage-build.log"));
        let replay_log = log_dir.join(format!("{crate_name}.fuzz.{target}.coverage-replay.log"));
        let object = build_fuzz_target(harness_root, target, &coverage_env, &build_log)?;
        objects.push(object.clone());

        let inputs = replay_inputs(harness_root, target)?;
        replay_inputs_seen += inputs.len();
        for (index, input) in inputs.iter().enumerate() {
            let per_input_log = if inputs.len() == 1 {
                replay_log.clone()
            } else {
                log_dir.join(format!(
                    "{crate_name}.fuzz.{target}.coverage-replay-{index}.log"
                ))
            };
            replay_fuzz_input(&object, input, &coverage_env, &per_input_log)?;
        }
    }

    if replay_inputs_seen == 0 {
        bail!("no fuzz corpus or artifact inputs were available for coverage replay");
    }

    export_json_from_profraw(&profraw_dir, &objects, output_json)
}

fn fuzz_coverage_env(
    profraw_dir: &Path,
    env_pairs: &[(String, String)],
) -> BTreeMap<String, String> {
    let mut env = coverage_env(profraw_dir);
    for (key, value) in env_pairs {
        env.insert(key.clone(), value.clone());
    }
    env.entry("LSAN_OPTIONS".into())
        .or_insert_with(|| "detect_leaks=0".into());
    env
}

fn build_fuzz_target(
    harness_root: &Path,
    target: &str,
    env: &BTreeMap<String, String>,
    log_path: &Path,
) -> Result<PathBuf> {
    let (execution, _) = CommandRunner::run(&CommandSpec {
        program: "cargo".into(),
        args: vec!["fuzz".into(), "build".into(), target.into()],
        env: env.clone(),
        current_dir: harness_root.to_path_buf(),
        log_path: log_path.to_path_buf(),
    })?;
    if !execution.success {
        bail!(
            "cargo fuzz build {target} failed; see {}",
            log_path.display()
        );
    }

    find_fuzz_binary(harness_root, target)
        .with_context(|| format!("locating fuzz binary for target `{target}`"))
}

fn find_fuzz_binary(harness_root: &Path, target: &str) -> Result<PathBuf> {
    let target_root = harness_root.join("fuzz").join("target");
    let mut candidates = WalkDir::new(&target_root)
        .follow_links(true)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.into_path())
        .filter(|path| path.is_file())
        .filter(|path| path.file_name().and_then(|name| name.to_str()) == Some(target))
        .collect::<Vec<_>>();
    candidates.sort();
    candidates
        .into_iter()
        .next_back()
        .context("no built fuzz binary was found under fuzz/target")
}

fn replay_inputs(harness_root: &Path, target: &str) -> Result<Vec<PathBuf>> {
    let mut corpus_inputs =
        collect_input_files(&harness_root.join("fuzz").join("corpus").join(target));
    corpus_inputs.sort();
    if corpus_inputs.len() > MAX_FUZZ_COVERAGE_REPLAY_INPUTS {
        corpus_inputs.truncate(MAX_FUZZ_COVERAGE_REPLAY_INPUTS);
    }

    let mut artifact_inputs =
        collect_input_files(&harness_root.join("fuzz").join("artifacts").join(target));
    artifact_inputs.sort();

    let mut inputs = artifact_inputs;
    inputs.extend(corpus_inputs);
    inputs.dedup();
    Ok(inputs)
}

fn collect_input_files(dir: &Path) -> Vec<PathBuf> {
    if !dir.exists() {
        return Vec::new();
    }
    WalkDir::new(dir)
        .follow_links(true)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.into_path())
        .filter(|path| path.is_file())
        .collect()
}

fn replay_fuzz_input(
    binary: &Path,
    input: &Path,
    env: &BTreeMap<String, String>,
    log_path: &Path,
) -> Result<()> {
    let _ = CommandRunner::run(&CommandSpec {
        program: binary.display().to_string(),
        args: vec!["-runs=1".into(), input.display().to_string()],
        env: env.clone(),
        current_dir: binary
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(".")),
        log_path: log_path.to_path_buf(),
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn collects_fuzz_replay_inputs_from_corpus_and_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let corpus = temp.path().join("fuzz/corpus/demo");
        let artifacts = temp.path().join("fuzz/artifacts/demo");
        fs::create_dir_all(&corpus).unwrap();
        fs::create_dir_all(&artifacts).unwrap();
        fs::write(corpus.join("seed"), b"a").unwrap();
        fs::write(artifacts.join("crash"), b"b").unwrap();

        let inputs = replay_inputs(temp.path(), "demo").unwrap();
        assert_eq!(inputs.len(), 2);
    }

    #[test]
    fn caps_corpus_replay_inputs_but_keeps_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let corpus = temp.path().join("fuzz/corpus/demo");
        let artifacts = temp.path().join("fuzz/artifacts/demo");
        fs::create_dir_all(&corpus).unwrap();
        fs::create_dir_all(&artifacts).unwrap();
        for index in 0..(MAX_FUZZ_COVERAGE_REPLAY_INPUTS + 10) {
            fs::write(corpus.join(format!("seed-{index:03}")), b"a").unwrap();
        }
        fs::write(artifacts.join("crash"), b"b").unwrap();

        let inputs = replay_inputs(temp.path(), "demo").unwrap();
        assert_eq!(inputs.len(), MAX_FUZZ_COVERAGE_REPLAY_INPUTS + 1);
        assert!(inputs.iter().any(|path| path.ends_with("crash")));
    }
}
