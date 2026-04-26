use super::*;
use clap::Parser;
use std::path::PathBuf;

#[test]
fn rejects_legacy_miri_dir_flag() {
    assert!(Cli::try_parse_from(["unsafe-audit", "--miri-dir", "h"]).is_err());
}

#[test]
fn rejects_legacy_fuzz_dir_flag() {
    assert!(Cli::try_parse_from(["unsafe-audit", "--fuzz-dir", "h"]).is_err());
}

#[test]
fn rejects_profraw_without_output_path() {
    let err = prepare_coverage_json("miri", None, Some(&PathBuf::from("p")), &[]).unwrap_err();
    assert!(err
        .to_string()
        .contains("--miri-profraw-dir requires --miri-coverage-json"));
}

#[test]
fn rejects_objects_without_profraw_dir() {
    let err = prepare_coverage_json(
        "fuzz",
        Some(&PathBuf::from("cov.json")),
        None,
        &[PathBuf::from("target")],
    )
    .unwrap_err();
    assert!(err
        .to_string()
        .contains("--fuzz-coverage-object requires --fuzz-profraw-dir"));
}

#[test]
fn strips_detach_flag_from_respawned_args() {
    let args = vec![
        OsString::from("/bin/unsafe-audit"),
        OsString::from("study/manifest.toml"),
        OsString::from("--detach"),
        OsString::from("--skip-fuzz"),
    ];
    let stripped = detached_child_args(&args);
    assert_eq!(
        stripped,
        vec![
            OsString::from("/bin/unsafe-audit"),
            OsString::from("study/manifest.toml"),
            OsString::from("--skip-fuzz"),
        ]
    );
}

#[test]
fn parses_exploration_flags() {
    let cli = Cli::try_parse_from([
        "unsafe-audit",
        "targets/httparse",
        "--max-rounds",
        "7",
        "--no-new-coverage-limit",
        "3",
        "--generate-harnesses",
        "--llm-provider-cmd",
        "llm-helper",
    ])
    .unwrap();
    assert!(!cli.classic);
    assert_eq!(cli.max_rounds, 7);
    assert_eq!(cli.no_new_coverage_limit, 3);
    assert!(cli.generate_harnesses);
    assert_eq!(cli.llm_provider_cmd.as_deref(), Some("llm-helper"));
}

#[test]
fn parses_classic_flag() {
    let cli = Cli::try_parse_from(["unsafe-audit", "targets/httparse", "--classic"]).unwrap();
    assert!(cli.classic);
}
