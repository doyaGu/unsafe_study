use super::*;
use tempfile::tempdir;

#[test]
fn single_crate_defaults_to_one_miri_case_and_one_fuzz_group() {
    let dir = tempdir().unwrap();
    std::fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname='demo'\nversion='0.1.0'\n",
    )
    .unwrap();

    let plan = load_plan(dir.path(), RunOptions::default()).unwrap();
    assert_eq!(plan.crates[0].name, "demo");
    assert_eq!(plan.crates[0].miri_cases[0].name, "upstream_full");
    assert!(plan.crates[0].fuzz_groups[0].all);
    assert_eq!(plan.jobs, 1);
    assert_eq!(plan.fuzz_jobs, 1);
    assert_eq!(
        plan.crates[0].fuzz_groups[0].env.get("ASAN_OPTIONS").unwrap(),
        "detect_leaks=0"
    );
}

#[test]
fn manifest_selection_filters_crates() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("study.toml");
    std::fs::write(
        &manifest,
        "[study]\nname='s'\n[[crate]]\nname='a'\npath='a'\n[[crate]]\nname='b'\npath='b'\n",
    )
    .unwrap();

    let plan = load_plan(
        &manifest,
        RunOptions {
            crates: vec!["b".into()],
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(plan.crates.len(), 1);
    assert_eq!(plan.crates[0].name, "b");
}

#[test]
fn smoke_profile_caps_fuzz_time() {
    let dir = tempdir().unwrap();
    std::fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname='demo'\nversion='0.1.0'\n",
    )
    .unwrap();
    let plan = load_plan(
        dir.path(),
        RunOptions {
            profile: RunProfile::Smoke,
            fuzz_time: Some(600),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(plan.fuzz_time, Some(30));
    assert_eq!(plan.crates[0].fuzz_groups[0].time, Some(30));
}

#[test]
fn baseline_profile_caps_manifest_group_times() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("study.toml");
    std::fs::write(
        &manifest,
        "[study]\nfuzz_time=3600\n[[crate]]\nname='a'\npath='a'\n[[crate.fuzz_group]]\nname='g'\ntargets=['x']\ntime=900\n",
    )
    .unwrap();
    let plan = load_plan(
        &manifest,
        RunOptions {
            profile: RunProfile::Baseline,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(plan.fuzz_time, Some(300));
    assert_eq!(plan.crates[0].fuzz_groups[0].time, Some(300));
}

#[test]
fn manifest_merges_fuzz_env_with_cli_precedence() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("study.toml");
    std::fs::write(
        &manifest,
        r#"
[study]
fuzz_time = 30
fuzz_env = { A = "study", B = "study" }

[[crate]]
name = "demo"
path = "demo"

[[crate.fuzz_group]]
name = "fg"
targets = ["parse"]
time = 5
env = { B = "group", C = "group" }
"#,
    )
    .unwrap();

    let plan = load_plan(
        &manifest,
        RunOptions {
            fuzz_env: BTreeMap::from([("C".into(), "cli".into()), ("D".into(), "cli".into())]),
            ..Default::default()
        },
    )
    .unwrap();
    let group = &plan.crates[0].fuzz_groups[0];
    assert_eq!(group.time, Some(5));
    assert_eq!(group.env.get("A").unwrap(), "study");
    assert_eq!(group.env.get("B").unwrap(), "group");
    assert_eq!(group.env.get("C").unwrap(), "cli");
    assert_eq!(group.env.get("D").unwrap(), "cli");
}

#[test]
fn manifest_prepends_builtin_miri_before_harness_cases() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("study.toml");
    std::fs::create_dir_all(dir.path().join("demo")).unwrap();
    std::fs::create_dir_all(dir.path().join("harness")).unwrap();
    std::fs::write(
        &manifest,
        "[[crate]]\nname='demo'\npath='demo'\n[[crate.miri_case]]\nname='targeted'\nharness_dir='harness'\ntest='demo'\ncase='case_name'\nexact=true\n",
    )
    .unwrap();

    let plan = load_plan(&manifest, RunOptions::default()).unwrap();
    let cases = &plan.crates[0].miri_cases;

    assert_eq!(cases.len(), 2);
    assert_eq!(cases[0].name, "upstream_full");
    assert!(cases[0].harness_dir.is_none());
    assert_eq!(cases[1].name, "targeted");
    assert!(cases[1].harness_dir.is_some());
}

#[test]
fn manifest_appends_detected_fuzz_harness_after_builtin_groups() {
    let dir = tempdir().unwrap();
    let study_dir = dir.path().join("study");
    std::fs::create_dir_all(&study_dir).unwrap();
    let manifest = study_dir.join("study.toml");
    std::fs::create_dir_all(dir.path().join("fuzz_harnesses/demo")).unwrap();
    std::fs::write(
        dir.path().join("fuzz_harnesses/demo/Cargo.toml"),
        "[package]\nname='demo-fuzz'\nversion='0.1.0'\n",
    )
    .unwrap();
    std::fs::write(
        &manifest,
        "[[crate]]\nname='demo'\npath='demo'\n[[crate.fuzz_group]]\nname='builtin'\nall=true\n",
    )
    .unwrap();

    let plan = load_plan(&manifest, RunOptions::default()).unwrap();
    let groups = &plan.crates[0].fuzz_groups;

    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0].name, "builtin");
    assert!(groups[0].harness_dir.is_none());
    assert_eq!(groups[1].name, "harness_targets");
    assert_eq!(
        groups[1].harness_dir.as_ref().unwrap(),
        &dir.path().join("fuzz_harnesses/demo")
    );
}

#[test]
fn manifest_injects_builtin_fuzz_group_before_harness_only_groups() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("study.toml");
    std::fs::create_dir_all(dir.path().join("demo/fuzz")).unwrap();
    std::fs::create_dir_all(dir.path().join("fuzz_harnesses/demo")).unwrap();
    std::fs::write(
        dir.path().join("demo/Cargo.toml"),
        "[package]\nname='demo'\nversion='0.1.0'\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("fuzz_harnesses/demo/Cargo.toml"),
        "[package]\nname='demo-fuzz'\nversion='0.1.0'\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("demo/fuzz/Cargo.toml"),
        "[package]\nname='demo-upstream-fuzz'\nversion='0.1.0'\n",
    )
    .unwrap();
    std::fs::write(
        &manifest,
        "[[crate]]\nname='demo'\npath='demo'\n[[crate.fuzz_group]]\nname='manual_harness'\nharness_dir='fuzz_harnesses/demo'\nall=true\n",
    )
    .unwrap();

    let plan = load_plan(&manifest, RunOptions::default()).unwrap();
    let groups = &plan.crates[0].fuzz_groups;

    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0].name, "existing_targets");
    assert!(groups[0].harness_dir.is_none());
    assert_eq!(groups[1].name, "manual_harness");
    assert!(groups[1].harness_dir.is_some());
}

#[test]
fn manifest_does_not_inject_builtin_fuzz_group_without_local_workspace() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("study.toml");
    std::fs::create_dir_all(dir.path().join("demo")).unwrap();
    std::fs::create_dir_all(dir.path().join("fuzz_harnesses/demo")).unwrap();
    std::fs::write(
        dir.path().join("demo/Cargo.toml"),
        "[package]\nname='demo'\nversion='0.1.0'\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("fuzz_harnesses/demo/Cargo.toml"),
        "[package]\nname='demo-fuzz'\nversion='0.1.0'\n",
    )
    .unwrap();
    std::fs::write(
        &manifest,
        "[[crate]]\nname='demo'\npath='demo'\n[[crate.fuzz_group]]\nname='manual_harness'\nharness_dir='fuzz_harnesses/demo'\nall=true\n",
    )
    .unwrap();

    let plan = load_plan(&manifest, RunOptions::default()).unwrap();
    let groups = &plan.crates[0].fuzz_groups;

    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].name, "manual_harness");
    assert!(groups[0].harness_dir.is_some());
}

#[test]
fn empty_format_list_restores_default_outputs() {
    let dir = tempdir().unwrap();
    std::fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname='demo'\nversion='0.1.0'\n",
    )
    .unwrap();
    let plan = load_plan(
        dir.path(),
        RunOptions {
            formats: Vec::new(),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(plan.formats, vec![OutputFormat::Json, OutputFormat::Markdown]);
}

#[test]
fn selecting_missing_manifest_crate_is_an_error() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("study.toml");
    std::fs::write(&manifest, "[[crate]]\nname='a'\npath='a'\n").unwrap();
    let err = load_plan(
        &manifest,
        RunOptions {
            crates: vec!["missing".into()],
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("selected no crates"));
}

#[test]
fn profile_and_phase_selection_labels_live_with_config_types() {
    assert_eq!(RunProfile::Smoke.label(), "smoke");
    assert_eq!(RunProfile::Baseline.label(), "baseline");
    assert_eq!(RunProfile::Full.label(), "full");

    assert_eq!(
        PhaseSelection {
            scan: true,
            geiger: false,
            miri: true,
            fuzz: false,
        }
        .label(),
        "scan, miri"
    );
    assert_eq!(
        PhaseSelection {
            scan: false,
            geiger: false,
            miri: false,
            fuzz: false,
        }
        .label(),
        "-"
    );
}
