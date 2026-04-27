use super::*;

#[test]
fn command_display_joins_program_and_args() {
    let spec = CommandSpec {
        program: "cargo".into(),
        args: vec!["test".into(), "--all".into()],
        env: BTreeMap::new(),
        current_dir: PathBuf::from("."),
    };
    assert_eq!(spec.display(), "cargo test --all");
}

#[test]
fn excerpt_truncates_on_char_boundaries() {
    let text = format!("{}{}", "a".repeat(800), "─".repeat(10));
    let shortened = excerpt(&text).unwrap();
    assert!(shortened.starts_with("..."));
    assert!(shortened.ends_with('─'));
}

#[test]
fn format_duration_ms_formats_short_and_long_values() {
    assert_eq!(format_duration_ms(532), "532ms");
    assert_eq!(format_duration_ms(1_530), "1.5s");
    assert_eq!(format_duration_ms(125_000), "2m05s");
}
