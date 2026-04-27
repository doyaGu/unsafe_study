use super::*;
use tempfile::tempdir;

#[test]
fn sanitize_keeps_paths_file_safe() {
    assert_eq!(sanitize("a/b:c"), "a_b_c");
}

#[test]
fn create_crate_output_dir_creates_directory_tree() {
    let dir = tempdir().unwrap();

    let crate_dir = create_crate_output_dir(dir.path(), "demo/crate").unwrap();

    assert!(crate_dir.is_dir());
    assert_eq!(crate_dir, dir.path().join("crates").join("demo_crate"));
}
