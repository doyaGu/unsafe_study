use super::*;

#[test]
fn sanitize_keeps_paths_file_safe() {
    assert_eq!(sanitize("a/b:c"), "a_b_c");
}
