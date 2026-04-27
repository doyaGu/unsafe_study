use super::*;
use tempfile::tempdir;

#[test]
fn scan_finds_core_unsafe_shapes() {
    let dir = tempdir().unwrap();
    std::fs::create_dir(dir.path().join("src")).unwrap();
    std::fs::write(
        dir.path().join("src/lib.rs"),
        r#"
pub unsafe fn f(p: *const u8, xs: &[u8]) {
    unsafe { *p };
    let _ = unsafe { std::mem::transmute::<u8, i8>(1) };
    let _ = xs.get_unchecked(0);
}
unsafe impl Send for T {}
struct T;
extern "C" { fn c(); }
"#,
    )
    .unwrap();
    let report = scan_crate(dir.path()).unwrap();
    assert!(report.summary.unsafe_fns >= 1);
    assert!(report.summary.unsafe_blocks >= 2);
    assert!(report.summary.transmutes >= 1);
    assert!(report.summary.unchecked_ops >= 1);
    assert!(report.summary.extern_blocks >= 1);
}

#[test]
fn scan_ignores_target_and_fuzz_directories() {
    let dir = tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::create_dir_all(dir.path().join("target/generated")).unwrap();
    std::fs::create_dir_all(dir.path().join("fuzz/fuzz_targets")).unwrap();
    std::fs::write(dir.path().join("src/lib.rs"), "pub unsafe fn kept() {}\n").unwrap();
    std::fs::write(
        dir.path().join("target/generated/lib.rs"),
        "pub unsafe fn ignored_target() {}\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("fuzz/fuzz_targets/f.rs"),
        "pub unsafe fn ignored_fuzz() {}\n",
    )
    .unwrap();

    let report = scan_crate(dir.path()).unwrap();
    assert_eq!(report.summary.unsafe_fns, 1);
    assert_eq!(report.sites[0].file, "src/lib.rs");
}

#[test]
fn scan_assigns_stable_sequential_site_ids() {
    let dir = tempdir().unwrap();
    std::fs::create_dir(dir.path().join("src")).unwrap();
    std::fs::write(
        dir.path().join("src/lib.rs"),
        "pub unsafe fn a() {}\npub unsafe fn b() {}\n",
    )
    .unwrap();

    let report = scan_crate(dir.path()).unwrap();
    let ids: Vec<_> = report.sites.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(ids, vec!["U0001", "U0002"]);
}

#[test]
fn scan_detects_inline_asm_macro_name() {
    let dir = tempdir().unwrap();
    std::fs::create_dir(dir.path().join("src")).unwrap();
    std::fs::write(dir.path().join("src/lib.rs"), "fn f() { asm!(); }\n").unwrap();

    let report = scan_crate(dir.path()).unwrap();
    assert_eq!(report.summary.inline_asm, 1);
}

#[test]
fn scan_skips_unparsable_rust_files() {
    let dir = tempdir().unwrap();
    std::fs::create_dir(dir.path().join("src")).unwrap();
    std::fs::create_dir_all(dir.path().join("benchmarks/haystacks/code")).unwrap();
    std::fs::write(dir.path().join("src/lib.rs"), "pub unsafe fn kept() {}\n").unwrap();
    std::fs::write(
        dir.path().join("benchmarks/haystacks/code/bad.rs"),
        "fn broken([) {}\n",
    )
    .unwrap();

    let report = scan_crate(dir.path()).unwrap();

    assert_eq!(report.summary.unsafe_fns, 1);
    assert_eq!(report.sites.len(), 1);
    assert_eq!(report.sites[0].file, "src/lib.rs");
}