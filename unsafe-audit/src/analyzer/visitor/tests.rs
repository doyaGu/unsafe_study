use super::*;

fn analyze(content: &str) -> FileAnalysis {
    analyze_source(Path::new("sample.rs"), content).unwrap()
}

#[test]
fn safe_child_expressions_inside_unsafe_block_are_not_findings() {
    let analysis = analyze(
        r#"
fn main() {
    unsafe {
        let x = 1 + 2;
        let y = x * 3;
    }
}
"#,
    );
    assert_eq!(analysis.findings.len(), 1);
    assert_eq!(analysis.findings[0].kind, FindingKind::UnsafeBlock);
    assert_eq!(analysis.findings[0].pattern, UnsafePattern::OtherUnsafe);
}

#[test]
fn tracks_unsafe_declarations_separately_from_findings() {
    let analysis = analyze(
        r#"
struct S;
unsafe impl Send for S {}
unsafe fn top_level(ptr: *const u8) -> u8 { *ptr }
impl S {
    unsafe fn method(ptr: *const u8) -> u8 { *ptr }
}
"#,
    );
    assert_eq!(
        analysis
            .findings
            .iter()
            .filter(|f| f.kind == FindingKind::UnsafeFnDecl)
            .count(),
        2
    );
    assert_eq!(
        analysis
            .findings
            .iter()
            .filter(|f| f.kind == FindingKind::UnsafeImplDecl)
            .count(),
        1
    );
    assert_eq!(
        analysis
            .findings
            .iter()
            .filter(|f| f.pattern == UnsafePattern::PtrDereference)
            .count(),
        2
    );
}

#[test]
fn union_declarations_are_not_reported_as_union_accesses() {
    let analysis = analyze(
        r#"
union U { a: u32, b: f32 }
"#,
    );
    assert!(analysis
        .findings
        .iter()
        .all(|f| f.pattern != UnsafePattern::UnionAccess));
}

#[test]
fn risky_calls_are_not_double_counted_through_child_paths() {
    let analysis = analyze(
        r#"
fn main() {
    unsafe {
        let _: u32 = std::mem::transmute(1u32);
    }
}
"#,
    );
    assert_eq!(
        analysis
            .findings
            .iter()
            .filter(|f| f.pattern == UnsafePattern::Transmute)
            .count(),
        1
    );
}

#[test]
fn classifies_risky_expression_shapes() {
    let analysis = analyze(
        r#"
fn main() {
    let value = 1u32;
    unsafe {
        let ptr = &value as *const u32;
        let _ = *ptr;
        let _ = ptr as *mut u32;
        let _ = std::mem::transmute::<u32, i32>(value);
        let _ = std::str::from_utf8_unchecked(b"x");
        let _ = [1u8].get_unchecked(0);
        std::hint::unreachable_unchecked();
        let _ = std::mem::zeroed::<u32>();
        let _ = std::ptr::read(ptr);
        let _ = std::ptr::addr_of!(value);
        core::arch::asm!("nop");
        let _ = _mm_setzero_si128();
    }
}
"#,
    );
    for pattern in [
        UnsafePattern::PtrDereference,
        UnsafePattern::Transmute,
        UnsafePattern::UncheckedConversion,
        UnsafePattern::UncheckedIndex,
        UnsafePattern::UnreachableUnchecked,
        UnsafePattern::UninitMemory,
        UnsafePattern::PtrReadWrite,
        UnsafePattern::AddrOf,
        UnsafePattern::InlineAsm,
        UnsafePattern::SimdIntrinsic,
    ] {
        assert!(
            analysis.findings.iter().any(|f| f.pattern == pattern),
            "missing pattern {pattern:?}"
        );
    }
}

#[test]
fn classifies_renamed_import_calls() {
    let analysis = analyze(
        r#"
use std::mem::transmute as t;
use std::str::from_utf8_unchecked as unchecked;
use std::ptr::read as ptr_read;

fn main() {
    let value = 1u32;
    let ptr = &value as *const u32;
    unsafe {
        let _: i32 = t(value);
        let _ = unchecked(b"x");
        let _ = ptr_read(ptr);
    }
}
"#,
    );
    assert!(analysis
        .findings
        .iter()
        .any(|f| f.pattern == UnsafePattern::Transmute));
    assert!(analysis
        .findings
        .iter()
        .any(|f| f.pattern == UnsafePattern::UncheckedConversion));
    assert!(analysis
        .findings
        .iter()
        .any(|f| f.pattern == UnsafePattern::PtrReadWrite));
}

#[test]
fn classifies_module_alias_calls() {
    let analysis = analyze(
        r#"
use std::mem as mem;
use std::ptr as raw_ptr;

fn main() {
    let value = 1u32;
    let ptr = &value as *const u32;
    unsafe {
        let _: i32 = mem::transmute(value);
        let _ = raw_ptr::read(ptr);
    }
}
"#,
    );
    assert!(analysis
        .findings
        .iter()
        .any(|f| f.pattern == UnsafePattern::Transmute));
    assert!(analysis
        .findings
        .iter()
        .any(|f| f.pattern == UnsafePattern::PtrReadWrite));
}

#[test]
fn classifies_macro_aliases() {
    let analysis = analyze(
        r#"
use core::arch::asm as arch_asm;
use std::ptr::addr_of as addr;

fn main() {
    let value = 1u32;
    unsafe {
        arch_asm!("nop");
        let _ = addr!(value);
    }
}
"#,
    );
    assert!(analysis
        .findings
        .iter()
        .any(|f| f.pattern == UnsafePattern::InlineAsm));
    assert!(analysis
        .findings
        .iter()
        .any(|f| f.pattern == UnsafePattern::AddrOf));
}
