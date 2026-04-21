//! unsafe-audit: Static unsafe pattern analyzer for Rust crates.
//!
//! Walks the AST of all `.rs` files in a crate using `syn` and classifies
//! unsafe code patterns into categories.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprUnsafe, ImplItem, ItemFn, ItemImpl, Type};

/// A single unsafe pattern occurrence found in the codebase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsafeFinding {
    pub kind: FindingKind,
    pub pattern: UnsafePattern,
    pub file: PathBuf,
    pub line: usize,
    pub column: usize,
    pub snippet: String,
    pub severity: Severity,
    pub context: String, // function name or module path
}

/// Source shape that produced a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FindingKind {
    UnsafeBlock,
    UnsafeFnDecl,
    UnsafeImplDecl,
    RiskyOperation,
    ExternItem,
}

impl std::fmt::Display for FindingKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            FindingKind::UnsafeBlock => "unsafe_block",
            FindingKind::UnsafeFnDecl => "unsafe_fn_decl",
            FindingKind::UnsafeImplDecl => "unsafe_impl_decl",
            FindingKind::RiskyOperation => "risky_operation",
            FindingKind::ExternItem => "extern_item",
        };
        write!(f, "{}", s)
    }
}

/// Category of unsafe pattern detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UnsafePattern {
    /// Raw pointer dereference: `*ptr`, `*mut T`, `*const T` deref
    PtrDereference,
    /// `std::ptr::read` / `std::ptr::write` / `copy` / `copy_nonoverlapping`
    PtrReadWrite,
    /// `std::mem::transmute` or `std::mem::transmute_copy`
    Transmute,
    /// `std::str::from_utf8_unchecked` or similar unchecked conversions
    UncheckedConversion,
    /// `get_unchecked`, `get_unchecked_mut` on slices/arrays
    UncheckedIndex,
    /// `std::hint::unreachable_unchecked`
    UnreachableUnchecked,
    /// SIMD intrinsics: `_mm_*`, `_mm256_*`, etc.
    SimdIntrinsic,
    /// `std::mem::zeroed` / `std::mem::uninitialized` / `MaybeUninit::assume_init`
    UninitMemory,
    /// `union` field access
    UnionAccess,
    /// `std::ptr::addr_of!` / `std::ptr::addr_of_mut!`
    AddrOf,
    /// Assembly: `std::arch::asm!` / `core::arch::asm!`
    InlineAsm,
    /// `extern` block (FFI)
    ExternBlock,
    /// Other unsafe expression not matching above categories
    OtherUnsafe,
}

impl std::fmt::Display for UnsafePattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            UnsafePattern::PtrDereference => "ptr_dereference",
            UnsafePattern::PtrReadWrite => "ptr_read_write",
            UnsafePattern::Transmute => "transmute",
            UnsafePattern::UncheckedConversion => "unchecked_conversion",
            UnsafePattern::UncheckedIndex => "unchecked_index",
            UnsafePattern::UnreachableUnchecked => "unreachable_unchecked",
            UnsafePattern::SimdIntrinsic => "simd_intrinsic",
            UnsafePattern::UninitMemory => "uninit_memory",
            UnsafePattern::UnionAccess => "union_access",
            UnsafePattern::AddrOf => "addr_of",
            UnsafePattern::InlineAsm => "inline_asm",
            UnsafePattern::ExternBlock => "extern_block",
            UnsafePattern::OtherUnsafe => "other_unsafe",
        };
        write!(f, "{}", s)
    }
}

/// Severity of the finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    /// Well-known dangerous pattern (transmute, uninit memory)
    High,
    /// Moderately risky (ptr deref, unchecked index)
    Medium,
    /// Low risk or common safe pattern in unsafe context
    Low,
    /// Informational only
    Info,
}

/// Summary statistics for a crate's unsafe patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsafeSummary {
    pub crate_name: String,
    pub crate_version: String,
    pub total_unsafe_exprs: usize,
    pub total_unsafe_fns: usize,
    pub total_unsafe_impls: usize,
    pub files_with_unsafe: usize,
    pub files_scanned: usize,
    pub patterns: Vec<PatternCount>,
    pub findings: Vec<UnsafeFinding>,
    pub risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternCount {
    pub pattern: UnsafePattern,
    pub count: usize,
}

// ---------------------------------------------------------------------------
// AST Visitor
// ---------------------------------------------------------------------------

struct UnsafeVisitor {
    findings: Vec<UnsafeFinding>,
    current_file: PathBuf,
    current_fn: String,
    unsafe_depth: usize,
    unsafe_fn_count: usize,
    unsafe_impl_count: usize,
    source_lines: Vec<String>,
}

struct FileAnalysis {
    findings: Vec<UnsafeFinding>,
    unsafe_fn_count: usize,
    unsafe_impl_count: usize,
}

impl UnsafeVisitor {
    fn get_source_line(&self, line_num: usize) -> String {
        if line_num == 0 || line_num > self.source_lines.len() {
            return String::new();
        }
        self.source_lines[line_num - 1].trim().to_string()
    }

    fn push_finding(
        &mut self,
        kind: FindingKind,
        expr: Option<&Expr>,
        span: proc_macro2::Span,
        pattern: UnsafePattern,
        severity: Severity,
    ) {
        let line = span.start().line;
        let col = span.start().column;
        let snippet = self.get_source_line(line);
        let snippet_trimmed = if snippet.len() > 120 {
            format!("{}...", &snippet[..117])
        } else if snippet.is_empty() {
            // Fallback to quote if source line unavailable
            let q = expr
                .map(|expr| format!("{:?}", quote::quote!(#expr)))
                .unwrap_or_else(|| format!("{:?}", pattern));
            if q.len() > 120 {
                format!("{}...", &q[..117])
            } else {
                q
            }
        } else {
            snippet
        };

        self.findings.push(UnsafeFinding {
            kind,
            pattern,
            file: self.current_file.clone(),
            line,
            column: col,
            snippet: snippet_trimmed,
            severity,
            context: self.current_fn.clone(),
        });
    }

    fn classify_expr(&mut self, expr: &Expr, span: proc_macro2::Span) {
        let should_inspect = matches!(
            expr,
            Expr::Call(_) | Expr::MethodCall(_) | Expr::Unary(_) | Expr::Cast(_)
        );
        if !should_inspect {
            return;
        }

        let (pattern, severity) = Self::identify_pattern(expr);
        if pattern != UnsafePattern::OtherUnsafe {
            self.push_finding(
                FindingKind::RiskyOperation,
                Some(expr),
                span,
                pattern,
                severity,
            );
        }
    }

    fn identify_pattern(expr: &Expr) -> (UnsafePattern, Severity) {
        match expr {
            Expr::Call(call) => Self::identify_call_pattern(call),
            Expr::MethodCall(method) => match method.method.to_string().as_str() {
                "get_unchecked" | "get_unchecked_mut" => {
                    (UnsafePattern::UncheckedIndex, Severity::Medium)
                }
                "assume_init" => (UnsafePattern::UninitMemory, Severity::High),
                name if is_simd_name(name) => (UnsafePattern::SimdIntrinsic, Severity::Medium),
                _ => (UnsafePattern::OtherUnsafe, Severity::Low),
            },
            Expr::Unary(unary) if matches!(unary.op, syn::UnOp::Deref(_)) => {
                (UnsafePattern::PtrDereference, Severity::Medium)
            }
            Expr::Cast(cast) if matches!(&*cast.ty, Type::Ptr(_)) => {
                (UnsafePattern::PtrDereference, Severity::Medium)
            }
            _ => (UnsafePattern::OtherUnsafe, Severity::Low),
        }
    }

    fn identify_macro_pattern(mac: &syn::Macro) -> (UnsafePattern, Severity) {
        let name = last_path_segment(&mac.path).unwrap_or_default();
        match name.as_str() {
            "asm" | "llvm_asm" => (UnsafePattern::InlineAsm, Severity::High),
            "addr_of" | "addr_of_mut" => (UnsafePattern::AddrOf, Severity::Low),
            name if is_simd_name(name) => (UnsafePattern::SimdIntrinsic, Severity::Medium),
            _ => (UnsafePattern::OtherUnsafe, Severity::Low),
        }
    }

    fn identify_call_pattern(call: &syn::ExprCall) -> (UnsafePattern, Severity) {
        let Some((name, path)) = call_name_and_path(&call.func) else {
            return (UnsafePattern::OtherUnsafe, Severity::Low);
        };

        if is_simd_name(&name) {
            return (UnsafePattern::SimdIntrinsic, Severity::Medium);
        }

        match name.as_str() {
            "transmute" | "transmute_copy" => (UnsafePattern::Transmute, Severity::High),
            "from_utf8_unchecked"
            | "from_utf16_unchecked"
            | "from_raw_parts"
            | "from_raw_parts_mut" => (UnsafePattern::UncheckedConversion, Severity::High),
            "unreachable_unchecked" => (UnsafePattern::UnreachableUnchecked, Severity::High),
            "zeroed" | "uninitialized" => (UnsafePattern::UninitMemory, Severity::High),
            "read"
            | "read_unaligned"
            | "write"
            | "write_unaligned"
            | "copy"
            | "copy_nonoverlapping"
            | "swap" => {
                if path.iter().any(|segment| segment == "ptr") {
                    (UnsafePattern::PtrReadWrite, Severity::Medium)
                } else {
                    (UnsafePattern::OtherUnsafe, Severity::Low)
                }
            }
            _ => (UnsafePattern::OtherUnsafe, Severity::Low),
        }
    }
}

fn call_name_and_path(func: &Expr) -> Option<(String, Vec<String>)> {
    match func {
        Expr::Path(path) => {
            let segments = path
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>();
            let name = segments.last()?.clone();
            Some((name, segments))
        }
        _ => None,
    }
}

fn last_path_segment(path: &syn::Path) -> Option<String> {
    path.segments
        .last()
        .map(|segment| segment.ident.to_string())
}

fn is_simd_name(name: &str) -> bool {
    name.starts_with("_mm") || name.starts_with("_mm256") || name.starts_with("_mm512")
}

impl<'ast> Visit<'ast> for UnsafeVisitor {
    fn visit_item_fn(&mut self, i: &'ast ItemFn) {
        let prev_fn = self.current_fn.clone();
        self.current_fn = i.sig.ident.to_string();
        if i.sig.unsafety.is_some() {
            self.unsafe_fn_count += 1;
            self.push_finding(
                FindingKind::UnsafeFnDecl,
                None,
                i.sig.ident.span(),
                UnsafePattern::OtherUnsafe,
                Severity::Info,
            );
            self.unsafe_depth += 1;
        }
        visit::visit_item_fn(self, i);
        if i.sig.unsafety.is_some() {
            self.unsafe_depth = self.unsafe_depth.saturating_sub(1);
        }
        self.current_fn = prev_fn;
    }

    fn visit_expr_unsafe(&mut self, i: &'ast ExprUnsafe) {
        self.push_finding(
            FindingKind::UnsafeBlock,
            None,
            i.unsafe_token.span,
            UnsafePattern::OtherUnsafe,
            Severity::Low,
        );
        self.unsafe_depth += 1;
        // Visit children to find specific patterns
        visit::visit_expr_unsafe(self, i);
        self.unsafe_depth = self.unsafe_depth.saturating_sub(1);
    }

    fn visit_item_impl(&mut self, i: &'ast ItemImpl) {
        if let Some(unsafety) = i.unsafety {
            self.unsafe_impl_count += 1;
            self.push_finding(
                FindingKind::UnsafeImplDecl,
                None,
                unsafety.span,
                UnsafePattern::OtherUnsafe,
                Severity::Info,
            );
        }
        visit::visit_item_impl(self, i);
    }

    fn visit_impl_item(&mut self, i: &'ast ImplItem) {
        if let ImplItem::Fn(fn_item) = i {
            let prev_fn = self.current_fn.clone();
            self.current_fn = fn_item.sig.ident.to_string();
            if fn_item.sig.unsafety.is_some() {
                self.unsafe_fn_count += 1;
                self.push_finding(
                    FindingKind::UnsafeFnDecl,
                    None,
                    fn_item.sig.ident.span(),
                    UnsafePattern::OtherUnsafe,
                    Severity::Info,
                );
                self.unsafe_depth += 1;
            }
            visit::visit_impl_item(self, i);
            if fn_item.sig.unsafety.is_some() {
                self.unsafe_depth = self.unsafe_depth.saturating_sub(1);
            }
            self.current_fn = prev_fn;
        } else {
            visit::visit_impl_item(self, i);
        }
    }

    fn visit_expr(&mut self, i: &'ast Expr) {
        if self.unsafe_depth > 0 {
            self.classify_expr(i, i.span());
        }
        visit::visit_expr(self, i);
    }

    fn visit_macro(&mut self, i: &'ast syn::Macro) {
        if self.unsafe_depth > 0 {
            let (pattern, severity) = Self::identify_macro_pattern(i);
            if pattern != UnsafePattern::OtherUnsafe {
                self.push_finding(
                    FindingKind::RiskyOperation,
                    None,
                    i.path.span(),
                    pattern,
                    severity,
                );
            }
        }
        visit::visit_macro(self, i);
    }

    fn visit_item_foreign_mod(&mut self, i: &'ast syn::ItemForeignMod) {
        for item in &i.items {
            let span = match item {
                syn::ForeignItem::Fn(f) => f.sig.ident.span(),
                syn::ForeignItem::Static(s) => s.ident.span(),
                syn::ForeignItem::Type(t) => t.ident.span(),
                _ => i.abi.span(),
            };
            let abi_str = i
                .abi
                .name
                .as_ref()
                .map(|v: &syn::LitStr| v.value())
                .unwrap_or_else(|| "C".to_string());
            self.push_finding(
                FindingKind::ExternItem,
                None,
                span,
                UnsafePattern::ExternBlock,
                Severity::Medium,
            );
            if let Some(finding) = self.findings.last_mut() {
                finding.snippet = format!("extern \"{}\"", abi_str);
            }
        }
        visit::visit_item_foreign_mod(self, i);
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Analyze a crate directory for unsafe patterns.
pub fn analyze_crate(crate_dir: &Path) -> anyhow::Result<UnsafeSummary> {
    let (crate_name, crate_version) = read_crate_metadata(crate_dir)?;

    let src_dir = crate_dir.join("src");
    let mut all_findings: Vec<UnsafeFinding> = Vec::new();
    let mut files_scanned = 0;
    let mut total_unsafe_fns = 0;
    let mut total_unsafe_impls = 0;

    let search_dirs = if src_dir.exists() {
        vec![src_dir]
    } else {
        vec![crate_dir.to_path_buf()]
    };

    for dir in &search_dirs {
        for entry in walkdir::WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                files_scanned += 1;
                if let Ok(analysis) = analyze_file(path) {
                    total_unsafe_fns += analysis.unsafe_fn_count;
                    total_unsafe_impls += analysis.unsafe_impl_count;
                    all_findings.extend(analysis.findings);
                }
            }
        }
    }

    // Count patterns
    let mut pattern_counts: std::collections::HashMap<UnsafePattern, usize> =
        std::collections::HashMap::new();
    for f in &all_findings {
        *pattern_counts.entry(f.pattern).or_insert(0) += 1;
    }

    let mut patterns: Vec<PatternCount> = pattern_counts
        .into_iter()
        .map(|(pattern, count)| PatternCount { pattern, count })
        .collect();
    patterns.sort_by(|a, b| b.count.cmp(&a.count));

    let files_with_unsafe = all_findings
        .iter()
        .map(|f| f.file.clone())
        .collect::<std::collections::HashSet<_>>()
        .len();

    let risk_score = compute_risk_score(&patterns, files_scanned, all_findings.len());

    Ok(UnsafeSummary {
        crate_name,
        crate_version,
        total_unsafe_exprs: all_findings.len(),
        total_unsafe_fns,
        total_unsafe_impls,
        files_with_unsafe,
        files_scanned,
        patterns,
        findings: all_findings,
        risk_score,
    })
}

fn analyze_file(path: &Path) -> anyhow::Result<FileAnalysis> {
    let content = std::fs::read_to_string(path)?;
    analyze_source(path, &content)
}

fn analyze_source(path: &Path, content: &str) -> anyhow::Result<FileAnalysis> {
    let parsed = syn::parse_file(&content)?;
    let mut visitor = UnsafeVisitor {
        findings: Vec::new(),
        current_file: path.to_path_buf(),
        current_fn: String::new(),
        unsafe_depth: 0,
        unsafe_fn_count: 0,
        unsafe_impl_count: 0,
        source_lines: content.lines().map(|l| l.to_string()).collect(),
    };
    visitor.visit_file(&parsed);
    Ok(FileAnalysis {
        findings: visitor.findings,
        unsafe_fn_count: visitor.unsafe_fn_count,
        unsafe_impl_count: visitor.unsafe_impl_count,
    })
}

fn read_crate_metadata(crate_dir: &Path) -> anyhow::Result<(String, String)> {
    let cargo_toml = crate_dir.join("Cargo.toml");
    let content = std::fs::read_to_string(&cargo_toml)?;
    let parsed = content.parse::<toml::Value>()?;
    let package = parsed.get("package").and_then(|value| value.as_table());
    let name = package
        .and_then(|pkg| pkg.get("name"))
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| crate_dir.file_name().unwrap().to_string_lossy().to_string());

    let version = package
        .and_then(|pkg| pkg.get("version"))
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "0.0.0".to_string());

    Ok((name, version))
}

/// Compute a 0-100 risk score based on pattern distribution and density.
fn compute_risk_score(
    patterns: &[PatternCount],
    files_scanned: usize,
    total_findings: usize,
) -> f64 {
    if files_scanned == 0 || total_findings == 0 {
        return 0.0;
    }

    let _density = total_findings as f64 / files_scanned as f64;

    // Weight by pattern severity
    let severity_weight: f64 = patterns
        .iter()
        .map(|pc| {
            let w = match pc.pattern {
                UnsafePattern::Transmute => 3.0,
                UnsafePattern::UninitMemory => 3.0,
                UnsafePattern::UnreachableUnchecked => 3.0,
                UnsafePattern::InlineAsm => 2.5,
                UnsafePattern::PtrDereference => 2.0,
                UnsafePattern::PtrReadWrite => 2.0,
                UnsafePattern::UncheckedConversion => 2.0,
                UnsafePattern::UncheckedIndex => 1.5,
                UnsafePattern::SimdIntrinsic => 1.5,
                UnsafePattern::UnionAccess => 2.0,
                UnsafePattern::ExternBlock => 1.5,
                UnsafePattern::AddrOf => 0.5,
                UnsafePattern::OtherUnsafe => 0.3,
            };
            w * pc.count as f64
        })
        .sum();

    let raw = (severity_weight / files_scanned as f64).sqrt() * 10.0;
    raw.min(100.0)
}

#[cfg(test)]
mod tests {
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
unsafe fn top_level(ptr: *const u8) -> u8 {
    *ptr
}
impl S {
    unsafe fn method(ptr: *const u8) -> u8 {
        *ptr
    }
}
"#,
        );

        assert_eq!(analysis.unsafe_fn_count, 2);
        assert_eq!(analysis.unsafe_impl_count, 1);
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
union U {
    a: u32,
    b: f32,
}
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
    fn analyze_crate_reads_package_metadata_with_toml_parser() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            r#"
[package]
name = "real-name"
version = "1.2.3"
edition = "2021"
"#,
        )
        .unwrap();
        std::fs::write(dir.path().join("src/lib.rs"), "pub fn f() {}\n").unwrap();

        let summary = analyze_crate(dir.path()).unwrap();

        assert_eq!(summary.crate_name, "real-name");
        assert_eq!(summary.crate_version, "1.2.3");
    }
}
