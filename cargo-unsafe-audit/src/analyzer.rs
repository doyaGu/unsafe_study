//! unsafe-audit: Static unsafe pattern analyzer for Rust crates.
//!
//! Walks the AST of all `.rs` files in a crate using `syn` and classifies
//! unsafe code patterns into categories.

use std::path::{Path, PathBuf};
use syn::visit::{self, Visit};
use syn::spanned::Spanned;
use syn::{Expr, ImplItem, ItemFn, ExprUnsafe};
use serde::{Serialize, Deserialize};

/// A single unsafe pattern occurrence found in the codebase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsafeFinding {
    pub pattern: UnsafePattern,
    pub file: PathBuf,
    pub line: usize,
    pub column: usize,
    pub snippet: String,
    pub severity: Severity,
    pub context: String, // function name or module path
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
    source_lines: Vec<String>,
}

impl UnsafeVisitor {
    fn new(file: &Path) -> Self {
        let source = std::fs::read_to_string(file).unwrap_or_default();
        Self {
            findings: Vec::new(),
            current_file: file.to_path_buf(),
            current_fn: String::new(),
            unsafe_depth: 0,
            source_lines: source.lines().map(|l| l.to_string()).collect(),
        }
    }

    fn get_source_line(&self, line_num: usize) -> String {
        if line_num == 0 || line_num > self.source_lines.len() {
            return String::new();
        }
        self.source_lines[line_num - 1].trim().to_string()
    }

    fn classify_expr(&mut self, expr: &Expr, span: proc_macro2::Span) {
        let line = span.start().line;
        let col = span.start().column;
        let snippet = self.get_source_line(line);
        let snippet_trimmed = if snippet.len() > 120 {
            format!("{}...", &snippet[..117])
        } else if snippet.is_empty() {
            // Fallback to quote if source line unavailable
            let q = format!("{:?}", quote::quote!(#expr));
            if q.len() > 120 { format!("{}...", &q[..117]) } else { q }
        } else {
            snippet
        };

        let (pattern, severity) = Self::identify_pattern(expr);

        if self.unsafe_depth > 0 {
            self.findings.push(UnsafeFinding {
                pattern,
                file: self.current_file.clone(),
                line,
                column: col,
                snippet: snippet_trimmed,
                severity,
                context: self.current_fn.clone(),
            });
        }
    }

    fn identify_pattern(expr: &Expr) -> (UnsafePattern, Severity) {
        let code = format!("{:?}", quote::quote!(#expr));
        let code_lower = code.to_lowercase();

        // Check patterns in order of specificity

        // SIMD intrinsics
        if code.contains("_mm") || code.contains("_mm256") || code.contains("_mm512") {
            return (UnsafePattern::SimdIntrinsic, Severity::Medium);
        }

        // Transmute
        if code_lower.contains("transmute") {
            return (UnsafePattern::Transmute, Severity::High);
        }

        // Unchecked conversions
        if code_lower.contains("from_utf8_unchecked")
            || code_lower.contains("from_utf16_unchecked")
            || code_lower.contains("from_raw_parts")
        {
            return (UnsafePattern::UncheckedConversion, Severity::High);
        }

        // Unchecked indexing
        if code_lower.contains("get_unchecked") || code_lower.contains("get_unchecked_mut") {
            return (UnsafePattern::UncheckedIndex, Severity::Medium);
        }

        // Unreachable unchecked
        if code_lower.contains("unreachable_unchecked") {
            return (UnsafePattern::UnreachableUnchecked, Severity::High);
        }

        // Uninit memory
        if code_lower.contains("mem::zeroed")
            || code_lower.contains("mem::uninitialized")
            || code_lower.contains("assume_init")
        {
            return (UnsafePattern::UninitMemory, Severity::High);
        }

        // Ptr read/write
        if code_lower.contains("ptr::read")
            || code_lower.contains("ptr::write")
            || code_lower.contains("copy_nonoverlapping")
            || code_lower.contains("ptr::copy")
            || code_lower.contains("ptr::swap")
        {
            return (UnsafePattern::PtrReadWrite, Severity::Medium);
        }

        // Addr of
        if code_lower.contains("addr_of") {
            return (UnsafePattern::AddrOf, Severity::Low);
        }

        // Inline asm
        if code_lower.contains("arch::asm") || code_lower.contains("llvm_asm") {
            return (UnsafePattern::InlineAsm, Severity::High);
        }

        // Raw pointer dereference: look for * prefix on a path/field
        if let Expr::Unary(unary) = expr {
            if matches!(unary.op, syn::UnOp::Deref(_)) {
                return (UnsafePattern::PtrDereference, Severity::Medium);
            }
        }

        // Cast to pointer types
        if code.contains(" as *mut ") || code.contains(" as *const ") {
            return (UnsafePattern::PtrDereference, Severity::Medium);
        }

        // Default
        (UnsafePattern::OtherUnsafe, Severity::Low)
    }
}

impl<'ast> Visit<'ast> for UnsafeVisitor {
    fn visit_item_fn(&mut self, i: &'ast ItemFn) {
        let prev_fn = self.current_fn.clone();
        self.current_fn = i.sig.ident.to_string();
        if i.sig.unsafety.is_some() {
            self.unsafe_depth += 1;
        }
        visit::visit_item_fn(self, i);
        if i.sig.unsafety.is_some() {
            self.unsafe_depth = self.unsafe_depth.saturating_sub(1);
        }
        self.current_fn = prev_fn;
    }

    fn visit_expr_unsafe(&mut self, i: &'ast ExprUnsafe) {
        self.unsafe_depth += 1;
        // Visit children to find specific patterns
        visit::visit_expr_unsafe(self, i);
        self.unsafe_depth = self.unsafe_depth.saturating_sub(1);
    }

    fn visit_impl_item(&mut self, i: &'ast ImplItem) {
        if let ImplItem::Fn(fn_item) = i {
            let prev_fn = self.current_fn.clone();
            self.current_fn = fn_item.sig.ident.to_string();
            if fn_item.sig.unsafety.is_some() {
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

    fn visit_item_union(&mut self, i: &'ast syn::ItemUnion) {
        // Union fields are implicitly unsafe to access
        for field in i.fields.named.iter() {
            let span = field.ident.as_ref().map(|id: &syn::Ident| id.span()).unwrap_or_else(|| i.union_token.span);
            self.findings.push(UnsafeFinding {
                pattern: UnsafePattern::UnionAccess,
                file: self.current_file.clone(),
                line: span.start().line,
                column: span.start().column,
                snippet: format!("union {} field", i.ident),
                severity: Severity::Medium,
                context: i.ident.to_string(),
            });
        }
        visit::visit_item_union(self, i);
    }

    fn visit_item_foreign_mod(&mut self, i: &'ast syn::ItemForeignMod) {
        for item in &i.items {
            let span = match item {
                syn::ForeignItem::Fn(f) => f.sig.ident.span(),
                syn::ForeignItem::Static(s) => s.ident.span(),
                syn::ForeignItem::Type(t) => t.ident.span(),
                _ => i.abi.span(),
            };
            let abi_str = i.abi.name.as_ref().map(|v: &syn::LitStr| v.value()).unwrap_or_else(|| "C".to_string());
            self.findings.push(UnsafeFinding {
                pattern: UnsafePattern::ExternBlock,
                file: self.current_file.clone(),
                line: span.start().line,
                column: span.start().column,
                snippet: format!("extern \"{}\"", abi_str),
                severity: Severity::Medium,
                context: String::new(),
            });
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
                if let Ok(findings) = analyze_file(path) {
                    all_findings.extend(findings);
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

    let unsafe_fn_count = all_findings
        .iter()
        .filter(|f| f.pattern == UnsafePattern::OtherUnsafe)
        .count();

    let risk_score = compute_risk_score(&patterns, files_scanned, all_findings.len());

    Ok(UnsafeSummary {
        crate_name,
        crate_version,
        total_unsafe_exprs: all_findings.len(),
        total_unsafe_fns: unsafe_fn_count,
        total_unsafe_impls: 0,
        files_with_unsafe,
        files_scanned,
        patterns,
        findings: all_findings,
        risk_score,
    })
}

fn analyze_file(path: &Path) -> anyhow::Result<Vec<UnsafeFinding>> {
    let content = std::fs::read_to_string(path)?;
    let parsed = syn::parse_file(&content)?;
    let mut visitor = UnsafeVisitor::new(path);
    visitor.visit_file(&parsed);
    Ok(visitor.findings)
}

fn read_crate_metadata(crate_dir: &Path) -> anyhow::Result<(String, String)> {
    let cargo_toml = crate_dir.join("Cargo.toml");
    let content = std::fs::read_to_string(&cargo_toml)?;
    let name = content
        .lines()
        .find(|l| l.trim().starts_with("name"))
        .and_then(|l| l.split('=').nth(1))
        .map(|v| v.trim().trim_matches('"').trim().to_string())
        .unwrap_or_else(|| crate_dir.file_name().unwrap().to_string_lossy().to_string());

    let version = content
        .lines()
        .find(|l| l.trim().starts_with("version"))
        .and_then(|l| l.split('=').nth(1))
        .map(|v| v.trim().trim_matches('"').trim().to_string())
        .unwrap_or_else(|| "0.0.0".to_string());

    Ok((name, version))
}

/// Compute a 0-100 risk score based on pattern distribution and density.
fn compute_risk_score(patterns: &[PatternCount], files_scanned: usize, total_findings: usize) -> f64 {
    if files_scanned == 0 || total_findings == 0 {
        return 0.0;
    }

    let _density = total_findings as f64 / files_scanned as f64;

    // Weight by pattern severity
    let severity_weight: f64 = patterns.iter().map(|pc| {
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
    }).sum();

    let raw = (severity_weight / files_scanned as f64).sqrt() * 10.0;
    raw.min(100.0)
}
