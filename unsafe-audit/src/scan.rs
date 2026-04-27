use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprUnsafe, File, ImplItem, Item, ItemFn, ItemImpl, Macro};
use walkdir::WalkDir;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanReport {
    pub sites: Vec<UnsafeSite>,
    pub summary: PatternSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsafeSite {
    pub id: String,
    pub file: String,
    pub line: usize,
    pub kind: String,
    pub pattern: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PatternSummary {
    pub unsafe_blocks: usize,
    pub unsafe_fns: usize,
    pub unsafe_impls: usize,
    pub extern_blocks: usize,
    pub ptr_ops: usize,
    pub transmutes: usize,
    pub unchecked_ops: usize,
    pub inline_asm: usize,
    pub other: usize,
}

pub fn scan_crate(crate_dir: &Path) -> Result<ScanReport> {
    let mut report = ScanReport::default();
    for entry in WalkDir::new(crate_dir)
        .into_iter()
        .filter_entry(|e| !is_ignored(e.path()))
    {
        let entry = entry?;
        if entry.file_type().is_file() && entry.path().extension().is_some_and(|e| e == "rs") {
            scan_file(crate_dir, entry.path(), &mut report)?;
        }
    }
    for (idx, site) in report.sites.iter_mut().enumerate() {
        site.id = format!("U{:04}", idx + 1);
    }
    Ok(report)
}

fn scan_file(crate_dir: &Path, path: &Path, report: &mut ScanReport) -> Result<()> {
    let source =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let file = syn::parse_file(&source).with_context(|| format!("parsing {}", path.display()))?;
    let relative = path
        .strip_prefix(crate_dir)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string();
    let mut visitor = UnsafeVisitor {
        file: relative,
        report,
    };
    visitor.visit_file(&file);
    Ok(())
}

fn is_ignored(path: &Path) -> bool {
    path.components().any(|component| {
        let name = component.as_os_str().to_string_lossy();
        matches!(
            name.as_ref(),
            "target" | ".git" | "fuzz" | "vendor" | ".cargo"
        )
    })
}

struct UnsafeVisitor<'a> {
    file: String,
    report: &'a mut ScanReport,
}

impl UnsafeVisitor<'_> {
    fn push(&mut self, line: usize, kind: &str, pattern: Option<&str>) {
        self.report.sites.push(UnsafeSite {
            id: String::new(),
            file: self.file.clone(),
            line,
            kind: kind.into(),
            pattern: pattern.map(str::to_string),
        });
        let summary = &mut self.report.summary;
        match (kind, pattern) {
            ("unsafe_block", _) => summary.unsafe_blocks += 1,
            ("unsafe_fn", _) => summary.unsafe_fns += 1,
            ("unsafe_impl", _) => summary.unsafe_impls += 1,
            ("extern_block", _) => summary.extern_blocks += 1,
            (_, Some("ptr_op")) => summary.ptr_ops += 1,
            (_, Some("transmute")) => summary.transmutes += 1,
            (_, Some("unchecked_op")) => summary.unchecked_ops += 1,
            (_, Some("inline_asm")) => summary.inline_asm += 1,
            _ => summary.other += 1,
        }
    }
}

impl<'ast> Visit<'ast> for UnsafeVisitor<'_> {
    fn visit_item(&mut self, node: &'ast Item) {
        if let Item::ForeignMod(item) = node {
            self.push(
                item.abi.extern_token.span.start().line,
                "extern_block",
                None,
            );
        }
        visit::visit_item(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        if node.sig.unsafety.is_some() {
            self.push(node.sig.fn_token.span.start().line, "unsafe_fn", None);
        }
        visit::visit_item_fn(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        if node.unsafety.is_some() {
            self.push(node.impl_token.span.start().line, "unsafe_impl", None);
        }
        visit::visit_item_impl(self, node);
    }

    fn visit_impl_item(&mut self, node: &'ast ImplItem) {
        if let ImplItem::Fn(method) = node {
            if method.sig.unsafety.is_some() {
                self.push(method.sig.fn_token.span.start().line, "unsafe_fn", None);
            }
        }
        visit::visit_impl_item(self, node);
    }

    fn visit_expr_unsafe(&mut self, node: &'ast ExprUnsafe) {
        self.push(
            node.unsafe_token.span.start().line,
            "unsafe_block",
            classify_block(&node.block),
        );
        visit::visit_expr_unsafe(self, node);
    }

    fn visit_expr(&mut self, node: &'ast Expr) {
        if let Some(pattern) = classify_expr(node) {
            self.push(node.span().start().line, "operation", Some(pattern));
        }
        visit::visit_expr(self, node);
    }

    fn visit_macro(&mut self, node: &'ast Macro) {
        let path = path_string(&node.path);
        if path == "asm" || path == "core::arch::asm" || path == "std::arch::asm" {
            self.push(
                node.path.span().start().line,
                "operation",
                Some("inline_asm"),
            );
        }
        visit::visit_macro(self, node);
    }
}

fn classify_block(block: &syn::Block) -> Option<&'static str> {
    for stmt in &block.stmts {
        if let syn::Stmt::Expr(expr, _) = stmt {
            if let Some(pattern) = classify_expr(expr) {
                return Some(pattern);
            }
        }
    }
    None
}

fn classify_expr(expr: &Expr) -> Option<&'static str> {
    match expr {
        Expr::Unary(unary) if matches!(unary.op, syn::UnOp::Deref(_)) => Some("ptr_op"),
        Expr::Call(call) => classify_path_expr(&call.func),
        Expr::MethodCall(call) => {
            let name = call.method.to_string();
            if name.contains("unchecked") {
                Some("unchecked_op")
            } else if matches!(name.as_str(), "read" | "write" | "copy_to" | "copy_from") {
                Some("ptr_op")
            } else {
                None
            }
        }
        Expr::Index(_) => Some("unchecked_op"),
        _ => None,
    }
}

fn classify_path_expr(expr: &Expr) -> Option<&'static str> {
    let Expr::Path(path) = expr else {
        return None;
    };
    let path = path_string(&path.path);
    if path.ends_with("transmute") {
        Some("transmute")
    } else if path.contains("unchecked") || path.ends_with("unreachable_unchecked") {
        Some("unchecked_op")
    } else if path.ends_with("read") || path.ends_with("write") {
        Some("ptr_op")
    } else {
        None
    }
}

fn path_string(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

#[allow(dead_code)]
fn _parse_source_for_tests(source: &str) -> Result<File> {
    Ok(syn::parse_file(source)?)
}

#[allow(dead_code)]
fn _normalize_path_for_tests(path: PathBuf) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
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
}
