mod aliases;
mod model;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprUnsafe, ImplItem, ItemFn, ItemImpl};

use super::classify::{identify_expr_pattern, identify_macro_pattern};
use aliases::collect_use_aliases;
pub use model::{FindingKind, PatternCount, Severity, UnsafeFinding, UnsafePattern};

pub(crate) struct FileAnalysis {
    pub findings: Vec<UnsafeFinding>,
}

struct UnsafeVisitor {
    findings: Vec<UnsafeFinding>,
    current_file: PathBuf,
    current_fn: String,
    unsafe_depth: usize,
    alias_scopes: Vec<HashMap<String, Vec<String>>>,
    source_lines: Vec<String>,
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
        let end_line = span.end().line;
        let end_col = span.end().column;
        let snippet = self.get_source_line(line);
        let snippet_trimmed = if snippet.len() > 120 {
            format!("{}...", &snippet[..117])
        } else if snippet.is_empty() {
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
            site_id: String::new(),
            kind,
            pattern,
            file: self.current_file.clone(),
            line,
            column: col,
            end_line,
            end_column: end_col,
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

        let (pattern, severity) =
            identify_expr_pattern(expr, |call| self.call_name_and_path(&call.func));
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

    fn call_name_and_path(&self, func: &Expr) -> Option<(String, Vec<String>)> {
        match func {
            Expr::Path(path) => {
                let segments = self.resolve_path_segments(&path.path);
                let name = segments.last()?.clone();
                Some((name, segments))
            }
            _ => None,
        }
    }
}

impl<'ast> Visit<'ast> for UnsafeVisitor {
    fn visit_block(&mut self, block: &'ast syn::Block) {
        self.alias_scopes.push(HashMap::new());
        visit::visit_block(self, block);
        self.alias_scopes.pop();
    }

    fn visit_item_fn(&mut self, i: &'ast ItemFn) {
        let prev_fn = self.current_fn.clone();
        self.current_fn = i.sig.ident.to_string();
        if i.sig.unsafety.is_some() {
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
        visit::visit_expr_unsafe(self, i);
        self.unsafe_depth = self.unsafe_depth.saturating_sub(1);
    }

    fn visit_item_impl(&mut self, i: &'ast ItemImpl) {
        if let Some(unsafety) = i.unsafety {
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
            let resolved = self.resolve_path_segments(&i.path);
            let (pattern, severity) = identify_macro_pattern(i, &resolved);
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

    fn visit_item_use(&mut self, i: &'ast syn::ItemUse) {
        let mut aliases = HashMap::new();
        collect_use_aliases(&[], &i.tree, &mut aliases);
        self.current_alias_scope_mut().extend(aliases);
        visit::visit_item_use(self, i);
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

pub(crate) fn analyze_source(path: &Path, content: &str) -> anyhow::Result<FileAnalysis> {
    let parsed = syn::parse_file(content)?;
    let mut visitor = UnsafeVisitor {
        findings: Vec::new(),
        current_file: path.to_path_buf(),
        current_fn: String::new(),
        unsafe_depth: 0,
        alias_scopes: vec![HashMap::new()],
        source_lines: content.lines().map(|l| l.to_string()).collect(),
    };
    visitor.visit_file(&parsed);
    Ok(FileAnalysis {
        findings: visitor.findings,
    })
}

#[cfg(test)]
mod tests;
