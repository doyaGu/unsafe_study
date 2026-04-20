use anyhow::{bail, Context, Result};
use proc_macro2::Span;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use syn::visit::{self, Visit};
use syn::*;

use crate::models::{FuzzTarget, InputKind};

// =========================================================================
// API Discovery -- scan a crate for fuzzable public functions
// =========================================================================

struct ApiVisitor {
    crate_name: String,
    current_file: PathBuf,
    current_mod: Vec<String>,
    targets: Vec<FuzzTarget>,
    /// Track impl blocks so we can resolve method targets
    current_impl_subject: Option<String>,
}

impl ApiVisitor {
    fn new(crate_name: &str, file: &Path) -> Self {
        Self {
            crate_name: crate_name.to_string(),
            current_file: file.to_path_buf(),
            current_mod: Vec::new(),
            targets: Vec::new(),
            current_impl_subject: None,
        }
    }

    fn classify_input(ty: &Type) -> Option<InputKind> {
        let code = format!("{}", quote::quote!(#ty));
        let code_trimmed = code.replace(' ', "");

        // &[u8]
        if code_trimmed.contains("&[u8]") || code_trimmed.contains("Vec<u8>") {
            return Some(InputKind::Bytes);
        }
        // &str / String
        if code_trimmed.contains("&str") || code_trimmed == "String" || code_trimmed.contains("String") {
            return Some(InputKind::Str);
        }
        // impl Read / impl std::io::Read / impl io::Read
        if code_trimmed.contains("implRead")
            || code_trimmed.contains("implstd::io::Read")
            || code_trimmed.contains("implio::Read")
            || code_trimmed.contains("Read")
        {
            // Only if it's actually an `impl Read` parameter
            if code_trimmed.starts_with("impl") && code_trimmed.contains("Read") {
                return Some(InputKind::Read);
            }
        }
        None
    }

    fn is_fuzzable_fn(sig: &Signature) -> Option<InputKind> {
        // Look for functions that take at least one parameter that is byte-like
        for input in &sig.inputs {
            if let FnArg::Typed(pat_type) = input {
                if let Some(kind) = Self::classify_input(&pat_type.ty) {
                    return Some(kind);
                }
            }
        }
        None
    }

    fn fn_path(&self, ident: &Ident) -> String {
        let mut parts = Vec::new();
        parts.push(self.crate_name.clone());
        for m in &self.current_mod {
            parts.push(m.clone());
        }
        parts.push(ident.to_string());
        parts.join("::")
    }

    fn calculate_priority(sig: &Signature, input_kind: InputKind) -> u8 {
        let mut p = 50u8;
        // Prefer Bytes (most direct fuzz) then Str then Read
        match input_kind {
            InputKind::Bytes => p += 20,
            InputKind::Str => p += 15,
            InputKind::Read => p += 10,
            InputKind::Other => {}
        }
        // Prefer shorter parameter lists (simpler API)
        if sig.inputs.len() <= 2 {
            p += 10;
        }
        // Prefer functions that return Result or a parsed type
        if let ReturnType::Type(_, ty) = &sig.output {
            let code = format!("{}", quote::quote!(#ty));
            if code.contains("Result") || code.contains("Option") || code.contains("parse") {
                p += 10;
            }
        }
        p.min(100)
    }
}

impl<'ast> Visit<'ast> for ApiVisitor {
    fn visit_item_mod(&mut self, i: &'ast ItemMod) {
        self.current_mod.push(i.ident.to_string());
        visit::visit_item_mod(self, i);
        self.current_mod.pop();
    }

    fn visit_item_fn(&mut self, i: &'ast ItemFn) {
        let vis = &i.vis;
        // Only consider public functions
        if matches!(vis, Visibility::Public(_)) {
            if let Some(input_kind) = Self::is_fuzzable_fn(&i.sig) {
                let full_path = match &self.current_impl_subject {
                    Some(subject) => format!("{}::{}::{}", self.crate_name, subject, i.sig.ident),
                    None => self.fn_path(&i.sig.ident),
                };
                let priority = Self::calculate_priority(&i.sig, input_kind);
                self.targets.push(FuzzTarget {
                    name: i.sig.ident.to_string(),
                    full_path,
                    input_kind,
                    is_method: self.current_impl_subject.is_some(),
                    return_type: match &i.sig.output {
                        ReturnType::Default => None,
                        ReturnType::Type(_, ty) => Some(format!("{}", quote::quote!(#ty))),
                    },
                    file: self.current_file.clone(),
                    line: i.sig.ident.span().start().line,
                    priority,
                });
            }
        }
        visit::visit_item_fn(self, i);
    }

    fn visit_item_impl(&mut self, i: &'ast ItemImpl) {
        // Track what type we're implementing on
        if let Type::Path(tp) = &*i.self_ty {
            self.current_impl_subject = Some(tp.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default());
        }
        visit::visit_item_impl(self, i);
        self.current_impl_subject = None;
    }
}

/// Discover fuzzable public APIs in a crate.
pub fn discover_apis(crate_dir: &Path, crate_name: &str) -> Result<Vec<FuzzTarget>> {
    let src_dir = crate_dir.join("src");
    let search_dir = if src_dir.exists() { &src_dir } else { crate_dir };

    let mut all_targets = Vec::new();

    for entry in walkdir::WalkDir::new(search_dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            if let Ok(parsed) = syn::parse_file(&content) {
                let mut visitor = ApiVisitor::new(crate_name, path);
                visitor.visit_file(&parsed);
                all_targets.extend(visitor.targets);
            }
        }
    }

    // Sort by priority (highest first)
    all_targets.sort_by(|a, b| b.priority.cmp(&a.priority));

    // Deduplicate by full_path
    let mut seen = std::collections::HashSet::new();
    all_targets.retain(|t| seen.insert(t.full_path.clone()));

    Ok(all_targets)
}
