use std::collections::HashMap;
use syn::UseTree;

use super::UnsafeVisitor;

impl UnsafeVisitor {
    pub(super) fn resolve_path_segments(&self, path: &syn::Path) -> Vec<String> {
        let segments = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        if let Some(first) = segments.first() {
            if let Some(resolved) = self.resolve_alias(first) {
                let mut combined = resolved;
                combined.extend(segments.iter().skip(1).cloned());
                return combined;
            }
        }
        segments
    }

    fn resolve_alias(&self, alias: &str) -> Option<Vec<String>> {
        self.alias_scopes
            .iter()
            .rev()
            .find_map(|scope| scope.get(alias).cloned())
    }

    pub(super) fn current_alias_scope_mut(&mut self) -> &mut HashMap<String, Vec<String>> {
        self.alias_scopes
            .last_mut()
            .expect("alias scope stack is never empty")
    }
}

pub(super) fn collect_use_aliases(
    prefix: &[String],
    tree: &UseTree,
    aliases: &mut HashMap<String, Vec<String>>,
) {
    match tree {
        UseTree::Path(path) => {
            let mut next = prefix.to_vec();
            next.push(path.ident.to_string());
            collect_use_aliases(&next, &path.tree, aliases);
        }
        UseTree::Name(name) => {
            let mut full = prefix.to_vec();
            full.push(name.ident.to_string());
            aliases.insert(name.ident.to_string(), full);
        }
        UseTree::Rename(rename) => {
            let mut full = prefix.to_vec();
            full.push(rename.ident.to_string());
            aliases.insert(rename.rename.to_string(), full);
        }
        UseTree::Group(group) => {
            for item in &group.items {
                collect_use_aliases(prefix, item, aliases);
            }
        }
        UseTree::Glob(_) => {}
    }
}
