use anyhow::{bail, Result};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::domain::{
    CommandInvocation, GeigerMetrics, GeigerMode, GeigerPackageResult, GeigerResult,
};
use crate::infra::{CommandRunner, CommandSpec, ManifestReader};

pub fn run(crate_dir: &Path, log_path: &Path) -> Result<GeigerResult> {
    let metadata = ManifestReader::read(crate_dir)?;
    let invocation = CommandInvocation {
        working_dir: crate_dir.to_path_buf(),
        args: vec!["geiger".into(), "--output-format".into(), "Json".into()],
    };
    let (execution, combined) = CommandRunner::run(&CommandSpec {
        program: "cargo".into(),
        args: invocation.args.clone(),
        env: BTreeMap::new(),
        current_dir: crate_dir.to_path_buf(),
        log_path: log_path.to_path_buf(),
    })?;

    if !execution.success {
        bail!(
            "cargo geiger failed (exit {:?})",
            execution.exit_code.unwrap_or(-1)
        );
    }

    let payload = extract_geiger_payload(&combined)?;
    let root_dir = crate_dir.canonicalize().ok();

    Ok(GeigerResult {
        mode: GeigerMode::DependencyAware,
        root_package: metadata.name.clone(),
        invocation,
        execution,
        packages: payload
            .packages
            .into_iter()
            .map(|entry| package_result(entry, &metadata.name, root_dir.as_deref()))
            .collect::<Result<Vec<_>>>()?,
        packages_without_metrics: payload
            .packages_without_metrics
            .into_iter()
            .map(|pkg| package_display_name(pkg.id))
            .collect(),
        used_but_not_scanned_files: payload
            .used_but_not_scanned_files
            .into_iter()
            .map(PathBuf::from)
            .collect(),
    })
}

fn extract_geiger_payload(combined: &str) -> Result<GeigerPayload> {
    for (idx, ch) in combined.char_indices() {
        if ch != '{' {
            continue;
        }
        let mut deserializer = serde_json::Deserializer::from_str(&combined[idx..]);
        if let Ok(payload) = GeigerPayload::deserialize(&mut deserializer) {
            return Ok(payload);
        }
    }
    Err(anyhow::anyhow!(
        "unable to extract cargo-geiger JSON payload from command output"
    ))
}

fn package_result(
    entry: GeigerPackageEntry,
    root_name: &str,
    root_dir: Option<&Path>,
) -> Result<GeigerPackageResult> {
    let source = source_string(entry.package.id.source.as_ref());
    let is_root = entry.package.id.name == root_name
        && source
            .as_ref()
            .map(|value| is_root_source(value, root_dir))
            .unwrap_or(false);

    Ok(GeigerPackageResult {
        name: entry.package.id.name,
        version: entry.package.id.version,
        source,
        is_root,
        used: entry.unsafety.used.into_metrics(),
        unused: entry.unsafety.unused.into_metrics(),
        forbids_unsafe: entry.unsafety.forbids_unsafe,
    })
}

fn is_root_source(source: &str, root_dir: Option<&Path>) -> bool {
    let Some(root_dir) = root_dir else {
        return false;
    };
    if let Some(path) = source.strip_prefix("path:") {
        return path.contains(&root_dir.to_string_lossy().replace('\\', "/"));
    }
    false
}

fn source_string(source: Option<&Value>) -> Option<String> {
    match source {
        Some(Value::Object(map)) => {
            if let Some(Value::String(path)) = map.get("Path") {
                Some(format!("path:{path}"))
            } else if let Some(Value::Object(registry)) = map.get("Registry") {
                let name = registry
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                Some(format!("registry:{name}"))
            } else {
                Some(source.unwrap().to_string())
            }
        }
        Some(other) => Some(other.to_string()),
        None => None,
    }
}

fn package_display_name(id: GeigerPackageId) -> String {
    format!("{} {}", id.name, id.version)
}

#[derive(Debug, Deserialize)]
struct GeigerPayload {
    packages: Vec<GeigerPackageEntry>,
    #[serde(default)]
    packages_without_metrics: Vec<GeigerPackageStub>,
    #[serde(default)]
    used_but_not_scanned_files: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct GeigerPackageEntry {
    package: GeigerPackage,
    unsafety: GeigerUnsafety,
}

#[derive(Debug, Deserialize)]
struct GeigerPackageStub {
    id: GeigerPackageId,
}

#[derive(Debug, Deserialize)]
struct GeigerPackage {
    id: GeigerPackageId,
}

#[derive(Debug, Deserialize)]
struct GeigerPackageId {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct GeigerUnsafety {
    used: GeigerCounterBlock,
    unused: GeigerCounterBlock,
    forbids_unsafe: bool,
}

#[derive(Debug, Deserialize, Default)]
struct GeigerCounterBlock {
    #[serde(default)]
    functions: crate::domain::CountPair,
    #[serde(default)]
    exprs: crate::domain::CountPair,
    #[serde(default)]
    item_impls: crate::domain::CountPair,
    #[serde(default)]
    item_traits: crate::domain::CountPair,
    #[serde(default)]
    methods: crate::domain::CountPair,
}

impl GeigerCounterBlock {
    fn into_metrics(self) -> GeigerMetrics {
        GeigerMetrics {
            functions: self.functions,
            exprs: self.exprs,
            item_impls: self.item_impls,
            item_traits: self.item_traits,
            methods: self.methods,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_final_geiger_json_after_log_noise() {
        let noisy = r#"Compiling demo v0.1.0
{"$message_type":"artifact","artifact":"ignore"}
{"packages":[{"package":{"id":{"name":"demo","version":"0.1.0","source":{"Path":"file:///tmp/demo"}}},"unsafety":{"used":{"functions":{"safe":0,"unsafe_":1},"exprs":{"safe":0,"unsafe_":2},"item_impls":{"safe":0,"unsafe_":0},"item_traits":{"safe":0,"unsafe_":0},"methods":{"safe":0,"unsafe_":0}},"unused":{"functions":{"safe":0,"unsafe_":0},"exprs":{"safe":0,"unsafe_":0},"item_impls":{"safe":0,"unsafe_":0},"item_traits":{"safe":0,"unsafe_":0},"methods":{"safe":0,"unsafe_":0}},"forbids_unsafe":false}}],"packages_without_metrics":[],"used_but_not_scanned_files":["README.md"]}
Finished dev build
"#;

        let payload = extract_geiger_payload(noisy).unwrap();
        assert_eq!(payload.packages.len(), 1);
        assert_eq!(payload.used_but_not_scanned_files, vec!["README.md"]);
    }
}
