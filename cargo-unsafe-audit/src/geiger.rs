use anyhow::{Context, Result};
use geiger::IncludeTests;
use std::path::Path;
use walkdir::WalkDir;

use crate::models::{GeigerMetrics, GeigerResult};

// =========================================================================
// Phase 1: Geiger -- scan .rs files via geiger lib API
// =========================================================================

/// Scan all `.rs` source files in a crate directory for unsafe usage.
///
/// Uses the `geiger` library directly (no subprocess), walking the crate's
/// `src/` directory and any top-level `.rs` files, aggregating counts.
pub fn run_geiger(crate_dir: &Path) -> Result<GeigerResult> {
    let crate_name = crate_dir
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or("unknown".into());

    let mut used = GeigerMetrics::default();
    let mut forbids_unsafe = false;
    let mut files_scanned = 0u64;

    let src_dir = crate_dir.join("src");
    let scan_dirs: Vec<&Path> = if src_dir.exists() {
        vec![&src_dir]
    } else {
        // Fallback: scan the crate dir itself (for simple crates with lib.rs at root)
        vec![crate_dir]
    };

    for dir in &scan_dirs {
        for entry in WalkDir::new(dir) {
            let entry = entry.context("walking source directory")?;
            let path = entry.path();

            if path.extension().map_or(true, |e| e != "rs") {
                continue;
            }

            match geiger::find_unsafe_in_file(path, IncludeTests::No) {
                Ok(metrics) => {
                    files_scanned += 1;
                    if metrics.forbids_unsafe {
                        forbids_unsafe = true;
                    }
                    merge_counter_block(&mut used, &metrics.counters);
                }
                Err(_) => {
                    // Skip files that fail to parse (e.g. generated, non-compilable)
                    continue;
                }
            }
        }
    }

    // Read version from Cargo.toml if possible
    let crate_version = read_crate_version(crate_dir);

    Ok(GeigerResult {
        crate_name,
        crate_version,
        used,
        unused: GeigerMetrics::default(), // lib API doesn't distinguish used/unused
        forbids_unsafe,
        files_scanned,
    })
}

fn merge_counter_block(target: &mut GeigerMetrics, cb: &cargo_geiger_serde::CounterBlock) {
    target.functions.safe += cb.functions.safe;
    target.functions.unsafe_ += cb.functions.unsafe_;
    target.exprs.safe += cb.exprs.safe;
    target.exprs.unsafe_ += cb.exprs.unsafe_;
    target.item_impls.safe += cb.item_impls.safe;
    target.item_impls.unsafe_ += cb.item_impls.unsafe_;
    target.item_traits.safe += cb.item_traits.safe;
    target.item_traits.unsafe_ += cb.item_traits.unsafe_;
    target.methods.safe += cb.methods.safe;
    target.methods.unsafe_ += cb.methods.unsafe_;
}

fn read_crate_version(crate_dir: &Path) -> String {
    let toml_path = crate_dir.join("Cargo.toml");
    let content = std::fs::read_to_string(&toml_path).unwrap_or_default();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("version") {
            if let Some(eq) = trimmed.find('=') {
                let v = trimmed[eq + 1..].trim().trim_matches('"').trim();
                return v.to_string();
            }
        }
        // Stop at first section
        if trimmed.starts_with('[') {
            break;
        }
    }
    "?.?.?".into()
}
