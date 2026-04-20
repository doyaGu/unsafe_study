use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;

use crate::models::{CountPair, GeigerMetrics, GeigerResult};

// =========================================================================
// Phase 1: Geiger -- run cargo-geiger as subprocess, parse JSON
// =========================================================================

/// Run `cargo geiger --output-format Json` in the crate directory.
pub fn run_geiger(crate_dir: &Path) -> Result<GeigerResult> {
    // Check that cargo-geiger is available.
    let check = Command::new("cargo")
        .args(["geiger", "--help"])
        .output()
        .context("failed to check cargo-geiger availability")?;

    if !check.status.success() {
        bail!("cargo-geiger is not installed. Install with: cargo install cargo-geiger");
    }

    let output = Command::new("cargo")
        .args(["geiger", "--output-format", "Json"])
        .current_dir(crate_dir)
        .env("TERM", "dumb")
        .output()
        .context("running cargo geiger")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() && !stdout.contains("\"packages\"") {
        bail!(
            "cargo geiger failed (exit {:?}):\n{}",
            output.status.code(),
            &stderr[..stderr.len().min(500)]
        );
    }

    parse_geiger_json(&stdout)
}

/// Parse the JSON line from cargo-geiger output.
/// The output is mixed: cargo status lines + one JSON line starting with `{"packages"`.
fn parse_geiger_json(raw: &str) -> Result<GeigerResult> {
    // Find the JSON report line.
    let json_line = raw
        .lines()
        .find(|l| l.trim_start().starts_with("{\"packages\""))
        .context("no geiger JSON found in output (cargo-geiger may have failed to compile)")
        .map(|l| l.to_string())?;

    let value: serde_json::Value = serde_json::from_str(&json_line)
        .context("parsing geiger JSON")?;

    let packages = value["packages"]
        .as_array()
        .context("geiger JSON missing 'packages' array")?;

    if packages.is_empty() {
        bail!("geiger reported 0 packages");
    }

    // First package is the target crate itself.
    let pkg = &packages[0];
    let id = &pkg["package"]["id"];
    let crate_name = id["name"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let crate_version = id["version"]
        .as_str()
        .unwrap_or("?.?.?")
        .to_string();

    let unsafety = &pkg["unsafety"];
    let used = parse_metrics(&unsafety["used"]);
    let unused = parse_metrics(&unsafety["unused"]);
    let forbids_unsafe = unsafety["forbids_unsafe"]
        .as_bool()
        .unwrap_or(false);

    Ok(GeigerResult {
        crate_name,
        crate_version,
        used,
        unused,
        forbids_unsafe,
    })
}

fn parse_metrics(v: &serde_json::Value) -> GeigerMetrics {
    GeigerMetrics {
        functions: parse_count_pair(&v["functions"]),
        exprs: parse_count_pair(&v["exprs"]),
        item_impls: parse_count_pair(&v["item_impls"]),
        item_traits: parse_count_pair(&v["item_traits"]),
        methods: parse_count_pair(&v["methods"]),
    }
}

fn parse_count_pair(v: &serde_json::Value) -> CountPair {
    CountPair {
        safe: v["safe"].as_u64().unwrap_or(0),
        unsafe_: v["unsafe_"].as_u64().unwrap_or(0),
    }
}
