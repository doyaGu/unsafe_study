use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::app::ExplorationOptions;
use crate::domain::{
    CrateAuditResult, HarnessCandidate, HarnessCandidateKind, HarnessValidationStatus,
    UnsafeSiteReach,
};

pub(super) fn generate_harness_candidates(
    result: &CrateAuditResult,
    exploration: &ExplorationOptions,
    ranked_sites: &[String],
    combined: &BTreeMap<String, UnsafeSiteReach>,
) -> Result<Vec<HarnessCandidate>> {
    let Some(command) = &exploration.llm_provider_cmd else {
        return Ok(vec![disabled_candidate(result, ranked_sites)]);
    };
    let prompt = HarnessPrompt {
        crate_name: result.target.display_name().to_string(),
        crate_dir: result.target.dir.display().to_string(),
        target_site_ids: super::reach::unreached_targets(ranked_sites, combined),
        public_api_candidates: discover_public_api_candidates(&result.target.dir)
            .unwrap_or_else(|_| Vec::new()),
        constraints: vec![
            "Return JSON with a `candidates` array.".into(),
            "Generate auditable patch drafts only; do not assume the tool will edit source files."
                .into(),
            "Prefer parser-like APIs accepting &str or &[u8].".into(),
        ],
    };
    let response = call_provider(command, &prompt)?;
    Ok(response.candidates)
}

pub(super) fn disabled_candidate(
    result: &CrateAuditResult,
    ranked_sites: &[String],
) -> HarnessCandidate {
    HarnessCandidate {
        id: format!("{}-harness-disabled", result.target.display_name()),
        kind: HarnessCandidateKind::FuzzTarget,
        target_api: None,
        target_site_ids: ranked_sites.iter().take(5).cloned().collect(),
        patch_text: String::new(),
        rationale: "Harness generation was requested without a configured provider; no source files were modified.".into(),
        suggested_command: "--llm-provider-cmd <command>".into(),
        validation_status: HarnessValidationStatus::Disabled,
    }
}

#[derive(Debug, Serialize)]
struct HarnessPrompt {
    crate_name: String,
    crate_dir: String,
    target_site_ids: Vec<String>,
    public_api_candidates: Vec<String>,
    constraints: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct HarnessProviderResponse {
    candidates: Vec<HarnessCandidate>,
}

fn call_provider(command: &str, prompt: &HarnessPrompt) -> Result<HarnessProviderResponse> {
    let mut parts = command.split_whitespace();
    let program = parts.next().context("empty LLM provider command")?;
    let args = parts.collect::<Vec<_>>();
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning LLM provider `{command}`"))?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(serde_json::to_string_pretty(prompt)?.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        anyhow::bail!(
            "LLM provider exited with {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    serde_json::from_slice(&output.stdout).context("parsing LLM provider JSON response")
}

fn discover_public_api_candidates(crate_dir: &Path) -> Result<Vec<String>> {
    let output = Command::new("cargo")
        .args([
            "rustdoc",
            "--lib",
            "--",
            "-Z",
            "unstable-options",
            "--output-format",
            "json",
        ])
        .current_dir(crate_dir)
        .output()
        .context("running cargo rustdoc for API discovery")?;
    if !output.status.success() {
        return Ok(Vec::new());
    }
    // Keep v6 conservative: use rustdoc generation as a capability check and
    // fall back to a small source scan for human-readable prompt candidates.
    source_api_candidates(crate_dir)
}

fn source_api_candidates(crate_dir: &Path) -> Result<Vec<String>> {
    let mut candidates = Vec::new();
    let src = crate_dir.join("src");
    if !src.exists() {
        return Ok(candidates);
    }
    for entry in walkdir::WalkDir::new(src)
        .into_iter()
        .filter_map(|entry| entry.ok())
    {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let content = std::fs::read_to_string(path)?;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("pub fn ") || trimmed.starts_with("pub unsafe fn ") {
                candidates.push(trimmed.chars().take(160).collect());
            }
        }
    }
    candidates.sort();
    candidates.dedup();
    Ok(candidates.into_iter().take(30).collect())
}
