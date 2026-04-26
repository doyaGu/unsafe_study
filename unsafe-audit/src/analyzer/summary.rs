use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::visitor::{PatternCount, UnsafeFinding, UnsafePattern};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileScanIssue {
    pub path: PathBuf,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsafeSite {
    pub site_id: String,
    pub kind: super::visitor::FindingKind,
    pub pattern: UnsafePattern,
    pub file: PathBuf,
    pub line: usize,
    pub column: usize,
    pub end_line: usize,
    pub end_column: usize,
    pub snippet: String,
    pub severity: super::visitor::Severity,
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UnsafeSiteUniverse {
    pub site_total: usize,
    pub risky_operation_sites: usize,
    pub unsafe_block_sites: usize,
    pub unsafe_declaration_sites: usize,
    pub extern_item_sites: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsafeSummary {
    pub crate_name: String,
    pub crate_version: String,
    pub total_findings: usize,
    pub risky_operation_findings: usize,
    pub unsafe_block_findings: usize,
    pub unsafe_declaration_findings: usize,
    pub extern_item_findings: usize,
    pub files_with_unsafe: usize,
    pub files_scanned: usize,
    pub files_failed_to_scan: usize,
    pub scan_failures: Vec<FileScanIssue>,
    pub patterns: Vec<PatternCount>,
    pub findings: Vec<UnsafeFinding>,
    pub unsafe_sites: Vec<UnsafeSite>,
    pub unsafe_site_universe: UnsafeSiteUniverse,
    pub risk_score: f64,
}

pub fn compute_risk_score(
    patterns: &[PatternCount],
    files_scanned: usize,
    total_findings: usize,
) -> f64 {
    if files_scanned == 0 || total_findings == 0 {
        return 0.0;
    }

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
