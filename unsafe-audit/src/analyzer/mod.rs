mod classify;
mod summary;
mod visitor;

pub use summary::{FileScanIssue, UnsafeSite, UnsafeSiteUniverse, UnsafeSummary};
pub use visitor::{FindingKind, PatternCount, Severity, UnsafeFinding, UnsafePattern};

use anyhow::Result;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use crate::infra::ManifestReader;
use summary::compute_risk_score;
use visitor::{analyze_source, FileAnalysis, FindingKind as Kind};

pub fn analyze_crate(crate_dir: &Path) -> Result<UnsafeSummary> {
    let metadata = ManifestReader::read(crate_dir)?;
    let src_dir = crate_dir.join("src");
    let mut all_findings = Vec::new();
    let mut files_scanned: usize = 0;
    let mut scan_failures = Vec::new();

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
                match analyze_file(path) {
                    Ok(analysis) => all_findings.extend(analysis.findings),
                    Err(error) => scan_failures.push(FileScanIssue {
                        path: path.to_path_buf(),
                        error: error.to_string(),
                    }),
                }
            }
        }
    }

    let mut pattern_counts: HashMap<UnsafePattern, usize> = HashMap::new();
    for finding in &all_findings {
        *pattern_counts.entry(finding.pattern).or_insert(0) += 1;
    }

    let mut patterns: Vec<PatternCount> = pattern_counts
        .into_iter()
        .map(|(pattern, count)| PatternCount { pattern, count })
        .collect();
    patterns.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| a.pattern.to_string().cmp(&b.pattern.to_string()))
    });

    let files_with_unsafe = all_findings
        .iter()
        .map(|f| f.file.clone())
        .collect::<HashSet<_>>()
        .len();

    let risky_operation_findings = count_kind(&all_findings, Kind::RiskyOperation);
    let unsafe_block_findings = count_kind(&all_findings, Kind::UnsafeBlock);
    let unsafe_declaration_findings = count_kind(&all_findings, Kind::UnsafeFnDecl)
        + count_kind(&all_findings, Kind::UnsafeImplDecl);
    let extern_item_findings = count_kind(&all_findings, Kind::ExternItem);
    assign_site_ids(&metadata.name, crate_dir, &mut all_findings);
    let unsafe_sites = collect_unsafe_sites(&all_findings);
    let risk_score = compute_risk_score(
        &patterns,
        files_scanned.saturating_sub(scan_failures.len()),
        all_findings.len(),
    );

    Ok(UnsafeSummary {
        crate_name: metadata.name,
        crate_version: metadata.version,
        total_findings: all_findings.len(),
        risky_operation_findings,
        unsafe_block_findings,
        unsafe_declaration_findings,
        extern_item_findings,
        files_with_unsafe,
        files_scanned,
        files_failed_to_scan: scan_failures.len(),
        scan_failures,
        patterns,
        findings: all_findings,
        unsafe_sites: unsafe_sites.clone(),
        unsafe_site_universe: UnsafeSiteUniverse {
            site_total: unsafe_sites.len(),
            risky_operation_sites: unsafe_sites
                .iter()
                .filter(|site| site.kind == Kind::RiskyOperation)
                .count(),
            unsafe_block_sites: unsafe_sites
                .iter()
                .filter(|site| site.kind == Kind::UnsafeBlock)
                .count(),
            unsafe_declaration_sites: unsafe_sites
                .iter()
                .filter(|site| matches!(site.kind, Kind::UnsafeFnDecl | Kind::UnsafeImplDecl))
                .count(),
            extern_item_sites: unsafe_sites
                .iter()
                .filter(|site| site.kind == Kind::ExternItem)
                .count(),
        },
        risk_score,
    })
}

fn analyze_file(path: &Path) -> Result<FileAnalysis> {
    let content = std::fs::read_to_string(path)?;
    analyze_source(path, &content)
}

fn count_kind(findings: &[UnsafeFinding], kind: Kind) -> usize {
    findings
        .iter()
        .filter(|finding| finding.kind == kind)
        .count()
}

fn assign_site_ids(crate_name: &str, crate_dir: &Path, findings: &mut [UnsafeFinding]) {
    for finding in findings {
        let relative_file = finding
            .file
            .strip_prefix(crate_dir)
            .unwrap_or(&finding.file)
            .display()
            .to_string();
        finding.site_id = format!(
            "{}:{}:{}:{}:{}:{}",
            crate_name, relative_file, finding.line, finding.column, finding.kind, finding.pattern
        );
    }
}

fn collect_unsafe_sites(findings: &[UnsafeFinding]) -> Vec<UnsafeSite> {
    let mut sites = BTreeMap::new();
    for finding in findings {
        sites
            .entry(finding.site_id.clone())
            .or_insert_with(|| UnsafeSite {
                site_id: finding.site_id.clone(),
                kind: finding.kind,
                pattern: finding.pattern,
                file: finding.file.clone(),
                line: finding.line,
                column: finding.column,
                end_line: finding.end_line,
                end_column: finding.end_column,
                snippet: finding.snippet.clone(),
                severity: finding.severity,
                context: finding.context.clone(),
            });
    }
    sites.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn assigns_stable_site_ids_and_rolls_up_unique_sites() {
        let crate_dir = Path::new("/tmp/demo");
        let mut findings = vec![
            UnsafeFinding {
                site_id: String::new(),
                kind: FindingKind::UnsafeBlock,
                pattern: UnsafePattern::OtherUnsafe,
                file: PathBuf::from("/tmp/demo/src/lib.rs"),
                line: 10,
                column: 4,
                end_line: 10,
                end_column: 10,
                snippet: "unsafe {}".into(),
                severity: Severity::Low,
                context: "f".into(),
            },
            UnsafeFinding {
                site_id: String::new(),
                kind: FindingKind::RiskyOperation,
                pattern: UnsafePattern::Transmute,
                file: PathBuf::from("/tmp/demo/src/lib.rs"),
                line: 11,
                column: 8,
                end_line: 11,
                end_column: 17,
                snippet: "transmute".into(),
                severity: Severity::High,
                context: "f".into(),
            },
        ];

        assign_site_ids("demo", crate_dir, &mut findings);
        let sites = collect_unsafe_sites(&findings);

        assert_eq!(
            findings[0].site_id,
            "demo:src/lib.rs:10:4:unsafe_block:other_unsafe"
        );
        assert_eq!(
            findings[1].site_id,
            "demo:src/lib.rs:11:8:risky_operation:transmute"
        );
        assert_eq!(sites.len(), 2);
        assert_eq!(sites[0].site_id, findings[0].site_id);
        assert_eq!(sites[1].site_id, findings[1].site_id);
    }
}
