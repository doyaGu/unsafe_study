use super::shared::append_phase_failures;
use crate::domain::{CrateAuditResult, PhaseKind};

pub(crate) fn append_geiger(md: &mut String, crates: &[CrateAuditResult]) {
    let geiger_crates: Vec<_> = crates.iter().filter(|c| c.geiger.is_some()).collect();
    let geiger_failures: Vec<_> = crates
        .iter()
        .filter_map(|c| c.phase_issue(PhaseKind::Geiger).map(|issue| (c, issue)))
        .collect();
    if geiger_crates.is_empty() && geiger_failures.is_empty() {
        return;
    }

    md.push_str("## Phase 1: Geiger\n\n");
    md.push_str(
        "| Crate | Mode | Root Total | Root Used Exprs | Dependency Packages | Scan Gaps |\n",
    );
    md.push_str(
        "|-------|------|------------|-----------------|---------------------|-----------|\n",
    );
    for result in &geiger_crates {
        let geiger = result.geiger.as_ref().unwrap();
        let root = geiger.root_package_result();
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            result.target.display_name(),
            geiger.mode,
            root.map(|pkg| pkg.total_unsafe().to_string())
                .unwrap_or_else(|| "-".into()),
            root.map(|pkg| pkg.used.exprs.unsafe_.to_string())
                .unwrap_or_else(|| "-".into()),
            geiger.packages.iter().filter(|pkg| !pkg.is_root).count(),
            geiger.used_but_not_scanned_files.len(),
        ));
    }
    md.push('\n');

    for result in geiger_crates {
        let geiger = result.geiger.as_ref().unwrap();
        md.push_str(&format!("### {}\n\n", result.target.display_name()));
        md.push_str(&format!("- **Mode:** `{}`\n", geiger.mode));
        md.push_str(&format!(
            "- **Invocation:** `cargo {}` in `{}`\n",
            geiger.invocation.args.join(" "),
            geiger.invocation.working_dir.display()
        ));
        md.push_str(&format!(
            "- **Log:** `{}`\n",
            geiger.execution.log_path.display()
        ));
        if !geiger.packages_without_metrics.is_empty() {
            md.push_str(&format!(
                "- **Packages without metrics:** {}\n",
                geiger.packages_without_metrics.join(", ")
            ));
        }
        if !geiger.used_but_not_scanned_files.is_empty() {
            md.push_str("- **Used but not scanned files:**\n");
            for path in &geiger.used_but_not_scanned_files {
                md.push_str(&format!("  - `{}`\n", path.display()));
            }
        }
        let mut ranked = geiger.packages.iter().collect::<Vec<_>>();
        ranked.sort_by(|a, b| {
            b.total_unsafe()
                .cmp(&a.total_unsafe())
                .then_with(|| a.name.cmp(&b.name))
        });
        if !ranked.is_empty() {
            md.push_str("\n| Package | Root | Used Total | Unused Total | Total |\n");
            md.push_str("|---------|------|------------|--------------|-------|\n");
            for pkg in ranked.iter().take(10) {
                md.push_str(&format!(
                    "| {} {} | {} | {} | {} | {} |\n",
                    pkg.name,
                    pkg.version,
                    if pkg.is_root { "yes" } else { "no" },
                    pkg.used.total_unsafe(),
                    pkg.unused.total_unsafe(),
                    pkg.total_unsafe()
                ));
            }
        }
        md.push('\n');
    }
    append_phase_failures(md, "Geiger failures", &geiger_failures);
}
