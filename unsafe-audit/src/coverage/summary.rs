use crate::domain::{UnsafeCoverageState, UnsafeCoverageSummary, UnsafeSiteReach};

#[derive(Debug, Clone, Copy)]
pub(super) struct DynamicEvidence {
    pub(super) dynamic_phase_present: bool,
    pub(super) computed_from_coverage: bool,
    pub(super) miri_total_locations: usize,
    pub(super) fuzz_total_locations: usize,
}

pub(super) fn static_universe_summary(total_sites: usize) -> UnsafeCoverageSummary {
    UnsafeCoverageSummary {
        state: UnsafeCoverageState::StaticUniverseOnly,
        total_sites,
        reached_by_miri: None,
        reached_by_fuzz: None,
        reached_by_any: None,
        triggered_by_miri: None,
        triggered_by_fuzz: None,
        triggered_by_any: None,
        unmapped_triggered_by_miri: None,
        unmapped_triggered_by_fuzz: None,
        unreached: None,
    }
}

pub(super) fn dynamic_summary(
    total_sites: usize,
    site_reach: &[UnsafeSiteReach],
    evidence: DynamicEvidence,
) -> UnsafeCoverageSummary {
    let counts = ReachCounts::from_sites(site_reach);
    UnsafeCoverageSummary {
        state: if evidence.computed_from_coverage {
            UnsafeCoverageState::Computed
        } else {
            UnsafeCoverageState::TriggeredEvidenceOnly
        },
        total_sites,
        reached_by_miri: Some(counts.reached_by_miri),
        reached_by_fuzz: Some(counts.reached_by_fuzz),
        reached_by_any: Some(counts.reached_by_any),
        triggered_by_miri: Some(counts.triggered_by_miri),
        triggered_by_fuzz: Some(counts.triggered_by_fuzz),
        triggered_by_any: Some(counts.triggered_by_any),
        unmapped_triggered_by_miri: Some(
            evidence
                .miri_total_locations
                .saturating_sub(counts.reached_by_miri),
        ),
        unmapped_triggered_by_fuzz: Some(
            evidence
                .fuzz_total_locations
                .saturating_sub(counts.reached_by_fuzz),
        ),
        unreached: None,
    }
}

struct ReachCounts {
    reached_by_miri: usize,
    reached_by_fuzz: usize,
    reached_by_any: usize,
    triggered_by_miri: usize,
    triggered_by_fuzz: usize,
    triggered_by_any: usize,
}

impl ReachCounts {
    fn from_sites(site_reach: &[UnsafeSiteReach]) -> Self {
        Self {
            reached_by_miri: site_reach
                .iter()
                .filter(|site| site.reached_by_miri)
                .count(),
            reached_by_fuzz: site_reach
                .iter()
                .filter(|site| site.reached_by_fuzz)
                .count(),
            reached_by_any: site_reach
                .iter()
                .filter(|site| site.reached_by_miri || site.reached_by_fuzz)
                .count(),
            triggered_by_miri: site_reach
                .iter()
                .filter(|site| site.triggered_by_miri)
                .count(),
            triggered_by_fuzz: site_reach
                .iter()
                .filter(|site| site.triggered_by_fuzz)
                .count(),
            triggered_by_any: site_reach
                .iter()
                .filter(|site| site.triggered_by_miri || site.triggered_by_fuzz)
                .count(),
        }
    }
}
