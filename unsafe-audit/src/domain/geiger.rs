use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::{CommandInvocation, ExecutionOutcome};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CountPair {
    pub safe: u64,
    #[serde(rename = "unsafe_")]
    pub unsafe_: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeigerMetrics {
    pub functions: CountPair,
    pub exprs: CountPair,
    pub item_impls: CountPair,
    pub item_traits: CountPair,
    pub methods: CountPair,
}

impl GeigerMetrics {
    pub fn total_unsafe(&self) -> u64 {
        self.functions.unsafe_
            + self.exprs.unsafe_
            + self.item_impls.unsafe_
            + self.item_traits.unsafe_
            + self.methods.unsafe_
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GeigerMode {
    DependencyAware,
}

impl std::fmt::Display for GeigerMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GeigerMode::DependencyAware => write!(f, "dependency_aware"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeigerPackageResult {
    pub name: String,
    pub version: String,
    pub source: Option<String>,
    pub is_root: bool,
    pub used: GeigerMetrics,
    pub unused: GeigerMetrics,
    pub forbids_unsafe: bool,
}

impl GeigerPackageResult {
    pub fn total_unsafe(&self) -> u64 {
        self.used.total_unsafe() + self.unused.total_unsafe()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeigerResult {
    pub mode: GeigerMode,
    pub root_package: String,
    pub invocation: CommandInvocation,
    pub execution: ExecutionOutcome,
    pub packages: Vec<GeigerPackageResult>,
    pub packages_without_metrics: Vec<String>,
    pub used_but_not_scanned_files: Vec<PathBuf>,
}

impl GeigerResult {
    pub fn root_package_result(&self) -> Option<&GeigerPackageResult> {
        self.packages.iter().find(|pkg| pkg.is_root)
    }
}
