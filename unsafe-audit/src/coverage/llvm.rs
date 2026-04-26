use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExecutedRange {
    pub(super) relative_file: PathBuf,
    pub(super) start_line: usize,
    pub(super) start_column: usize,
    pub(super) end_line: usize,
    pub(super) end_column: usize,
}

#[derive(Debug, Deserialize)]
struct LlvmCoverageExport {
    data: Vec<LlvmCoverageData>,
}

#[derive(Debug, Deserialize)]
struct LlvmCoverageData {
    files: Vec<LlvmCoverageFile>,
}

#[derive(Debug, Deserialize)]
struct LlvmCoverageFile {
    filename: String,
    segments: Vec<LlvmCoverageSegment>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct LlvmCoverageSegment(usize, usize, u64, bool, bool, bool);

pub(super) fn load_executed_ranges(
    crate_dir: &Path,
    coverage_json: &Path,
) -> anyhow::Result<Vec<ExecutedRange>> {
    let content = fs::read_to_string(coverage_json)?;
    let export: LlvmCoverageExport = serde_json::from_str(&content)?;
    let mut ranges = Vec::new();
    for data in export.data {
        for file in data.files {
            let path = Path::new(&file.filename);
            let relative_file = match path.strip_prefix(crate_dir) {
                Ok(relative) => relative.to_path_buf(),
                Err(_) => continue,
            };
            for window in file.segments.windows(2) {
                let current = &window[0];
                let next = &window[1];
                if current.3 && current.2 > 0 {
                    ranges.push(ExecutedRange {
                        relative_file: relative_file.clone(),
                        start_line: current.0,
                        start_column: current.1,
                        end_line: next.0,
                        end_column: next.1,
                    });
                }
            }
        }
    }
    Ok(ranges)
}
