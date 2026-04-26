use std::path::Path;

use crate::analyzer::UnsafeSummary;

use super::llvm::ExecutedRange;
use super::location::SourceLocation;

pub(super) fn match_site_index(
    crate_dir: &Path,
    patterns: &UnsafeSummary,
    location: &SourceLocation,
) -> Option<usize> {
    patterns.unsafe_sites.iter().position(|site| {
        let site_file = site
            .file
            .strip_prefix(crate_dir)
            .unwrap_or(&site.file)
            .to_path_buf();
        site_file == location.relative_file
            && line_column_in_range(
                location.line,
                location.column,
                site.line,
                site.column,
                site.end_line,
                site.end_column,
            )
    })
}

pub(super) fn match_site_index_for_range(
    crate_dir: &Path,
    patterns: &UnsafeSummary,
    range: &ExecutedRange,
) -> Option<usize> {
    patterns.unsafe_sites.iter().position(|site| {
        let site_file = site
            .file
            .strip_prefix(crate_dir)
            .unwrap_or(&site.file)
            .to_path_buf();
        site_file == range.relative_file
            && ranges_overlap(
                site.line,
                site.column,
                site.end_line,
                site.end_column,
                range.start_line,
                range.start_column,
                range.end_line,
                range.end_column,
            )
    })
}

fn line_column_in_range(
    line: usize,
    column: usize,
    start_line: usize,
    start_column: usize,
    end_line: usize,
    end_column: usize,
) -> bool {
    let after_start = line > start_line || (line == start_line && column >= start_column);
    let before_end = line < end_line || (line == end_line && column <= end_column);
    after_start && before_end
}

fn ranges_overlap(
    a_start_line: usize,
    a_start_column: usize,
    a_end_line: usize,
    a_end_column: usize,
    b_start_line: usize,
    b_start_column: usize,
    b_end_line: usize,
    b_end_column: usize,
) -> bool {
    let a_starts_before_b_ends =
        a_start_line < b_end_line || (a_start_line == b_end_line && a_start_column <= b_end_column);
    let b_starts_before_a_ends =
        b_start_line < a_end_line || (b_start_line == a_end_line && b_start_column <= a_end_column);
    a_starts_before_b_ends && b_starts_before_a_ends
}
