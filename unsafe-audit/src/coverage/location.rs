use std::fs;
use std::path::{Path, PathBuf};

use crate::domain::{FuzzStatus, FuzzTargetResult, MiriResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SourceLocation {
    pub(super) relative_file: PathBuf,
    pub(super) line: usize,
    pub(super) column: usize,
}

pub(super) fn miri_locations(miri: &MiriResult) -> Vec<SourceLocation> {
    let mut locations = Vec::new();
    if let Ok(content) = fs::read_to_string(&miri.primary_run.execution.log_path) {
        locations.extend(extract_locations_from_text(
            &miri.invocation.working_dir,
            &content,
        ));
    }
    if let Some(location) = &miri.primary_run.ub_location {
        if let Some(parsed) = parse_location(location) {
            locations.push(parsed);
        }
    }
    if let Some(baseline) = &miri.baseline_run {
        if let Ok(content) = fs::read_to_string(&baseline.execution.log_path) {
            locations.extend(extract_locations_from_text(
                &miri.invocation.working_dir,
                &content,
            ));
        }
        if let Some(location) = &baseline.ub_location {
            if let Some(parsed) = parse_location(location) {
                locations.push(parsed);
            }
        }
    }
    locations.sort_by(|a, b| {
        a.relative_file
            .cmp(&b.relative_file)
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
    });
    locations.dedup();
    locations
}

pub(super) fn fuzz_locations(crate_dir: &Path, target: &FuzzTargetResult) -> Vec<SourceLocation> {
    if target.status != FuzzStatus::Panic {
        return Vec::new();
    }
    let execution = match &target.execution {
        Some(execution) => execution,
        None => return Vec::new(),
    };
    let content = match fs::read_to_string(&execution.log_path) {
        Ok(content) => content,
        Err(_) => return Vec::new(),
    };
    extract_locations_from_text(crate_dir, &content)
}

fn extract_locations_from_text(crate_dir: &Path, text: &str) -> Vec<SourceLocation> {
    let mut locations = Vec::new();
    for line in text.lines() {
        if let Some(location) = parse_crate_location(crate_dir, line) {
            locations.push(location);
        }
    }
    locations
}

fn parse_crate_location(crate_dir: &Path, line: &str) -> Option<SourceLocation> {
    let marker = ".rs:";
    let marker_index = line.find(marker)?;
    let path_end = marker_index + 3;
    let start = line[..marker_index]
        .rfind(|c: char| c.is_whitespace() || matches!(c, '(' | ')' | '`' | '\'' | '"' | '<'))
        .map(|index| index + 1)
        .unwrap_or(0);
    let path = &line[start..path_end];
    let suffix = &line[path_end + 1..];
    let (line_num, column) = parse_line_column(suffix)?;

    let path = Path::new(path);
    let relative_file = if path.is_absolute() {
        path.strip_prefix(crate_dir).ok()?.to_path_buf()
    } else {
        path.to_path_buf()
    };

    Some(SourceLocation {
        relative_file,
        line: line_num,
        column,
    })
}

fn parse_location(location: &str) -> Option<SourceLocation> {
    let mut parts = location.rsplitn(3, ':');
    let column = parts.next()?.parse().ok()?;
    let line = parts.next()?.parse().ok()?;
    let file = PathBuf::from(parts.next()?);
    Some(SourceLocation {
        relative_file: file,
        line,
        column,
    })
}

fn parse_line_column(text: &str) -> Option<(usize, usize)> {
    let mut chars = text.chars().peekable();
    let mut line = String::new();
    while matches!(chars.peek(), Some(ch) if ch.is_ascii_digit()) {
        line.push(chars.next()?);
    }
    if chars.next()? != ':' {
        return None;
    }
    let mut column = String::new();
    while matches!(chars.peek(), Some(ch) if ch.is_ascii_digit()) {
        column.push(chars.next()?);
    }
    Some((line.parse().ok()?, column.parse().ok()?))
}
