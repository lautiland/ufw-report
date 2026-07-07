use std::io::BufRead;
use std::path::{Path, PathBuf};

use chrono::{Datelike, NaiveDate};
use flate2::read::GzDecoder;
use std::fs::File;

use crate::domain::LogEntry;
use crate::error::UfwError;

use super::line::parse_log_line;
use super::reports::build_daily_reports;

#[derive(Debug)]
pub struct ParseResult {
    pub reports: Vec<crate::domain::DailyReport>,
    pub all_entries: Vec<LogEntry>,
}

/// Discover all rotated UFW log files in a directory, sorted from oldest to newest.
/// Matches patterns: ufw.log, ufw.log.1, ufw.log.2, ufw.log.2.gz, etc.
fn discover_log_files(log_dir: &str, base_name: &str) -> Vec<PathBuf> {
    let dir = Path::new(log_dir);
    if !dir.is_dir() {
        return Vec::new();
    }

    let mut files: Vec<PathBuf> = Vec::new();

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let Some(filename) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };

            // Match: ufw.log, ufw.log.1, ufw.log.2.gz, etc.
            if filename == base_name || filename.starts_with(&format!("{base_name}.")) {
                files.push(path);
            }
        }
    }

    // Sort: base file first, then by rotation number (oldest first)
    files.sort_by(|a, b| {
        let a_name = a.file_name().unwrap_or_default().to_string_lossy();
        let b_name = b.file_name().unwrap_or_default().to_string_lossy();

        // ufw.log comes last (most recent)
        if a_name == base_name {
            return std::cmp::Ordering::Greater;
        }
        if b_name == base_name {
            return std::cmp::Ordering::Less;
        }

        // Extract rotation numbers: ufw.log.1 -> 1, ufw.log.2.gz -> 2
        let a_num = a_name
            .strip_prefix(&format!("{base_name}."))
            .and_then(|s| s.split('.').next())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let b_num = b_name
            .strip_prefix(&format!("{base_name}."))
            .and_then(|s| s.split('.').next())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        // Higher number = older file = should come first
        b_num.cmp(&a_num)
    });

    files
}

/// Read lines from a file, handling both plain text and gzip compressed files.
fn read_lines_from_file(path: &Path) -> Result<Vec<String>, std::io::Error> {
    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    if Path::new(filename)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("gz"))
    {
        let file = File::open(path)?;
        let decoder = GzDecoder::new(file);
        let reader = std::io::BufReader::new(decoder);
        reader.lines().collect()
    } else {
        let file = File::open(path)?;
        let reader = std::io::BufReader::new(file);
        reader.lines().collect()
    }
}

fn get_cache_path(log_path: &str) -> PathBuf {
    let path = Path::new(log_path);
    let stem = path.file_stem().unwrap_or_default();
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!("{}.cache.json", stem.to_string_lossy()))
}

fn try_load_cache(
    cache_path: &Path,
    log_path: &Path,
    from: NaiveDate,
    to: NaiveDate,
) -> Option<ParseResult> {
    let log_modified = log_path.metadata().ok()?.modified().ok()?;
    let cache_modified = cache_path.metadata().ok()?.modified().ok()?;

    if cache_modified < log_modified {
        return None;
    }

    let data: Vec<LogEntry> = std::fs::read_to_string(cache_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())?;

    let filtered: Vec<LogEntry> = data
        .into_iter()
        .filter(|e| e.date >= from && e.date <= to)
        .collect();

    let reports = build_daily_reports(&filtered, from, to);
    Some(ParseResult {
        reports,
        all_entries: filtered,
    })
}

fn save_cache(cache_path: &Path, entries: &[LogEntry]) {
    if let Ok(json) = serde_json::to_string(entries) {
        let _ = std::fs::write(cache_path, json);
    }
}

/// Public wrapper for testing. Parses a single UFW log line.
#[must_use]
pub fn parse_log_line_standalone(
    line: &str,
    current_year: i32,
) -> Option<(NaiveDate, u32, LogEntry)> {
    parse_log_line(line, current_year)
}

/// # Errors
///
/// Returns `UfwError::LogNotFound` if the file doesn't exist, or `UfwError::PermissionDenied`
/// if reading is denied.
pub fn parse_ufw_log_range(
    log_path: &str,
    log_dir: &str,
    from: NaiveDate,
    to: NaiveDate,
) -> Result<ParseResult, UfwError> {
    let path = Path::new(log_path);
    if !path.exists() {
        return Err(UfwError::LogNotFound(log_path.to_string()));
    }

    // Get base name for log file discovery (e.g., "ufw.log" from "/var/log/ufw.log")
    let base_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("ufw.log");

    let cache_path = get_cache_path(log_path);
    if let Some(cached) = try_load_cache(&cache_path, path, from, to) {
        tracing::debug!("Loaded {} cached entries", cached.all_entries.len());
        return Ok(cached);
    }

    // Discover all rotated log files
    let log_files = discover_log_files(log_dir, base_name);
    if log_files.is_empty() {
        return Err(UfwError::LogNotFound(log_path.to_string()));
    }

    tracing::info!("Found {} log files: {:?}", log_files.len(), log_files);

    let current_year = chrono::Local::now().year();
    let mut entries: Vec<LogEntry> = Vec::new();

    // Read entries from all log files
    for file_path in &log_files {
        let lines = read_lines_from_file(file_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                UfwError::PermissionDenied {
                    path: file_path.to_string_lossy().to_string(),
                    hint: "Ejecuta con 'sudo' o agrega tu usuario al grupo 'adm'".into(),
                }
            } else {
                UfwError::LogRead(e)
            }
        })?;

        for line in lines {
            if let Some((date, _hour, entry)) = parse_log_line(&line, current_year) {
                if date >= from && date <= to {
                    entries.push(entry);
                }
            }
        }
    }

    save_cache(&cache_path, &entries);

    let reports = build_daily_reports(&entries, from, to);

    Ok(ParseResult {
        reports,
        all_entries: entries,
    })
}
