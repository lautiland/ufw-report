use std::path::{Path, PathBuf};

use chrono::NaiveDate;

use crate::models::LogEntry;

pub(crate) fn get_cache_path(log_path: &str) -> PathBuf {
    let path = Path::new(log_path);
    let stem = path.file_stem().unwrap_or_default();
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!("{}.cache.json", stem.to_string_lossy()))
}

pub(crate) fn try_load_cache(
    cache_path: &Path,
    log_path: &Path,
    from: NaiveDate,
    to: NaiveDate,
) -> Option<Vec<LogEntry>> {
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

    Some(filtered)
}

pub(crate) fn save_cache(cache_path: &Path, entries: &[LogEntry]) {
    if let Ok(json) = serde_json::to_string(entries) {
        let _ = std::fs::write(cache_path, json);
    }
}
