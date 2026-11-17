use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use crate::models::LogEntry;

const CACHE_VERSION: u32 = 2;
const PARSER_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct CacheFile {
    cache_version: u32,
    parser_version: u32,
    log_len: u64,
    log_mtime_secs: u64,
    entries: Vec<LogEntry>,
}

/// Returns the per-user cache directory, following the XDG base directory
/// specification when `XDG_CACHE_HOME` is available.
#[must_use]
pub fn default_cache_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(dir).join("ufw-report");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".cache").join("ufw-report");
    }
    std::env::temp_dir().join("ufw-report")
}

pub(crate) fn cache_file_for(log_path: &Path, cache_dir: &Path) -> PathBuf {
    let canonical = std::fs::canonicalize(log_path).unwrap_or_else(|_| log_path.to_path_buf());
    let mut hasher = DefaultHasher::new();
    canonical.hash(&mut hasher);
    cache_dir.join(format!("{:016x}.json", hasher.finish()))
}

fn metadata_snapshot(log_path: &Path) -> Option<(u64, u64)> {
    let metadata = std::fs::metadata(log_path).ok()?;
    let len = metadata.len();
    let mtime = metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some((len, mtime))
}

/// Tries to load cached entries for the requested range.
///
/// The cache stores every parsed entry, so a cache created for a narrow range
/// still serves a wider range later. The cache is ignored if the log file
/// changed, if the cache/parser format version differs, or if the file is
/// corrupt.
pub(crate) fn try_load_cache(
    cache_path: &Path,
    log_path: &Path,
    from: NaiveDate,
    to: NaiveDate,
) -> Option<Vec<LogEntry>> {
    let (log_len, log_mtime_secs) = metadata_snapshot(log_path)?;
    let raw = std::fs::read_to_string(cache_path).ok()?;
    let cache: CacheFile = serde_json::from_str(&raw).ok()?;

    if cache.cache_version != CACHE_VERSION
        || cache.parser_version != PARSER_VERSION
        || cache.log_len != log_len
        || cache.log_mtime_secs != log_mtime_secs
    {
        return None;
    }

    Some(
        cache
            .entries
            .into_iter()
            .filter(|entry| entry.date >= from && entry.date <= to)
            .collect(),
    )
}

/// Persists every parsed entry along with the log fingerprint.
///
/// Returns `false` when the cache could not be written. The caller decides
/// whether to surface that as a warning.
pub(crate) fn save_cache(cache_path: &Path, log_path: &Path, entries: &[LogEntry]) -> bool {
    let Some((log_len, log_mtime_secs)) = metadata_snapshot(log_path) else {
        return false;
    };
    let Some(parent) = cache_path.parent() else {
        return false;
    };
    if std::fs::create_dir_all(parent).is_err() {
        return false;
    }

    let cache = CacheFile {
        cache_version: CACHE_VERSION,
        parser_version: PARSER_VERSION,
        log_len,
        log_mtime_secs,
        entries: entries.to_vec(),
    };
    let Ok(json) = serde_json::to_vec(&cache) else {
        return false;
    };

    let tmp_path = cache_path.with_extension(format!("{}.tmp", std::process::id()));
    if std::fs::write(&tmp_path, json).is_err() {
        let _ = std::fs::remove_file(&tmp_path);
        return false;
    }
    if std::fs::rename(&tmp_path, cache_path).is_err() {
        let _ = std::fs::remove_file(&tmp_path);
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Direction;

    fn entry(date: NaiveDate) -> LogEntry {
        LogEntry {
            date,
            hour: 12,
            src_ip: "203.0.113.10".to_string(),
            dst_ip: None,
            src_port: None,
            dst_port: Some(22),
            protocol: Some("TCP".to_string()),
            direction: Direction::Incoming,
        }
    }

    fn sample_entries() -> Vec<LogEntry> {
        vec![
            entry(NaiveDate::from_ymd_opt(2026, 6, 28).unwrap()),
            entry(NaiveDate::from_ymd_opt(2026, 7, 4).unwrap()),
        ]
    }

    #[test]
    fn test_cache_serves_wider_range() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("ufw.log");
        std::fs::write(&log_path, "log contents").unwrap();
        let cache_path = cache_file_for(&log_path, dir.path());

        assert!(save_cache(&cache_path, &log_path, &sample_entries()));

        let from = NaiveDate::from_ymd_opt(2026, 6, 1).unwrap();
        let to_june = NaiveDate::from_ymd_opt(2026, 6, 30).unwrap();
        let cached = try_load_cache(&cache_path, &log_path, from, to_june).unwrap();
        assert_eq!(cached.len(), 1);

        let to_july = NaiveDate::from_ymd_opt(2026, 7, 31).unwrap();
        let cached = try_load_cache(&cache_path, &log_path, from, to_july).unwrap();
        assert_eq!(cached.len(), 2);
    }

    #[test]
    fn test_cache_invalidated_when_log_changes() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("ufw.log");
        std::fs::write(&log_path, "first").unwrap();
        let cache_path = cache_file_for(&log_path, dir.path());
        assert!(save_cache(&cache_path, &log_path, &sample_entries()));

        std::fs::write(&log_path, "second, longer contents").unwrap();

        let from = NaiveDate::from_ymd_opt(2026, 6, 1).unwrap();
        let to = NaiveDate::from_ymd_opt(2026, 7, 31).unwrap();
        assert!(try_load_cache(&cache_path, &log_path, from, to).is_none());
    }

    #[test]
    fn test_cache_invalidated_by_version() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("ufw.log");
        std::fs::write(&log_path, "log contents").unwrap();
        let cache_path = cache_file_for(&log_path, dir.path());
        assert!(save_cache(&cache_path, &log_path, &sample_entries()));

        let raw = std::fs::read_to_string(&cache_path).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        value["cache_version"] = serde_json::json!(0);
        std::fs::write(&cache_path, value.to_string()).unwrap();

        let from = NaiveDate::from_ymd_opt(2026, 6, 1).unwrap();
        let to = NaiveDate::from_ymd_opt(2026, 7, 31).unwrap();
        assert!(try_load_cache(&cache_path, &log_path, from, to).is_none());
    }

    #[test]
    fn test_corrupt_cache_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("ufw.log");
        std::fs::write(&log_path, "log contents").unwrap();
        let cache_path = cache_file_for(&log_path, dir.path());
        std::fs::write(&cache_path, "{not json").unwrap();

        let from = NaiveDate::from_ymd_opt(2026, 6, 1).unwrap();
        let to = NaiveDate::from_ymd_opt(2026, 7, 31).unwrap();
        assert!(try_load_cache(&cache_path, &log_path, from, to).is_none());
    }

    #[test]
    fn test_default_cache_dir_uses_xdg_when_set() {
        // The variable is process-wide, so only assert the shape when it is set
        // by the test environment (CI usually leaves it unset).
        if let Some(dir) = std::env::var_os("XDG_CACHE_HOME") {
            assert_eq!(default_cache_dir(), PathBuf::from(dir).join("ufw-report"));
        }
    }
}
