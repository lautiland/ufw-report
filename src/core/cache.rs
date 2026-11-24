use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};

use crate::models::{LogEntry, ParseStats};

const CACHE_VERSION: u32 = 5;
const PARSER_VERSION: u32 = 2;

#[derive(Debug, Serialize, Deserialize)]
struct CacheFile {
    cache_version: u32,
    parser_version: u32,
    log_len: u64,
    log_mtime_secs: u64,
    #[serde(default)]
    sha256: String,
    #[serde(default)]
    decompressed_bytes: u64,
    #[serde(default)]
    stats: ParseStats,
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

/// A cache candidate loaded from disk.
pub(crate) struct CachedLog {
    pub entries: Vec<LogEntry>,
    pub stats: ParseStats,
    pub decompressed_bytes: u64,
    pub sha256: String,
}

/// Tries to load a cache candidate for one file.
///
/// The cache is ignored if the log metadata changed, if the cache/parser
/// format version differs, or if the stored entries are inconsistent. The
/// caller must still compare [`CachedLog::sha256`] against the digest of the
/// bytes on disk before trusting the entries.
pub(crate) fn load_cache(cache_path: &Path, log_path: &Path) -> Option<CachedLog> {
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

    if cache
        .entries
        .iter()
        .any(|entry| !entry.has_consistent_time())
    {
        tracing::warn!("Ignoring cache with inconsistent entry timestamps");
        return None;
    }

    Some(CachedLog {
        entries: cache.entries,
        stats: cache.stats,
        decompressed_bytes: cache.decompressed_bytes,
        sha256: cache.sha256,
    })
}

/// Persists every parsed entry along with the log fingerprint.
///
/// Returns `false` when the cache could not be written. The caller decides
/// whether to surface that as a warning.
pub(crate) fn save_cache(
    cache_path: &Path,
    log_path: &Path,
    entries: &[LogEntry],
    stats: &ParseStats,
    sha256: &str,
    decompressed_bytes: u64,
) -> bool {
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
        sha256: sha256.to_string(),
        decompressed_bytes,
        stats: stats.clone(),
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
    use chrono::NaiveDate;

    const SHA256: &str = "0123456789abcdef";

    fn entry(date: NaiveDate) -> LogEntry {
        let timestamp = date
            .and_hms_opt(12, 34, 56)
            .expect("test timestamp should be valid");
        let mut entry = LogEntry::new(timestamp, "203.0.113.10".to_string());
        entry.dst_port = Some(22);
        entry.protocol = Some("TCP".to_string());
        entry.direction = Direction::Incoming;
        entry
    }

    fn sample_entries() -> Vec<LogEntry> {
        vec![
            entry(NaiveDate::from_ymd_opt(2026, 6, 28).unwrap()),
            entry(NaiveDate::from_ymd_opt(2026, 7, 4).unwrap()),
        ]
    }

    fn sample_stats() -> ParseStats {
        ParseStats {
            total_lines: 2,
            block_lines: 2,
            ..ParseStats::default()
        }
    }

    fn save_sample(cache_path: &Path, log_path: &Path, decompressed: u64) -> bool {
        save_cache(
            cache_path,
            log_path,
            &sample_entries(),
            &sample_stats(),
            SHA256,
            decompressed,
        )
    }

    #[test]
    fn test_cache_preserves_second_precision() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("ufw.log");
        std::fs::write(&log_path, "log contents").unwrap();
        let cache_path = cache_file_for(&log_path, dir.path());

        assert!(save_sample(&cache_path, &log_path, 2));

        let cached = load_cache(&cache_path, &log_path).unwrap();
        assert_eq!(
            cached.entries[0].timestamp.to_string(),
            "2026-06-28 12:34:56"
        );
    }

    #[test]
    fn test_cache_returns_all_entries() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("ufw.log");
        std::fs::write(&log_path, "log contents").unwrap();
        let cache_path = cache_file_for(&log_path, dir.path());

        assert!(save_sample(&cache_path, &log_path, 2));

        let cached = load_cache(&cache_path, &log_path).unwrap();
        assert_eq!(cached.entries.len(), 2);
        assert_eq!(cached.stats.total_lines, 2);
    }

    #[test]
    fn test_cache_exposes_digest_and_decompressed_size() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("ufw.log");
        std::fs::write(&log_path, "log contents").unwrap();
        let cache_path = cache_file_for(&log_path, dir.path());

        assert!(save_sample(&cache_path, &log_path, 123_456));

        let cached = load_cache(&cache_path, &log_path).unwrap();
        assert_eq!(cached.sha256, SHA256);
        assert_eq!(cached.decompressed_bytes, 123_456);
    }

    #[test]
    fn test_cache_rejects_inconsistent_timestamps() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("ufw.log");
        std::fs::write(&log_path, "log contents").unwrap();
        let cache_path = cache_file_for(&log_path, dir.path());
        assert!(save_sample(&cache_path, &log_path, 2));

        let raw = std::fs::read_to_string(&cache_path).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        value["entries"][0]["hour"] = serde_json::json!(99);
        std::fs::write(&cache_path, value.to_string()).unwrap();

        assert!(load_cache(&cache_path, &log_path).is_none());
    }

    #[test]
    fn test_cache_invalidated_when_log_changes() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("ufw.log");
        std::fs::write(&log_path, "first").unwrap();
        let cache_path = cache_file_for(&log_path, dir.path());
        assert!(save_sample(&cache_path, &log_path, 2));

        std::fs::write(&log_path, "second, longer contents").unwrap();

        assert!(load_cache(&cache_path, &log_path).is_none());
    }

    #[test]
    fn test_cache_invalidated_by_version() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("ufw.log");
        std::fs::write(&log_path, "log contents").unwrap();
        let cache_path = cache_file_for(&log_path, dir.path());
        assert!(save_sample(&cache_path, &log_path, 2));

        let raw = std::fs::read_to_string(&cache_path).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        value["cache_version"] = serde_json::json!(0);
        std::fs::write(&cache_path, value.to_string()).unwrap();

        assert!(load_cache(&cache_path, &log_path).is_none());
    }

    #[test]
    fn test_corrupt_cache_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("ufw.log");
        std::fs::write(&log_path, "log contents").unwrap();
        let cache_path = cache_file_for(&log_path, dir.path());
        std::fs::write(&cache_path, "{not json").unwrap();

        assert!(load_cache(&cache_path, &log_path).is_none());
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
