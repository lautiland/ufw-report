use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, NaiveDate, Utc};

use crate::error::UfwError;
use crate::models::{
    DailyReport, EvidenceFile, FileError, FileErrorKind, HourBreak, IpEntry, LogEntry, ParseStats,
    PortEntry,
};

use super::cache::{cache_file_for, default_cache_dir, load_cache, save_cache};
use super::hash::sha256_file;
use super::inputs::{read_input, resolve_inputs, InputFile, DEFAULT_MAX_DECOMPRESSED_BYTES};

#[derive(Debug, Clone)]
pub struct ParseOptions {
    pub use_cache: bool,
    pub cache_dir: Option<PathBuf>,
    /// Reference date used to resolve syslog entries that omit the year.
    /// Defaults to today; tests pin it for deterministic results.
    pub reference_date: Option<NaiveDate>,
    /// Also read `<base>.<N>` and `<base>.<N>.gz` next to every input.
    pub include_rotated: bool,
    /// Maximum decompressed bytes allowed per `.gz` input.
    pub max_decompressed_bytes: u64,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            use_cache: true,
            cache_dir: None,
            reference_date: None,
            include_rotated: false,
            max_decompressed_bytes: DEFAULT_MAX_DECOMPRESSED_BYTES,
        }
    }
}

#[derive(Debug)]
pub struct ParseResult {
    pub reports: Vec<DailyReport>,
    pub all_entries: Vec<LogEntry>,
    /// Whole-file line counters, not restricted to the requested range.
    pub stats: ParseStats,
    /// One entry per resolved input file, including files that failed to read.
    pub files: Vec<EvidenceFile>,
}

struct FileOutcome {
    entries: Vec<LogEntry>,
    stats: ParseStats,
    sha256: String,
    decompressed_bytes: u64,
    error: Option<FileError>,
    from_cache: bool,
}

/// # Errors
///
/// Returns [`UfwError::LogNotFound`] if the log file doesn't exist, or
/// [`UfwError::PermissionDenied`] if the file cannot be read.
pub fn parse_ufw_log_range(
    log_path: &str,
    from: NaiveDate,
    to: NaiveDate,
) -> Result<ParseResult, UfwError> {
    parse_ufw_log_range_with_options(log_path, from, to, &ParseOptions::default())
}

/// Same as [`parse_ufw_log_range`], with explicit cache and ingestion options.
///
/// # Errors
///
/// Returns [`UfwError::LogNotFound`] if an explicit log file doesn't exist,
/// or [`UfwError::PermissionDenied`] if an explicit file cannot be read.
pub fn parse_ufw_log_range_with_options(
    log_path: &str,
    from: NaiveDate,
    to: NaiveDate,
    options: &ParseOptions,
) -> Result<ParseResult, UfwError> {
    let paths = [log_path.to_string()];
    parse_logs_with_options(&paths, from, to, options)
}

/// Parses one or more UFW logs, optionally including rotated siblings.
///
/// Files that fail halfway through are reported in [`ParseResult::files`], and
/// the entries read before the failure are still included in the analysis.
///
/// # Errors
///
/// Returns an error when an explicit input is missing, is not a regular file,
/// or cannot be opened.
pub fn parse_logs_with_options(
    log_paths: &[String],
    from: NaiveDate,
    to: NaiveDate,
    options: &ParseOptions,
) -> Result<ParseResult, UfwError> {
    let inputs = resolve_inputs(log_paths, options.include_rotated)?;
    let cache_dir = options.cache_dir.clone().unwrap_or_else(default_cache_dir);
    let today = options
        .reference_date
        .unwrap_or_else(|| chrono::Local::now().date_naive());

    let mut entries = Vec::new();
    let mut stats = ParseStats::default();
    let mut files = Vec::with_capacity(inputs.len());

    for input in inputs {
        let metadata = match fs::metadata(&input.path) {
            Ok(metadata) => metadata,
            Err(error) => {
                files.push(unread_evidence(&input, &error));
                continue;
            }
        };

        let cache_path = cache_file_for(&input.path, &cache_dir);
        let outcome = load_or_read(&input, &cache_path, options, today);

        for entry in outcome.entries {
            if entry.date >= from && entry.date <= to {
                entries.push(entry);
            }
        }
        stats.merge(&outcome.stats);
        files.push(EvidenceFile {
            path: input.path.to_string_lossy().into_owned(),
            canonical_path: input.canonical_path.to_string_lossy().into_owned(),
            sha256: outcome.sha256,
            size_bytes: metadata.len(),
            decompressed_bytes: outcome.decompressed_bytes,
            modified_at: metadata.modified().ok().map(DateTime::<Utc>::from),
            compressed: input.compressed,
            from_cache: outcome.from_cache,
            parse_stats: outcome.stats,
            error: outcome.error,
        });
    }

    entries.sort_by_key(|entry| entry.timestamp);
    let reports = build_daily_reports(&entries, from, to);

    Ok(ParseResult {
        reports,
        all_entries: entries,
        stats,
        files,
    })
}

fn load_or_read(
    input: &InputFile,
    cache_path: &Path,
    options: &ParseOptions,
    today: NaiveDate,
) -> FileOutcome {
    if options.use_cache {
        if let Some(cache) = load_cache(cache_path, &input.path) {
            if let Ok(digest) = sha256_file(&input.path) {
                if cache.sha256 == digest {
                    return FileOutcome {
                        entries: cache.entries,
                        stats: cache.stats,
                        sha256: digest,
                        decompressed_bytes: cache.decompressed_bytes,
                        error: None,
                        from_cache: true,
                    };
                }
            }
        }
    }

    let read = read_input(input, today, options.max_decompressed_bytes);
    if options.use_cache
        && read.error.is_none()
        && !save_cache(
            cache_path,
            &input.path,
            &read.entries,
            &read.stats,
            &read.sha256,
            read.decompressed_bytes,
        )
    {
        tracing::warn!(
            "Could not write the parse cache to {}; continuing without cache",
            cache_path.display()
        );
    }

    FileOutcome {
        entries: read.entries,
        stats: read.stats,
        sha256: read.sha256,
        decompressed_bytes: read.decompressed_bytes,
        error: read.error,
        from_cache: false,
    }
}

fn unread_evidence(input: &InputFile, error: &std::io::Error) -> EvidenceFile {
    EvidenceFile {
        path: input.path.to_string_lossy().into_owned(),
        canonical_path: input.canonical_path.to_string_lossy().into_owned(),
        sha256: String::new(),
        size_bytes: 0,
        decompressed_bytes: 0,
        modified_at: None,
        compressed: input.compressed,
        from_cache: false,
        parse_stats: ParseStats::default(),
        error: Some(FileError::new(FileErrorKind::Io, error.to_string())),
    }
}

pub(crate) fn build_daily_reports(
    entries: &[LogEntry],
    from: NaiveDate,
    to: NaiveDate,
) -> Vec<DailyReport> {
    let mut day_map: HashMap<NaiveDate, Vec<&LogEntry>> = HashMap::new();
    for entry in entries {
        day_map.entry(entry.date).or_default().push(entry);
    }

    let mut reports = Vec::new();
    let mut current = from;
    while current <= to {
        let day_entries = day_map.remove(&current).unwrap_or_default();
        let report = build_single_report(current, &day_entries);
        reports.push(report);
        current += chrono::Duration::days(1);
    }

    reports
}

fn build_single_report(date: NaiveDate, entries: &[&LogEntry]) -> DailyReport {
    let total_blocked = entries.len() as u64;

    let mut hourly_map: HashMap<u32, u64> = HashMap::new();
    let mut ip_map: HashMap<String, u64> = HashMap::new();
    let mut port_map: HashMap<u16, u64> = HashMap::new();
    let mut proto_map: HashMap<String, u64> = HashMap::new();

    for entry in entries {
        *hourly_map.entry(entry.hour).or_default() += 1;
        *ip_map.entry(entry.src_ip.clone()).or_default() += 1;
        if let Some(port) = entry.dst_port {
            *port_map.entry(port).or_default() += 1;
        }
        if let Some(ref proto) = entry.protocol {
            *proto_map.entry(proto.clone()).or_insert(0u64) += 1;
        }
    }

    let mut hourly: Vec<HourBreak> = hourly_map
        .into_iter()
        .map(|(hour, count)| HourBreak { hour, count })
        .collect();
    hourly.sort_by_key(|h| h.hour);

    let mut top_ips: Vec<IpEntry> = ip_map
        .into_iter()
        .map(|(ip, count)| IpEntry { ip, count })
        .collect();
    top_ips.sort_by_key(|b| std::cmp::Reverse(b.count));
    top_ips.truncate(10);

    let mut top_ports: Vec<PortEntry> = port_map
        .into_iter()
        .map(|(port, count)| PortEntry { port, count })
        .collect();
    top_ports.sort_by_key(|b| std::cmp::Reverse(b.count));
    top_ports.truncate(10);

    DailyReport {
        date,
        total_blocked,
        hourly,
        top_ips,
        top_ports,
        protocols: proto_map,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Direction;

    fn entry(date: NaiveDate, hour: u32, second: u32) -> LogEntry {
        let timestamp = date
            .and_hms_opt(hour, 0, second)
            .expect("test timestamp should be valid");
        let mut entry = LogEntry::new(timestamp, "1.2.3.4".to_string());
        entry.dst_port = Some(80);
        entry.protocol = Some("TCP".to_string());
        entry.direction = Direction::Incoming;
        entry
    }

    #[test]
    fn test_build_reports_zero_fills_missing_days() {
        let from = NaiveDate::from_ymd_opt(2026, 6, 28).unwrap();
        let to = NaiveDate::from_ymd_opt(2026, 6, 30).unwrap();

        let entries = vec![entry(NaiveDate::from_ymd_opt(2026, 6, 29).unwrap(), 10, 0)];

        let reports = build_daily_reports(&entries, from, to);
        assert_eq!(reports.len(), 3);

        assert_eq!(reports[0].date.to_string(), "2026-06-28");
        assert_eq!(reports[0].total_blocked, 0);

        assert_eq!(reports[1].date.to_string(), "2026-06-29");
        assert_eq!(reports[1].total_blocked, 1);

        assert_eq!(reports[2].date.to_string(), "2026-06-30");
        assert_eq!(reports[2].total_blocked, 0);
    }

    #[test]
    fn test_empty_log() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("empty.log");
        std::fs::write(&log_path, "").unwrap();

        let from = NaiveDate::from_ymd_opt(2026, 6, 28).unwrap();
        let to = NaiveDate::from_ymd_opt(2026, 6, 30).unwrap();
        let options = ParseOptions {
            use_cache: false,
            ..ParseOptions::default()
        };
        let result =
            parse_ufw_log_range_with_options(log_path.to_str().unwrap(), from, to, &options);

        assert!(result.is_ok());
        let parse_result = result.unwrap();
        assert_eq!(parse_result.all_entries.len(), 0);
        for report in &parse_result.reports {
            assert_eq!(report.total_blocked, 0);
        }
    }

    #[test]
    fn test_parse_stats_classify_and_flag_lines() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("ufw.log");
        std::fs::write(
            &log_path,
            concat!(
                "2026-06-28T08:00:00 host kernel: [UFW BLOCK] IN=eth0 SRC=10.0.0.1 DPT=22 PROTO=TCP\n",
                "2026-06-28T09:00:00 host kernel: [UFW ALLOW] IN=eth0 SRC=1.2.3.4 DPT=80 PROTO=TCP\n",
                "2026-06-28T10:00:00 host kernel: [UFW AUDIT] IN=eth0 SRC=10.0.0.2 DPT=443 PROTO=TCP\n",
                "2026-06-28T07:00:00 host kernel: [UFW BLOCK] IN=eth0 SRC=10.0.0.3 DPT=80 PROTO=TCP\n",
                "2026-06-28T11:00:00 host kernel: [UFW BLOCK] IN=eth0\n",
                "\n",
                "some random line\n",
            ),
        )
        .unwrap();

        let options = ParseOptions {
            use_cache: false,
            reference_date: Some(NaiveDate::from_ymd_opt(2026, 6, 30).unwrap()),
            ..ParseOptions::default()
        };
        let from = NaiveDate::from_ymd_opt(2026, 6, 1).unwrap();
        let to = NaiveDate::from_ymd_opt(2026, 6, 30).unwrap();
        let result =
            parse_ufw_log_range_with_options(log_path.to_str().unwrap(), from, to, &options)
                .unwrap();

        assert_eq!(result.stats.total_lines, 7);
        assert_eq!(result.stats.block_lines, 3);
        assert_eq!(result.stats.allow_lines, 1);
        assert_eq!(result.stats.audit_lines, 1);
        assert_eq!(result.stats.other_lines, 2);
        assert_eq!(result.stats.unparsed_block_lines, 1);
        assert_eq!(result.stats.out_of_order_lines, 1);
        assert_eq!(result.stats.future_entries, 0);
        assert_eq!(result.stats.parsed_block_lines(), 2);
    }

    #[test]
    fn test_parse_stats_flags_future_entries() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("ufw.log");
        std::fs::write(
            &log_path,
            "2026-06-28T08:00:00 host kernel: [UFW BLOCK] IN=eth0 SRC=10.0.0.1 DPT=22 PROTO=TCP\n",
        )
        .unwrap();

        let options = ParseOptions {
            use_cache: false,
            reference_date: Some(NaiveDate::from_ymd_opt(2026, 6, 27).unwrap()),
            ..ParseOptions::default()
        };
        let from = NaiveDate::from_ymd_opt(2026, 6, 1).unwrap();
        let to = NaiveDate::from_ymd_opt(2026, 6, 30).unwrap();
        let result =
            parse_ufw_log_range_with_options(log_path.to_str().unwrap(), from, to, &options)
                .unwrap();

        assert_eq!(result.stats.future_entries, 1);
    }

    #[test]
    fn test_entries_are_sorted_by_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("ufw.log");
        std::fs::write(
            &log_path,
            concat!(
                "2026-06-28T10:00:05 host kernel: [UFW BLOCK] IN=eth0 SRC=10.0.0.5 DPT=22 PROTO=TCP\n",
                "2026-06-28T10:00:01 host kernel: [UFW BLOCK] IN=eth0 SRC=10.0.0.1 DPT=22 PROTO=TCP\n",
                "2026-06-28T09:59:59 host kernel: [UFW BLOCK] IN=eth0 SRC=10.0.0.0 DPT=22 PROTO=TCP\n",
            ),
        )
        .unwrap();

        let options = ParseOptions {
            use_cache: false,
            reference_date: Some(NaiveDate::from_ymd_opt(2026, 6, 30).unwrap()),
            ..ParseOptions::default()
        };
        let day = NaiveDate::from_ymd_opt(2026, 6, 28).unwrap();
        let result =
            parse_ufw_log_range_with_options(log_path.to_str().unwrap(), day, day, &options)
                .unwrap();

        assert_eq!(result.stats.out_of_order_lines, 2);
        assert!(result
            .all_entries
            .windows(2)
            .all(|window| window[0].timestamp <= window[1].timestamp));
    }

    #[test]
    fn test_cache_serves_wider_range_after_narrow_run() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("ufw.log");
        std::fs::write(
            &log_path,
            concat!(
                "2026-06-28T08:00:00 host kernel: [UFW BLOCK] IN=eth0 SRC=10.0.0.1 DPT=22 PROTO=TCP\n",
                "2026-07-04T09:00:00 host kernel: [UFW BLOCK] IN=eth0 SRC=10.0.0.2 DPT=80 PROTO=TCP\n",
            ),
        )
        .unwrap();

        let options = ParseOptions {
            use_cache: true,
            cache_dir: Some(dir.path().join("cache")),
            ..ParseOptions::default()
        };
        let from = NaiveDate::from_ymd_opt(2026, 6, 1).unwrap();
        let to_june = NaiveDate::from_ymd_opt(2026, 6, 30).unwrap();
        let first =
            parse_ufw_log_range_with_options(log_path.to_str().unwrap(), from, to_june, &options)
                .unwrap();
        assert_eq!(first.all_entries.len(), 1);

        let to_july = NaiveDate::from_ymd_opt(2026, 7, 31).unwrap();
        let second =
            parse_ufw_log_range_with_options(log_path.to_str().unwrap(), from, to_july, &options)
                .unwrap();
        assert_eq!(second.all_entries.len(), 2);
    }

    #[test]
    fn test_no_cache_does_not_create_cache_files() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("ufw.log");
        std::fs::write(
            &log_path,
            "2026-06-28T08:00:00 host kernel: [UFW BLOCK] IN=eth0 SRC=10.0.0.1 DPT=22 PROTO=TCP\n",
        )
        .unwrap();

        let cache_dir = dir.path().join("cache");
        let options = ParseOptions {
            use_cache: false,
            cache_dir: Some(cache_dir.clone()),
            ..ParseOptions::default()
        };
        let from = NaiveDate::from_ymd_opt(2026, 6, 1).unwrap();
        let to = NaiveDate::from_ymd_opt(2026, 6, 30).unwrap();
        parse_ufw_log_range_with_options(log_path.to_str().unwrap(), from, to, &options).unwrap();

        assert!(!cache_dir.exists());
    }

    #[test]
    fn test_log_not_found() {
        let from = NaiveDate::from_ymd_opt(2026, 6, 28).unwrap();
        let to = NaiveDate::from_ymd_opt(2026, 6, 30).unwrap();
        let result = parse_ufw_log_range("/nonexistent/ufw.log", from, to);
        assert!(result.is_err());
        match result.unwrap_err() {
            UfwError::LogNotFound(_) => {}
            _ => panic!("Expected LogNotFound error"),
        }
    }
}
