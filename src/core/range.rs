use std::collections::HashMap;
use std::io::BufRead;
use std::path::{Path, PathBuf};

use chrono::NaiveDate;

use crate::error::UfwError;
use crate::models::{DailyReport, HourBreak, IpEntry, LogEntry, PortEntry};

use super::cache::{cache_file_for, default_cache_dir, save_cache, try_load_cache};
use super::parser::parse_log_line;

#[derive(Debug, Clone)]
pub struct ParseOptions {
    pub use_cache: bool,
    pub cache_dir: Option<PathBuf>,
    /// Reference date used to resolve syslog entries that omit the year.
    /// Defaults to today; tests pin it for deterministic results.
    pub reference_date: Option<NaiveDate>,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            use_cache: true,
            cache_dir: None,
            reference_date: None,
        }
    }
}

#[derive(Debug)]
pub struct ParseResult {
    pub reports: Vec<DailyReport>,
    pub all_entries: Vec<LogEntry>,
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

/// Same as [`parse_ufw_log_range`], with explicit cache options.
///
/// # Errors
///
/// Returns [`UfwError::LogNotFound`] if the log file doesn't exist, or
/// [`UfwError::PermissionDenied`] if the file cannot be read.
pub fn parse_ufw_log_range_with_options(
    log_path: &str,
    from: NaiveDate,
    to: NaiveDate,
    options: &ParseOptions,
) -> Result<ParseResult, UfwError> {
    let path = Path::new(log_path);
    if !path.exists() {
        return Err(UfwError::LogNotFound(log_path.to_string()));
    }

    let cache_dir = options.cache_dir.clone().unwrap_or_else(default_cache_dir);
    let cache_path = cache_file_for(path, &cache_dir);

    if options.use_cache {
        if let Some(cached_entries) = try_load_cache(&cache_path, path, from, to) {
            tracing::debug!("Loaded {} cached entries", cached_entries.len());
            let reports = build_daily_reports(&cached_entries, from, to);
            return Ok(ParseResult {
                reports,
                all_entries: cached_entries,
            });
        }
    }

    let file = std::fs::File::open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            UfwError::PermissionDenied {
                path: log_path.to_string(),
                hint: "Run with 'sudo' or add your user to the 'adm' group".into(),
            }
        } else {
            UfwError::LogRead(e)
        }
    })?;
    let reader = std::io::BufReader::new(file);

    let today = options
        .reference_date
        .unwrap_or_else(|| chrono::Local::now().date_naive());
    let mut entries: Vec<LogEntry> = Vec::new();
    let mut all_entries: Vec<LogEntry> = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if let Some((date, _hour, entry)) = parse_log_line(&line, today) {
            if options.use_cache {
                all_entries.push(entry.clone());
            }
            if date >= from && date <= to {
                entries.push(entry);
            }
        }
    }

    if options.use_cache && !save_cache(&cache_path, path, &all_entries) {
        tracing::warn!(
            "Could not write the parse cache to {}; continuing without cache",
            cache_path.display()
        );
    }

    let reports = build_daily_reports(&entries, from, to);

    Ok(ParseResult {
        reports,
        all_entries: entries,
    })
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

    #[test]
    fn test_build_reports_zero_fills_missing_days() {
        let from = NaiveDate::from_ymd_opt(2026, 6, 28).unwrap();
        let to = NaiveDate::from_ymd_opt(2026, 6, 30).unwrap();

        let entries = vec![LogEntry {
            date: NaiveDate::from_ymd_opt(2026, 6, 29).unwrap(),
            hour: 10,
            src_ip: "1.2.3.4".to_string(),
            dst_ip: None,
            src_port: None,
            dst_port: Some(80),
            protocol: Some("TCP".to_string()),
            direction: Direction::Incoming,
        }];

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
        assert!(parse_result.all_entries.is_empty());
        for report in &parse_result.reports {
            assert_eq!(report.total_blocked, 0);
        }
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
