use std::collections::HashMap;
use std::io::BufRead;
use std::path::Path;

use chrono::{Datelike, NaiveDate};

use crate::error::UfwError;
use crate::models::{DailyReport, HourBreak, IpEntry, LogEntry, PortEntry};

use super::cache::{get_cache_path, save_cache, try_load_cache};
use super::parser::parse_log_line;

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
    let path = Path::new(log_path);
    if !path.exists() {
        return Err(UfwError::LogNotFound(log_path.to_string()));
    }

    let cache_path = get_cache_path(log_path);
    if let Some(cached_entries) = try_load_cache(&cache_path, path, from, to) {
        tracing::debug!("Loaded {} cached entries", cached_entries.len());
        let reports = build_daily_reports(&cached_entries, from, to);
        return Ok(ParseResult {
            reports,
            all_entries: cached_entries,
        });
    }

    let file = std::fs::File::open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            UfwError::PermissionDenied {
                path: log_path.to_string(),
                hint: "Ejecuta con 'sudo' o agrega tu usuario al grupo 'adm'".into(),
            }
        } else {
            UfwError::LogRead(e)
        }
    })?;
    let reader = std::io::BufReader::new(file);

    let current_year = chrono::Local::now().year();
    let mut entries: Vec<LogEntry> = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if let Some((date, _hour, entry)) = parse_log_line(&line, current_year) {
            if date >= from && date <= to {
                entries.push(entry);
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
        let result = parse_ufw_log_range(log_path.to_str().unwrap(), from, to);

        assert!(result.is_ok());
        let parse_result = result.unwrap();
        assert!(parse_result.all_entries.is_empty());
        for report in &parse_result.reports {
            assert_eq!(report.total_blocked, 0);
        }
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
