use std::collections::HashMap;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use chrono::{Datelike, NaiveDate};
use regex::Regex;

use crate::error::UfwError;
use crate::models::{DailyReport, Direction, HourBreak, IpEntry, LogEntry, PortEntry};

static RE_SYSLOG_DATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(\w{3}\s+\d{1,2})\s+(\d{2}:\d{2}:\d{2})").unwrap());

static RE_ISO_DATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(\d{4}-\d{2}-\d{2})T(\d{2}):\d{2}:\d{2}").unwrap());

static RE_SRC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"SRC=([0-9a-fA-F:.]+)").unwrap());

static RE_DPT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"DPT=(\d+)").unwrap());

static RE_PROTO: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"PROTO=(\w+)").unwrap());

static RE_DST: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"DST=([0-9a-fA-F:.]+)").unwrap());

static RE_SPT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"SPT=(\d+)").unwrap());

static RE_IN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bIN=(\S*)").unwrap());

static RE_OUT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bOUT=(\S*)").unwrap());

fn parse_syslog_month(abbr: &str) -> Option<u32> {
    match abbr {
        "Jan" => Some(1),
        "Feb" => Some(2),
        "Mar" => Some(3),
        "Apr" => Some(4),
        "May" => Some(5),
        "Jun" => Some(6),
        "Jul" => Some(7),
        "Aug" => Some(8),
        "Sep" => Some(9),
        "Oct" => Some(10),
        "Nov" => Some(11),
        "Dec" => Some(12),
        _ => None,
    }
}

fn resolve_year(parsed_date: NaiveDate, current_year: i32) -> NaiveDate {
    let candidate = NaiveDate::from_ymd_opt(current_year, parsed_date.month(), parsed_date.day());
    match candidate {
        Some(d) if d > chrono::Local::now().date_naive() + chrono::TimeDelta::days(30) => {
            NaiveDate::from_ymd_opt(current_year - 1, parsed_date.month(), parsed_date.day())
                .unwrap_or(parsed_date)
        }
        Some(d) => d,
        None => parsed_date,
    }
}

fn normalize_protocol(raw: &str) -> String {
    match raw.to_uppercase().as_str() {
        "TCP" | "6" => "TCP".to_string(),
        "UDP" | "17" => "UDP".to_string(),
        "ICMP" | "1" => "ICMP".to_string(),
        "IGMP" | "2" => "IGMP".to_string(),
        "IPV6-ICMP" | "58" => "IPv6-ICMP".to_string(),
        "GRE" | "47" => "GRE".to_string(),
        "ESP" | "50" => "ESP".to_string(),
        "AH" | "51" => "AH".to_string(),
        "SCTP" | "132" => "SCTP".to_string(),
        other => other.to_string(),
    }
}

fn parse_direction(line: &str) -> Direction {
    let in_val = RE_IN
        .captures(line)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str());
    let out_val = RE_OUT
        .captures(line)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str());

    match (in_val, out_val) {
        (Some(in_iface), _) if !in_iface.is_empty() => Direction::Incoming,
        (_, Some(out_iface)) if !out_iface.is_empty() => Direction::Outgoing,
        _ => Direction::Unknown,
    }
}

fn parse_log_line(line: &str, current_year: i32) -> Option<(NaiveDate, u32, LogEntry)> {
    let line = line.trim();
    if !line.contains("[UFW BLOCK]") {
        return None;
    }

    let (date_str, hour) = if let Some(caps) = RE_ISO_DATE.captures(line) {
        let d = NaiveDate::parse_from_str(caps.get(1)?.as_str(), "%Y-%m-%d").ok()?;
        let h: u32 = caps.get(2)?.as_str().parse().ok()?;
        (d, h)
    } else if let Some(caps) = RE_SYSLOG_DATE.captures(line) {
        let date_part = caps.get(1)?.as_str();
        let time_part = caps.get(2)?.as_str();
        let h: u32 = time_part[..2].parse().ok()?;

        let mut parts = date_part.split_whitespace();
        let month_abbr = parts.next()?;
        let day_str = parts.next()?;
        let month = parse_syslog_month(month_abbr)?;
        let day: u32 = day_str.parse().ok()?;

        let d = NaiveDate::from_ymd_opt(current_year, month, day)?;
        let resolved = resolve_year(d, current_year);
        (resolved, h)
    } else {
        return None;
    };

    let src_ip = RE_SRC.captures(line)?.get(1)?.as_str().to_string();
    let dst_ip = RE_DST
        .captures(line)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string());
    let src_port = RE_SPT
        .captures(line)
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse::<u16>().ok());
    let dst_port = RE_DPT
        .captures(line)
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse::<u16>().ok());
    let protocol = RE_PROTO
        .captures(line)
        .map(|c| normalize_protocol(c.get(1).unwrap().as_str()));
    let direction = parse_direction(line);

    Some((
        date_str,
        hour,
        LogEntry {
            date: date_str,
            hour,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            direction,
        },
    ))
}

#[derive(Debug)]
pub struct ParseResult {
    pub reports: Vec<DailyReport>,
    pub all_entries: Vec<LogEntry>,
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
    if let Some(cached) = try_load_cache(&cache_path, path, from, to) {
        tracing::debug!("Loaded {} cached entries", cached.all_entries.len());
        return Ok(cached);
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

fn build_daily_reports(entries: &[LogEntry], from: NaiveDate, to: NaiveDate) -> Vec<DailyReport> {
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
            *proto_map.entry(proto.clone()).or_default() += 1;
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

    #[test]
    fn test_parse_ipv4_syslog() {
        let line = "Jun 29 01:23:45 hostname kernel: [UFW BLOCK] IN=eth0 SRC=192.168.1.1 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";
        let result = parse_log_line(line, 2026);
        assert!(result.is_some());
        let (date, hour, entry) = result.unwrap();
        assert_eq!(date.to_string(), "2026-06-29");
        assert_eq!(hour, 1);
        assert_eq!(entry.src_ip, "192.168.1.1");
        assert_eq!(entry.dst_port, Some(22));
        assert_eq!(entry.protocol, Some("TCP".to_string()));
    }

    #[test]
    fn test_parse_ipv6_iso() {
        let line = "2026-06-29T14:30:00 hostname kernel: [UFW BLOCK] IN=eth0 SRC=2001:db8::1 DST=::1 PROTO=UDP SPT=123 DPT=53";
        let result = parse_log_line(line, 2026);
        assert!(result.is_some());
        let (date, hour, entry) = result.unwrap();
        assert_eq!(date.to_string(), "2026-06-29");
        assert_eq!(hour, 14);
        assert_eq!(entry.src_ip, "2001:db8::1");
        assert_eq!(entry.dst_port, Some(53));
        assert_eq!(entry.protocol, Some("UDP".to_string()));
    }

    #[test]
    fn test_skip_non_block() {
        let line = "Jun 29 01:23:45 hostname kernel: [UFW ALLOW] IN=eth0 SRC=1.2.3.4 DST=10.0.0.1 PROTO=TCP SPT=80 DPT=8080";
        assert!(parse_log_line(line, 2026).is_none());
    }

    #[test]
    fn test_skip_no_src() {
        let line = "Jun 29 01:23:45 hostname kernel: [UFW BLOCK] IN=eth0";
        assert!(parse_log_line(line, 2026).is_none());
    }

    #[test]
    fn test_parse_minimal_fields() {
        let line = "Jul  4 08:05:00 hostname kernel: [UFW BLOCK] SRC=10.0.0.1";
        let result = parse_log_line(line, 2026);
        assert!(result.is_some());
        let (_date, _hour, entry) = result.unwrap();
        assert_eq!(entry.src_ip, "10.0.0.1");
        assert!(entry.dst_port.is_none());
        assert!(entry.protocol.is_none());
    }

    #[test]
    fn test_hour_extraction() {
        let line = "2026-06-29T23:59:59 hostname kernel: [UFW BLOCK] SRC=10.0.0.1";
        let result = parse_log_line(line, 2026);
        assert!(result.is_some());
        let (_date, hour, _entry) = result.unwrap();
        assert_eq!(hour, 23);
    }

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
    fn test_syslog_single_digit_day() {
        let line = "Jul  4 08:05:00 hostname kernel: [UFW BLOCK] SRC=10.0.0.1 DPT=22 PROTO=TCP";
        let result = parse_log_line(line, 2026);
        assert!(result.is_some());
        let (date, hour, entry) = result.unwrap();
        assert_eq!(date.to_string(), "2026-07-04");
        assert_eq!(hour, 8);
        assert_eq!(entry.dst_port, Some(22));
    }

    #[test]
    fn test_fields_reordered() {
        let line = "Jun 29 01:23:45 hostname kernel: [UFW BLOCK] SRC=10.0.0.1 PROTO=TCP DPT=443";
        let result = parse_log_line(line, 2026);
        assert!(result.is_some());
        let (_date, _hour, entry) = result.unwrap();
        assert_eq!(entry.dst_port, Some(443));
        assert_eq!(entry.protocol, Some("TCP".to_string()));
    }

    #[test]
    fn test_resolve_year_rollover() {
        let today = NaiveDate::from_ymd_opt(2026, 1, 5).unwrap();
        let dec_log = NaiveDate::from_ymd_opt(2025, 12, 31).unwrap();
        let resolved = resolve_year(dec_log, today.year());
        assert_eq!(resolved.year(), 2025);
        assert_eq!(resolved, dec_log);
    }

    #[test]
    fn test_resolve_year_normal() {
        let today = NaiveDate::from_ymd_opt(2026, 6, 29).unwrap();
        let jun_log = NaiveDate::from_ymd_opt(2026, 6, 15).unwrap();
        let resolved = resolve_year(jun_log, today.year());
        assert_eq!(resolved, jun_log);
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
