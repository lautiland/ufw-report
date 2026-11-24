use std::sync::LazyLock;

use chrono::{Datelike, NaiveDate, NaiveDateTime, NaiveTime};
use regex::Regex;

use crate::models::{Direction, LogEntry};

static RE_SYSLOG_DATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(\w{3}\s+\d{1,2})\s+(\d{2}:\d{2}:\d{2})").unwrap());

static RE_ISO_DATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2}):(\d{2})").unwrap());

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

pub(crate) fn resolve_year(parsed_date: NaiveDate, today: NaiveDate) -> NaiveDate {
    let candidate = NaiveDate::from_ymd_opt(today.year(), parsed_date.month(), parsed_date.day());
    match candidate {
        Some(d) if d > today + chrono::TimeDelta::days(30) => {
            NaiveDate::from_ymd_opt(today.year() - 1, parsed_date.month(), parsed_date.day())
                .unwrap_or(parsed_date)
        }
        Some(d) => d,
        None => parsed_date,
    }
}

pub(crate) fn normalize_protocol(raw: &str) -> String {
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

pub(crate) fn parse_log_line(line: &str, today: NaiveDate) -> Option<LogEntry> {
    let line = line.trim();
    if !line.contains("[UFW BLOCK]") {
        return None;
    }

    let timestamp = if let Some(caps) = RE_ISO_DATE.captures(line) {
        let date = NaiveDate::parse_from_str(caps.get(1)?.as_str(), "%Y-%m-%d").ok()?;
        let hour: u32 = caps.get(2)?.as_str().parse().ok()?;
        let minute: u32 = caps.get(3)?.as_str().parse().ok()?;
        let second: u32 = caps.get(4)?.as_str().parse().ok()?;
        NaiveDateTime::new(date, NaiveTime::from_hms_opt(hour, minute, second)?)
    } else {
        let caps = RE_SYSLOG_DATE.captures(line)?;
        let date_part = caps.get(1)?.as_str();
        let time_part = caps.get(2)?.as_str();
        let time = NaiveTime::parse_from_str(time_part, "%H:%M:%S").ok()?;

        let mut parts = date_part.split_whitespace();
        let month_abbr = parts.next()?;
        let day_str = parts.next()?;
        let month = parse_syslog_month(month_abbr)?;
        let day: u32 = day_str.parse().ok()?;

        let date = NaiveDate::from_ymd_opt(today.year(), month, day)?;
        NaiveDateTime::new(resolve_year(date, today), time)
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

    let mut entry = LogEntry::new(timestamp, src_ip);
    entry.dst_ip = dst_ip;
    entry.src_port = src_port;
    entry.dst_port = dst_port;
    entry.protocol = protocol;
    entry.direction = direction;
    Some(entry)
}

/// Public wrapper for testing. Parses a single UFW log line.
#[must_use]
pub fn parse_log_line_standalone(line: &str, today: NaiveDate) -> Option<LogEntry> {
    parse_log_line(line, today)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn today() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 7, 10).unwrap()
    }

    #[test]
    fn test_parse_ipv4_syslog() {
        let line = "Jun 29 01:23:45 hostname kernel: [UFW BLOCK] IN=eth0 SRC=192.168.1.1 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";
        let entry = parse_log_line(line, today()).expect("line should parse");
        assert_eq!(entry.date.to_string(), "2026-06-29");
        assert_eq!(entry.hour, 1);
        assert_eq!(entry.timestamp.to_string(), "2026-06-29 01:23:45");
        assert_eq!(entry.src_ip, "192.168.1.1");
        assert_eq!(entry.dst_port, Some(22));
        assert_eq!(entry.protocol, Some("TCP".to_string()));
        assert!(entry.has_consistent_time());
    }

    #[test]
    fn test_parse_ipv6_iso() {
        let line = "2026-06-29T14:30:00 hostname kernel: [UFW BLOCK] IN=eth0 SRC=2001:db8::1 DST=::1 PROTO=UDP SPT=123 DPT=53";
        let entry = parse_log_line(line, today()).expect("line should parse");
        assert_eq!(entry.date.to_string(), "2026-06-29");
        assert_eq!(entry.hour, 14);
        assert_eq!(entry.timestamp.to_string(), "2026-06-29 14:30:00");
        assert_eq!(entry.src_ip, "2001:db8::1");
        assert_eq!(entry.dst_port, Some(53));
        assert_eq!(entry.protocol, Some("UDP".to_string()));
    }

    #[test]
    fn test_skip_non_block() {
        let line = "Jun 29 01:23:45 hostname kernel: [UFW ALLOW] IN=eth0 SRC=1.2.3.4 DST=10.0.0.1 PROTO=TCP SPT=80 DPT=8080";
        assert!(parse_log_line(line, today()).is_none());
    }

    #[test]
    fn test_skip_no_src() {
        let line = "Jun 29 01:23:45 hostname kernel: [UFW BLOCK] IN=eth0";
        assert!(parse_log_line(line, today()).is_none());
    }

    #[test]
    fn test_parse_minimal_fields() {
        let line = "Jul  4 08:05:00 hostname kernel: [UFW BLOCK] SRC=10.0.0.1";
        let entry = parse_log_line(line, today()).expect("line should parse");
        assert_eq!(entry.timestamp.to_string(), "2026-07-04 08:05:00");
        assert_eq!(entry.src_ip, "10.0.0.1");
        assert!(entry.dst_port.is_none());
        assert!(entry.protocol.is_none());
    }

    #[test]
    fn test_hour_extraction() {
        let line = "2026-06-29T23:59:59 hostname kernel: [UFW BLOCK] SRC=10.0.0.1";
        let entry = parse_log_line(line, today()).expect("line should parse");
        assert_eq!(entry.hour, 23);
        assert_eq!(entry.timestamp.to_string(), "2026-06-29 23:59:59");
    }

    #[test]
    fn test_syslog_single_digit_day() {
        let line = "Jul  4 08:05:00 hostname kernel: [UFW BLOCK] SRC=10.0.0.1 DPT=22 PROTO=TCP";
        let entry = parse_log_line(line, today()).expect("line should parse");
        assert_eq!(entry.date.to_string(), "2026-07-04");
        assert_eq!(entry.hour, 8);
        assert_eq!(entry.dst_port, Some(22));
    }

    #[test]
    fn test_fields_reordered() {
        let line = "Jun 29 01:23:45 hostname kernel: [UFW BLOCK] SRC=10.0.0.1 PROTO=TCP DPT=443";
        let entry = parse_log_line(line, today()).expect("line should parse");
        assert_eq!(entry.dst_port, Some(443));
        assert_eq!(entry.protocol, Some("TCP".to_string()));
    }

    #[test]
    fn test_iso_fractional_seconds_are_accepted() {
        let line = "2026-06-29T14:30:07.123456+00:00 hostname kernel: [UFW BLOCK] SRC=10.0.0.1";
        let entry = parse_log_line(line, today()).expect("line should parse");
        assert_eq!(entry.timestamp.to_string(), "2026-06-29 14:30:07");
    }

    #[test]
    fn test_invalid_time_is_rejected() {
        let iso = "2026-06-29T25:00:00 hostname kernel: [UFW BLOCK] SRC=10.0.0.1";
        assert!(parse_log_line(iso, today()).is_none());

        let syslog = "Jun 29 01:60:00 hostname kernel: [UFW BLOCK] SRC=10.0.0.1";
        assert!(parse_log_line(syslog, today()).is_none());
    }

    #[test]
    fn test_resolve_year_rollover() {
        let today = NaiveDate::from_ymd_opt(2026, 1, 5).unwrap();
        let dec_log = NaiveDate::from_ymd_opt(2025, 12, 31).unwrap();
        let resolved = resolve_year(dec_log, today);
        assert_eq!(resolved.year(), 2025);
        assert_eq!(resolved, dec_log);
    }

    #[test]
    fn test_resolve_year_normal() {
        let today = NaiveDate::from_ymd_opt(2026, 6, 29).unwrap();
        let jun_log = NaiveDate::from_ymd_opt(2026, 6, 15).unwrap();
        let resolved = resolve_year(jun_log, today);
        assert_eq!(resolved, jun_log);
    }

    #[test]
    fn test_resolve_year_keeps_late_december_in_current_year() {
        let today = NaiveDate::from_ymd_opt(2026, 12, 15).unwrap();
        let dec_log = NaiveDate::from_ymd_opt(2026, 12, 31).unwrap();
        let resolved = resolve_year(dec_log, today);
        assert_eq!(resolved, dec_log);
    }

    #[test]
    fn test_resolve_year_january_reads_previous_june() {
        let today = NaiveDate::from_ymd_opt(2026, 1, 5).unwrap();
        let jun_log = NaiveDate::from_ymd_opt(2026, 6, 15).unwrap();
        let resolved = resolve_year(jun_log, today);
        assert_eq!(resolved, NaiveDate::from_ymd_opt(2025, 6, 15).unwrap());
    }
}
